from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from scripts.hash_artifact import build_manifest
from scripts.notarization_transaction import PublishedTransactionEvidence
from scripts.publication.common import PublicationError, canonical_json
from scripts.publication.orchestrator import (
    CAPABILITY_IDS,
    FINAL_BUILD,
    PRODUCT_VERSION,
    SEALED_OUTPUT,
    VALIDATION_BUILD,
    ProductionContext,
    _inner_evidence_manifest,
    _observe_signed_app_tree,
    _parse_codesign_details,
    _physical_candidate_hash_manifest,
    _publish_outputs,
    _require_final_inputs_unchanged,
    _require_physical_candidate_binding,
    _requirement_digest,
    _run_checked,
    seal_production_evidence,
    self_check,
)
from scripts.release_capability_inventory import expected_report_contracts


REPOSITORY = Path(__file__).resolve().parent.parent.parent


def _write(repository: Path, relative: str, data: bytes = b"evidence\n") -> Path:
    path = repository / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _context(repository: Path) -> ProductionContext:
    ci_path = "target/candidates/0.4.0/validation/40002/evidence/unsigned-ci-lanes.json"
    validation_manifest = (
        "target/candidates/0.4.0/validation/40002/signed/"
        "Clash for Mac.app.manifest.json"
    )
    receipt_path = repository / "target/notarization-receipt.json"
    return ProductionContext(
        repository=repository,
        source_identity={"repositoryCommit": "a" * 40, "releaseSourceSha256": "b" * 64},
        review={
            "candidate": {
                "ci_evidence_path": ci_path,
                "app_manifest_path": validation_manifest,
            }
        },
        ci_document={"toolchain_sha256": "c" * 64},
        toolchain_metadata={},
        app_manifest={"sha256": "d" * 64},
        machine_closure={},
        publication_inventory={},
        notary_log={"jobId": "submission-id", "sha256": "f" * 64},
        gatekeeper={},
        libbox_manifest={"sha256": "e" * 64},
        transaction=PublishedTransactionEvidence(
            receipt={
                "state": "publish-ready",
                "submission_id": "submission-id",
                "archive_sha256": "f" * 64,
                "post_staple_app_tree_sha256": "d" * 64,
                "sealed_at": "2026-07-29T12:01:00.000000Z",
            },
            receipt_path=receipt_path,
            prepared_at="2026-07-29T12:00:00.000000Z",
        ),
    )


class ProductionOrchestratorIdentityTests(unittest.TestCase):
    def test_release_identity_has_no_caller_selected_builds(self) -> None:
        self.assertEqual(
            (PRODUCT_VERSION, VALIDATION_BUILD, FINAL_BUILD),
            ("0.4.0", "40002", "40003"),
        )
        signature = inspect.signature(seal_production_evidence)
        self.assertEqual(tuple(signature.parameters), ("repository",))

    def test_cli_has_no_fixture_build_path_output_or_override_option(self) -> None:
        completed = subprocess.run(
            ["python3", "-B", "scripts/production_release_evidence.py", "--help"],
            cwd=REPOSITORY,
            capture_output=True,
            text=True,
            check=True,
        )
        for forbidden in ("--fixture", "--build", "--path", "--output", "--override"):
            self.assertNotIn(forbidden, completed.stdout)

    def test_source_bound_self_check_passes(self) -> None:
        self_check(REPOSITORY)


class ProductionOrchestratorDerivationTests(unittest.TestCase):
    def test_physical_candidate_manifest_and_final_guard_reject_input_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            paths = (
                "target/candidates/0.4.0/signed/Clash for Mac.app.manifest.json",
                "target/native-dependencies/Libbox.xcframework.manifest.json",
                "target/candidates/0.4.0/signed/Clash.for.Mac_0.4.0_40003_notary.zip",
                "target/candidates/0.4.0/signed/notarization.json",
                "target/candidates/0.4.0/signed/notarization-log.json",
                "target/candidates/0.4.0/signed/gatekeeper.json",
                "target/candidates/0.4.0/release/publication/machine-closure.json",
                "target/candidates/0.4.0/release/publication/inventory.json",
                "target/candidates/0.4.0/release/publication/evidence-manifest.json",
                "target/candidates/0.4.0/release/publication/sbom.spdx.json",
                "target/candidates/0.4.0/release/publication/sbom.cyclonedx.json",
            )
            for index, relative in enumerate(paths):
                _write(repository, relative, f"evidence-{index}\n".encode())
            libbox = repository / "target/native-dependencies/Libbox.xcframework"
            _write(
                repository,
                "target/native-dependencies/Libbox.xcframework/Libbox",
                b"libbox\n",
            )
            libbox_manifest = build_manifest(libbox, algorithm="sha256-tree-v2")
            (repository / paths[1]).write_bytes(canonical_json(libbox_manifest))
            context = replace(
                _context(repository),
                libbox_manifest=libbox_manifest,
            )
            _write(
                repository,
                "target/notarization-receipt.json",
                canonical_json(context.transaction.receipt),
            )
            _write(
                repository,
                "target/candidates/0.4.0/notary-attempts/release/40003/intent.json",
                b"intent\n",
            )
            _write(
                repository,
                "target/candidates/0.4.0/notary-attempts/release/40003/events/00000000.json",
                b"event\n",
            )
            first = _physical_candidate_hash_manifest(context)
            with patch(
                "scripts.publication.orchestrator.current_identity",
                return_value=context.source_identity,
            ), patch(
                "scripts.publication.orchestrator.verify_publication_evidence"
            ):
                _require_final_inputs_unchanged(context, first)
            with patch(
                "scripts.publication.orchestrator.current_identity",
                return_value={
                    **context.source_identity,
                    "releaseSourceSha256": "0" * 64,
                },
            ), self.assertRaisesRegex(PublicationError, "source identity changed"):
                _require_final_inputs_unchanged(context, first)
            with patch(
                "scripts.publication.orchestrator.current_identity",
                return_value=context.source_identity,
            ), patch(
                "scripts.publication.orchestrator.verify_publication_evidence",
                side_effect=PublicationError("publication drift"),
            ), self.assertRaisesRegex(PublicationError, "publication inputs changed"):
                _require_final_inputs_unchanged(context, first)
            manifest_path = repository / paths[0]
            original_app_manifest = manifest_path.read_bytes()
            manifest_path.write_bytes(b"drift\n")
            second = _physical_candidate_hash_manifest(context)
            self.assertNotEqual(first["sha256"], second["sha256"])
            with patch(
                "scripts.publication.orchestrator.current_identity",
                return_value=context.source_identity,
            ), patch(
                "scripts.publication.orchestrator.verify_publication_evidence"
            ), self.assertRaisesRegex(PublicationError, "inputs changed"):
                _require_final_inputs_unchanged(context, first)
            manifest_path.write_bytes(original_app_manifest)
            (libbox / "Libbox").write_bytes(b"mutated libbox\n")
            with patch(
                "scripts.publication.orchestrator.current_identity",
                return_value=context.source_identity,
            ), patch(
                "scripts.publication.orchestrator.verify_publication_evidence"
            ), self.assertRaisesRegex(PublicationError, "libbox XCFramework differs"):
                _require_final_inputs_unchanged(context, first)
            self.assertEqual(len(first["entries"]), 16)
            self.assertFalse(any("dmg" in entry["path"] for entry in first["entries"]))
            self.assertFalse(any("updater" in entry["path"] for entry in first["entries"]))

    def test_codesign_identity_parser_rejects_missing_duplicate_and_wrong_team(self) -> None:
        valid = (
            b"Identifier=com.bill.clashformac\n"
            b"TeamIdentifier=YKUPL7Z869\n"
            b"CDHash=0123456789abcdef0123456789abcdef01234567\n"
        )
        parsed = _parse_codesign_details(valid, "host")
        self.assertEqual(parsed["Identifier"], "com.bill.clashformac")
        with self.assertRaisesRegex(PublicationError, "omit identity"):
            _parse_codesign_details(valid.replace(b"CDHash=", b"Other="), "host")
        with self.assertRaisesRegex(PublicationError, "repeat Identifier"):
            _parse_codesign_details(valid + b"Identifier=duplicate\n", "host")
        with self.assertRaisesRegex(PublicationError, "Team ID"):
            _parse_codesign_details(valid.replace(b"YKUPL7Z869", b"AAAAAAAAAA"), "host")

    def test_designated_requirement_must_be_unique(self) -> None:
        digest = _requirement_digest(b"Executable=/tmp/app\ndesignated => anchor apple\n", "host")
        self.assertEqual(len(digest), 64)
        with self.assertRaisesRegex(PublicationError, "no unique"):
            _requirement_digest(b"Executable=/tmp/app\n", "host")

    def test_inner_manifest_uses_all_nine_capabilities_and_real_report_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            report_paths = sorted({
                contract["path"] for contract in expected_report_contracts()
            })
            for index, relative in enumerate(report_paths):
                _write(repository, relative, f"report-{index}\n".encode())
            manifest = _inner_evidence_manifest(_context(repository))
            self.assertEqual(
                [capability["id"] for capability in manifest["capabilities"]],
                list(CAPABILITY_IDS),
            )
            self.assertEqual(len(manifest["capabilities"]), 9)
            self.assertEqual(len(manifest["reports"]), 99)
            self.assertNotIn("evidence_binding", json.dumps(manifest))
            report = next(
                entry
                for entry in manifest["reports"]
                if entry["id"] == "platform-command-boundary-physical-machine"
            )
            physical = repository / report["path"]
            self.assertEqual(report["sha256"], hashlib.sha256(physical.read_bytes()).hexdigest())

    def test_post_verification_performs_a_fresh_tree_v2_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            app = repository / "target/candidates/0.4.0/signed/Clash for Mac.app"
            _write(repository, app.relative_to(repository).as_posix() + "/Contents/data", b"one")
            expected = build_manifest(app, algorithm="sha256-tree-v2")["sha256"]
            context = replace(_context(repository), app_manifest={"sha256": expected})
            observation = _observe_signed_app_tree(context)
            self.assertEqual(observation["app_tree_sha256"], expected)
            (app / "Contents/data").write_bytes(b"two")
            with self.assertRaisesRegex(PublicationError, "differs"):
                _observe_signed_app_tree(context)

    def test_physical_candidate_built_at_must_equal_receipt_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            app_manifest = _write(
                repository,
                "target/candidates/0.4.0/signed/Clash for Mac.app.manifest.json",
                b"app manifest\n",
            )
            context = _context(repository)
            physical_manifest = {"sha256": "9" * 64}
            candidate = {
                "version": PRODUCT_VERSION,
                "build_number": FINAL_BUILD,
                "signed_app_tree_sha256": context.app_manifest["sha256"],
                "app_manifest_sha256": hashlib.sha256(app_manifest.read_bytes()).hexdigest(),
                "artifact_hash_manifest_sha256": physical_manifest["sha256"],
                "built_at": context.transaction.prepared_at,
            }
            _require_physical_candidate_binding(context, candidate, physical_manifest)
            candidate["built_at"] = "2026-07-29T12:00:00.000001Z"
            with self.assertRaisesRegex(PublicationError, "receipt-prepared"):
                _require_physical_candidate_binding(context, candidate, physical_manifest)


class ProductionOrchestratorProcessTests(unittest.TestCase):
    def test_bounded_runner_terminates_oversized_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(PublicationError, "output exceeds"):
                _run_checked(
                    [sys.executable, "-c", "import os; os.write(1, b'x' * 4096)"],
                    Path(temporary),
                    "oversized test",
                    timeout=5,
                    output_limit=1024,
                )

    def test_bounded_runner_timeout_kills_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            pid_path = repository / "child.pid"
            source = (
                "import pathlib, subprocess, time; "
                "p=subprocess.Popen(['/bin/sleep','30']); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(p.pid)); "
                "time.sleep(30)"
            )
            with self.assertRaisesRegex(PublicationError, "time limit"):
                _run_checked(
                    [sys.executable, "-c", source],
                    repository,
                    "timeout test",
                    timeout=0.5,
                    output_limit=1024,
                )
            child_pid = int(pid_path.read_text(encoding="utf-8"))
            for _attempt in range(100):
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                self.fail("bounded runner left its descendant alive")


class ProductionOrchestratorPublicationTests(unittest.TestCase):
    def test_output_directory_is_atomic_and_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / SEALED_OUTPUT.parent).mkdir(parents=True)
            destination = _publish_outputs(repository, {"one.json": {"passed": True}})
            self.assertEqual(
                (destination / "one.json").read_bytes(),
                canonical_json({"passed": True}),
            )
            with self.assertRaisesRegex(PublicationError, "refusing to replace"):
                _publish_outputs(repository, {"two.json": {"passed": True}})


if __name__ == "__main__":
    unittest.main()
