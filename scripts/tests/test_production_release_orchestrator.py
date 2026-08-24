from __future__ import annotations

from dataclasses import replace
import errno
import hashlib
import inspect
import json
import os
import subprocess
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from scripts.hash_artifact import build_manifest
from scripts.notarization_transaction import PublishedTransactionEvidence
from scripts.publication.common import (
    PublicationError,
    canonical_json,
)
from scripts.publication import durable_file
from scripts.publication.orchestrator import (
    CAPABILITY_IDS,
    FINAL_BUILD,
    PRODUCT_VERSION,
    PHYSICAL_CANDIDATE_MANIFEST,
    PHYSICAL_COLLECTOR_CANDIDATE,
    SEALED_OUTPUT,
    VALIDATION_BUILD,
    ProductionContext,
    _inner_evidence_manifest,
    _observe_signed_app_tree,
    _parse_codesign_details,
    _physical_candidate_hash_manifest,
    _physical_collector_candidate,
    _production_context,
    _publish_outputs,
    _recover_sealed_outputs,
    _require_final_inputs_unchanged,
    _require_physical_candidate_binding,
    _requirement_digest,
    _run_checked,
    prepare_physical_candidate_manifest,
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
    ci_path = "target/candidates/0.4.0/validation/40030/evidence/unsigned-ci-lanes.json"
    validation_manifest = (
        "target/candidates/0.4.0/validation/40030/signed/"
        "Clash for Mac.app.manifest.json"
    )
    receipt_path = repository / "target/notarization-receipt.json"
    return ProductionContext(
        repository=repository,
        release_environment={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
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
            ("0.4.0", "40030", "40031"),
        )
        self.assertEqual(int(FINAL_BUILD), int(VALIDATION_BUILD) + 1)
        signature = inspect.signature(seal_production_evidence)
        self.assertEqual(tuple(signature.parameters), ("repository",))

    def test_retired_validation_reviews_cannot_authorize_the_final_build(self) -> None:
        source_identity = {
            "repositoryCommit": "a" * 40,
            "releaseSourceSha256": "b" * 64,
        }
        for retired in ("40004", "40019", "40020", "40021"):
            with self.subTest(retired=retired), patch(
                "scripts.publication.orchestrator.release_tool_environment",
                return_value={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            ), patch(
                "scripts.publication.orchestrator.current_identity",
                return_value=source_identity,
            ), patch("scripts.publication.orchestrator.validate_inventory"), patch(
                "scripts.publication.orchestrator.validate_candidate_review",
                return_value={
                    "product": {"version": PRODUCT_VERSION, "build_number": retired},
                    "candidate": {},
                },
            ), self.assertRaisesRegex(
                PublicationError, "validated candidate is not exactly build 40030"
            ):
                _production_context(REPOSITORY)

    def test_cli_has_no_fixture_build_path_output_or_override_option(self) -> None:
        completed = subprocess.run(
            [
                "/bin/bash",
                "-p",
                "-c",
                'source "$1"; cfw_run_release_python_script "$2" '
                '"$2/scripts/production_release_evidence.py" --help',
                "production-release-help-test",
                str(REPOSITORY / "scripts/release_python_launcher.sh"),
                str(REPOSITORY),
            ],
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
    def test_prepare_physical_candidate_outputs_are_transactional_and_reopened(self) -> None:
        manifest = {"entries": [], "sha256": "a" * 64}
        candidate = {
            "version": PRODUCT_VERSION,
            "build_number": FINAL_BUILD,
            "app_manifest_sha256": "b" * 64,
            "signed_app_tree_sha256": "c" * 64,
            "artifact_hash_manifest_sha256": manifest["sha256"],
            "built_at": "2026-07-29T12:00:00.000000Z",
        }

        def patches(repository: Path):
            return (
                patch(
                    "scripts.publication.orchestrator._production_context",
                    return_value=_context(repository),
                ),
                patch(
                    "scripts.publication.orchestrator._physical_candidate_hash_manifest",
                    return_value=manifest,
                ),
                patch(
                    "scripts.publication.orchestrator._physical_collector_candidate",
                    return_value=candidate,
                ),
            )

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / PHYSICAL_CANDIDATE_MANIFEST.parent.parent).mkdir(
                parents=True
            )
            context_patch, manifest_patch, candidate_patch = patches(repository)
            with context_patch, manifest_patch, candidate_patch:
                self.assertEqual(
                    prepare_physical_candidate_manifest(repository), manifest
                )
                self.assertEqual(
                    json.loads((repository / PHYSICAL_CANDIDATE_MANIFEST).read_bytes()),
                    manifest,
                )
                self.assertEqual(
                    json.loads((repository / PHYSICAL_COLLECTOR_CANDIDATE).read_bytes()),
                    candidate,
                )
                self.assertEqual(
                    prepare_physical_candidate_manifest(repository), manifest
                )

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / PHYSICAL_CANDIDATE_MANIFEST.parent.parent).mkdir(
                parents=True
            )

            def fail_commit_marker(
                directory_descriptor: int,
                directory: Path,
                name: str,
                data: bytes,
            ) -> None:
                if name == PHYSICAL_COLLECTOR_CANDIDATE.name:
                    raise PublicationError("simulated commit-marker failure")
                durable_file.write_private_pending_locked(
                    directory_descriptor,
                    directory,
                    name,
                    data,
                )

            context_patch, manifest_patch, candidate_patch = patches(repository)
            with context_patch, manifest_patch, candidate_patch, patch(
                "scripts.publication.orchestrator.write_private_pending_locked",
                side_effect=fail_commit_marker,
            ), self.assertRaisesRegex(PublicationError, "commit-marker failure"):
                prepare_physical_candidate_manifest(repository)
            self.assertTrue((repository / PHYSICAL_CANDIDATE_MANIFEST).exists())
            self.assertFalse((repository / PHYSICAL_COLLECTOR_CANDIDATE).exists())
            context_patch, manifest_patch, candidate_patch = patches(repository)
            with context_patch, manifest_patch, candidate_patch:
                self.assertEqual(
                    prepare_physical_candidate_manifest(repository), manifest
                )
            self.assertTrue((repository / PHYSICAL_CANDIDATE_MANIFEST).exists())
            self.assertTrue((repository / PHYSICAL_COLLECTOR_CANDIDATE).exists())

    def test_physical_candidate_manifest_and_final_guard_reject_input_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            paths = (
                "target/candidates/0.4.0/signed/Clash for Mac.app.manifest.json",
                "target/native-dependencies/Libbox.xcframework.manifest.json",
                "target/candidates/0.4.0/signed/Clash.for.Mac_0.4.0_40031_notary.zip",
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
                "target/candidates/0.4.0/notary-attempts/release/40031/intent.json",
                b"intent\n",
            )
            _write(
                repository,
                "target/candidates/0.4.0/notary-attempts/release/40031/events/00000000.json",
                b"event\n",
            )
            first = _physical_candidate_hash_manifest(context)
            collector_candidate = _physical_collector_candidate(context, first)
            self.assertEqual(
                set(collector_candidate),
                {
                    "version",
                    "build_number",
                    "app_manifest_sha256",
                    "signed_app_tree_sha256",
                    "artifact_hash_manifest_sha256",
                    "built_at",
                },
            )
            self.assertEqual(collector_candidate["version"], "0.4.0")
            self.assertEqual(collector_candidate["build_number"], "40031")
            self.assertEqual(
                collector_candidate["artifact_hash_manifest_sha256"],
                first["sha256"],
            )
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
                    dict(os.environ),
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
                    dict(os.environ),
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
    def test_output_publication_rejects_concurrent_parent_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            parent = repository / SEALED_OUTPUT.parent
            parent.mkdir(parents=True)

            with durable_file.exclusive_directory_lock(parent):
                with self.assertRaisesRegex(PublicationError, "lock is already held"):
                    _publish_outputs(repository, {"one.json": {"passed": True}})

            self.assertFalse((repository / SEALED_OUTPUT).exists())

    def test_output_publication_rejects_intermediate_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            outside = root / "outside"
            repository.mkdir()
            outside_parent = outside / SEALED_OUTPUT.parent.relative_to("target")
            outside_parent.mkdir(parents=True)
            (repository / "target").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(PublicationError, "rooted publication directory"):
                _publish_outputs(repository, {"one.json": {"passed": True}})

            self.assertFalse((outside_parent / SEALED_OUTPUT.name).exists())

    def test_output_publication_reports_parent_replacement_as_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            parent = repository / SEALED_OUTPUT.parent
            parent.mkdir(parents=True)
            displaced = repository / "displaced-release"

            def publish_then_replace(
                parent_descriptor: int,
                parent_path: Path,
                destination_name: str,
                files: dict[str, bytes],
            ) -> None:
                durable_file.publish_private_directory_locked(
                    parent_descriptor,
                    parent_path,
                    destination_name,
                    files,
                )
                parent_path.rename(displaced)
                parent_path.mkdir(mode=0o700)

            with patch(
                "scripts.publication.orchestrator.publish_private_directory_locked",
                side_effect=publish_then_replace,
            ):
                with self.assertRaises(durable_file.DurabilityOutcomeUnknown):
                    _publish_outputs(repository, {"one.json": {"passed": True}})

            self.assertFalse((repository / SEALED_OUTPUT).exists())
            self.assertTrue((displaced / SEALED_OUTPUT.name).exists())

    def test_output_publication_reports_ancestor_rebinding_as_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            parent = repository / SEALED_OUTPUT.parent
            parent.mkdir(parents=True)
            ancestor = parent.parent
            displaced = repository / "displaced-generation"

            def publish_then_rebind_ancestor(
                parent_descriptor: int,
                parent_path: Path,
                destination_name: str,
                files: dict[str, bytes],
            ) -> None:
                durable_file.publish_private_directory_locked(
                    parent_descriptor,
                    parent_path,
                    destination_name,
                    files,
                )
                ancestor.rename(displaced)
                ancestor.mkdir(mode=0o700)
                (displaced / parent.name).rename(ancestor / parent.name)

            with patch(
                "scripts.publication.orchestrator.publish_private_directory_locked",
                side_effect=publish_then_rebind_ancestor,
            ):
                with self.assertRaises(durable_file.DurabilityOutcomeUnknown):
                    _publish_outputs(repository, {"one.json": {"passed": True}})

            self.assertTrue((repository / SEALED_OUTPUT).is_dir())
            self.assertEqual(
                (repository / SEALED_OUTPUT / "one.json").read_bytes(),
                canonical_json({"passed": True}),
            )

    def test_output_directory_is_atomic_and_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / SEALED_OUTPUT.parent).mkdir(parents=True)
            destination = _publish_outputs(repository, {"one.json": {"passed": True}})
            self.assertEqual(
                (destination / "one.json").read_bytes(),
                canonical_json({"passed": True}),
            )
            self.assertEqual(
                _publish_outputs(repository, {"one.json": {"passed": True}}),
                destination,
            )
            with self.assertRaisesRegex(PublicationError, "refusing to replace"):
                _publish_outputs(repository, {"two.json": {"passed": True}})

    def test_post_rename_durability_failure_is_recoverable_on_exact_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            parent = repository / SEALED_OUTPUT.parent
            parent.mkdir(parents=True)
            destination = repository / SEALED_OUTPUT
            parent_identity = (parent.stat().st_dev, parent.stat().st_ino)
            documents = {"one.json": {"passed": True}}
            real_full_fsync = durable_file.full_fsync

            def fail_promoted_parent(descriptor: int) -> None:
                metadata = os.fstat(descriptor)
                if (
                    stat.S_ISDIR(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == parent_identity
                    and destination.exists()
                ):
                    raise OSError(errno.EIO, "injected parent full-fsync failure")
                real_full_fsync(descriptor)

            with patch.object(
                durable_file,
                "full_fsync",
                side_effect=fail_promoted_parent,
            ):
                with self.assertRaises(durable_file.DurabilityOutcomeUnknown):
                    _publish_outputs(repository, documents)

            self.assertEqual(
                (destination / "one.json").read_bytes(),
                canonical_json({"passed": True}),
            )
            self.assertEqual(_publish_outputs(repository, documents), destination)

    def test_production_recovery_reuses_valid_seal_with_original_observation_time(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            parent = repository / SEALED_OUTPUT.parent
            parent.mkdir(parents=True)
            destination = repository / SEALED_OUTPUT
            context = _context(repository)
            physical_candidate_manifest = {"sha256": "a" * 64}
            normalized_source = {"source": "current"}
            normalized_ci = {"ci": "current"}
            descriptor = {"physical": "current"}
            original_post = {
                "app_tree_sha256": context.app_manifest["sha256"],
                "observed_at": "2026-08-24T01:00:00.000000Z",
            }
            closure_request = {"closure_request": "current"}
            closure = {"closure": "sealed"}
            inner_manifest = {"inner": "current"}
            final_request = {
                "final_request": "current",
                "post_verification": original_post,
            }
            final_binding = {"final": "sealed"}
            outer_request = {
                "product": {"version": PRODUCT_VERSION, "build_number": FINAL_BUILD},
                "commit": context.source_identity["repositoryCommit"],
                "evidence_manifest": inner_manifest,
                "p0_source": normalized_source,
                "unsigned_ci": normalized_ci,
                "signed_installed": descriptor,
                "sealed_closure": closure,
                "final_candidate": final_binding,
            }
            outer = {"outer": "sealed"}
            documents = {
                "p0-source-gates.json": normalized_source,
                "unsigned-ci-lanes.json": normalized_ci,
                "physical-evidence.json": descriptor,
                "sealed-closure.request.json": closure_request,
                "sealed-closure.json": closure,
                "final-candidate.request.json": final_request,
                "final-candidate.json": final_binding,
                "evidence-manifest.json": inner_manifest,
                "sealed-evidence-manifest.request.json": outer_request,
                "sealed-evidence-manifest.json": outer,
            }
            parent_identity = (parent.stat().st_dev, parent.stat().st_ino)
            real_full_fsync = durable_file.full_fsync

            def fail_promoted_parent(descriptor_fd: int) -> None:
                metadata = os.fstat(descriptor_fd)
                if (
                    stat.S_ISDIR(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == parent_identity
                    and destination.exists()
                ):
                    raise OSError(errno.EIO, "injected parent full-fsync failure")
                real_full_fsync(descriptor_fd)

            with patch.object(
                durable_file,
                "full_fsync",
                side_effect=fail_promoted_parent,
            ):
                with self.assertRaises(durable_file.DurabilityOutcomeUnknown):
                    _publish_outputs(repository, documents)

            def current_final_request(
                _context_value: ProductionContext,
                _physical_manifest: dict[str, object],
                _descriptor: dict[str, object],
                post_verification: dict[str, str],
            ) -> dict[str, object]:
                return {
                    "final_request": "current",
                    "post_verification": post_verification,
                }

            with patch(
                "scripts.publication.orchestrator._sealed_closure_request",
                return_value=closure_request,
            ), patch(
                "scripts.publication.orchestrator.build_sealed_closure",
                return_value=closure,
            ), patch(
                "scripts.publication.orchestrator.validate_sealed_closure",
            ), patch(
                "scripts.publication.orchestrator._inner_evidence_manifest",
                return_value=inner_manifest,
            ), patch(
                "scripts.publication.orchestrator._final_candidate_request",
                side_effect=current_final_request,
            ), patch(
                "scripts.publication.orchestrator._validated_final_binding",
                return_value=final_binding,
            ), patch(
                "scripts.publication.orchestrator._validated_outer_manifest",
                return_value=outer,
            ), patch(
                "scripts.publication.orchestrator._require_final_inputs_unchanged",
            ) as final_inputs_guard, patch(
                "scripts.publication.orchestrator._observe_signed_app_tree",
                return_value={
                    "app_tree_sha256": context.app_manifest["sha256"],
                    "observed_at": "2026-08-24T01:00:01.000000Z",
                },
            ) as observe_signed_app:
                recovered = _recover_sealed_outputs(
                    context,
                    physical_candidate_manifest,
                    normalized_source,
                    normalized_ci,
                    descriptor,
                    object(),
                )
            self.assertEqual(recovered, outer)
            final_inputs_guard.assert_called_once_with(
                context,
                physical_candidate_manifest,
            )
            observe_signed_app.assert_called_once_with(context)

            (destination / "sealed-closure.request.json").write_bytes(
                canonical_json({"closure_request": "forged"})
            )
            with patch(
                "scripts.publication.orchestrator._sealed_closure_request",
                return_value=closure_request,
            ), self.assertRaisesRegex(
                PublicationError,
                "sealed-closure request differs from current release inputs",
            ):
                _recover_sealed_outputs(
                    context,
                    physical_candidate_manifest,
                    normalized_source,
                    normalized_ci,
                    descriptor,
                    object(),
                )

    def test_existing_output_recovery_rejects_tamper_mode_and_extra_entries(self) -> None:
        mutations = {
            "tampered bytes": lambda destination: (destination / "one.json").write_bytes(
                canonical_json({"passed": False})
            ),
            "non-private file mode": lambda destination: (destination / "one.json").chmod(
                0o640
            ),
            "extra entry": lambda destination: (destination / "extra.json").write_bytes(b"{}\n"),
            "non-private directory mode": lambda destination: destination.chmod(0o750),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                (repository / SEALED_OUTPUT.parent).mkdir(parents=True)
                documents = {"one.json": {"passed": True}}
                destination = _publish_outputs(repository, documents)
                mutate(destination)

                with self.assertRaisesRegex(PublicationError, "refusing to replace"):
                    _publish_outputs(repository, documents)


if __name__ == "__main__":
    unittest.main()
