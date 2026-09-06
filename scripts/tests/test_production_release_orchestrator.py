from __future__ import annotations

from contextlib import contextmanager, nullcontext
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

from scripts import ga_acceptance_journal_export as journal_export
from scripts import production_release_evidence
from scripts import candidate_freeze
from scripts.publication import durable_file
from scripts.publication import ga_release_contract as contract
from scripts.publication.common import (
    PublicationError,
    canonical_json,
    sha256_bytes,
    sha256_file,
)
from scripts.release_build_identity import RETIRED_GA_WORKSPACE_PATHS
from scripts.release_executor_source import (
    ExecutorSource,
    FrozenReleaseSources,
)
from scripts.publication.ga_release_contract import (
    ACCEPTANCE_INPUT_ROOT,
    ASSURANCE_ROOT,
    CANDIDATE_ROOT,
    DMG_SET,
    GA_APP_ARTIFACT_KIND,
    GA_BUILD,
    GA_NATIVE_PRODUCTS,
    GA_ROOT,
    GA_RUNTIME_CHECKS,
    INSTALL_JOURNAL_INPUT,
    MIGRATION_JOURNAL_INPUT,
    PACKAGE_ROOT,
    PREPACKAGE_OUTPUT,
    PRODUCT_VERSION,
    RUNTIME_ACCEPTANCE_DOCUMENT,
    RUNTIME_ACCEPTANCE_INPUT,
    RUNTIME_EVIDENCE_INPUT,
    SERVICE_JOURNAL_INPUT,
    SERVICE_ENVIRONMENT_INPUT,
    SIGNED_APP,
    STAGES,
    STAGE_FILE_NAMES,
    STAGE_OUTPUTS,
    STAGE_SCHEMA_VERSIONS,
    UPDATER_SET,
    _parse_strict_json,
    _prepackage_ci_bindings,
    _record,
    _repo_relative,
    _require_hosted_ci_source_binding,
    _require_artifact_set_adapter,
    _stage_manifest,
    _tree_record,
    _validate_signing_notarization_binding,
    _validate_stage_manifest,
    _verified_acceptance_inputs,
    _verified_migration_journals,
    _verified_prepackage_inputs,
    _verified_runtime_acceptance_adapter,
    _verify_publication_adapter,
    derive_runtime_expectation,
    self_check,
    verify_stage,
)
from scripts.publication.orchestrator import (
    _publish_stage,
    seal_ga_acceptance,
    seal_prepackage,
    seal_publication,
)


FIXTURE_EXECUTOR_SOURCE = {
    "repositoryCommit": "1" * 40,
    "releaseSourceSha256": "2" * 64,
}


class StageFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        self.ga_root = self.repository.joinpath(*GA_ROOT.parts)
        self.ga_root.mkdir(parents=True)
        self.executor = ExecutorSource(
            self.repository,
            FIXTURE_EXECUTOR_SOURCE["repositoryCommit"],
            FIXTURE_EXECUTOR_SOURCE["releaseSourceSha256"],
        )
        self.candidate_source = {
            "release_source_sha256": "d" * 64,
            "repository_commit": "e" * 40,
        }

    def cleanup(self) -> None:
        self.temporary.cleanup()

    def prepackage_files(
        self, marker: str = "a", *, executor_source: dict[str, str] = FIXTURE_EXECUTOR_SOURCE
    ) -> dict[str, bytes]:
        manifest = _stage_manifest(
            "prepackage",
            {
                "candidate": {"signed_app_tree_sha256": marker * 64},
                "ci": {"sha256": "b" * 64},
                "legal_source": {"sha256": "c" * 64},
                "source": dict(self.candidate_source),
                "toolchain": {"toolchainSha256": "f" * 64},
            },
            executor_source,
        )
        return {
            "hosted-ci.json": canonical_json(
                {
                    "document": "cfw-github-hosted-ci-receipt-v3",
                    "run": {"id": 1, "run_attempt": 1},
                    "schema_version": 3,
                }
            ),
            "local-ci-lanes.json": canonical_json(
                {
                    "document": "unsigned-ci-lanes-v2",
                    "lanes": [],
                    "release_source_sha256": "d" * 64,
                    "schema_version": 2,
                    "toolchain_sha256": "f" * 64,
                }
            ),
            "manifest.json": canonical_json(manifest),
        }

    def ga_acceptance_files(
        self,
        repository: Path,
        prepackage: dict[str, object],
        executor_source: dict[str, str],
        *,
        freeze_verifier: contract.FreezeVerifier | None = None,
    ) -> dict[str, bytes]:
        del freeze_verifier
        self.assert_repository(repository)
        self.assert_stage(prepackage, "prepackage")
        manifest = _stage_manifest(
            "ga-acceptance",
            {
                "package_sets": {
                    "dmg": {"seal": {"sha256": "1" * 64}},
                    "updater": {"seal": {"sha256": "2" * 64}},
                },
                "prepackage_manifest_sha256": sha256_file(
                    self.ga_root / "prepackage/manifest.json"
                ),
                "runtime_acceptance": {"adapter": {"sha256": "3" * 64}},
            },
            executor_source,
        )
        return {"manifest.json": canonical_json(manifest)}

    def publication_files(
        self,
        repository: Path,
        prepackage: dict[str, object],
        ga_acceptance: dict[str, object],
        executor_source: dict[str, str],
        *,
        freeze_verifier: contract.FreezeVerifier | None = None,
    ) -> dict[str, bytes]:
        del freeze_verifier
        self.assert_repository(repository)
        self.assert_stage(prepackage, "prepackage")
        self.assert_stage(ga_acceptance, "ga-acceptance")
        manifest = _stage_manifest(
            "publication",
            {
                "ga_acceptance_manifest_sha256": sha256_file(
                    self.ga_root / "ga-acceptance/manifest.json"
                ),
                "legal_source": {"sha256": "c" * 64},
                "package_sets": ga_acceptance["bindings"]["package_sets"],
                "prepackage_manifest_sha256": sha256_file(
                    self.ga_root / "prepackage/manifest.json"
                ),
            },
            executor_source,
        )
        return {
            "legal-review.json": canonical_json({"status": "approved"}),
            "manifest.json": canonical_json(manifest),
            "sbom.cyclonedx.json": canonical_json({"bomFormat": "CycloneDX"}),
            "sbom.spdx.json": canonical_json({"spdxVersion": "SPDX-2.3"}),
        }

    def patches(self, prepackage_files: dict[str, bytes] | None = None):
        prepackage = prepackage_files or self.prepackage_files()
        return (
            patch(
                "scripts.publication.ga_release_contract._prepackage_files",
                return_value=prepackage,
            ),
            patch(
                "scripts.publication.ga_release_contract._ga_acceptance_files",
                side_effect=self.ga_acceptance_files,
            ),
            patch(
                "scripts.publication.ga_release_contract._publication_files",
                side_effect=self.publication_files,
            ),
        )

    def assert_repository(self, repository: Path) -> None:
        if repository != self.repository:
            raise AssertionError(f"unexpected repository: {repository}")

    @staticmethod
    def assert_stage(manifest: dict[str, object], stage: str) -> None:
        if manifest.get("stage") != stage:
            raise AssertionError(f"unexpected stage: {manifest}")


class ProductionStageIdentityTests(unittest.TestCase):
    def test_contract_is_one_ga_root_and_three_ordered_stages(self) -> None:
        self.assertEqual((PRODUCT_VERSION, GA_BUILD), ("0.4.0", "40044"))
        self.assertEqual(GA_APP_ARTIFACT_KIND, "notarized-ga-candidate-v1")
        self.assertEqual(
            GA_ROOT,
            Path("target/candidates/0.4.0/ga/40044"),
        )
        self.assertEqual(STAGES, ("prepackage", "ga-acceptance", "publication"))
        self.assertEqual(SIGNED_APP, GA_ROOT / "signed/Clash for Mac.app")
        self.assertEqual(
            GA_NATIVE_PRODUCTS,
            GA_ROOT / "signing-output/signed-native-products",
        )
        self.assertEqual(PACKAGE_ROOT, GA_ROOT / "packages")
        self.assertEqual(DMG_SET, PACKAGE_ROOT / "dmg/v0.4.0")
        self.assertEqual(UPDATER_SET, PACKAGE_ROOT / "updater/v0.4.0")

    def test_migration_journal_layout_is_owned_by_the_exporter(self) -> None:
        self.assertEqual(
            ACCEPTANCE_INPUT_ROOT,
            journal_export.ACCEPTANCE_ROOT_RELATIVE,
        )
        self.assertEqual(
            MIGRATION_JOURNAL_INPUT,
            journal_export.MIGRATION_RELATIVE,
        )
        self.assertEqual(
            INSTALL_JOURNAL_INPUT,
            journal_export.INSTALL_RELATIVE,
        )
        self.assertEqual(
            SERVICE_JOURNAL_INPUT,
            journal_export.SERVICE_RELATIVE,
        )
        self.assertEqual(
            SERVICE_ENVIRONMENT_INPUT,
            journal_export.ENVIRONMENT_RELATIVE,
        )

    def test_assurance_namespace_is_not_a_ga_stage_input(self) -> None:
        self.assertEqual(ASSURANCE_ROOT, CANDIDATE_ROOT / "assurance")
        required = " ".join(
            str(path)
            for path in (
                ACCEPTANCE_INPUT_ROOT,
                DMG_SET,
                INSTALL_JOURNAL_INPUT,
                RUNTIME_ACCEPTANCE_INPUT,
                RUNTIME_EVIDENCE_INPUT,
                SERVICE_JOURNAL_INPUT,
                UPDATER_SET,
                *STAGE_OUTPUTS.values(),
            )
        )
        for forbidden in ("physical", "performance", "99-report", "assurance"):
            self.assertNotIn(forbidden, required)

    def test_stage_status_and_authorization_are_closed(self) -> None:
        for stage in STAGES:
            manifest = _stage_manifest(stage, {"fixture": stage}, FIXTURE_EXECUTOR_SOURCE)
            validated = _validate_stage_manifest(manifest, stage)
            self.assertEqual(validated["gate_class"], "ga_required")
            self.assertEqual(validated["gate_status"], "passed")
            self.assertEqual(
                validated["ga_status"],
                "eligible" if stage == "publication" else "blocked",
            )
            self.assertEqual(
                validated["authorization"],
                {
                    "create_packages": stage == "prepackage",
                    "upload": stage == "publication",
                },
            )
            self.assertEqual(
                validated["schema_version"],
                STAGE_SCHEMA_VERSIONS[stage],
            )

    def test_old_stage_schema_is_rejected_without_compatibility(self) -> None:
        for document in (
            "validated-candidate-v2",
            "final-candidate-binding-v1",
            "sealed-evidence-manifest-v1",
        ):
            with self.subTest(document=document):
                value = _stage_manifest("prepackage", {"fixture": True}, FIXTURE_EXECUTOR_SOURCE)
                value["document"] = document
                with self.assertRaisesRegex(PublicationError, "identity or status"):
                    _validate_stage_manifest(value, "prepackage")

        for stage, old_document in (
            ("prepackage", "cfm-ga-prepackage-seal-v1"),
            ("ga-acceptance", "cfm-ga-acceptance-seal-v1"),
            ("ga-acceptance", "cfm-ga-acceptance-seal-v2"),
            ("publication", "cfm-ga-publication-seal-v1"),
            ("publication", "cfm-ga-publication-seal-v2"),
        ):
            for field, old_value in (
                ("document", old_document),
                ("schema_version", 1),
            ):
                with self.subTest(stage=stage, field=field):
                    value = _stage_manifest(stage, {"fixture": True}, FIXTURE_EXECUTOR_SOURCE)
                    value[field] = old_value
                    with self.assertRaisesRegex(
                        PublicationError,
                        "identity or status",
                    ):
                        _validate_stage_manifest(value, stage)

    def test_sealing_executor_is_required_and_has_one_closed_source_identity(self) -> None:
        malformed = (
            None,
            {},
            {"repositoryCommit": "1" * 40},
            {"repositoryCommit": "1" * 40, "releaseSourceSha256": "invalid"},
            {"repositoryCommit": "invalid", "releaseSourceSha256": "2" * 64},
            {**FIXTURE_EXECUTOR_SOURCE, "repository": "/untrusted"},
        )
        for stage in STAGES:
            manifest = _stage_manifest(stage, {"fixture": True}, FIXTURE_EXECUTOR_SOURCE)
            del manifest["executor_source"]
            with self.subTest(stage=stage, field="missing"), self.assertRaises(PublicationError):
                _validate_stage_manifest(manifest, stage)
            for identity in malformed:
                manifest["executor_source"] = identity
                with self.subTest(stage=stage, identity=identity), self.assertRaises(PublicationError):
                    _validate_stage_manifest(manifest, stage)

    def test_boolean_schema_or_integer_authorization_is_rejected(self) -> None:
        for field, value in (
            ("schema_version", True),
            ("authorization", {"create_packages": 1, "upload": 0}),
        ):
            with self.subTest(field=field):
                manifest = _stage_manifest("prepackage", {"fixture": True}, FIXTURE_EXECUTOR_SOURCE)
                manifest[field] = value
                with self.assertRaises(PublicationError):
                    _validate_stage_manifest(manifest, "prepackage")

    def test_duplicate_or_nonfinite_stage_json_is_rejected(self) -> None:
        for raw in (b'{"field":1,"field":2}\n', b'{"field":NaN}\n'):
            with self.subTest(raw=raw), self.assertRaises(PublicationError):
                _parse_strict_json(raw, Path("manifest.json"))

    def test_extreme_stage_json_failures_are_publication_errors(self) -> None:
        deeply_nested = (
            "{\"nested\":" * 10_000 + "0" + "}" * 10_000
        ).encode("ascii")
        excessive_integer = b'{"value":' + b"9" * 5_000 + b"}\n"
        for raw in (deeply_nested, excessive_integer):
            with self.subTest(size=len(raw)), self.assertRaises(PublicationError):
                _parse_strict_json(raw, Path("manifest.json"))

        with patch(
            "scripts.publication.ga_release_contract.canonical_json",
            side_effect=RecursionError("fixture canonical recursion"),
        ), self.assertRaisesRegex(PublicationError, "not canonical"):
            _parse_strict_json(b"{}\n", Path("manifest.json"))

        with self.assertRaisesRegex(PublicationError, "not canonical"):
            _parse_strict_json(
                b'{"value":"\\ud800"}\n',
                Path("manifest.json"),
            )

    def test_self_check_has_no_filesystem_side_effect(self) -> None:
        fixture = StageFixture()
        self.addCleanup(fixture.cleanup)
        self_check(fixture.repository)
        self.assertEqual(os.listdir(fixture.ga_root), [])

    def test_self_check_does_not_require_or_create_the_runtime_ga_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve(strict=True)
            self_check(repository)
            self.assertEqual(os.listdir(repository), [])


class DurableStageTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = StageFixture()
        self.addCleanup(self.fixture.cleanup)

    def test_prepackage_is_atomic_private_and_idempotent(self) -> None:
        files = self.fixture.prepackage_files()
        first = _publish_stage(self.fixture.repository, "prepackage", files)
        second = _publish_stage(self.fixture.repository, "prepackage", files)
        self.assertEqual(first, second)
        output = self.fixture.ga_root / "prepackage"
        self.assertEqual(set(os.listdir(output)), set(STAGE_FILE_NAMES["prepackage"]))
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for name in STAGE_FILE_NAMES["prepackage"]:
            self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600)
        self.assertFalse(
            any(name.startswith(".publication-pending-") for name in os.listdir(self.fixture.ga_root))
        )

    def test_immutable_stage_refuses_replacement(self) -> None:
        original = self.fixture.prepackage_files()
        _publish_stage(self.fixture.repository, "prepackage", original)
        changed = self.fixture.prepackage_files("9")
        with self.assertRaisesRegex(PublicationError, "refusing to replace"):
            _publish_stage(self.fixture.repository, "prepackage", changed)
        self.assertEqual(
            (self.fixture.ga_root / "prepackage/manifest.json").read_bytes(),
            original["manifest.json"],
        )

    def test_malformed_stage_schema_fails_before_publication(self) -> None:
        files = self.fixture.prepackage_files()
        manifest = _stage_manifest("prepackage", {"fixture": True}, FIXTURE_EXECUTOR_SOURCE)
        manifest["document"] = "validated-candidate-v2"
        files["manifest.json"] = canonical_json(manifest)
        with self.assertRaises(PublicationError):
            _publish_stage(self.fixture.repository, "prepackage", files)
        self.assertFalse((self.fixture.ga_root / "prepackage").exists())

    def test_partial_stage_write_is_cleaned_without_success(self) -> None:
        with patch(
            "scripts.publication.durable_file._write_private_pending_at",
            side_effect=PublicationError("simulated short write"),
        ):
            with self.assertRaisesRegex(PublicationError, "short write"):
                _publish_stage(
                    self.fixture.repository,
                    "prepackage",
                    self.fixture.prepackage_files(),
                )
        self.assertFalse((self.fixture.ga_root / "prepackage").exists())
        self.assertFalse(
            any(name.startswith(".publication-pending-") for name in os.listdir(self.fixture.ga_root))
        )

    def test_stage_file_addition_is_detected(self) -> None:
        _publish_stage(
            self.fixture.repository,
            "prepackage",
            self.fixture.prepackage_files(),
        )
        extra = self.fixture.ga_root / "prepackage/extra.json"
        extra.write_bytes(b"{}\n")
        extra.chmod(0o600)
        with self.assertRaises(PublicationError):
            _publish_stage(
                self.fixture.repository,
                "prepackage",
                self.fixture.prepackage_files(),
            )

    def test_parent_identity_loss_after_publish_is_outcome_unknown(self) -> None:
        real_lock = durable_file.exclusive_rooted_directory_lock
        lock_calls = 0

        @contextmanager
        def lose_reply(root: Path, directory: Path):
            nonlocal lock_calls
            lock_calls += 1
            call_number = lock_calls
            with real_lock(root, directory) as descriptor:
                yield descriptor
            if call_number == 2:
                raise durable_file.RootedDirectoryChanged("simulated parent rebind")

        with patch(
            "scripts.publication.orchestrator.exclusive_rooted_directory_lock",
            lose_reply,
        ), patch(
            "scripts.publication.ga_release_contract.exclusive_rooted_directory_lock",
            lose_reply,
        ):
            with self.assertRaises(durable_file.DurabilityOutcomeUnknown):
                _publish_stage(
                    self.fixture.repository,
                    "prepackage",
                    self.fixture.prepackage_files(),
                )
        self.assertTrue((self.fixture.ga_root / "prepackage/manifest.json").is_file())

    def test_existing_stage_rejects_a_symlinked_ga_ancestor(self) -> None:
        files = self.fixture.prepackage_files()
        _publish_stage(self.fixture.repository, "prepackage", files)
        target = self.fixture.repository / "target"
        rebound = self.fixture.repository / "rebound-target"
        os.rename(target, rebound)
        os.symlink(rebound.name, target)
        with patch(
            "scripts.publication.ga_release_contract._prepackage_files",
            return_value=files,
        ), self.assertRaisesRegex(PublicationError, "without symlinks"):
            verify_stage(self.fixture.repository, "prepackage")

    def test_stage_cannot_be_created_after_a_later_stage(self) -> None:
        publication_files = {
            "legal-review.json": canonical_json({"status": "approved"}),
            "manifest.json": canonical_json(
                _stage_manifest("publication", {"fixture": True}, FIXTURE_EXECUTOR_SOURCE)
            ),
            "sbom.cyclonedx.json": canonical_json({"bomFormat": "CycloneDX"}),
            "sbom.spdx.json": canonical_json({"spdxVersion": "SPDX-2.3"}),
        }
        _publish_stage(
            self.fixture.repository,
            "publication",
            publication_files,
        )
        with self.assertRaisesRegex(PublicationError, "after a later GA stage"):
            _publish_stage(
                self.fixture.repository,
                "prepackage",
                self.fixture.prepackage_files(),
            )


class StageOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = StageFixture()
        self.addCleanup(self.fixture.cleanup)
        live = patch(
            "scripts.publication.ga_release_contract.live_verify_hosted_ci_receipt",
            return_value={"document": "live-hosted-ci-fixture"},
        )
        self.live_hosted_ci = live.start()
        self.addCleanup(live.stop)
        for source_patch in (
            patch.object(contract, "_current_stage_executor", return_value=self.fixture.executor),
            patch.object(contract, "require_executor_unchanged"),
            patch.object(contract, "identity_at_commit", return_value=self.fixture.executor.identity),
        ):
            source_patch.start()
            self.addCleanup(source_patch.stop)

    def test_prepackage_live_checks_once_but_plain_stage_verify_is_offline(self) -> None:
        files = self.fixture.prepackage_files()
        with patch(
            "scripts.publication.ga_release_contract._prepackage_files",
            return_value=files,
        ) as compose:
            sealed = seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
            self.assertEqual(self.live_hosted_ci.call_count, 1)
            self.assertEqual(
                compose.call_args_list[0].kwargs,
                {
                    "expected_live_hosted_ci": {"document": "live-hosted-ci-fixture"},
                    "freeze_verifier": None,
                },
            )
            self.live_hosted_ci.reset_mock()
            self.assertEqual(verify_stage(self.fixture.repository, "prepackage"), sealed)
            self.live_hosted_ci.assert_not_called()

    def test_ga_acceptance_cannot_skip_prepackage(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre, ga, publication:
            with self.assertRaises(PublicationError):
                seal_ga_acceptance(self.fixture.repository, executor=self.fixture.executor)
        self.assertFalse((self.fixture.ga_root / "ga-acceptance").exists())

    def test_publication_cannot_skip_ga_acceptance(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre, ga, publication:
            seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
            with self.assertRaises(PublicationError):
                seal_publication(self.fixture.repository, executor=self.fixture.executor)
        self.assertFalse((self.fixture.ga_root / "publication").exists())

    def test_three_stages_publish_in_order_and_bind_predecessors(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre, ga, publication:
            prepackage = seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
            ga_acceptance = seal_ga_acceptance(self.fixture.repository, executor=self.fixture.executor)
            final = seal_publication(self.fixture.repository, executor=self.fixture.executor)
            self.assertEqual(verify_stage(self.fixture.repository, "publication"), final)
        self.assertEqual(prepackage["stage"], "prepackage")
        self.assertEqual(ga_acceptance["stage"], "ga-acceptance")
        self.assertEqual(final["stage"], "publication")
        self.assertEqual(
            ga_acceptance["bindings"]["prepackage_manifest_sha256"],
            sha256_file(self.fixture.ga_root / "prepackage/manifest.json"),
        )
        self.assertEqual(
            final["bindings"]["ga_acceptance_manifest_sha256"],
            sha256_file(self.fixture.ga_root / "ga-acceptance/manifest.json"),
        )
        self.assertTrue(final["authorization"]["upload"])

    def test_reopened_input_drift_invalidates_existing_stage(self) -> None:
        original = self.fixture.prepackage_files()
        with patch(
            "scripts.publication.ga_release_contract._prepackage_files",
            return_value=original,
        ):
            seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
        with patch(
            "scripts.publication.ga_release_contract._prepackage_files",
            return_value=self.fixture.prepackage_files("9"),
        ):
            with self.assertRaisesRegex(PublicationError, "reopened GA inputs"):
                verify_stage(self.fixture.repository, "prepackage")

    def test_input_drift_during_publication_never_returns_authorization(self) -> None:
        original = self.fixture.prepackage_files()
        changed = self.fixture.prepackage_files("9")
        with patch(
            "scripts.publication.ga_release_contract._prepackage_files",
            side_effect=(original, changed),
        ):
            with self.assertRaisesRegex(
                durable_file.DurabilityOutcomeUnknown,
                "post-publication input binding is unknown",
            ):
                seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
        self.assertTrue((self.fixture.ga_root / "prepackage/manifest.json").is_file())
        self.assertEqual(
            (self.fixture.ga_root / "prepackage/manifest.json").read_bytes(),
            original["manifest.json"],
        )

    def test_publication_stage_contains_only_publication_legal_copies(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre, ga, publication:
            seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
            seal_ga_acceptance(self.fixture.repository, executor=self.fixture.executor)
            manifest = seal_publication(self.fixture.repository, executor=self.fixture.executor)
        output = self.fixture.ga_root / "publication"
        self.assertEqual(set(os.listdir(output)), set(STAGE_FILE_NAMES["publication"]))
        encoded = canonical_json(manifest)
        for forbidden in (b"physical", b"performance", b"99-report", b"assurance"):
            self.assertNotIn(forbidden, encoded)


class AdapterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = StageFixture()
        self.addCleanup(self.fixture.cleanup)

    def test_prepackage_ci_records_use_fixed_repository_relative_output_paths(self) -> None:
        normalized_ci = {"toolchain_sha256": "a" * 64}
        hosted_ci = {
            "repository": {"id": 12},
            "run": {"id": 34, "run_attempt": 2},
            "workflow": {"id": 56},
        }
        expected = {
            "hosted": {
                "path": (PREPACKAGE_OUTPUT / "hosted-ci.json").as_posix(),
                "repository_id": 12,
                "run_attempt": 2,
                "run_id": 34,
                "sha256": sha256_bytes(canonical_json(hosted_ci)),
                "workflow_id": 56,
            },
            "local_deterministic": {
                "path": (PREPACKAGE_OUTPUT / "local-ci-lanes.json").as_posix(),
                "sha256": sha256_bytes(canonical_json(normalized_ci)),
                "toolchain_sha256": "a" * 64,
            },
        }
        for repository in (
            self.fixture.repository,
            self.fixture.repository / "target/release-worktrees/40044",
        ):
            with self.subTest(repository=repository):
                self.assertEqual(
                    _prepackage_ci_bindings(repository, normalized_ci, hosted_ci),
                    expected,
                )
        self.assertFalse((self.fixture.ga_root / "prepackage").exists())

    def test_evidence_path_boundary_rejects_relative_and_foreign_paths(self) -> None:
        repository = self.fixture.repository
        for path in (
            PREPACKAGE_OUTPUT / "hosted-ci.json",
            repository.parent / "foreign/hosted-ci.json",
        ):
            with self.subTest(path=path), self.assertRaisesRegex(
                PublicationError, "outside the repository"
            ):
                _repo_relative(repository, path)

    def test_hosted_ci_source_binding_requires_v3_workflow_identity(self) -> None:
        expected_source = {
            "candidate_freeze_intent_sha256": "a" * 64,
            "release_source_sha256": "b" * 64,
            "repository_commit": "c" * 40,
            "workflow_sha256": "d" * 64,
        }
        valid = {
            "source": dict(expected_source),
            "workflow": {"source": {"sha256": "d" * 64}},
        }
        arguments = {
            "candidate_freeze_intent_sha256": "a" * 64,
            "release_source_sha256": "b" * 64,
            "repository_commit": "c" * 40,
        }
        _require_hosted_ci_source_binding(valid, **arguments)

        old_source = dict(expected_source)
        old_source.pop("workflow_sha256")
        variants = (
            {"source": old_source, "workflow": valid["workflow"]},
            {
                "source": dict(expected_source),
                "workflow": {"source": {"sha256": "e" * 64}},
            },
            {
                "source": {**expected_source, "workflow_sha256": "e" * 64},
                "workflow": valid["workflow"],
            },
            {
                "source": dict(expected_source),
                "workflow": {"source": {"sha256": "invalid"}},
            },
        )
        for hosted_ci in variants:
            with self.subTest(hosted_ci=hosted_ci), self.assertRaises(
                PublicationError
            ):
                _require_hosted_ci_source_binding(hosted_ci, **arguments)

    def test_package_adapter_uses_the_fixed_ga_candidate_contract(self) -> None:
        adapter = _require_artifact_set_adapter(self.fixture.repository)

        self.assertEqual(
            adapter.CANDIDATE_APP_RELATIVE,
            "target/candidates/0.4.0/ga/40044/signed/Clash for Mac.app",
        )
        self.assertTrue(callable(adapter.verify_dmg_set))
        self.assertTrue(callable(adapter.verify_updater_set))

    def test_publication_adapter_uses_the_fixed_ga_stage_inputs(self) -> None:
        _verify_publication_adapter(self.fixture.repository)

    def test_signing_notarization_binding_rejects_every_identity_drift(self) -> None:
        transformation = {
            "pre_sign_app_manifest_sha256": "1" * 64,
            "pre_sign_app_tree_sha256": "2" * 64,
            "signed_app_tree_sha256": "3" * 64,
        }
        receipt = {
            "app_manifest_sha256": "4" * 64,
            "candidate_freeze_intent_sha256": "5" * 64,
            "post_staple_app_tree_sha256": "6" * 64,
            "pre_sign_app_manifest_sha256": "1" * 64,
            "pre_sign_app_tree_sha256": "2" * 64,
            "pre_staple_app_tree_sha256": "3" * 64,
            "signed_app_tree_sha256": "3" * 64,
            "signing_transformation_receipt_sha256": "7" * 64,
        }
        arguments = {
            "candidate_freeze_intent_sha256": "5" * 64,
            "transformation": transformation,
            "transformation_sha256": "7" * 64,
            "notarization_receipt": receipt,
            "app_manifest_tree_sha256": "6" * 64,
            "app_manifest_sha256": "4" * 64,
        }
        _validate_signing_notarization_binding(**arguments)
        for field in receipt:
            with self.subTest(field=field):
                drifted = dict(receipt)
                drifted[field] = "8" * 64
                with self.assertRaisesRegex(PublicationError, "differ"):
                    _validate_signing_notarization_binding(
                        **{**arguments, "notarization_receipt": drifted}
                    )

    def test_legacy_paths_are_rejected_even_when_the_ga_root_exists(self) -> None:
        for relative in RETIRED_GA_WORKSPACE_PATHS:
            with self.subTest(path=relative):
                fixture = StageFixture()
                try:
                    path = fixture.repository.joinpath(*relative.parts)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"legacy\n")
                    with self.assertRaisesRegex(PublicationError, "retired"):
                        _verified_prepackage_inputs(fixture.repository)
                finally:
                    fixture.cleanup()

    def test_local_all_passed_summary_cannot_replace_a_real_runtime_verifier(self) -> None:
        runtime_path = self.fixture.repository.joinpath(*RUNTIME_ACCEPTANCE_INPUT.parts)
        runtime_path.parent.mkdir(parents=True)
        runtime_path.write_bytes(
            canonical_json(
                {
                    "checks": {name: "passed" for name in GA_RUNTIME_CHECKS},
                    "document": RUNTIME_ACCEPTANCE_DOCUMENT,
                    "schema_version": 1,
                }
            )
        )
        runtime_path.chmod(0o600)
        raw_root = self.fixture.repository.joinpath(*RUNTIME_EVIDENCE_INPUT.parts)
        raw_root.mkdir()
        (raw_root / "arbitrary.txt").write_text("not runtime proof\n", encoding="utf-8")
        with self.assertRaisesRegex(PublicationError, "runtime raw evidence is invalid"):
            _verified_runtime_acceptance_adapter(
                self.fixture.repository,
                packages={
                    "dmg": {
                        "dmg_sha256": "6" * 64,
                        "gatekeeper_sha256": "7" * 64,
                        "seal": {"sha256": "8" * 64},
                    }
                },
                ga_environment_sha256="9" * 64,
                install_journal_sha256="a" * 64,
                service_journal_tree_sha256="b" * 64,
            )

    def _runtime_adapter_fixture(self) -> tuple[Path, Path]:
        adapter = self.fixture.repository.joinpath(*RUNTIME_ACCEPTANCE_INPUT.parts)
        adapter.parent.mkdir(parents=True, exist_ok=True)
        adapter.write_bytes(canonical_json({"document": RUNTIME_ACCEPTANCE_DOCUMENT}))
        adapter.chmod(0o600)
        evidence = self.fixture.repository.joinpath(*RUNTIME_EVIDENCE_INPUT.parts)
        evidence.mkdir()
        raw = evidence / "launch.json"
        raw.write_bytes(canonical_json({"status": "passed"}))
        raw.chmod(0o600)
        return adapter, evidence

    def _runtime_packages(self) -> dict[str, object]:
        return {
            "dmg": {
                "dmg_sha256": "6" * 64,
                "gatekeeper_sha256": "7" * 64,
                "seal": {"sha256": "8" * 64},
            }
        }

    def test_runtime_verifier_must_return_the_fixed_reopened_records(self) -> None:
        adapter, evidence = self._runtime_adapter_fixture()
        module = ModuleType("scripts.ga_runtime_acceptance")
        module.validate_ga_runtime_acceptance = lambda **_kwargs: {
            "adapter": _record(self.fixture.repository, adapter),
            "runtime_evidence": _tree_record(self.fixture.repository, evidence),
        }
        with patch.dict(sys.modules, {module.__name__: module}):
            result = _verified_runtime_acceptance_adapter(
                self.fixture.repository,
                packages=self._runtime_packages(),
                ga_environment_sha256="9" * 64,
                install_journal_sha256="a" * 64,
                service_journal_tree_sha256="b" * 64,
            )
        self.assertEqual(result["adapter"]["path"], RUNTIME_ACCEPTANCE_INPUT.as_posix())
        self.assertEqual(
            result["runtime_evidence"]["path"],
            RUNTIME_EVIDENCE_INPUT.as_posix(),
        )

    def test_runtime_verifier_cannot_return_a_legacy_or_caller_selected_path(self) -> None:
        _adapter, evidence = self._runtime_adapter_fixture()
        module = ModuleType("scripts.ga_runtime_acceptance")
        module.validate_ga_runtime_acceptance = lambda **_kwargs: {
            "adapter": {
                "path": "target/candidates/0.4.0/validation/runtime-acceptance.json",
                "sha256": "c" * 64,
            },
            "runtime_evidence": _tree_record(self.fixture.repository, evidence),
        }
        with patch.dict(sys.modules, {module.__name__: module}), self.assertRaisesRegex(
            PublicationError,
            "fixed adapter and raw-evidence paths",
        ):
            _verified_runtime_acceptance_adapter(
                self.fixture.repository,
                packages=self._runtime_packages(),
                ga_environment_sha256="9" * 64,
                install_journal_sha256="a" * 64,
                service_journal_tree_sha256="b" * 64,
            )

    def test_runtime_digest_drift_after_verification_is_rejected(self) -> None:
        adapter, evidence = self._runtime_adapter_fixture()
        module = ModuleType("scripts.ga_runtime_acceptance")

        def validate(**_kwargs):
            result = {
                "adapter": _record(self.fixture.repository, adapter),
                "runtime_evidence": _tree_record(self.fixture.repository, evidence),
            }
            adapter.write_bytes(canonical_json({"document": "changed-after-verification"}))
            return result

        module.validate_ga_runtime_acceptance = validate
        with patch.dict(sys.modules, {module.__name__: module}), self.assertRaisesRegex(
            PublicationError,
            "fixed adapter and raw-evidence paths",
        ):
            _verified_runtime_acceptance_adapter(
                self.fixture.repository,
                packages=self._runtime_packages(),
                ga_environment_sha256="9" * 64,
                install_journal_sha256="a" * 64,
                service_journal_tree_sha256="b" * 64,
            )

    def test_acceptance_binds_prepackage_journals_and_trusted_runtime_result(self) -> None:
        install = {
            "candidate": {
                "build_number": "40044",
                "manifest_sha256": "1" * 64,
                "release_source_sha256": "2" * 64,
                "repository_commit": "3" * 40,
                "tree_sha256": "4" * 64,
                "version": "0.4.0",
            },
            "guards": [{"after": {"closed": True}}],
            "ga_environment_sha256": "9" * 64,
            "phase": "installed",
            "previous": {
                "build_number": "40043",
                "tree_sha256": "5" * 64,
                "version": "0.4.0",
            },
        }
        service_intent = {
            "candidate": install["candidate"],
            "ga_environment_sha256": "9" * 64,
            "previous": install["previous"],
        }
        migration = {
            "candidate": install["candidate"],
            "environment": {
                "document": {"document": "cfm-ga-environment-identity-v1"},
                "record": {
                    "path": "migration/service/environment.json",
                    "sha256": "e" * 64,
                },
                "sha256": "9" * 64,
            },
            "export": {
                "intent": {"document": "cfm-ga-journal-export-intent-v1"},
                "receipt": {"document": "cfm-ga-journal-export-receipt-v1"},
                "record": {"path": "migration-journals", "sha256": "f" * 64},
            },
            "install_journal": {
                "document": install,
                "record": {"path": "dormant-install.json", "sha256": "a" * 64},
            },
            "previous": install["previous"],
            "service_journal": {
                "events": [{"phase": "recommissioned"}],
                "intent": service_intent,
                "record": {"path": "service-transaction", "sha256": "b" * 64},
            },
        }
        packages = {
            "dmg": {
                "dmg_sha256": "6" * 64,
                "gatekeeper_sha256": "7" * 64,
                "seal": {"sha256": "8" * 64},
            }
        }
        prepackage = _stage_manifest(
            "prepackage",
            {
                "candidate": {
                    "app_manifest": {"sha256": "1" * 64},
                    "signed_app": {"tree_sha256": "4" * 64},
                },
                "source": {
                    "release_source_sha256": "2" * 64,
                    "repository_commit": "3" * 40,
                },
            },
            FIXTURE_EXECUTOR_SOURCE,
        )
        with (
            patch(
                "scripts.publication.ga_release_contract._verified_migration_journals",
                return_value=migration,
            ),
            patch(
                "scripts.publication.ga_release_contract._verified_runtime_acceptance_adapter",
                return_value={
                    "adapter": {"path": "runtime-acceptance.json", "sha256": "c" * 64},
                    "runtime_evidence": {"path": "runtime-evidence", "sha256": "d" * 64},
                },
            ),
        ):
            accepted = _verified_acceptance_inputs(
                self.fixture.repository,
                prepackage,
                packages,
            )
            self.assertEqual(accepted["runtime_evidence"]["sha256"], "d" * 64)
            self.assertEqual(
                accepted["migration_journals"]["export"]["sha256"],
                "f" * 64,
            )
            self.assertEqual(accepted["ga_environment_sha256"], "9" * 64)
            install["candidate"]["tree_sha256"] = "9" * 64
            with self.assertRaises(PublicationError):
                _verified_acceptance_inputs(
                    self.fixture.repository,
                    prepackage,
                    packages,
                )


class MigrationJournalContractIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(
        os.uname().sysname == "Darwin",
        "durable rename is macOS-only",
    )
    def test_contract_reopens_the_exact_atomic_export_record(self) -> None:
        from scripts.tests.test_ga_acceptance_journal_export import (
            JournalExportFixture,
        )

        fixture = JournalExportFixture()
        self.addCleanup(fixture.cleanup)
        exported = fixture.export()

        with patch.object(
            journal_export.JournalExportPaths,
            "verification",
            return_value=fixture.paths,
        ):
            verified = _verified_migration_journals(fixture.repository)

        self.assertEqual(verified, exported)
        self.assertEqual(
            verified["export"]["record"]["path"],
            MIGRATION_JOURNAL_INPUT.as_posix(),
        )
        self.assertEqual(
            verified["environment"]["record"]["path"],
            SERVICE_ENVIRONMENT_INPUT.as_posix(),
        )

    def test_export_verification_failure_stops_before_contract_reopen(self) -> None:
        fixture = StageFixture()
        self.addCleanup(fixture.cleanup)

        with (
            patch(
                "scripts.publication.ga_release_contract."
                "verify_ga_acceptance_journal_export",
                side_effect=journal_export.GAAcceptanceJournalExportError(
                    "fixture invalid export"
                ),
            ),
            patch(
                "scripts.publication.ga_release_contract._record"
            ) as record,
            patch(
                "scripts.publication.ga_release_contract._tree_record"
            ) as tree_record,
            self.assertRaisesRegex(
                PublicationError,
                "atomic GA migration journal export is invalid",
            ),
        ):
            _verified_migration_journals(fixture.repository)

        record.assert_not_called()
        tree_record.assert_not_called()

    def test_mixed_candidate_is_rejected_before_runtime_collection(self) -> None:
        from scripts import ga_runtime_acceptance

        fixture = StageFixture()
        self.addCleanup(fixture.cleanup)
        expected_candidate = {
            "build_number": "40044",
            "manifest_sha256": "1" * 64,
            "release_source_sha256": "2" * 64,
            "repository_commit": "3" * 40,
            "tree_sha256": "4" * 64,
            "version": "0.4.0",
        }
        previous = {
            "build_number": "40043",
            "tree_sha256": "5" * 64,
            "version": "0.4.0",
        }
        prepackage = _stage_manifest(
            "prepackage",
            {
                "candidate": {
                    "app_manifest": {"sha256": "1" * 64},
                    "signed_app": {"tree_sha256": "4" * 64},
                },
                "source": {
                    "release_source_sha256": "2" * 64,
                    "repository_commit": "3" * 40,
                },
            },
            FIXTURE_EXECUTOR_SOURCE,
        )
        packages = {
            "dmg": {
                "dmg_sha256": "c" * 64,
                "gatekeeper_sha256": "d" * 64,
                "seal": {"sha256": "e" * 64},
            }
        }
        collection_path = fixture.repository.joinpath(
            *ga_runtime_acceptance.COLLECTION_RELATIVE.parts
        )

        for field, drifted_value in (
            ("manifest_sha256", "6" * 64),
            ("release_source_sha256", "7" * 64),
            ("repository_commit", "8" * 40),
            ("tree_sha256", "9" * 64),
        ):
            with self.subTest(field=field):
                mixed_candidate = {
                    **expected_candidate,
                    field: drifted_value,
                }
                migration = {
                    "candidate": mixed_candidate,
                    "environment": {
                        "document": {
                            "document": "cfm-ga-environment-identity-v1"
                        },
                        "record": {
                            "path": "environment.json",
                            "sha256": "6" * 64,
                        },
                        "sha256": "7" * 64,
                    },
                    "export": {
                        "intent": {
                            "document": "cfm-ga-journal-export-intent-v1"
                        },
                        "receipt": {
                            "document": "cfm-ga-journal-export-receipt-v1"
                        },
                        "record": {
                            "path": "migration-journals",
                            "sha256": "8" * 64,
                        },
                    },
                    "install_journal": {
                        "document": {
                            "candidate": mixed_candidate,
                            "guards": [{"after": {"closed": True}}],
                            "phase": "installed",
                            "previous": previous,
                        },
                        "record": {
                            "path": "dormant-install.json",
                            "sha256": "a" * 64,
                        },
                    },
                    "previous": previous,
                    "service_journal": {
                        "events": [{"phase": "recommissioned"}],
                        "intent": {
                            "candidate": mixed_candidate,
                            "ga_environment_sha256": "7" * 64,
                            "previous": previous,
                        },
                        "record": {
                            "path": "service-transaction",
                            "sha256": "b" * 64,
                        },
                    },
                }

                with (
                    patch(
                        "scripts.publication.ga_release_contract.verify_stage",
                        return_value=prepackage,
                    ),
                    patch(
                        "scripts.publication.ga_release_contract."
                        "_verified_package_sets",
                        return_value=packages,
                    ),
                    patch(
                        "scripts.publication.ga_release_contract."
                        "_verified_migration_journals",
                        return_value=migration,
                    ),
                    patch.object(
                        ga_runtime_acceptance,
                        "_repository",
                        return_value=fixture.repository,
                    ),
                    patch.object(
                        ga_runtime_acceptance,
                        "collect_ga_runtime_acceptance",
                    ) as collector,
                    patch.object(
                        sys,
                        "argv",
                        ["ga-runtime-acceptance", "collect"],
                    ),
                    self.assertRaisesRegex(
                        SystemExit,
                        "GA migration export targets different bytes than prepackage",
                    ),
                ):
                    ga_runtime_acceptance.main(
                        derive_runtime_expectation,
                        lambda _repository: {},
                    )

                collector.assert_not_called()
                self.assertFalse(os.path.lexists(collection_path))


class CommandBoundaryTests(unittest.TestCase):
    def test_retired_commands_are_explicitly_rejected(self) -> None:
        for command in (
            "prepare-physical-candidate-manifest",
            "seal",
            "validation",
            "final",
        ):
            with self.subTest(command=command), patch(
                "sys.stderr", new_callable=io.StringIO
            ) as stderr, self.assertRaises(SystemExit) as captured:
                production_release_evidence._arguments([command])
            self.assertEqual(captured.exception.code, 2)
            self.assertIn("is retired", stderr.getvalue())

    def test_only_three_stage_commands_and_explicit_verification_are_admitted(self) -> None:
        for stage in STAGES:
            self.assertEqual(
                production_release_evidence._arguments([stage]).command,
                stage,
            )
            arguments = production_release_evidence._arguments(["verify", stage])
            self.assertEqual((arguments.command, arguments.stage), ("verify", stage))

    def test_main_dispatches_exactly_one_stage(self) -> None:
        manifest = _stage_manifest("prepackage", {"fixture": True}, FIXTURE_EXECUTOR_SOURCE)
        freeze_verifier = Mock()
        sources = FrozenReleaseSources(
            executor=ExecutorSource(Path("/executor"), "1" * 40, "2" * 64),
            artifact=ExecutorSource(Path("/artifact"), "3" * 40, "4" * 64),
        )
        with (
            patch.object(sys, "argv", ["production_release_evidence.py", "prepackage"]),
            patch.object(production_release_evidence, "require_closed_release_runtime"),
            patch.object(
                production_release_evidence, "capture_frozen_release_sources",
                return_value=sources,
            ) as capture,
            patch.object(
                production_release_evidence, "require_frozen_sources_unchanged"
            ) as unchanged,
            patch.object(
                production_release_evidence, "frozen_candidate_verification_session",
                return_value=nullcontext(freeze_verifier),
            ) as verifier_session,
            patch(
                "scripts.publication.orchestrator.seal_prepackage",
                return_value=manifest,
            ) as prepackage,
            patch("scripts.publication.orchestrator.seal_ga_acceptance") as ga,
            patch("scripts.publication.orchestrator.seal_publication") as publication,
            patch("builtins.print"),
        ):
            production_release_evidence.main()
        prepackage.assert_called_once_with(
            production_release_evidence._repository(),
            executor=sources.executor,
            freeze_verifier=freeze_verifier,
        )
        verifier_session.assert_called_once_with(production_release_evidence._repository())
        capture.assert_called_once_with(
            Path(production_release_evidence.__file__).resolve().parent.parent
        )
        unchanged.assert_called_once_with(sources)
        ga.assert_not_called()
        publication.assert_not_called()

    def test_main_self_check_is_exactly_source_only(self) -> None:
        with (
            patch.object(
                sys,
                "argv",
                ["production_release_evidence.py", "self-check"],
            ),
            patch.object(
                production_release_evidence,
                "require_closed_release_runtime",
                side_effect=AssertionError("source-only self-check requested admission"),
            ) as admission,
            patch(
                "scripts.publication.ga_release_contract.self_check"
            ) as source_self_check,
            patch("builtins.print"),
        ):
            production_release_evidence.main()
        admission.assert_not_called()
        source_self_check.assert_called_once_with(
            Path(production_release_evidence.__file__).resolve().parent.parent
        )

    def test_dirty_executor_stops_before_any_stage_mutation(self) -> None:
        with (
            patch.object(sys, "argv", ["production_release_evidence.py", "prepackage"]),
            patch.object(production_release_evidence, "require_closed_release_runtime"),
            patch.object(
                production_release_evidence, "capture_frozen_release_sources",
                side_effect=production_release_evidence.ExecutorSourceError("dirty executor"),
            ),
            patch("scripts.publication.orchestrator.seal_prepackage") as prepackage,
            self.assertRaisesRegex(SystemExit, "dirty executor"),
        ):
            production_release_evidence.main()
        prepackage.assert_not_called()

    def test_executor_drift_after_stage_publication_is_explicitly_unknown(self) -> None:
        manifest = _stage_manifest("prepackage", {"fixture": True}, FIXTURE_EXECUTOR_SOURCE)
        with (
            patch.object(sys, "argv", ["production_release_evidence.py", "prepackage"]),
            patch.object(production_release_evidence, "require_closed_release_runtime"),
            patch.object(production_release_evidence, "capture_frozen_release_sources"),
            patch.object(
                production_release_evidence, "frozen_candidate_verification_session",
                return_value=nullcontext(Mock()),
            ),
            patch.object(
                production_release_evidence, "require_frozen_sources_unchanged",
                side_effect=production_release_evidence.ExecutorSourceError("source drift"),
            ),
            patch(
                "scripts.publication.orchestrator.seal_prepackage", return_value=manifest
            ) as prepackage,
            self.assertRaisesRegex(SystemExit, "outcome is unknown"),
        ):
            production_release_evidence.main()
        prepackage.assert_called_once()

    def test_main_reports_primary_and_verifier_cleanup_failures(self) -> None:
        fixture = StageFixture()
        self.addCleanup(fixture.cleanup)
        cause = OSError("source input became unreadable")
        primary = PublicationError("stage inputs failed")

        @contextmanager
        def session(_repository: Path):
            try:
                yield Mock()
            finally:
                raise candidate_freeze.UpdaterKeyPossessionOperationalError("timeout")

        def reject_stage(
            _repository: Path, *, executor: ExecutorSource, freeze_verifier: contract.FreezeVerifier
        ):
            del executor, freeze_verifier
            raise primary from cause

        with (
            patch.object(sys, "argv", ["production_release_evidence.py", "prepackage"]),
            patch.object(production_release_evidence, "require_closed_release_runtime"),
            patch.object(production_release_evidence, "capture_frozen_release_sources"),
            patch.object(production_release_evidence, "_repository", return_value=fixture.repository),
            patch.object(candidate_freeze, "production_embedded_verifier_session", side_effect=session),
            patch("scripts.publication.orchestrator.seal_prepackage", side_effect=reject_stage),
            patch("builtins.print") as output,
            self.assertRaises(SystemExit) as caught,
        ):
            production_release_evidence.main()

        self.assertIn("stage inputs failed", str(caught.exception))
        self.assertIn("secondary frozen candidate verifier cleanup failure", str(caught.exception))
        self.assertIn("UpdaterKeyPossessionOperationalError", str(caught.exception))
        self.assertIs(caught.exception.__cause__, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertNotIsInstance(primary, durable_file.DurabilityOutcomeUnknown)
        output.assert_not_called()

    def test_main_production_commands_remain_closed_runtime_only(self) -> None:
        commands = (
            ["prepackage"],
            ["ga-acceptance"],
            ["publication"],
            ["verify", "prepackage"],
        )
        for command in commands:
            with self.subTest(command=command), patch.object(
                sys,
                "argv",
                ["production_release_evidence.py", *command],
            ), patch.object(
                production_release_evidence,
                "require_closed_release_runtime",
                side_effect=production_release_evidence.ReleasePythonRuntimeError(
                    "fixture admission rejected"
                ),
            ) as admission, self.assertRaisesRegex(
                SystemExit, "fixture admission rejected"
            ):
                production_release_evidence.main()
            admission.assert_called_once_with()

    def test_main_rejects_broadened_self_check_shape(self) -> None:
        with patch.object(
            sys,
            "argv",
            ["production_release_evidence.py", "self-check", "--unexpected"],
        ), patch.object(
            production_release_evidence,
            "require_closed_release_runtime",
        ) as admission, patch(
            "sys.stderr", new_callable=io.StringIO
        ), self.assertRaises(SystemExit) as captured:
            production_release_evidence.main()
        self.assertEqual(captured.exception.code, 2)
        admission.assert_not_called()


if __name__ == "__main__":
    unittest.main()
