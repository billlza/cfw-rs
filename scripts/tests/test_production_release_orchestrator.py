from __future__ import annotations

import ast
from collections import Counter
from contextlib import ExitStack, contextmanager, nullcontext
from functools import partial
import inspect
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import DEFAULT, Mock, patch

from scripts import ga_acceptance_journal_export as journal_export
from scripts import production_release_evidence
from scripts import candidate_freeze
from scripts import github_hosted_ci_receipt as hosted_ci_receipt
from scripts.candidate_artifact_binding import CandidateBindingError
from scripts.publication import durable_file
from scripts.publication import ga_release_contract as contract
from scripts.publication import release_contract
from scripts.publication.common import (
    PublicationError,
    canonical_json,
    sha256_bytes,
    sha256_file,
)
from scripts.publication.release_app_verifier import verify_release_app
from scripts.release_app_verifier_output import (
    NotarizationCheck,
    parse_release_app_verifier_output,
)
from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY
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
                    "document": "cfw-github-hosted-ci-receipt-v5",
                    "run": {"id": 1, "run_attempt": 1},
                    "schema_version": 4,
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
        dmg_seal_marker: str = "1",
    ) -> dict[str, bytes]:
        del freeze_verifier
        self.assert_repository(repository)
        self.assert_stage(prepackage, "prepackage")
        manifest = _stage_manifest(
            "ga-acceptance",
            {
                "package_sets": {
                    "dmg": {"seal": {"sha256": dmg_seal_marker * 64}},
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
                autospec=True,
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


def write_frozen_prepackage_inputs(fixture: StageFixture) -> SimpleNamespace:
    """Write the frozen GA files that `_verified_prepackage_inputs` parses itself.

    Its other collaborators are replaced by each test.
    """

    repository = fixture.repository
    source = dict(fixture.candidate_source)
    product_input_path = repository.joinpath(*contract.PRODUCT_INPUT.parts)
    product_input_path.write_bytes(
        canonical_json(
            {
                "document": "cfm-ga-product-input-v1",
                "product": {"build_number": GA_BUILD, "version": PRODUCT_VERSION},
                "schema_version": 1,
                "source": source,
                "toolchain": {
                    name: "f" * 64
                    for name in (
                        "cargoWorkspaceSourcesTreeSha256",
                        "goModuleCacheTreeSha256",
                        "goToolchainTreeSha256",
                        "goToolsTreeSha256",
                        "nodeToolchainTreeSha256",
                        "tauriToolchainTreeSha256",
                        "toolchainSha256",
                        "uiDependenciesTreeSha256",
                        "xcodegenToolchainTreeSha256",
                    )
                },
            }
        )
    )
    intent_path = repository.joinpath(*contract.CANDIDATE_FREEZE_INTENT.parts)
    intent_path.parent.mkdir(parents=True)
    intent = {
        name: "0" * 64
        for name in (
            "allocation_ledger_sha256",
            "entitlements_tree_sha256",
            "native_products_tree_sha256",
            "pre_sign_app_tree_sha256",
            "pre_sign_tree_sha256",
            "product_input_sha256",
            "profiles_tree_sha256",
            "signing_preflight_sha256",
            "signing_plan_sha256",
            "updater_embedded_public_key_sha256",
            "updater_key_possession_proof_sha256",
            "updater_tauri_config_sha256",
        )
    }
    intent.update(
        {
            "build_number": GA_BUILD,
            "consumption_state": "candidate_frozen_consumed",
            "document": "cfm-candidate-freeze-intent-v3",
            "product_input_document_sha256": sha256_file(product_input_path),
            "product_version": PRODUCT_VERSION,
            "schema_version": 3,
            **source,
        }
    )
    intent_path.write_bytes(canonical_json(intent))
    frozen = SimpleNamespace(
        intent_path=intent_path,
        intent_sha256=sha256_file(intent_path),
        root=fixture.ga_root,
    )
    workflow = repository / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_bytes(b"name: CI\n")
    bound_source = {
        "candidate_freeze_intent_sha256": frozen.intent_sha256,
        "workflow_sha256": sha256_file(workflow),
        **source,
    }
    app_manifest_path = repository.joinpath(*contract.SIGNED_APP_MANIFEST.parts)
    app_manifest_path.parent.mkdir(parents=True)
    app_manifest_path.write_bytes(b"{}\n")
    transformation_bytes = b'{"fixture":"signing transformation"}'
    transformation_path = repository.joinpath(*contract.SIGNING_TRANSFORMATION.parts)
    transformation_path.parent.mkdir(parents=True)
    transformation_path.write_bytes(transformation_bytes)
    return SimpleNamespace(
        frozen=frozen,
        bound_source=bound_source,
        transformation_bytes=transformation_bytes,
    )


class SealedReopenFixture:
    """Real prepackage composition over the minimal frozen GA files.

    Below the contract only the evidence validators, hashing and the GitHub
    and release-app adapters are fixtures, so every composition or reopen of
    prepackage reaches the real `_validate_release_application`. Each adapter
    call records its notarization check and the stages sealed at that time.
    `events` records in order each live hosted-CI check, and for each reopen
    of the prepackage inputs its freeze proof, the binding of the app tree to
    its sealed manifest, the verifier run and the rehash of the tree.
    """

    def __init__(self, fixture: StageFixture) -> None:
        self.fixture = fixture
        inputs = write_frozen_prepackage_inputs(fixture)
        self.frozen = inputs.frozen
        self.transformation_bytes = inputs.transformation_bytes
        repository = fixture.repository
        for relative in (
            contract.NOTARY_ARCHIVE,
            contract.NOTARY_LOG,
            contract.NOTARY_RESULT,
        ):
            repository.joinpath(*relative.parts).write_bytes(b"fixture notary evidence\n")
        repository.joinpath(*contract.GATEKEEPER_EVIDENCE.parts).write_bytes(
            canonical_json({"fixture": "gatekeeper"})
        )
        self.receipt_path = fixture.ga_root / "notarization-receipt.fixture.json"
        self.receipt_path.write_bytes(b"fixture notarization receipt\n")
        self.hosted_ci = {
            "repository": {"id": 12},
            "run": {"id": 34, "run_attempt": 1},
            "source": inputs.bound_source,
            "workflow": {"id": 56, "source": {"sha256": inputs.bound_source["workflow_sha256"]}},
        }
        self.calls: list[tuple[NotarizationCheck, tuple[str, ...]]] = []
        self.events: list[str] = []
        self.live_failure: PublicationError | None = None

    def freeze_verifier(self, repository: Path) -> SimpleNamespace:
        self.fixture.assert_repository(repository)
        self.events.append("freeze")
        return self.frozen

    def live_hosted_ci(self, *_arguments: object, **_keywords: object) -> object:
        self.events.append("hosted-ci live")
        return DEFAULT

    def bind_manifest(self, *_arguments: object, **_keywords: object) -> object:
        self.events.append("bind manifest")
        return DEFAULT

    def rehash_app(self, *_arguments: object, **_keywords: object) -> object:
        self.events.append("rehash app")
        return DEFAULT

    def verify_release_app(
        self, *, repository: Path, environment: dict[str, str], notarization: NotarizationCheck
    ) -> None:
        self.fixture.assert_repository(repository)
        if environment != {"PATH": "/usr/bin:/bin"}:
            raise AssertionError(f"unexpected verifier environment: {environment}")
        sealed = tuple(
            stage
            for stage in STAGES
            if self.fixture.repository.joinpath(*STAGE_OUTPUTS[stage].parts).exists()
        )
        self.calls.append((notarization, sealed))
        self.events.append(f"verify {notarization.name}")
        if notarization is NotarizationCheck.LIVE and self.live_failure is not None:
            raise self.live_failure

    def take_calls(self) -> list[tuple[NotarizationCheck, tuple[str, ...]]]:
        calls, self.calls = self.calls, []
        return calls

    def take_events(self) -> list[str]:
        events, self.events = self.events, []
        return events

    def patches(self):
        return (
            patch.object(
                contract,
                "live_verify_hosted_ci_receipt",
                side_effect=self.live_hosted_ci,
                return_value=self.hosted_ci,
            ),
            patch.object(contract, "validate_hosted_ci_receipt_offline", return_value=self.hosted_ci),
            patch.object(
                contract,
                "validate_candidate_app_manifest",
                side_effect=self.bind_manifest,
                return_value={"algorithm": "sha256-tree-v2", "sha256": "a" * 64},
            ),
            patch.object(
                contract,
                "bundle_build_identity",
                return_value=SimpleNamespace(
                    product_version=PRODUCT_VERSION, build_version=GA_BUILD
                ),
            ),
            patch.object(contract, "_release_environment", return_value={"PATH": "/usr/bin:/bin"}),
            patch.object(contract, "verify_release_app", side_effect=self.verify_release_app),
            patch.object(
                contract,
                "validate_published_transaction_receipt",
                return_value=SimpleNamespace(
                    receipt={"fixture": "notarization"},
                    receipt_path=self.receipt_path,
                    retained_signed_app=self.fixture.repository / "retained.app",
                ),
            ),
            patch.object(
                contract,
                "verify_signing_transformation_receipt",
                return_value={"fixture": "signing transformation"},
            ),
            patch.object(
                contract,
                "canonical_signing_transformation_json",
                return_value=self.transformation_bytes,
            ),
            patch.object(contract, "_validate_signing_notarization_binding"),
            patch.object(contract, "validate_notary_files", return_value={"jobId": "fixture-job"}),
            patch.object(
                contract,
                "validate_gatekeeper_evidence",
                return_value={"target_signed_app_tree_sha256": "a" * 64},
            ),
            patch.object(
                contract,
                "_verified_legal_source_closure",
                return_value=({"tree": {"path": "legal", "sha256": "c" * 64}}, {}),
            ),
            patch.object(
                contract,
                "build_manifest",
                side_effect=self.rehash_app,
                return_value={"sha256": "a" * 64},
            ),
            patch.object(
                contract, "_ga_acceptance_files", side_effect=self.fixture.ga_acceptance_files
            ),
            patch.object(contract, "_publication_files", side_effect=self.fixture.publication_files),
        )


class ProductionStageIdentityTests(unittest.TestCase):
    def test_contract_is_one_ga_root_and_three_ordered_stages(self) -> None:
        self.assertEqual(
            (PRODUCT_VERSION, GA_BUILD),
            (ACTIVE_RELEASE_IDENTITY.product_version, ACTIVE_RELEASE_IDENTITY.ga_build),
        )
        self.assertEqual(GA_APP_ARTIFACT_KIND, "notarized-ga-candidate-v1")
        self.assertEqual(
            GA_ROOT,
            Path(f"target/candidates/{PRODUCT_VERSION}/ga/{GA_BUILD}"),
        )
        self.assertEqual(STAGES, ("prepackage", "ga-acceptance", "publication"))
        self.assertEqual(SIGNED_APP, GA_ROOT / "signed/Clash for Mac.app")
        self.assertEqual(
            GA_NATIVE_PRODUCTS,
            GA_ROOT / "signing-output/signed-native-products",
        )
        self.assertEqual(PACKAGE_ROOT, GA_ROOT / "packages")
        self.assertEqual(DMG_SET, PACKAGE_ROOT / f"dmg/v{PRODUCT_VERSION}")
        self.assertEqual(UPDATER_SET, PACKAGE_ROOT / f"updater/v{PRODUCT_VERSION}")

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
            # These compositions reopen no prepackage inputs, so reaching the
            # release-app verifier would mean a check outside that reopen.
            *(
                patch.object(
                    contract,
                    name,
                    side_effect=AssertionError(f"stage-order fixture reached {name}"),
                )
                for name in ("_release_environment", "verify_release_app")
            ),
        ):
            source_patch.start()
            self.addCleanup(source_patch.stop)

    def test_seal_live_revalidation_is_exactly_a_boolean(self) -> None:
        # A value that is not a boolean must not quietly drop the live checks.
        for value in (None, 0, 1, "true"):
            with self.subTest(value=value), patch.object(contract, "_prepackage_files") as compose:
                with self.assertRaisesRegex(PublicationError, "must be a boolean"):
                    contract.build_expected_stage_files(
                        self.fixture.repository,
                        "prepackage",
                        executor=self.fixture.executor,
                        live_revalidation=value,
                    )
                compose.assert_not_called()
        self.live_hosted_ci.assert_not_called()

    def test_prepackage_live_checks_once_but_plain_stage_verify_is_offline(self) -> None:
        files = self.fixture.prepackage_files()
        with patch(
            "scripts.publication.ga_release_contract._prepackage_files",
            return_value=files,
        ) as compose:
            sealed = seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
            self.assertEqual(self.live_hosted_ci.call_count, 1)
            # The composing reopen checks notarization live; the confirmation
            # reopens the same inputs with the sealed check.
            self.assertEqual(
                [call.kwargs for call in compose.call_args_list],
                [
                    {
                        "notarization": NotarizationCheck.LIVE,
                        "expected_live_hosted_ci": {"document": "live-hosted-ci-fixture"},
                        "freeze_verifier": None,
                    },
                    {
                        "notarization": NotarizationCheck.SEALED,
                        "expected_live_hosted_ci": None,
                        "freeze_verifier": None,
                    },
                ],
            )
            self.live_hosted_ci.reset_mock()
            compose.reset_mock()
            self.assertEqual(verify_stage(self.fixture.repository, "prepackage"), sealed)
            self.live_hosted_ci.assert_not_called()
            self.assertEqual(
                [call.kwargs for call in compose.call_args_list],
                [
                    {
                        "notarization": NotarizationCheck.SEALED,
                        "expected_live_hosted_ci": None,
                        "freeze_verifier": None,
                    }
                ],
            )

    def test_ga_acceptance_seal_makes_no_live_check(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre as compose_prepackage, ga, publication:
            seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
            self.live_hosted_ci.reset_mock()
            compose_prepackage.reset_mock()
            seal_ga_acceptance(self.fixture.repository, executor=self.fixture.executor)
        self.live_hosted_ci.assert_not_called()
        # Its composing and confirming reopens of prepackage are both sealed.
        self.assertEqual(
            [call.kwargs for call in compose_prepackage.call_args_list],
            [
                {
                    "notarization": NotarizationCheck.SEALED,
                    "expected_live_hosted_ci": None,
                    "freeze_verifier": None,
                }
            ]
            * 2,
        )
        self.assertTrue((self.fixture.ga_root / "ga-acceptance/manifest.json").is_file())

    def test_prepackage_refuses_without_the_hosted_ci_receipt(self) -> None:
        workflow = self.fixture.repository / hosted_ci_receipt.WORKFLOW_PATH
        workflow.parent.mkdir(parents=True)
        workflow.write_bytes(b"name: CI\n")
        self.fixture.ga_root.chmod(0o700)
        stage_inputs = self.fixture.repository / hosted_ci_receipt.RECEIPT_RELATIVE.parent
        stage_inputs.mkdir(mode=0o700)
        source = {
            "candidate_freeze_intent_sha256": "3" * 64,
            "release_source_sha256": self.fixture.candidate_source["release_source_sha256"],
            "repository_commit": self.fixture.candidate_source["repository_commit"],
            "workflow_sha256": sha256_bytes(b"name: CI\n"),
        }
        with patch.object(
            contract,
            "live_verify_hosted_ci_receipt",
            new=hosted_ci_receipt.verify_receipt,
        ), patch.object(
            hosted_ci_receipt, "_source_binding", return_value=source
        ), patch.object(
            hosted_ci_receipt,
            "_fetch_api_json",
            side_effect=AssertionError("a missing receipt reached GitHub"),
        ), patch.object(contract, "_prepackage_files") as compose:
            with self.assertRaisesRegex(
                PublicationError,
                "cannot inspect private pending file .*/stage-inputs/hosted-ci.json",
            ):
                seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
        compose.assert_not_called()
        self.assertFalse((self.fixture.ga_root / "prepackage").exists())

    def test_ga_acceptance_cannot_skip_prepackage(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre, ga as compose_acceptance, publication:
            with self.assertRaisesRegex(
                PublicationError, "cannot inspect private publication directory .*/prepackage"
            ):
                seal_ga_acceptance(self.fixture.repository, executor=self.fixture.executor)
        compose_acceptance.assert_not_called()
        self.assertFalse((self.fixture.ga_root / "ga-acceptance").exists())

    def test_ga_acceptance_refuses_a_prepackage_seal_that_no_longer_reopens(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre, ga, publication:
            seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
        with patch.object(
            contract, "_prepackage_files", return_value=self.fixture.prepackage_files("9")
        ), patch.object(
            contract, "_ga_acceptance_files", side_effect=self.fixture.ga_acceptance_files
        ) as compose_acceptance:
            with self.assertRaisesRegex(
                PublicationError, "sealed prepackage stage differs from reopened GA inputs"
            ):
                seal_ga_acceptance(self.fixture.repository, executor=self.fixture.executor)
        compose_acceptance.assert_not_called()
        self.assertFalse((self.fixture.ga_root / "ga-acceptance").exists())

    def test_publication_cannot_skip_ga_acceptance(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre, ga, publication as compose_publication:
            seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
            with self.assertRaisesRegex(
                PublicationError, "cannot inspect private publication directory .*/ga-acceptance"
            ):
                seal_publication(self.fixture.repository, executor=self.fixture.executor)
        compose_publication.assert_not_called()
        self.assertFalse((self.fixture.ga_root / "publication").exists())

    def test_publication_refuses_a_ga_acceptance_seal_that_no_longer_reopens(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre, ga, publication:
            seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
            seal_ga_acceptance(self.fixture.repository, executor=self.fixture.executor)
        pre, _ga, publication = self.fixture.patches()
        with pre, patch.object(
            contract,
            "_ga_acceptance_files",
            side_effect=partial(self.fixture.ga_acceptance_files, dmg_seal_marker="4"),
        ), publication as compose_publication:
            with self.assertRaisesRegex(
                PublicationError, "sealed ga-acceptance stage differs from reopened GA inputs"
            ):
                seal_publication(self.fixture.repository, executor=self.fixture.executor)
        compose_publication.assert_not_called()
        self.assertFalse((self.fixture.ga_root / "publication").exists())

    def test_publication_refuses_when_live_hosted_ci_verification_fails(self) -> None:
        pre, ga, publication = self.fixture.patches()
        with pre, ga, publication:
            seal_prepackage(self.fixture.repository, executor=self.fixture.executor)
            seal_ga_acceptance(self.fixture.repository, executor=self.fixture.executor)
        self.live_hosted_ci.reset_mock()
        self.live_hosted_ci.side_effect = hosted_ci_receipt.HostedCIReceiptError(
            "fixture retained hosted CI receipt differs from live GitHub state"
        )
        pre, ga, publication = self.fixture.patches()
        with pre as compose_prepackage, ga, publication as compose_publication:
            with self.assertRaisesRegex(
                PublicationError, "differs from live GitHub state"
            ):
                seal_publication(self.fixture.repository, executor=self.fixture.executor)
        self.live_hosted_ci.assert_called_once()
        # No reopen, and so no live notarization check, follows the refusal.
        compose_prepackage.assert_not_called()
        compose_publication.assert_not_called()
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


class NotarizationRevalidationMatrixTests(unittest.TestCase):
    """Only the prepackage and publication seals check notarization live."""

    def setUp(self) -> None:
        self.fixture = StageFixture()
        self.addCleanup(self.fixture.cleanup)
        self.reopen = SealedReopenFixture(self.fixture)
        for source_patch in (
            patch.object(contract, "_current_stage_executor", return_value=self.fixture.executor),
            patch.object(contract, "require_executor_unchanged"),
            patch.object(contract, "identity_at_commit", return_value=self.fixture.executor.identity),
            *self.reopen.patches(),
        ):
            source_patch.start()
            self.addCleanup(source_patch.stop)
        self.repository = self.fixture.repository
        self.seal = {
            "prepackage": partial(
                seal_prepackage, executor=self.fixture.executor,
                freeze_verifier=self.reopen.freeze_verifier,
            ),
            "ga-acceptance": partial(
                seal_ga_acceptance, executor=self.fixture.executor,
                freeze_verifier=self.reopen.freeze_verifier,
            ),
            "publication": partial(
                seal_publication, executor=self.fixture.executor,
                freeze_verifier=self.reopen.freeze_verifier,
            ),
        }

    @staticmethod
    def reopens(*checks: str) -> list[str]:
        """The events of one reopen of the prepackage inputs per check."""

        return [
            step
            for check in checks
            for step in ("freeze", "bind manifest", f"verify {check}", "rehash app")
        ]

    def seal_predecessors(self, stage: str) -> list[str]:
        """Seal every stage before `stage`, clear the records, list the GA root."""

        for earlier in STAGES[: STAGES.index(stage)]:
            self.seal[earlier](self.repository)
        self.reopen.take_calls()
        self.reopen.take_events()
        return sorted(os.listdir(self.fixture.ga_root))

    def assert_refused(self, stage: str, listing: list[str], message: str) -> BaseException:
        """Require that sealing `stage` fails with `message` and writes nothing."""

        with self.assertRaisesRegex(PublicationError, message) as refused:
            self.seal[stage](self.repository)
        self.assertEqual(sorted(os.listdir(self.fixture.ga_root)), listing)
        return refused.exception

    def swap_app_until_a_live_check_passes(self) -> None:
        """Put another app at the fixed path until a live check has passed."""

        sealed_tree = contract.validate_candidate_app_manifest.return_value["sha256"]
        tree = ["e" * 64]
        verifier = contract.verify_release_app.side_effect

        def bind_current_tree(*arguments: object, **keywords: object) -> object:
            bound = self.reopen.bind_manifest(*arguments, **keywords)
            if tree[0] != sealed_tree:
                raise CandidateBindingError("fixture app tree differs from its manifest")
            return bound

        def verify_then_restore(
            *, repository: Path, environment: dict[str, str], notarization: NotarizationCheck
        ) -> None:
            verifier(repository=repository, environment=environment, notarization=notarization)
            if notarization is NotarizationCheck.LIVE:
                tree[0] = sealed_tree

        def rehash_current_tree(*arguments: object, **keywords: object) -> dict[str, str]:
            self.reopen.rehash_app(*arguments, **keywords)
            return {"sha256": tree[0]}

        contract.validate_candidate_app_manifest.side_effect = bind_current_tree
        contract.verify_release_app.side_effect = verify_then_restore
        contract.build_manifest.side_effect = rehash_current_tree

    def change_app_after_the_live_check(self) -> None:
        """Leave another app at the fixed path once a live check has passed."""

        verifier = contract.verify_release_app.side_effect

        def verify_then_change(
            *, repository: Path, environment: dict[str, str], notarization: NotarizationCheck
        ) -> None:
            verifier(repository=repository, environment=environment, notarization=notarization)
            if notarization is NotarizationCheck.LIVE:
                contract.build_manifest.return_value = {"sha256": "e" * 64}

        contract.verify_release_app.side_effect = verify_then_change

    def test_each_seal_and_reopen_selects_its_notarization_check(self) -> None:
        live, sealed = NotarizationCheck.LIVE, NotarizationCheck.SEALED
        prepackage = ("prepackage",)
        acceptance = ("prepackage", "ga-acceptance")
        complete = ("prepackage", "ga-acceptance", "publication")
        # The composing reopen is the seal's one live check; the confirmation
        # after the stage exists is sealed like every other reopen.
        self.seal["prepackage"](self.repository)
        self.assertEqual(self.reopen.take_calls(), [(live, ()), (sealed, prepackage)])
        self.seal["ga-acceptance"](self.repository)
        self.assertEqual(self.reopen.take_calls(), [(sealed, prepackage), (sealed, acceptance)])
        # Its first reopen of prepackage is the publication seal's one live
        # check; its reopen of ga-acceptance and the confirmation are sealed.
        self.seal["publication"](self.repository)
        self.assertEqual(
            self.reopen.take_calls(),
            [(live, acceptance), (sealed, acceptance), (sealed, complete), (sealed, complete)],
        )
        for stage, count in (("prepackage", 1), ("ga-acceptance", 1), ("publication", 2)):
            verify_stage(self.repository, stage, freeze_verifier=self.reopen.freeze_verifier)
            self.assertEqual(self.reopen.take_calls(), [(sealed, complete)] * count, stage)

    def test_every_check_runs_between_the_two_hashes_of_the_app(self) -> None:
        # A check vouches only for the app tree its reopen binds to the sealed
        # manifest before it and rehashes after it: the live check asks
        # stapler and Gatekeeper about the tree those equal hashes bracket,
        # and the sealed check asks neither because the stapled ticket is part
        # of that tree. Hosted CI is checked live once, before any reopen.
        self.seal["prepackage"](self.repository)
        self.assertEqual(
            self.reopen.take_events(), ["hosted-ci live", *self.reopens("LIVE", "SEALED")]
        )
        self.seal["ga-acceptance"](self.repository)
        self.assertEqual(self.reopen.take_events(), self.reopens("SEALED", "SEALED"))
        self.seal["publication"](self.repository)
        self.assertEqual(
            self.reopen.take_events(),
            ["hosted-ci live", *self.reopens("LIVE", "SEALED", "SEALED", "SEALED")],
        )
        verify_stage(self.repository, "publication", freeze_verifier=self.reopen.freeze_verifier)
        self.assertEqual(self.reopen.take_events(), self.reopens("SEALED", "SEALED"))

    def test_prepackage_seal_never_vouches_live_for_swapped_bytes(self) -> None:
        # The other app is gone again once a live check passes, so only a
        # binding before that check can notice it.
        listing = self.seal_predecessors("prepackage")
        self.swap_app_until_a_live_check_passes()
        self.assert_refused("prepackage", listing, "signed GA app manifest is invalid")
        self.assertEqual(self.reopen.take_calls(), [])
        self.assertEqual(self.reopen.take_events(), ["hosted-ci live", "freeze", "bind manifest"])

    def test_publication_seal_never_vouches_live_for_swapped_bytes(self) -> None:
        listing = self.seal_predecessors("publication")
        self.swap_app_until_a_live_check_passes()
        self.assert_refused("publication", listing, "signed GA app manifest is invalid")
        self.assertEqual(self.reopen.take_calls(), [])
        self.assertEqual(self.reopen.take_events(), ["hosted-ci live", "freeze", "bind manifest"])

    def test_prepackage_seal_refuses_an_app_changed_after_its_live_check(self) -> None:
        listing = self.seal_predecessors("prepackage")
        self.change_app_after_the_live_check()
        self.assert_refused(
            "prepackage", listing, "signed GA application changed during prepackage"
        )
        self.assertEqual(self.reopen.take_calls(), [(NotarizationCheck.LIVE, ())])
        self.assertEqual(self.reopen.take_events(), ["hosted-ci live", *self.reopens("LIVE")])

    def test_publication_seal_refuses_an_app_changed_after_its_live_check(self) -> None:
        listing = self.seal_predecessors("publication")
        self.change_app_after_the_live_check()
        self.assert_refused(
            "publication", listing, "signed GA application changed during prepackage"
        )
        self.assertEqual(
            self.reopen.take_calls(),
            [(NotarizationCheck.LIVE, ("prepackage", "ga-acceptance"))],
        )
        self.assertEqual(self.reopen.take_events(), ["hosted-ci live", *self.reopens("LIVE")])

    def test_prepackage_seal_refuses_when_the_live_check_fails(self) -> None:
        listing = self.seal_predecessors("prepackage")
        failure = PublicationError("release app verifier failed with exit code 1")
        self.reopen.live_failure = failure
        refused = self.assert_refused("prepackage", listing, "failed with exit code 1")
        self.assertIs(refused, failure)
        self.assertEqual(self.reopen.take_calls(), [(NotarizationCheck.LIVE, ())])
        # The check failed inside the composing reopen, after the binding.
        self.assertEqual(
            self.reopen.take_events(), ["hosted-ci live", "freeze", "bind manifest", "verify LIVE"]
        )

    def test_publication_seal_refuses_when_the_live_check_fails(self) -> None:
        listing = self.seal_predecessors("publication")
        failure = PublicationError("release app verifier failed with exit code 1")
        self.reopen.live_failure = failure
        refused = self.assert_refused("publication", listing, "failed with exit code 1")
        self.assertIs(refused, failure)
        self.assertEqual(
            self.reopen.take_calls(),
            [(NotarizationCheck.LIVE, ("prepackage", "ga-acceptance"))],
        )
        self.assertEqual(
            self.reopen.take_events(), ["hosted-ci live", "freeze", "bind manifest", "verify LIVE"]
        )
        # The sealed stages still reopen offline after the refusal.
        verify_stage(self.repository, "ga-acceptance", freeze_verifier=self.reopen.freeze_verifier)
        self.assertEqual(
            [check for check, _sealed in self.reopen.take_calls()],
            [NotarizationCheck.SEALED],
        )

    def test_reopen_refuses_an_app_that_changed_after_the_sealed_check(self) -> None:
        self.seal["prepackage"](self.repository)
        self.reopen.take_calls()
        contract.build_manifest.return_value = {"sha256": "b" * 64}
        with self.assertRaisesRegex(
            PublicationError, "signed GA application changed during prepackage"
        ):
            verify_stage(
                self.repository, "prepackage", freeze_verifier=self.reopen.freeze_verifier
            )
        self.assertEqual(
            [check for check, _sealed in self.reopen.take_calls()],
            [NotarizationCheck.SEALED],
        )


RELEASE_SCRIPTS = Path(__file__).resolve().parents[1]
GA_CONTRACT_SOURCE = "publication/ga_release_contract.py"
CHECK_DEFINITION_SOURCE = "release_app_verifier_output.py"
# The calls that run the release-app verifier with a check their caller chose.
VERIFIER_RUNS = frozenset({"_validate_release_application", "verify_release_app"})


def _names_notarization_check(node: ast.AST) -> bool:
    return (isinstance(node, ast.Name) and node.id == "NotarizationCheck") or (
        isinstance(node, ast.Attribute) and node.attr == "NotarizationCheck"
    )


def _requires_keyword(function: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    arguments = function.args
    return any(
        argument.arg == name and default is None
        for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults)
    )


def _rebinds(function: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    """Whether anything in `function` but its own parameter binds `name`."""

    own = {id(node) for node in ast.walk(function.args) if isinstance(node, ast.arg)}
    for node in ast.walk(function):
        if isinstance(node, ast.Name):
            bound = node.id == name and not isinstance(node.ctx, ast.Load)
        elif isinstance(node, ast.arg):
            bound = node.arg == name and id(node) not in own
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound = node is not function and node.name == name
        elif isinstance(node, ast.alias):
            bound = (node.asname or node.name.partition(".")[0]) == name
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound = name in node.names
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            bound = node.name == name
        elif isinstance(node, ast.MatchMapping):
            bound = node.rest == name
        else:
            bound = False
        if bound:
            return True
    return False


class NotarizationCheckUses(ast.NodeVisitor):
    """Where the release-tool sources choose a notarization check or run the verifier.

    `runs` counts each direct call of a name in VERIFIER_RUNS by (source,
    scope, callee, check). Its check is the member `LIVE` or `SEALED` named
    in the call; `parameter` when the innermost enclosing function passes on
    its own required `notarization` keyword and binds that name nowhere else;
    `unbound` without exactly one explicit `notarization=` keyword or with
    unpacked arguments; and `other` otherwise. `members` counts each
    `NotarizationCheck.LIVE` and `.SEALED` by (source, scope, member); a
    parameter default counts in the scope `<function>.<defaults>`.
    `violations` lists, outside the module that defines the check, each import
    alias of these names, each reference to a verifier run that is not a
    direct call, and each use of the check other than one of its two members,
    an annotation or the class of an `isinstance` test.
    """

    def __init__(self) -> None:
        self.runs: Counter[tuple[str, str, str, str]] = Counter()
        self.members: Counter[tuple[str, str, str]] = Counter()
        self.violations: list[tuple[str, int, str]] = []
        self._source = ""
        self._scopes: list[tuple[str, ast.AST]] = []
        self._direct: set[int] = set()
        self._annotations = 0

    @classmethod
    def of_release_scripts(cls) -> NotarizationCheckUses:
        uses = cls()
        for path in sorted(RELEASE_SCRIPTS.rglob("*.py")):
            source = path.relative_to(RELEASE_SCRIPTS).as_posix()
            text = path.read_text(encoding="utf-8")
            if not source.startswith("tests/") and any(
                name in text for name in ("NotarizationCheck", *VERIFIER_RUNS)
            ):
                uses.scan(source, ast.parse(text, filename=source))
        return uses

    def scan(self, source: str, tree: ast.AST) -> None:
        self._source = source
        self._direct = set()
        self.visit(tree)

    def _scope(self) -> str:
        return ".".join(name for name, _node in self._scopes) or "<module>"

    def _visit_annotation(self, node: ast.expr | None) -> None:
        if node is not None:
            self._annotations += 1
            self.visit(node)
            self._annotations -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._scopes.append((node.name, node))
        self.visit(node.args)
        self._visit_annotation(node.returns)
        for statement in node.body:
            self.visit(statement)
        self._scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(expression)
        self._scopes.append((node.name, node))
        for statement in node.body:
            self.visit(statement)
        self._scopes.pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._scopes.append(("<lambda>", node))
        self.visit(node.args)
        self.visit(node.body)
        self._scopes.pop()

    def _visit_comprehension(self, node: ast.expr) -> None:
        self._scopes.append(("<comprehension>", node))
        self.generic_visit(node)
        self._scopes.pop()

    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _visit_comprehension

    def visit_arguments(self, node: ast.arguments) -> None:
        for argument in (*node.posonlyargs, *node.args, node.vararg, *node.kwonlyargs, node.kwarg):
            if argument is not None:
                self._visit_annotation(argument.annotation)
        self._scopes.append(("<defaults>", node))
        for default in (*node.defaults, *node.kw_defaults):
            if default is not None:
                self.visit(default)
        self._scopes.pop()

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.target)
        self._visit_annotation(node.annotation)
        if node.value is not None:
            self.visit(node.value)

    def _check(self, call: ast.Call) -> str:
        values = [keyword.value for keyword in call.keywords if keyword.arg == "notarization"]
        if (
            len(values) != 1
            or any(keyword.arg is None for keyword in call.keywords)
            or any(isinstance(argument, ast.Starred) for argument in call.args)
        ):
            return "unbound"
        value = values[0]
        if (
            isinstance(value, ast.Attribute)
            and value.attr in {"LIVE", "SEALED"}
            and _names_notarization_check(value.value)
        ):
            return value.attr
        function = self._scopes[-1][1] if self._scopes else None
        if (
            isinstance(value, ast.Name)
            and value.id == "notarization"
            and isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
            and _requires_keyword(function, "notarization")
            and not _rebinds(function, "notarization")
        ):
            return "parameter"
        return "other"

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            callee = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee = node.func.attr
        else:
            callee = None
        if callee in VERIFIER_RUNS:
            self._direct.add(id(node.func))
            self.runs[(self._source, self._scope(), callee, self._check(node))] += 1
        elif callee == "isinstance" and len(node.args) == 2:
            if _names_notarization_check(node.args[1]):
                self._direct.add(id(node.args[1]))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in {"LIVE", "SEALED"} and _names_notarization_check(node.value):
            self._direct.add(id(node.value))
            self.members[(self._source, self._scope(), node.attr)] += 1
        self._reference(node, node.attr)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self._reference(node, node.id)

    def _reference(self, node: ast.expr, name: str) -> None:
        if id(node) in self._direct or self._source == CHECK_DEFINITION_SOURCE:
            return
        if name in VERIFIER_RUNS or (name == "NotarizationCheck" and not self._annotations):
            self.violations.append((self._source, node.lineno, name))

    def visit_alias(self, node: ast.alias) -> None:
        name = node.name.rpartition(".")[2]
        if (name == "NotarizationCheck" or name in VERIFIER_RUNS) and node.asname not in (
            None,
            name,
        ):
            self.violations.append((self._source, node.lineno, name))


class SealedNotarizationCallSiteTests(unittest.TestCase):
    """Only a reopen that hashes the app around the verifier may skip its live checks."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.uses = NotarizationCheckUses.of_release_scripts()

    def test_only_the_bracketed_prepackage_reopen_runs_the_ga_app_verifier(self) -> None:
        # In the contract the verifier runs only inside the reopen that binds
        # the app tree to its sealed manifest before it and rehashes it after,
        # with the check that reopen's caller chose; elsewhere it runs live.
        self.assertEqual(
            self.uses.runs,
            Counter(
                {
                    (
                        GA_CONTRACT_SOURCE,
                        "_verified_prepackage_inputs",
                        "_validate_release_application",
                        "parameter",
                    ): 1,
                    (
                        GA_CONTRACT_SOURCE,
                        "_validate_release_application",
                        "verify_release_app",
                        "parameter",
                    ): 1,
                    ("publication/preparer.py", "prepare", "verify_release_app", "LIVE"): 1,
                }
            ),
        )

    def test_only_the_contract_reopens_choose_the_sealed_check(self) -> None:
        # The contract maps a seal's live revalidation to the check of its
        # first reopen of prepackage and reopens everything else sealed.
        self.assertEqual(
            Counter(
                {
                    member: count
                    for member, count in self.uses.members.items()
                    if member[0] == GA_CONTRACT_SOURCE
                }
            ),
            Counter(
                {
                    (GA_CONTRACT_SOURCE, "_compose_stage_files", "LIVE"): 1,
                    (GA_CONTRACT_SOURCE, "_compose_stage_files", "SEALED"): 1,
                    (GA_CONTRACT_SOURCE, "_reopen_stage_files", "SEALED"): 1,
                    (GA_CONTRACT_SOURCE, "verify_stage", "SEALED"): 1,
                }
            ),
        )
        # Besides the parser that defines it, only the adapter that turns it
        # into the verifier's flag names the sealed check.
        self.assertEqual(
            Counter(
                {
                    member: count
                    for member, count in self.uses.members.items()
                    if member[2] == "SEALED"
                    and member[0] not in {GA_CONTRACT_SOURCE, CHECK_DEFINITION_SOURCE}
                }
            ),
            Counter({("publication/release_app_verifier.py", "verify_release_app", "SEALED"): 1}),
        )
        self.assertEqual(self.uses.violations, [])

    def test_reopen_chain_and_verifier_require_their_check_without_a_default(self) -> None:
        for function, name, annotation in (
            (contract._reopen_stage_files, "notarization", "NotarizationCheck"),
            (contract._verify_stage, "notarization", "NotarizationCheck"),
            (contract._prepackage_files, "notarization", "NotarizationCheck"),
            (_verified_prepackage_inputs, "notarization", "NotarizationCheck"),
            (contract._validate_release_application, "notarization", "NotarizationCheck"),
            (verify_release_app, "notarization", "NotarizationCheck"),
            (parse_release_app_verifier_output, "notarization", "NotarizationCheck"),
            (contract._compose_stage_files, "live_revalidation", "bool"),
            (contract.build_expected_stage_files, "live_revalidation", "bool"),
        ):
            with self.subTest(function=function.__name__, parameter=name):
                parameters = inspect.signature(function).parameters
                self.assertIs(parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
                self.assertIs(parameters[name].default, inspect.Parameter.empty)
                self.assertEqual(parameters[name].annotation, annotation)
                self.assertNotIn(
                    inspect.Parameter.VAR_KEYWORD,
                    {parameter.kind for parameter in parameters.values()},
                )
        # No seal and no verification can name a check for its reopens.
        for function in (
            seal_prepackage,
            seal_ga_acceptance,
            seal_publication,
            contract.build_expected_stage_files,
            verify_stage,
            contract.verify_prepackage_authorization,
            contract.verify_publication_authorization,
            derive_runtime_expectation,
        ):
            with self.subTest(function=function.__name__):
                parameters = inspect.signature(function).parameters
                self.assertNotIn("notarization", parameters)
                self.assertNotIn(
                    inspect.Parameter.VAR_KEYWORD,
                    {parameter.kind for parameter in parameters.values()},
                )

    def test_the_scan_classifies_each_way_to_choose_or_run_a_check(self) -> None:
        def scan(source: str) -> NotarizationCheckUses:
            uses = NotarizationCheckUses()
            uses.scan("fixture.py", ast.parse(source))
            return uses

        for source, scope, check in (
            (
                "def run(*, notarization):\n    verify_release_app(notarization=notarization)",
                "run",
                "parameter",
            ),
            (
                "def run(*, notarization=None):\n    verify_release_app(notarization=notarization)",
                "run",
                "other",
            ),
            (
                "def run(*, notarization):\n"
                "    notarization = NotarizationCheck.LIVE\n"
                "    verify_release_app(notarization=notarization)",
                "run",
                "other",
            ),
            (
                "def run(*, notarization):\n"
                "    return lambda: verify_release_app(notarization=notarization)",
                "run.<lambda>",
                "other",
            ),
            ("verify_release_app(**arguments)", "<module>", "unbound"),
            (
                "verify_release_app(*arguments, notarization=NotarizationCheck.LIVE)",
                "<module>",
                "unbound",
            ),
            (
                "contract._validate_release_application(notarization=NotarizationCheck.SEALED)",
                "<module>",
                "SEALED",
            ),
        ):
            with self.subTest(source=source):
                (run,) = scan(source).runs
                self.assertEqual((run[1], run[3]), (scope, check))
        self.assertEqual(
            scan("def run(*, notarization=NotarizationCheck.SEALED):\n    pass").members,
            Counter({("fixture.py", "run.<defaults>", "SEALED"): 1}),
        )
        direct = scan(
            "from scripts.release_app_verifier_output import NotarizationCheck\n"
            "def live(check: NotarizationCheck) -> bool:\n"
            "    return isinstance(check, NotarizationCheck) and check is NotarizationCheck.LIVE\n"
        )
        self.assertEqual(direct.members, Counter({("fixture.py", "live", "LIVE"): 1}))
        self.assertEqual(direct.violations, [])
        for source in (
            "from scripts.release_app_verifier_output import NotarizationCheck as Check",
            "from scripts.publication.release_app_verifier import verify_release_app as run",
            "run = partial(verify_release_app, notarization=NotarizationCheck.LIVE)",
            "run = contract._validate_release_application",
            "check = NotarizationCheck('sealed')",
            "check = NotarizationCheck['SEALED']",
            "check = getattr(NotarizationCheck, 'SEALED')",
            "checks = [check for check in NotarizationCheck]",
            "checks = NotarizationCheck.__members__",
            "Check = NotarizationCheck",
        ):
            with self.subTest(source=source):
                self.assertNotEqual(scan(source).violations, [])


class AdapterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = StageFixture()
        self.addCleanup(self.fixture.cleanup)

    def test_prepackage_ci_records_use_fixed_repository_relative_output_paths(self) -> None:
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
        }
        for repository in (
            self.fixture.repository,
            self.fixture.repository / f"target/release-worktrees/{GA_BUILD}",
        ):
            with self.subTest(repository=repository):
                self.assertEqual(
                    _prepackage_ci_bindings(repository, hosted_ci),
                    expected,
                )
        self.assertFalse((self.fixture.ga_root / "prepackage").exists())

    def test_prepackage_has_no_duplicate_local_ci_output(self) -> None:
        hosted_ci = {"run": {"id": 34, "run_attempt": 2}}
        bindings = {"ci": {"hosted": {"run_id": 34}}}
        with patch.object(
            contract, "_verified_prepackage_inputs",
            return_value=(bindings, hosted_ci, {}),
        ) as inputs:
            for notarization in NotarizationCheck:
                with self.subTest(notarization=notarization):
                    inputs.reset_mock()
                    files = contract._prepackage_files(
                        self.fixture.repository,
                        FIXTURE_EXECUTOR_SOURCE,
                        notarization=notarization,
                        expected_live_hosted_ci=hosted_ci,
                    )
                    # The reopen runs exactly the check its caller chose.
                    inputs.assert_called_once_with(
                        self.fixture.repository,
                        notarization=notarization,
                        freeze_verifier=None,
                    )
                    self.assertEqual(set(files), {"hosted-ci.json", "manifest.json"})
                    self.assertEqual(files["hosted-ci.json"], canonical_json(hosted_ci))
            with self.assertRaisesRegex(PublicationError, "changed after live"):
                contract._prepackage_files(
                    self.fixture.repository,
                    FIXTURE_EXECUTOR_SOURCE,
                    notarization=NotarizationCheck.LIVE,
                    expected_live_hosted_ci={"run": {"id": 35, "run_attempt": 2}},
                )

    def test_prepackage_rejects_previous_schema_without_rewriting_it(self) -> None:
        manifest = _stage_manifest(
            "prepackage", {"ci": {"hosted": {"run_id": 34}}},
            FIXTURE_EXECUTOR_SOURCE,
        )
        self.assertEqual(manifest["schema_version"], 3)
        self.assertEqual(manifest["document"], "cfm-ga-prepackage-seal-v3")
        manifest.update(schema_version=2, document="cfm-ga-prepackage-seal-v2")
        original = canonical_json(manifest)
        with self.assertRaisesRegex(PublicationError, "identity or status"):
            _validate_stage_manifest(manifest, "prepackage")
        self.assertEqual(canonical_json(manifest), original)

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

    def test_hosted_ci_source_binding_keeps_exact_frozen_workflow_identity(self) -> None:
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
            "artifact_workflow_sha256": "d" * 64,
        }
        _require_hosted_ci_source_binding(valid, **arguments)
        # The hosted receipt independently verifies the newer validation
        # workflow against its actual tested commit; artifact identity stays fixed.
        _require_hosted_ci_source_binding(
            {"source": dict(expected_source), "workflow": {"source": {"sha256": "e" * 64}}},
            **arguments,
        )

        old_source = dict(expected_source)
        old_source.pop("workflow_sha256")
        variants = (
            {"source": old_source, "workflow": valid["workflow"]},
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

    def test_prepackage_inputs_refuse_when_any_unconsumed_guard_rejects(self) -> None:
        repository = self.fixture.repository
        inputs = write_frozen_prepackage_inputs(self.fixture)
        frozen = inputs.frozen
        bound_source = inputs.bound_source
        transformation_bytes = inputs.transformation_bytes

        def run(
            hosted_source: dict[str, str],
            *,
            notarization: NotarizationCheck,
            release_application_error: PublicationError | None = None,
            signing_binding_error: PublicationError | None = None,
        ) -> tuple[PublicationError, dict[str, Mock]]:
            collaborators = {
                "validate_hosted_ci_receipt_offline": Mock(
                    return_value={
                        "source": hosted_source,
                        "workflow": {"source": {"sha256": bound_source["workflow_sha256"]}},
                    }
                ),
                "_require_hosted_ci_source_binding": Mock(
                    wraps=_require_hosted_ci_source_binding
                ),
                "validate_candidate_app_manifest": Mock(
                    return_value={"algorithm": "sha256-tree-v2", "sha256": "a" * 64}
                ),
                "bundle_build_identity": Mock(
                    return_value=SimpleNamespace(
                        product_version=PRODUCT_VERSION, build_version=GA_BUILD
                    )
                ),
                "_release_environment": Mock(return_value={}),
                "_validate_release_application": Mock(
                    side_effect=release_application_error
                ),
                "validate_published_transaction_receipt": Mock(
                    return_value=SimpleNamespace(
                        receipt={"fixture": "notarization"},
                        receipt_path=repository / "notarization-receipt.json",
                        retained_signed_app=repository / "retained.app",
                    )
                ),
                "verify_signing_transformation_receipt": Mock(
                    return_value={"fixture": "signing transformation"}
                ),
                "canonical_signing_transformation_json": Mock(
                    return_value=transformation_bytes
                ),
                "_validate_signing_notarization_binding": Mock(
                    side_effect=signing_binding_error
                ),
                "validate_notary_files": Mock(
                    side_effect=OSError("fixture has no notary evidence")
                ),
            }
            with ExitStack() as stack:
                for name, collaborator in collaborators.items():
                    stack.enter_context(patch.object(contract, name, collaborator))
                with self.assertRaises(PublicationError) as rejected:
                    _verified_prepackage_inputs(
                        repository,
                        notarization=notarization,
                        freeze_verifier=lambda _repository: frozen,
                    )
            return rejected.exception, collaborators

        # Control: every guard accepts, so the chain reaches the notary evidence.
        for notarization in NotarizationCheck:
            with self.subTest(notarization=notarization):
                rejected, called = run(bound_source, notarization=notarization)
                self.assertEqual(
                    str(rejected), "GA application notarization evidence is invalid"
                )
                for name in (
                    "_require_hosted_ci_source_binding",
                    "_validate_release_application",
                    "_validate_signing_notarization_binding",
                    "validate_notary_files",
                ):
                    called[name].assert_called_once()
                # The reopen runs exactly the check its caller selected.
                called["_validate_release_application"].assert_called_once_with(
                    repository, {}, notarization=notarization
                )

        sealed = NotarizationCheck.SEALED
        rejected, called = run(
            {**bound_source, "repository_commit": "9" * 40}, notarization=sealed
        )
        self.assertEqual(str(rejected), "hosted CI receipt differs from the frozen candidate")
        called["validate_candidate_app_manifest"].assert_not_called()

        release_error = PublicationError("fixture release application rejected")
        rejected, called = run(
            bound_source, notarization=sealed, release_application_error=release_error
        )
        self.assertIs(rejected, release_error)
        called["validate_published_transaction_receipt"].assert_not_called()

        binding_error = PublicationError("fixture signing binding rejected")
        rejected, called = run(
            bound_source, notarization=sealed, signing_binding_error=binding_error
        )
        self.assertIs(rejected, binding_error)
        called["validate_notary_files"].assert_not_called()

    def test_package_adapter_uses_the_fixed_ga_candidate_contract(self) -> None:
        adapter = _require_artifact_set_adapter()

        self.assertEqual(
            adapter.CANDIDATE_APP_RELATIVE,
            f"target/candidates/{PRODUCT_VERSION}/ga/{GA_BUILD}/signed/Clash for Mac.app",
        )
        self.assertTrue(callable(adapter.verify_dmg_set))
        self.assertTrue(callable(adapter.verify_updater_set))

    def test_publication_verifier_and_stage_contract_share_the_ga_paths(self) -> None:
        repository = self.fixture.repository
        self.assertEqual(
            release_contract.signed_app(repository), repository.joinpath(*SIGNED_APP.parts)
        )
        self.assertEqual(
            release_contract.native_products_root(repository, GA_BUILD),
            repository.joinpath(*GA_NATIVE_PRODUCTS.parts),
        )
        self.assertEqual(
            release_contract.evidence_root(repository),
            repository.joinpath(*contract.PUBLICATION_INPUT_ROOT.parts),
        )

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
                "path": f"target/candidates/{PRODUCT_VERSION}/validation/runtime-acceptance.json",
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
                "build_number": GA_BUILD,
                "manifest_sha256": "1" * 64,
                "release_source_sha256": "2" * 64,
                "repository_commit": "3" * 40,
                "tree_sha256": "4" * 64,
                "version": PRODUCT_VERSION,
            },
            "guards": [{"after": {"closed": True}}],
            "ga_environment_sha256": "9" * 64,
            "phase": "installed",
            "previous": {
                "build_number": journal_export.PREVIOUS_BUILD,
                "tree_sha256": "5" * 64,
                "version": PRODUCT_VERSION,
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
        candidate = verified["candidate"]
        prepackage = {"bindings": {
            "candidate": {
                "app_manifest": {"sha256": candidate["manifest_sha256"]},
                "signed_app": {"tree_sha256": candidate["tree_sha256"]},
            },
            "source": {
                "release_source_sha256": candidate["release_source_sha256"],
                "repository_commit": candidate["repository_commit"],
            },
        }}
        contract._require_migration_matches_prepackage(prepackage, verified)
        packages = {"dmg": {"dmg_sha256": "6" * 64, "gatekeeper_sha256": "7" * 64,
                            "seal": {"sha256": "8" * 64}}}
        with patch.object(contract, "verify_stage", return_value=prepackage), patch.object(contract, "_verified_package_sets", return_value=packages), patch.object(contract, "_verified_migration_journals", return_value=verified):
            expectation = derive_runtime_expectation(fixture.repository)
        self.assertEqual(expectation["from_build"], journal_export.PREVIOUS_BUILD)
        verified["install_journal"]["document"]["previous"]["build_number"] = "40048"
        with self.assertRaisesRegex(PublicationError, "closed"):
            contract._require_migration_matches_prepackage(prepackage, verified)

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
            "build_number": GA_BUILD,
            "manifest_sha256": "1" * 64,
            "release_source_sha256": "2" * 64,
            "repository_commit": "3" * 40,
            "tree_sha256": "4" * 64,
            "version": PRODUCT_VERSION,
        }
        previous = {
            "build_number": journal_export.PREVIOUS_BUILD,
            "tree_sha256": "5" * 64,
            "version": PRODUCT_VERSION,
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
    def test_unknown_commands_are_rejected_by_usage(self) -> None:
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
            self.assertIn(f"invalid choice: '{command}'", stderr.getvalue())

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
