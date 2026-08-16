from __future__ import annotations

import atexit
import copy
from contextlib import redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.harness.physical_evidence_aggregator import (
    AGGREGATOR_VERSION,
    RECEIPT_SCHEMA_VERSION,
    SCHEMA_VERSION,
    GRANTED_LEVEL,
    PhysicalEvidenceError,
    _receipt_payload,
    load_physical_evidence,
    load_physical_evidence_artifact,
    main,
    self_check,
    validate_physical_evidence,
)
from scripts.harness.raw_artifacts import canonical_json
from scripts.tests.physical_evidence_fixture import (
    APP_MANIFEST as _APP_MANIFEST,
    BUILD_NUMBER as _BUILD_NUMBER,
    BUILT_AT as _BUILT_AT,
    SIGNED_TREE as _SIGNED_TREE,
    TEST_POLICY,
    PhysicalEvidenceFixture,
    fixture_packet_policy,
    ps256_sign,
)

APP_MANIFEST = _APP_MANIFEST
BUILD_NUMBER = _BUILD_NUMBER
BUILT_AT = _BUILT_AT
SIGNED_TREE = _SIGNED_TREE


REPOSITORY = Path(__file__).resolve().parent.parent.parent
PHYSICAL_EVIDENCE_ROOT = REPOSITORY
PHYSICAL_TRUST_POLICY = TEST_POLICY
_CACHED_FIXTURE: PhysicalEvidenceFixture | None = None
_CACHED_AGGREGATE_ARTIFACT: dict | None = None
_CACHED_TEMPORARY: tempfile.TemporaryDirectory | None = None
_CACHED_FOREIGN_FIXTURE: PhysicalEvidenceFixture | None = None
_CACHED_FOREIGN_AGGREGATE_ARTIFACT: dict | None = None
_CACHED_FOREIGN_TEMPORARY: tempfile.TemporaryDirectory | None = None


def fixture() -> dict:
    """Private-archive descriptor for publication tests under repository/target."""

    global _CACHED_FIXTURE, _CACHED_AGGREGATE_ARTIFACT, _CACHED_TEMPORARY
    if _CACHED_FIXTURE is None:
        parent = REPOSITORY / "target/test-physical-evidence"
        parent.mkdir(parents=True, exist_ok=True)
        _CACHED_TEMPORARY = tempfile.TemporaryDirectory(prefix="v4-", dir=parent)
        atexit.register(_CACHED_TEMPORARY.cleanup)
        prefix = Path(_CACHED_TEMPORARY.name).relative_to(REPOSITORY).as_posix()
        _CACHED_FIXTURE = PhysicalEvidenceFixture(
            REPOSITORY, prefix=prefix
        )
        _CACHED_AGGREGATE_ARTIFACT = _CACHED_FIXTURE.write_aggregate_artifact()
    assert _CACHED_AGGREGATE_ARTIFACT is not None
    return copy.deepcopy(_CACHED_AGGREGATE_ARTIFACT)


def aggregate_fixture() -> dict:
    """Parsed aggregate fixture for tests that inspect private archive contents."""

    fixture()
    assert _CACHED_FIXTURE is not None
    return copy.deepcopy(_CACHED_FIXTURE.aggregate)


def foreign_tree_fixture() -> dict:
    """Valid PS256 aggregate that consistently binds a different app tree."""

    global _CACHED_FOREIGN_FIXTURE
    global _CACHED_FOREIGN_AGGREGATE_ARTIFACT
    global _CACHED_FOREIGN_TEMPORARY
    if _CACHED_FOREIGN_FIXTURE is None:
        parent = REPOSITORY / "target/test-physical-evidence"
        parent.mkdir(parents=True, exist_ok=True)
        _CACHED_FOREIGN_TEMPORARY = tempfile.TemporaryDirectory(
            prefix="v4-foreign-tree-", dir=parent
        )
        atexit.register(_CACHED_FOREIGN_TEMPORARY.cleanup)
        prefix = Path(_CACHED_FOREIGN_TEMPORARY.name).relative_to(REPOSITORY).as_posix()
        _CACHED_FOREIGN_FIXTURE = PhysicalEvidenceFixture(
            REPOSITORY,
            prefix=prefix,
            signed_tree_sha256="f" * 64,
        )
        _CACHED_FOREIGN_AGGREGATE_ARTIFACT = (
            _CACHED_FOREIGN_FIXTURE.write_aggregate_artifact()
        )
    assert _CACHED_FOREIGN_AGGREGATE_ARTIFACT is not None
    return copy.deepcopy(_CACHED_FOREIGN_AGGREGATE_ARTIFACT)


class PhysicalEvidenceAggregatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet_policy = fixture_packet_policy()
        self.packet_policy.__enter__()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)

    def tearDown(self) -> None:
        try:
            self.temporary.cleanup()
        finally:
            self.packet_policy.__exit__(None, None, None)

    def validate(self) -> dict:
        return validate_physical_evidence(
            self.fixture.aggregate,
            evidence_root=self.root,
            trust_policy=self.fixture.policy,
            fixture=True,
        )

    def test_complete_signed_raw_set_grants_only_physical_level(self) -> None:
        summary = self.validate()
        self.assertEqual(summary["granted_level"], GRANTED_LEVEL)
        self.assertEqual(summary["reports"], 8)
        self.assertEqual(len(summary["report_bindings"]), 10)
        self.assertGreater(summary["artifact_count"], 200)
        self.assertEqual(
            summary["candidate"]["artifact_hash_manifest_sha256"],
            self.fixture.candidate["artifact_hash_manifest_sha256"],
        )
        self.assertEqual(
            len(
                {
                    run["machine_sha256"]
                    for run in self.fixture.aggregate["runs"]
                }
            ),
            1,
        )

    def test_zero_one_or_three_runs_are_rejected(self) -> None:
        original = self.fixture.aggregate["runs"]
        cases = ([], original[:1], [*original, copy.deepcopy(original[0])])
        for runs in cases:
            with self.subTest(run_count=len(runs)):
                self.fixture.aggregate["runs"] = runs
                try:
                    with self.assertRaisesRegex(
                        PhysicalEvidenceError, "both required physical run sets"
                    ):
                        self.validate()
                finally:
                    self.fixture.aggregate["runs"] = original

    def test_private_runtime_extensions_are_in_the_signed_raw_set(self) -> None:
        self.validate()
        subjects = {binding["subject"] for binding in self.fixture.raw_bindings[0]}
        self.assertTrue(
            {
                "renderer-ready-v2:trace",
                "network-extension-approval:trace",
                "network-extension-denial:trace",
                "network-extension-pending:trace",
                "sleep-wake:trace",
                "sleep-wake:packet",
                "wkwebview-850x603:metadata",
                "wkwebview-850x603:pixels",
                "inside-out-signatures:observation",
                "team-id:observation",
                "bundle-identifiers:observation",
                "entitlements:observation",
                "provisioning:observation",
            }.issubset(subjects)
        )

    def test_missing_identity_observation_breaks_aggregate_rebuild(self) -> None:
        binding = next(
            item
            for item in self.fixture.raw_bindings[0]
            if item["subject"] == "inside-out-signatures:observation"
        )
        (self.root / binding["descriptor"]["path"]).unlink()
        with self.assertRaisesRegex(PhysicalEvidenceError, "cannot be opened"):
            self.validate()

    def test_resigned_receipt_cannot_hide_tampered_identity_observation(self) -> None:
        lifecycle = self.fixture.report_documents[0]["lifecycle"]
        probe = next(item for item in lifecycle["probes"] if item["id"] == "team-id")
        raw_path = self.root / probe["artifact"]["path"]
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        observation_descriptor = raw["observation_artifact"]
        observation_path = self.root / observation_descriptor["path"]
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
        observation["command"]["stdout"] += "warning: forged success\n"
        observation["command"]["stdout_sha256"] = hashlib.sha256(
            observation["command"]["stdout"].encode("utf-8")
        ).hexdigest()
        self.fixture.rewrite_json(observation_descriptor, observation)
        observation_binding = next(
            item
            for item in self.fixture.raw_bindings[0]
            if item["subject"] == "team-id:observation"
        )
        observation_binding["descriptor"] = copy.deepcopy(observation_descriptor)
        self.fixture.rewrite_json(probe["artifact"], raw)
        self.fixture.resign_run(0)

        with self.assertRaisesRegex(PhysicalEvidenceError, "warning or error"):
            self.validate()

    def test_static_self_check_accepts_the_source_pinned_policy(self) -> None:
        self.assertEqual(self_check(), "configured")

    def test_self_check_output_reports_the_actual_policy_state(self) -> None:
        output = io.StringIO()
        with patch("sys.argv", ["physical_evidence_aggregator.py", "--self-check"]):
            with redirect_stdout(output):
                main()
        self.assertIn("policy state=configured", output.getvalue())
        self.assertNotIn("remains fail-closed until", output.getvalue())

    def test_receipt_v3_binds_manifest_algorithm_and_key_version(self) -> None:
        run = self.fixture.aggregate["runs"][0]
        payload = _receipt_payload(
            policy_sha256=self.fixture.policy.policy_sha256,
            candidate=self.fixture.candidate,
            run=run,
            collector=run["collector"],
            report_bindings=self.fixture.report_bindings[0],
            raw_bindings=self.fixture.raw_bindings[0],
        )
        self.assertEqual(payload["schema_version"], RECEIPT_SCHEMA_VERSION)
        self.assertEqual(
            payload["candidate"]["artifact_hash_manifest_sha256"],
            self.fixture.candidate["artifact_hash_manifest_sha256"],
        )
        self.assertEqual(payload["collector"]["algorithm"], "PS256")
        self.assertEqual(
            payload["collector"]["key_version"], self.fixture.policy.key_version
        )

    def test_every_harness_report_uses_proof_v3_and_binds_trust_identity(self) -> None:
        for run_index, documents in enumerate(self.fixture.report_documents):
            for harness, report in documents.items():
                with self.subTest(run=run_index, harness=harness):
                    self.assertEqual(report["proof"]["schema_version"], 3)
                    self.assertEqual(
                        report["proof"]["candidate"][
                            "artifact_hash_manifest_sha256"
                        ],
                        self.fixture.candidate["artifact_hash_manifest_sha256"],
                    )
                    self.assertEqual(report["proof"]["collector"]["algorithm"], "PS256")
                    self.assertEqual(
                        report["proof"]["collector"]["key_version"],
                        self.fixture.policy.key_version,
                    )

    def test_proof_v2_is_rejected_without_compatibility(self) -> None:
        report = self.fixture.report_documents[0]["packet"]
        report["proof"]["schema_version"] = 2
        self.fixture.resign_run(0)
        with self.assertRaisesRegex(PhysicalEvidenceError, "schema_version must be 3"):
            self.validate()

    def test_receipt_v2_signature_is_rejected_without_compatibility(self) -> None:
        run = self.fixture.aggregate["runs"][0]
        payload = _receipt_payload(
            policy_sha256=self.fixture.policy.policy_sha256,
            candidate=self.fixture.candidate,
            run=run,
            collector=run["collector"],
            report_bindings=self.fixture.report_bindings[0],
            raw_bindings=self.fixture.raw_bindings[0],
        )
        payload["schema_version"] = 2
        run["collector"]["signature"] = ps256_sign(canonical_json(payload))
        with self.assertRaisesRegex(PhysicalEvidenceError, "collector receipt failed"):
            self.validate()

    def test_proof_schema_rejects_float_and_bool(self) -> None:
        for schema_version in (3.0, True):
            report = self.fixture.report_documents[0]["packet"]
            original = report["proof"]["schema_version"]
            report["proof"]["schema_version"] = schema_version
            self.fixture.resign_run(0)
            try:
                with self.subTest(schema_version=schema_version), self.assertRaisesRegex(
                    PhysicalEvidenceError, "schema_version must be 3"
                ):
                    self.validate()
            finally:
                report["proof"]["schema_version"] = original
                self.fixture.resign_run(0)

    def test_proof_without_artifact_manifest_digest_is_rejected(self) -> None:
        report = self.fixture.report_documents[0]["packet"]
        del report["proof"]["candidate"]["artifact_hash_manifest_sha256"]
        self.fixture.resign_run(0)
        with self.assertRaisesRegex(PhysicalEvidenceError, "missing required fields"):
            self.validate()

    def test_resigned_receipt_cannot_hide_report_manifest_drift(self) -> None:
        report = self.fixture.report_documents[0]["packet"]
        report["proof"]["candidate"]["artifact_hash_manifest_sha256"] = "9" * 64
        self.fixture.resign_run(0)
        with self.assertRaisesRegex(PhysicalEvidenceError, "proof differs"):
            self.validate()

    def test_resigned_receipt_cannot_hide_proof_algorithm_downgrade(self) -> None:
        report = self.fixture.report_documents[0]["packet"]
        report["proof"]["collector"]["algorithm"] = "RS256"
        self.fixture.resign_run(0)
        with self.assertRaisesRegex(PhysicalEvidenceError, "algorithm must be PS256"):
            self.validate()

    def test_resigned_receipt_cannot_hide_proof_key_version_substitution(self) -> None:
        report = self.fixture.report_documents[0]["packet"]
        report["proof"]["collector"]["key_version"] = (
            "projects/cfw-fixture/locations/global/keyRings/physical-evidence/"
            "cryptoKeys/collector/cryptoKeyVersions/2"
        )
        self.fixture.resign_run(0)
        with self.assertRaisesRegex(PhysicalEvidenceError, "proof differs"):
            self.validate()

    def test_aggregate_v4_is_rejected_without_compatibility(self) -> None:
        self.fixture.aggregate["schema_version"] = 4
        self.fixture.aggregate["aggregator_version"] = "physical-evidence-aggregator-v4"
        self.assertEqual(SCHEMA_VERSION, 5)
        self.assertEqual(
            AGGREGATOR_VERSION,
            "physical-evidence-aggregator-v5-single-machine",
        )
        with self.assertRaisesRegex(PhysicalEvidenceError, "schema_version must be 5"):
            self.validate()

    def test_old_two_machine_aggregator_marker_is_rejected(self) -> None:
        self.fixture.aggregate["aggregator_version"] = (
            "physical-evidence-aggregator-v4-single-machine"
        )
        with self.assertRaisesRegex(PhysicalEvidenceError, "aggregator_version"):
            self.validate()

    def test_legacy_policy_receipts_cannot_be_rewrapped_with_new_marker(self) -> None:
        legacy_policy_sha256 = "1" * 64
        original_signatures: list[str] = []
        for index, run in enumerate(self.fixture.aggregate["runs"]):
            payload = _receipt_payload(
                policy_sha256=legacy_policy_sha256,
                candidate=self.fixture.candidate,
                run=run,
                collector=run["collector"],
                report_bindings=self.fixture.report_bindings[index],
                raw_bindings=self.fixture.raw_bindings[index],
            )
            signature = ps256_sign(canonical_json(payload))
            run["collector"]["signature"] = signature
            original_signatures.append(signature)

        self.assertEqual(
            self.fixture.aggregate["aggregator_version"], AGGREGATOR_VERSION
        )
        self.assertEqual(
            [run["collector"]["signature"] for run in self.fixture.aggregate["runs"]],
            original_signatures,
        )
        with self.assertRaisesRegex(PhysicalEvidenceError, "collector receipt failed"):
            self.validate()

    def test_aggregate_schema_rejects_float_and_bool(self) -> None:
        for schema_version in (5.0, True):
            self.fixture.aggregate["schema_version"] = schema_version
            with self.subTest(schema_version=schema_version), self.assertRaisesRegex(
                PhysicalEvidenceError, "schema_version must be 5"
            ):
                self.validate()

    def test_handwritten_json_and_random_hash_is_rejected(self) -> None:
        self.fixture.aggregate["runs"][0]["reports"]["packet"]["artifact"][
            "sha256"
        ] = "f" * 64
        with self.assertRaisesRegex(PhysicalEvidenceError, "does not match"):
            self.validate()

    def test_missing_raw_artifact_fails_closed(self) -> None:
        raw = self.fixture.raw_bindings[0][0]["descriptor"]
        (self.root / raw["path"]).unlink()
        with self.assertRaisesRegex(PhysicalEvidenceError, "cannot be opened"):
            self.validate()

    def test_raw_artifact_byte_drift_fails_closed(self) -> None:
        raw = self.fixture.raw_bindings[0][0]["descriptor"]
        path = self.root / raw["path"]
        path.write_bytes(path.read_bytes() + b"drift")
        with self.assertRaisesRegex(PhysicalEvidenceError, "size does not match"):
            self.validate()

    def test_report_byte_drift_fails_closed(self) -> None:
        report = self.fixture.aggregate["runs"][0]["reports"]["packet"]["artifact"]
        path = self.root / report["path"]
        path.write_bytes(path.read_bytes() + b"drift")
        with self.assertRaisesRegex(PhysicalEvidenceError, "size does not match"):
            self.validate()

    def test_report_and_artifact_replay_across_runs_fails(self) -> None:
        self.fixture.aggregate["runs"][1]["reports"]["packet"]["artifact"] = copy.deepcopy(
            self.fixture.aggregate["runs"][0]["reports"]["packet"]["artifact"]
        )
        with self.assertRaisesRegex(PhysicalEvidenceError, "reuses artifact"):
            self.validate()

    def test_candidate_run_mismatch_fails_before_receipt(self) -> None:
        self.fixture.aggregate["runs"][0]["run_id"] = "foreign-run"
        with self.assertRaisesRegex(PhysicalEvidenceError, "proof differs"):
            self.validate()

    def test_candidate_identity_mismatch_fails(self) -> None:
        self.fixture.aggregate["candidate"]["app_manifest_sha256"] = "e" * 64
        with self.assertRaisesRegex(PhysicalEvidenceError, "proof differs"):
            self.validate()

    def test_duplicate_run_nonce_fails(self) -> None:
        self.fixture.aggregate["runs"][1]["run_nonce"] = self.fixture.aggregate["runs"][0][
            "run_nonce"
        ]
        with self.assertRaisesRegex(PhysicalEvidenceError, "reuse a run nonce"):
            self.validate()

    def test_distinct_machines_fail_the_single_machine_policy(self) -> None:
        fixture = PhysicalEvidenceFixture(
            self.root,
            prefix="distinct-machines",
            single_machine=False,
        )
        with self.assertRaisesRegex(PhysicalEvidenceError, "different machine"):
            validate_physical_evidence(
                fixture.aggregate,
                evidence_root=self.root,
                trust_policy=fixture.policy,
                fixture=True,
            )

    def test_resigned_distinct_hardware_models_fail_single_machine_policy(self) -> None:
        run = self.fixture.aggregate["runs"][1]
        run["hardware_model"] = "MacBookPro18,2"
        documents = self.fixture.report_documents[1]
        documents["lifecycle"]["environment"]["hardware_model"] = "MacBookPro18,2"
        documents["packet"]["platform"]["hardware_model"] = "MacBookPro18,2"
        documents["performance"]["parameters"]["machine"]["hardware_model"] = (
            "MacBookPro18,2"
        )
        documents["adversarial"]["platform"]["hardware_model"] = "MacBookPro18,2"
        self.fixture.resign_run(1)

        with self.assertRaisesRegex(PhysicalEvidenceError, "different hardware models"):
            self.validate()

    def test_boot_environments_must_be_distinct(self) -> None:
        self.fixture.aggregate["runs"][1]["boot_environment_sha256"] = (
            self.fixture.aggregate["runs"][0]["boot_environment_sha256"]
        )
        with self.assertRaisesRegex(
            PhysicalEvidenceError, "reuse a boot/install environment"
        ):
            self.validate()

    def test_single_machine_run_timelines_are_sequential_at_the_boundary(self) -> None:
        first, second = self.fixture.aggregate["runs"]
        self.assertEqual(second["captured_at"], first["signed_at"])
        self.validate()

    def test_resigned_overlapping_single_machine_run_is_rejected(self) -> None:
        self.fixture.aggregate["runs"][1]["captured_at"] = (
            "2026-07-27T15:59:59Z"
        )
        self.fixture.resign_run(1)
        with self.assertRaisesRegex(PhysicalEvidenceError, "timelines overlap"):
            self.validate()

    def test_virtual_hardware_model_is_rejected_before_receipt_acceptance(self) -> None:
        self.fixture.aggregate["runs"][0]["hardware_model"] = "VirtualMac2,1"
        with self.assertRaisesRegex(PhysicalEvidenceError, "physical Apple Mac"):
            self.validate()

    def test_os_labels_require_the_exact_source_pinned_stable_versions(self) -> None:
        cases = (
            (0, "26.6"),
            (1, "15.7.8"),
            (1, "27.0"),
        )
        for run_index, version in cases:
            with self.subTest(run_index=run_index, version=version):
                original = self.fixture.aggregate["runs"][run_index]["macos_version"]
                self.fixture.aggregate["runs"][run_index]["macos_version"] = version
                try:
                    with self.assertRaisesRegex(
                        PhysicalEvidenceError, "source-pinned stable version"
                    ):
                        self.validate()
                finally:
                    self.fixture.aggregate["runs"][run_index]["macos_version"] = original

    def test_prerelease_build_cannot_masquerade_as_current_stable(self) -> None:
        self.fixture.aggregate["runs"][1]["macos_build"] = "25G5123a"
        with self.assertRaisesRegex(PhysicalEvidenceError, "source-pinned stable build"):
            self.validate()

    def test_wrong_darwin_build_train_is_rejected_for_macos15(self) -> None:
        self.fixture.aggregate["runs"][0]["macos_build"] = "25G123"
        with self.assertRaisesRegex(PhysicalEvidenceError, "source-pinned stable build"):
            self.validate()

    def test_same_train_but_unpinned_build_is_rejected(self) -> None:
        self.fixture.aggregate["runs"][1]["macos_build"] = "25G123"
        with self.assertRaisesRegex(PhysicalEvidenceError, "source-pinned stable build"):
            self.validate()

    def test_pre_ga_run_is_rejected(self) -> None:
        run = self.fixture.aggregate["runs"][0]
        run["captured_at"] = "2026-07-26T23:59:59Z"
        with self.assertRaisesRegex(PhysicalEvidenceError, "predates stable GA"):
            self.validate()

    def test_reversed_run_completion_and_signing_is_rejected(self) -> None:
        run = self.fixture.aggregate["runs"][0]
        run["completed_at"] = "2026-07-28T14:00:00Z"
        run["signed_at"] = "2026-07-28T13:00:00Z"
        with self.assertRaisesRegex(PhysicalEvidenceError, "reversed"):
            self.validate()

    def test_future_run_timestamp_is_rejected(self) -> None:
        self.fixture.aggregate["runs"][0]["signed_at"] = "2099-01-01T00:00:00Z"
        with self.assertRaisesRegex(PhysicalEvidenceError, "future"):
            self.validate()

    def test_report_completion_after_run_completion_is_rejected(self) -> None:
        report = self.fixture.aggregate["runs"][0]["reports"]["packet"]
        report["completed_at"] = "2026-07-28T12:00:01Z"
        report["signed_at"] = "2026-07-28T12:30:01Z"
        with self.assertRaisesRegex(PhysicalEvidenceError, "after its run"):
            self.validate()

    def test_collector_signature_missing_fails(self) -> None:
        del self.fixture.aggregate["runs"][0]["collector"]["signature"]
        with self.assertRaisesRegex(PhysicalEvidenceError, "missing required fields"):
            self.validate()

    def test_collector_signature_tamper_fails(self) -> None:
        signature = self.fixture.aggregate["runs"][0]["collector"]["signature"]
        self.fixture.aggregate["runs"][0]["collector"]["signature"] = (
            "A" if signature[0] != "A" else "B"
        ) + signature[1:]
        with self.assertRaisesRegex(PhysicalEvidenceError, "collector receipt failed"):
            self.validate()

    def test_collector_algorithm_downgrade_is_rejected_before_signature(self) -> None:
        self.fixture.aggregate["runs"][0]["collector"]["algorithm"] = "RS256"
        with self.assertRaisesRegex(PhysicalEvidenceError, "source-pinned policy"):
            self.validate()

    def test_collector_key_version_substitution_is_rejected(self) -> None:
        self.fixture.aggregate["runs"][0]["collector"]["key_version"] = (
            "projects/cfw-fixture/locations/global/keyRings/physical-evidence/"
            "cryptoKeys/collector/cryptoKeyVersions/2"
        )
        with self.assertRaisesRegex(PhysicalEvidenceError, "source-pinned policy"):
            self.validate()

    def test_collector_source_digest_must_match_source_pinned_policy(self) -> None:
        self.fixture.aggregate["runs"][0]["collector"]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(PhysicalEvidenceError, "source-pinned policy"):
            self.validate()

    def test_aggregate_policy_digest_cannot_be_swapped(self) -> None:
        self.fixture.aggregate["trust_policy_sha256"] = "0" * 64
        with self.assertRaisesRegex(PhysicalEvidenceError, "source-pinned policy"):
            self.validate()

    def test_semantic_declaration_mismatch_fails_even_with_resigned_receipt(self) -> None:
        report = self.fixture.report_documents[0]["performance"]
        report["latency"]["connect_ms"]["p95"] = 1.0
        self.fixture.resign_run(0)
        with self.assertRaisesRegex(PhysicalEvidenceError, "differs from the retained ledger"):
            self.validate()

    def test_stale_report_fails(self) -> None:
        self.fixture.aggregate["runs"][0]["reports"]["packet"][
            "captured_at"
        ] = "2026-01-01T00:00:00Z"
        with self.assertRaisesRegex(PhysicalEvidenceError, "stale"):
            self.validate()

    def test_old_claim_only_schema_is_rejected(self) -> None:
        value = {
            "schema_version": 1,
            "aggregator_version": "physical-evidence-aggregator-v1",
            "granted_level": GRANTED_LEVEL,
            "candidate": self.fixture.aggregate["candidate"],
            "runs": [],
        }
        with self.assertRaisesRegex(PhysicalEvidenceError, "missing required fields"):
            validate_physical_evidence(
                value,
                evidence_root=self.root,
                trust_policy=self.fixture.policy,
                fixture=True,
            )


class PhysicalEvidenceLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet_policy = fixture_packet_policy()
        self.packet_policy.__enter__()

    def tearDown(self) -> None:
        self.packet_policy.__exit__(None, None, None)

    def test_aggregate_path_and_root_are_used_for_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture_value = PhysicalEvidenceFixture(Path(temporary))
            path = fixture_value.write_aggregate()
            summary = load_physical_evidence(
                path,
                evidence_root=Path(temporary),
                trust_policy=fixture_value.policy,
                fixture=True,
            )
            self.assertEqual(summary["granted_level"], GRANTED_LEVEL)
            self.assertEqual(summary["aggregate_artifact"]["kind"], "physical-aggregate")
            self.assertEqual(
                summary["private_archive"]["aggregate_artifact"],
                summary["aggregate_artifact"],
            )
            self.assertEqual(
                summary["private_archive"]["artifact_count"], summary["artifact_count"]
            )

    def test_bound_aggregate_bytes_are_required_not_only_summary_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_value = PhysicalEvidenceFixture(root)
            artifact = fixture_value.write_aggregate_artifact()
            path = root / artifact["path"]
            path.write_bytes(path.read_bytes() + b"drift")
            with self.assertRaisesRegex(PhysicalEvidenceError, "size does not match"):
                load_physical_evidence_artifact(
                    artifact,
                    evidence_root=root,
                    trust_policy=fixture_value.policy,
                    fixture=True,
                )

    def test_aggregate_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_value = PhysicalEvidenceFixture(root)
            path = fixture_value.write_aggregate()
            link = root / "aggregate-link.json"
            os.symlink(path, link)
            with self.assertRaisesRegex(PhysicalEvidenceError, "non-symlink"):
                load_physical_evidence(
                    link,
                    evidence_root=root,
                    trust_policy=fixture_value.policy,
                    fixture=True,
                )

    def test_caller_supplied_test_policy_cannot_grant_production(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_value = PhysicalEvidenceFixture(root)
            path = fixture_value.write_aggregate()
            with self.assertRaisesRegex(PhysicalEvidenceError, "require fixture mode"):
                load_physical_evidence(
                    path,
                    evidence_root=root,
                    trust_policy=fixture_value.policy,
                )

    def test_forged_source_pinned_flag_cannot_bypass_configured_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_value = PhysicalEvidenceFixture(root)
            artifact = fixture_value.write_aggregate_artifact()
            forged = replace(fixture_value.policy, release_source_pinned=True)
            with self.assertRaisesRegex(PhysicalEvidenceError, "source-pinned policy"):
                load_physical_evidence_artifact(
                    artifact,
                    evidence_root=root,
                    trust_policy=forged,
                )

    def test_production_policy_object_must_equal_reloaded_source_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_value = PhysicalEvidenceFixture(root)
            artifact = fixture_value.write_aggregate_artifact()
            canonical = replace(fixture_value.policy, release_source_pinned=True)
            forged = replace(
                canonical,
                key_version=(
                    "projects/cfw-fixture/locations/global/keyRings/physical-evidence/"
                    "cryptoKeys/collector/cryptoKeyVersions/2"
                ),
            )
            with patch(
                "scripts.harness.physical_evidence_aggregator.load_release_trust_policy",
                return_value=canonical,
            ):
                with self.assertRaisesRegex(PhysicalEvidenceError, "does not exactly match"):
                    load_physical_evidence_artifact(
                        artifact,
                        evidence_root=root,
                        trust_policy=forged,
                    )

    def test_parsed_aggregate_api_is_fixture_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_value = PhysicalEvidenceFixture(root)
            forged = replace(fixture_value.policy, release_source_pinned=True)
            with self.assertRaisesRegex(PhysicalEvidenceError, "fixture-only"):
                validate_physical_evidence(
                    fixture_value.aggregate,
                    evidence_root=root,
                    trust_policy=forged,
                )

    def test_default_release_policy_blocks_an_unbound_fixture_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture_value = PhysicalEvidenceFixture(Path(temporary))
            path = fixture_value.write_aggregate()
            with self.assertRaisesRegex(PhysicalEvidenceError, "source-pinned policy"):
                load_physical_evidence(path, evidence_root=Path(temporary))


if __name__ == "__main__":
    unittest.main()
