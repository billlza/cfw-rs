from __future__ import annotations

import copy
import hashlib
import inspect
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts.harness.lifecycle_matrix import (
    EXPECTED_LIFECYCLE_RAW_SUBJECTS,
    IDENTITY_OBSERVATION_SUBJECTS,
    expected_lifecycle_raw_kinds,
)
from scripts.harness.performance_ledger import (
    LEDGER_KIND as PERFORMANCE_LEDGER_KIND,
    LEDGER_SUBJECT as PERFORMANCE_LEDGER_SUBJECT,
    SHAPING_INTENT_SUBJECT,
    SHAPING_KIND as PERFORMANCE_SHAPING_KIND,
    SHAPING_RESTORATION_SUBJECT,
)
from scripts.harness.physical_evidence_aggregator import _receipt_payload
from scripts.harness.raw_artifacts import (
    COLLECTOR_SIGNATURE_ALGORITHM,
    EVIDENCE_PROFILE,
    RELEASE_TRUST_POLICY_SHA256,
    CollectorTrustPolicy,
    RawArtifactError,
    canonical_json,
)
from scripts.physical_capture import composition
from scripts.physical_capture.composition import (
    AGGREGATE_RELATIVE_PATH,
    DESCRIPTOR_RELATIVE_PATH,
    PhysicalCaptureCompositionError,
    compose_physical_aggregate,
    compose_receipt_bindings,
    compose_run_record,
    publish_physical_evidence,
)
from scripts.physical_capture.policy import PhysicalCapturePolicyError


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _descriptor(kind: str, path: str, identity: int) -> dict[str, object]:
    return {
        "kind": kind,
        "path": path,
        "size": 100 + identity,
        "sha256": f"{identity:064x}",
    }


def _reports() -> dict[str, dict[str, object]]:
    values: dict[str, dict[str, object]] = {}
    for index, harness in enumerate(sorted(composition.EXPECTED_REPORTS), start=1):
        version, kind = composition.EXPECTED_REPORTS[harness]
        values[harness] = {
            "tool_version": version,
            "captured_at": "2026-07-29T04:00:00Z",
            "completed_at": "2026-07-29T07:00:00Z",
            "signed_at": "2026-07-29T07:00:01Z",
            "artifact": _descriptor(
                kind, f"private/run-macos15/reports/{harness}.json", index
            ),
        }
    return values


def _raw_artifacts() -> list[dict[str, object]]:
    lifecycle = tuple(
        (
            subject,
            sorted(expected_lifecycle_raw_kinds(subject))[0],
        )
        for subject in sorted(EXPECTED_LIFECYCLE_RAW_SUBJECTS)
    )
    bindings: list[dict[str, object]] = []
    identity = 10
    for subject, kind in lifecycle:
        suffix = ".pcap" if kind == "packet-pcap" else ".rgba" if kind == "wkwebview-rgba" else ".json"
        bindings.append(
            {
                "harness": "lifecycle",
                "subject": subject,
                "descriptor": _descriptor(
                    kind,
                    "private/run-macos15/raw/lifecycle/"
                    f"{subject.replace(':', '-')}{suffix}",
                    identity,
                ),
            }
        )
        identity += 1
    for harness, subject, kind, suffix in (
        ("packet", "tcp-ipv4", "packet-pcap", ".pcap"),
        ("performance", PERFORMANCE_LEDGER_SUBJECT, PERFORMANCE_LEDGER_KIND, ".json"),
        ("performance", SHAPING_INTENT_SUBJECT, PERFORMANCE_SHAPING_KIND, ".json"),
        ("performance", SHAPING_RESTORATION_SUBJECT, PERFORMANCE_SHAPING_KIND, ".json"),
        ("adversarial", "baseline", "adversarial-transcript", ".json"),
    ):
        bindings.append(
            {
                "harness": harness,
                "subject": subject,
                "descriptor": _descriptor(
                    kind,
                    f"private/run-macos15/raw/{harness}/{subject}{suffix}",
                    identity,
                ),
            }
        )
        identity += 1
    return bindings


def _candidate() -> dict[str, object]:
    return {
        "version": "0.4.0",
        "build_number": "40029",
        "app_manifest_sha256": _sha("app-manifest"),
        "signed_app_tree_sha256": _sha("signed-app-tree"),
        "artifact_hash_manifest_sha256": _sha("artifact-manifest"),
        "built_at": "2026-07-27T00:00:00Z",
    }


def _profile_sha256() -> str:
    return hashlib.sha256(canonical_json(EVIDENCE_PROFILE)).hexdigest()


def _context() -> dict[str, object]:
    return {
        "schema_version": 1,
        "document": "cfw-physical-run-context-v1",
        "evidence_profile_sha256": _profile_sha256(),
        "candidate": _candidate(),
        "run": {
            "os": "macos15",
            "macos_version": "15.7.8",
            "macos_build": "24G824",
            "machine_sha256": _sha("machine"),
            "machine_identity_scheme": EVIDENCE_PROFILE["machine_identity_scheme"],
            "hardware_model": "Mac16,1",
            "virtualization_present": False,
            "boot_environment_sha256": _sha("boot-macos15"),
            "boot_environment_scheme": EVIDENCE_PROFILE["boot_environment_scheme"],
            "clean_install": True,
            "run_id": "run-40029-macos15",
        },
        "initialized_at": "2026-07-29T03:59:59Z",
    }


def _policy() -> CollectorTrustPolicy:
    return CollectorTrustPolicy(
        policy_sha256=RELEASE_TRUST_POLICY_SHA256,
        key_version=(
            "projects/cfw-release-evidence-20260730/locations/asia-east1/"
            "keyRings/physical-evidence/cryptoKeys/collector-receipts-v040/"
            "cryptoKeyVersions/1"
        ),
        algorithm=COLLECTOR_SIGNATURE_ALGORITHM,
        kms_algorithm="RSA_SIGN_PSS_3072_SHA256",
        protection_level="HSM",
        attestation_format="CAVIUM_V2_COMPRESSED",
        public_key_sha256=_sha("public-key"),
        attestation_sha256=_sha("attestation"),
        modulus=(1 << 3071) + 1,
        exponent=65537,
        collector_version="physical-collector-v1",
        collector_source_sha256=_sha("collector-source"),
        collector_executable_sha256=_sha("collector-executable"),
        evidence_profile_sha256=_profile_sha256(),
        aggregate_schema_version=EVIDENCE_PROFILE["aggregate_schema_version"],
        aggregator_version=EVIDENCE_PROFILE["aggregator_version"],
        boot_environment_scheme=EVIDENCE_PROFILE["boot_environment_scheme"],
        machine_identity_scheme=EVIDENCE_PROFILE["machine_identity_scheme"],
        machine_topology=EVIDENCE_PROFILE["machine_topology"],
        release_source_pinned=True,
    )


def _receipt_request() -> dict[str, object]:
    bindings = compose_receipt_bindings(_reports(), _raw_artifacts())
    context = _context()
    run = context["run"]
    assert isinstance(run, dict)
    return {
        "schema_version": 1,
        "candidate": copy.deepcopy(context["candidate"]),
        "run": {
            "os": run["os"],
            "macos_version": run["macos_version"],
            "macos_build": run["macos_build"],
            "machine_sha256": run["machine_sha256"],
            "clean_install": True,
            "captured_at": bindings["captured_at"],
            "completed_at": bindings["completed_at"],
            "run_id": run["run_id"],
            "run_nonce": _sha("nonce-macos15"),
        },
        "reports": bindings["reports"],
        "raw_artifacts": bindings["raw_artifacts"],
    }


def _receipt_response(
    context: dict[str, object], request: dict[str, object], policy: CollectorTrustPolicy
) -> dict[str, object]:
    context_run = context["run"]
    request_run = request["run"]
    assert isinstance(context_run, dict)
    assert isinstance(request_run, dict)
    collector = {
        "version": policy.collector_version,
        "source_sha256": policy.collector_source_sha256,
        "executable_sha256": policy.collector_executable_sha256,
        "key_version": policy.key_version,
        "algorithm": policy.algorithm,
        "signature": "fixture-signature",
    }
    run = {
        "os": request_run["os"],
        "macos_version": request_run["macos_version"],
        "macos_build": request_run["macos_build"],
        "machine_sha256": request_run["machine_sha256"],
        "machine_identity_scheme": context_run["machine_identity_scheme"],
        "hardware_model": context_run["hardware_model"],
        "virtualization_present": False,
        "boot_environment_sha256": context_run["boot_environment_sha256"],
        "boot_environment_scheme": context_run["boot_environment_scheme"],
        "clean_install": True,
        "captured_at": request_run["captured_at"],
        "completed_at": request_run["completed_at"],
        "signed_at": "2026-07-29T07:00:02Z",
        "run_id": request_run["run_id"],
        "run_nonce": request_run["run_nonce"],
    }
    payload = _receipt_payload(
        policy_sha256=policy.policy_sha256,
        candidate=request["candidate"],
        run=run,
        collector=collector,
        report_bindings=request["reports"],
        raw_bindings=request["raw_artifacts"],
    )
    return {
        "schema_version": 1,
        "signed_at": run["signed_at"],
        "receipt_sha256": hashlib.sha256(canonical_json(payload)).hexdigest(),
        "signature": collector["signature"],
    }


def _run_record() -> dict[str, object]:
    context = _context()
    request = _receipt_request()
    policy = _policy()
    response = _receipt_response(context, request, policy)
    with (
        patch.object(composition, "validate_context", return_value=context),
        patch.object(composition, "load_source_pinned_policy", return_value=policy),
        patch.object(composition, "verify_ps256"),
    ):
        return compose_run_record(context, request, response)


def _two_run_records() -> list[dict[str, object]]:
    first = _run_record()
    second = copy.deepcopy(first)
    run = second["run"]
    assert isinstance(run, dict)
    run.update(
        {
            "os": "current-macos",
            "macos_version": "26.6",
            "macos_build": "25G72",
            "boot_environment_sha256": _sha("boot-current"),
            "run_id": "run-40029-current-macos",
            "run_nonce": _sha("nonce-current"),
            "captured_at": "2026-07-29T08:00:00Z",
            "completed_at": "2026-07-29T11:00:00Z",
            "signed_at": "2026-07-29T11:00:02Z",
        }
    )
    collector = run["collector"]
    assert isinstance(collector, dict)
    collector["signature"] = "second-signature"
    return [second, first]


def _prepare_repository(root: Path) -> None:
    final_candidate = (
        root / "target/candidates/0.4.0/release/final-candidate"
    )
    final_candidate.mkdir(parents=True, mode=0o700)
    os.chmod(final_candidate, 0o700)


class ReceiptBindingCompositionTests(unittest.TestCase):
    def test_four_verified_reports_and_raw_artifacts_compose_canonically(self) -> None:
        reports = _reports()
        reports["packet"]["captured_at"] = "2026-07-29T04:00:01Z"
        bindings = compose_receipt_bindings(reports, _raw_artifacts())

        self.assertEqual(bindings["schema_version"], 1)
        self.assertEqual(bindings["captured_at"], "2026-07-29T04:00:00Z")
        self.assertEqual(bindings["completed_at"], "2026-07-29T07:00:00Z")
        self.assertEqual(
            [report["harness"] for report in bindings["reports"]],
            sorted(composition.EXPECTED_REPORTS),
        )
        self.assertEqual(
            bindings["raw_artifacts"],
            sorted(
                bindings["raw_artifacts"],
                key=lambda entry: (entry["harness"], entry["subject"]),
            ),
        )

    def test_missing_duplicate_or_malformed_bindings_fail_closed(self) -> None:
        missing_report = _reports()
        del missing_report["packet"]
        with self.assertRaisesRegex(
            PhysicalCaptureCompositionError, "exactly the four"
        ):
            compose_receipt_bindings(missing_report, _raw_artifacts())

        missing_lifecycle = [
            binding
            for binding in _raw_artifacts()
            if binding["subject"] != "sleep-wake:trace"
        ]
        with self.assertRaisesRegex(
            PhysicalCaptureCompositionError, "lifecycle subject set"
        ):
            compose_receipt_bindings(_reports(), missing_lifecycle)

        missing_identity_observation = [
            binding
            for binding in _raw_artifacts()
            if binding["subject"] != "team-id:observation"
        ]
        with self.assertRaisesRegex(
            PhysicalCaptureCompositionError, "lifecycle subject set"
        ):
            compose_receipt_bindings(_reports(), missing_identity_observation)

        unknown_lifecycle = _raw_artifacts()
        unknown_lifecycle.append(
            {
                "harness": "lifecycle",
                "subject": "invented-success",
                "descriptor": _descriptor(
                    "lifecycle-event",
                    "private/run-macos15/raw/lifecycle/invented-success.json",
                    999,
                ),
            }
        )
        with self.assertRaisesRegex(
            PhysicalCaptureCompositionError, "exact lifecycle matrix"
        ):
            compose_receipt_bindings(_reports(), unknown_lifecycle)

        wrong_lifecycle_kind = _raw_artifacts()
        lifecycle_event = next(
            binding
            for binding in wrong_lifecycle_kind
            if binding["harness"] == "lifecycle"
            and binding["subject"] == "bundle-identifiers"
        )
        lifecycle_event["descriptor"]["kind"] = "network-extension-trace"
        with self.assertRaisesRegex(
            PhysicalCaptureCompositionError,
            "kind differs from its lifecycle subject",
        ):
            compose_receipt_bindings(_reports(), wrong_lifecycle_kind)

        duplicate = _raw_artifacts()
        lifecycle_events = [
            index
            for index, binding in enumerate(duplicate)
            if binding["harness"] == "lifecycle"
            and binding["descriptor"]["kind"] == "lifecycle-event"
        ]
        duplicate[lifecycle_events[1]]["descriptor"] = copy.deepcopy(
            duplicate[lifecycle_events[0]]["descriptor"]
        )
        with self.assertRaisesRegex(
            PhysicalCaptureCompositionError, "reuses artifact path"
        ):
            compose_receipt_bindings(_reports(), duplicate)

        unknown = _reports()
        unknown["packet"]["success"] = True
        with self.assertRaisesRegex(
            PhysicalCaptureCompositionError, "unknown fields"
        ):
            compose_receipt_bindings(unknown, _raw_artifacts())


class RunRecordCompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = _context()
        self.request = _receipt_request()
        self.policy = _policy()
        self.response = _receipt_response(self.context, self.request, self.policy)

    def compose(self) -> dict[str, object]:
        with (
            patch.object(
                composition,
                "validate_context",
                return_value=copy.deepcopy(self.context),
            ),
            patch.object(
                composition,
                "load_source_pinned_policy",
                return_value=self.policy,
            ),
            patch.object(composition, "verify_ps256") as verifier,
        ):
            result = compose_run_record(
                self.context, self.request, self.response
            )
        verifier.assert_called_once()
        return result

    def test_run_record_reconstructs_policy_owned_collector_and_verifies_ps256(
        self,
    ) -> None:
        record = self.compose()
        self.assertEqual(record["document"], "cfw-physical-run-record-v1")
        self.assertEqual(record["candidate"], self.context["candidate"])
        run = record["run"]
        self.assertEqual(
            run["machine_identity_scheme"],
            EVIDENCE_PROFILE["machine_identity_scheme"],
        )
        self.assertEqual(run["collector"]["key_version"], self.policy.key_version)
        self.assertEqual(run["collector"]["signature"], "fixture-signature")
        self.assertEqual(set(run["reports"]), set(composition.EXPECTED_REPORTS))

    def test_request_or_response_drift_fails_before_a_run_record_is_returned(self) -> None:
        mismatched = copy.deepcopy(self.request)
        mismatched["candidate"]["app_manifest_sha256"] = _sha("foreign")
        with (
            patch.object(composition, "validate_context", return_value=self.context),
            patch.object(
                composition, "load_source_pinned_policy", return_value=self.policy
            ),
            self.assertRaisesRegex(
                PhysicalCaptureCompositionError, "candidate differs"
            ),
        ):
            compose_run_record(self.context, mismatched, self.response)

        bad_digest = copy.deepcopy(self.response)
        bad_digest["receipt_sha256"] = _sha("wrong-receipt")
        with (
            patch.object(composition, "validate_context", return_value=self.context),
            patch.object(
                composition, "load_source_pinned_policy", return_value=self.policy
            ),
            patch.object(composition, "verify_ps256") as verifier,
            self.assertRaisesRegex(
                PhysicalCaptureCompositionError, "digest differs"
            ),
        ):
            compose_run_record(self.context, self.request, bad_digest)
        verifier.assert_not_called()

    def test_invalid_signature_and_non_source_policy_fail_closed(self) -> None:
        with (
            patch.object(composition, "validate_context", return_value=self.context),
            patch.object(
                composition, "load_source_pinned_policy", return_value=self.policy
            ),
            patch.object(
                composition,
                "verify_ps256",
                side_effect=RawArtifactError("invalid signature"),
            ),
            self.assertRaisesRegex(
                PhysicalCaptureCompositionError, "PS256 signature is invalid"
            ),
        ):
            compose_run_record(self.context, self.request, self.response)

        with (
            patch.object(composition, "validate_context", return_value=self.context),
            patch.object(
                composition,
                "load_source_pinned_policy",
                side_effect=PhysicalCapturePolicyError(
                    "physical collector trust policy differs from the release-source contract"
                ),
            ),
            self.assertRaisesRegex(
                PhysicalCaptureCompositionError, "release-source contract"
            ),
        ):
            compose_run_record(self.context, self.request, self.response)


class AggregateCompositionTests(unittest.TestCase):
    def test_two_run_records_compose_in_source_pinned_order(self) -> None:
        policy = _policy()
        with patch.object(
            composition, "load_source_pinned_policy", return_value=policy
        ):
            aggregate = compose_physical_aggregate(_two_run_records())
        self.assertEqual(aggregate["schema_version"], 5)
        self.assertEqual(
            [run["os"] for run in aggregate["runs"]],
            [entry["os"] for entry in EVIDENCE_PROFILE["required_runs"]],
        )
        self.assertEqual(aggregate["candidate"], _candidate())

    def test_duplicate_os_or_candidate_drift_is_rejected(self) -> None:
        policy = _policy()
        records = _two_run_records()
        records[0]["run"]["os"] = "macos15"
        with (
            patch.object(
                composition, "load_source_pinned_policy", return_value=policy
            ),
            self.assertRaisesRegex(
                PhysicalCaptureCompositionError, "unknown or duplicated"
            ),
        ):
            compose_physical_aggregate(records)

        records = _two_run_records()
        records[0]["candidate"]["app_manifest_sha256"] = _sha("foreign")
        with (
            patch.object(
                composition, "load_source_pinned_policy", return_value=policy
            ),
            self.assertRaisesRegex(
                PhysicalCaptureCompositionError, "different candidates"
            ),
        ):
            compose_physical_aggregate(records)


class FixedPublicationTests(unittest.TestCase):
    def test_fixed_descriptor_is_private_exclusive_and_validated_twice(self) -> None:
        policy = _policy()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _prepare_repository(root)
            with (
                patch.object(
                    composition, "load_source_pinned_policy", return_value=policy
                ),
                patch.object(
                    composition,
                    "load_physical_evidence_artifact",
                    return_value={"granted_level": "Signed_Installed_Verified"},
                ) as validator,
            ):
                descriptor = publish_physical_evidence(root, _two_run_records())

            aggregate_path = root / AGGREGATE_RELATIVE_PATH
            descriptor_path = root / DESCRIPTOR_RELATIVE_PATH
            self.assertEqual(descriptor["path"], AGGREGATE_RELATIVE_PATH.as_posix())
            self.assertEqual(stat.S_IMODE(aggregate_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(descriptor_path.stat().st_mode), 0o600)
            self.assertEqual(
                descriptor_path.read_bytes(), canonical_json(descriptor) + b"\n"
            )
            self.assertEqual(validator.call_count, 2)
            for call in validator.call_args_list:
                self.assertEqual(call.kwargs["evidence_root"], root.absolute())
                self.assertIs(call.kwargs["trust_policy"], policy)
                self.assertIs(call.kwargs["fixture"], False)

    def test_existing_output_is_never_replaced(self) -> None:
        policy = _policy()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _prepare_repository(root)
            destination = root / DESCRIPTOR_RELATIVE_PATH
            destination.write_bytes(b"existing")
            os.chmod(destination, 0o600)
            with (
                patch.object(
                    composition, "load_source_pinned_policy", return_value=policy
                ),
                patch.object(composition, "load_physical_evidence_artifact"),
                self.assertRaisesRegex(
                    PhysicalCaptureCompositionError, "refusing to replace"
                ),
            ):
                publish_physical_evidence(root, _two_run_records())
            self.assertEqual(destination.read_bytes(), b"existing")
            self.assertFalse((root / AGGREGATE_RELATIVE_PATH).exists())

    def test_failed_production_validation_publishes_no_descriptor(self) -> None:
        policy = _policy()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _prepare_repository(root)
            with (
                patch.object(
                    composition, "load_source_pinned_policy", return_value=policy
                ),
                patch.object(
                    composition,
                    "load_physical_evidence_artifact",
                    side_effect=PhysicalCaptureCompositionError("invalid aggregate"),
                ),
                self.assertRaises(PhysicalCaptureCompositionError),
            ):
                publish_physical_evidence(root, _two_run_records())
            self.assertFalse((root / AGGREGATE_RELATIVE_PATH).exists())
            self.assertFalse((root / DESCRIPTOR_RELATIVE_PATH).exists())

    def test_symlinked_private_directory_is_rejected(self) -> None:
        policy = _policy()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _prepare_repository(root)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            private = root / AGGREGATE_RELATIVE_PATH.parent
            os.symlink(outside, private)
            with (
                patch.object(
                    composition, "load_source_pinned_policy", return_value=policy
                ),
                patch.object(composition, "load_physical_evidence_artifact"),
                self.assertRaisesRegex(
                    PhysicalCaptureCompositionError, "directory is unsafe"
                ),
            ):
                publish_physical_evidence(root, _two_run_records())

    def test_public_api_has_no_policy_or_output_override_and_no_fixture_import(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(compose_run_record).parameters),
            ("context", "receipt_request", "receipt_response"),
        )
        self.assertEqual(
            tuple(inspect.signature(publish_physical_evidence).parameters),
            ("repository", "run_records"),
        )
        source = inspect.getsource(composition)
        self.assertNotIn("scripts.tests", source)
        self.assertNotIn("fixture=True", source)


if __name__ == "__main__":
    unittest.main()
