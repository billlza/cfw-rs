from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.harness.adversarial_clients import (
    COVERAGE_DOCUMENT,
    MAX_SECRET_COVERAGE_ENTRY_BYTES,
    PRODUCT_OBSERVATION_PREFIX,
    AdversarialMatrixError,
    case_spec,
    validate_adversarial_matrix,
    validate_secret_coverage,
)
from scripts.harness.raw_artifacts import ArtifactReader, canonical_json
from scripts.tests.physical_evidence_fixture import PhysicalEvidenceFixture


class AdversarialClientsV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)
        self.document = copy.deepcopy(
            self.fixture.report_documents[0]["adversarial"]
        )

    def _entry(self, case_id: str) -> dict:
        if case_id == "baseline":
            return self.document["baseline"]
        return next(case for case in self.document["cases"] if case["id"] == case_id)

    def _read(self, descriptor: dict) -> dict:
        return json.loads((self.root / descriptor["path"]).read_text(encoding="utf-8"))

    def _rewrite(self, descriptor: dict, value: dict) -> None:
        data = canonical_json(value) + b"\n"
        (self.root / descriptor["path"]).write_bytes(data)
        descriptor["size"] = len(data)
        descriptor["sha256"] = hashlib.sha256(data).hexdigest()

    def _mutate_observation(self, case_id: str, mutation) -> None:
        entry = self._entry(case_id)
        transcript = self._read(entry["artifact"])
        observation = self._read(transcript["observation_artifact"])
        mutation(observation)
        self._rewrite(transcript["observation_artifact"], observation)
        self._rewrite(entry["artifact"], transcript)

    def _validate(self) -> None:
        with ArtifactReader(self.root) as artifacts:
            validate_adversarial_matrix(self.document, artifacts)

    def test_fixture_is_complete_and_source_derived(self) -> None:
        self._validate()

    def test_missing_precondition_fails(self) -> None:
        self._mutate_observation(
            "wrong-team-id",
            lambda observation: observation.__setitem__("precondition", ""),
        )
        with self.assertRaisesRegex(AdversarialMatrixError, "binding differs"):
            self._validate()

    def test_missing_server_trace_fails(self) -> None:
        self._mutate_observation(
            "replayed-operation",
            lambda observation: observation.__setitem__("server_record", {}),
        )
        with self.assertRaisesRegex(AdversarialMatrixError, "server_record"):
            self._validate()

    def test_xpc_rejection_cannot_relabel_service_unavailability(self) -> None:
        def mutate(observation: dict) -> None:
            observation["boundary_record"]["evidence"]["transport_error_code"] = (
                "global_authority_unavailable"
            )

        self._mutate_observation("wrong-team-id", mutate)
        with self.assertRaisesRegex(AdversarialMatrixError, "requirement rejection is unproven"):
            self._validate()

    def test_claimed_code_differing_from_product_event_fails(self) -> None:
        def mutate(observation: dict) -> None:
            event = observation["server_record"]["event"]
            event["payload"]["actual_code"] = "invalid_message"
            message = PRODUCT_OBSERVATION_PREFIX.encode("utf-8") + canonical_json(event)
            observation["server_record"]["log"]["event_message_sha256"] = hashlib.sha256(
                message
            ).hexdigest()

        self._mutate_observation("replayed-operation", mutate)
        with self.assertRaisesRegex(AdversarialMatrixError, "decision/code differs"):
            self._validate()

    def test_identity_cases_cannot_reuse_a_denied_binary(self) -> None:
        first = self._entry("wrong-team-id")
        first_transcript = self._read(first["artifact"])
        first_client = self._read(first_transcript["client_signature_artifact"])

        second = self._entry("wrong-bundle-identifier")
        second_transcript = self._read(second["artifact"])
        second_client = self._read(second_transcript["client_signature_artifact"])
        second_client["binary_sha256"] = first_client["binary_sha256"]
        second_transcript["peer"]["binary_sha256"] = first_client["binary_sha256"]
        self._rewrite(second_transcript["client_signature_artifact"], second_client)
        self._rewrite(second["artifact"], second_transcript)
        with self.assertRaisesRegex(AdversarialMatrixError, "reuse one client binary"):
            self._validate()

    def test_secret_coverage_cannot_archive_plaintext_canary(self) -> None:
        entry = self._entry("secret-extraction-logs")
        transcript = self._read(entry["artifact"])
        coverage = self._read(transcript["secret_coverage_artifact"])
        coverage["canary"] = "plaintext-must-never-be-retained"
        self._rewrite(transcript["secret_coverage_artifact"], coverage)
        self._rewrite(entry["artifact"], transcript)
        with self.assertRaisesRegex(AdversarialMatrixError, "unknown fields"):
            self._validate()


class AdversarialProbeBuilderTests(unittest.TestCase):
    def test_probe_builder_is_fixed_isolated_and_root_safe(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        source = (repository / "scripts/build_adversarial_probe_variants.sh").read_text(
            encoding="utf-8"
        )
        for required in (
            "CFW_ADVERSARIAL_SAME_TEAM_NON_DEVELOPER_IDENTITY",
            'SAME_TEAM_HOST_REQUIREMENT="anchor apple generic',
            '"${CODESIGN}" --verify --strict -R="${SAME_TEAM_HOST_REQUIREMENT}"',
            '"${CODESIGN}" --verify --strict -R="${HOST_REQUIREMENT}"',
            "/private/var/tmp/cfw-adversarial-probes.XXXXXX",
            "require_safe_existing_directory",
            "refusing to clean an unexpected scratch path",
            "EXTERNAL_FIXTURE_IDS",
            "external_case_count",
            'destination="${INSTALL_ROOT}/PhysicalFixtures/${fixture_id}/${case_id}/CFWAdversarialFixture"',
            '"${CODESIGN}" --verify --strict -R="${HOST_REQUIREMENT}"',
            "external fixtures reused a signed executable byte digest",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertNotIn("target/adversarial-probes", source)
        self.assertNotIn("adversarial-wrong.requirements", source)


class AdversarialSecretCoverageContractTests(unittest.TestCase):
    case_id = "secret-extraction-logs"

    def coverage(self) -> dict:
        return {
            "schema_version": 1,
            "document": COVERAGE_DOCUMENT,
            "case_id": self.case_id,
            "surface": case_spec(self.case_id).secret_surface,
            "canary_sha256": "a" * 64,
            "started_at": "2026-07-27T12:00:00Z",
            "finished_at": "2026-07-27T12:00:01Z",
            "enumeration_complete": True,
            "unreadable_count": 0,
            "excluded_count": 0,
            "entry_count": 1,
            "total_scanned_bytes": 0,
            "total_match_count": 0,
            "entries": [
                {
                    "location_sha256": "b" * 64,
                    "content_sha256": "c" * 64,
                    "scanned_bytes": 0,
                    "match_count": 0,
                }
            ],
        }

    def test_empty_covered_location_is_valid(self) -> None:
        validated = validate_secret_coverage(self.coverage(), case_id=self.case_id)
        self.assertEqual(validated["total_scanned_bytes"], 0)

    def test_boolean_counter_is_rejected(self) -> None:
        coverage = self.coverage()
        coverage["unreadable_count"] = False
        with self.assertRaisesRegex(AdversarialMatrixError, "nonnegative bounded integer"):
            validate_secret_coverage(coverage, case_id=self.case_id)

    def test_per_location_byte_bound_is_enforced(self) -> None:
        coverage = self.coverage()
        coverage["entries"][0]["scanned_bytes"] = MAX_SECRET_COVERAGE_ENTRY_BYTES + 1
        coverage["total_scanned_bytes"] = MAX_SECRET_COVERAGE_ENTRY_BYTES + 1
        with self.assertRaisesRegex(AdversarialMatrixError, "nonnegative bounded integer"):
            validate_secret_coverage(coverage, case_id=self.case_id)


if __name__ == "__main__":
    unittest.main()
