from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.harness.adversarial_clients import (
    REQUIRED_CASES,
    AdversarialMatrixError,
    validate_adversarial_matrix,
)
from scripts.harness.raw_artifacts import ArtifactReader
from scripts.tests.physical_evidence_fixture import PhysicalEvidenceFixture


class AdversarialMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)
        self.document = self.fixture.report_documents[0]["adversarial"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self) -> dict:
        with ArtifactReader(self.root) as artifacts:
            return validate_adversarial_matrix(self.document, artifacts)

    def transcript(self, index: int) -> tuple[dict, dict]:
        case = self.document["cases"][index]
        raw = json.loads((self.root / case["artifact"]["path"]).read_text(encoding="utf-8"))
        return case, raw

    def test_full_matrix_reopens_signature_and_transcript_bytes(self) -> None:
        result = self.validate()
        self.assertEqual(len(self.document["cases"]), len(REQUIRED_CASES))
        self.assertEqual(len(result["artifacts"]), 138)

    def test_schema_versions_require_json_integers(self) -> None:
        for invalid in (2.0, True):
            with self.subTest(scope="report", invalid=invalid):
                document = copy.deepcopy(self.document)
                document["schema_version"] = invalid
                with ArtifactReader(self.root) as artifacts, self.assertRaisesRegex(
                    AdversarialMatrixError, "schema_version must be 3"
                ):
                    validate_adversarial_matrix(document, artifacts)

        case, original = self.transcript(0)
        try:
            for invalid in (1.0, True):
                with self.subTest(scope="transcript", invalid=invalid):
                    transcript = copy.deepcopy(original)
                    transcript["schema_version"] = invalid
                    self.fixture.rewrite_json(case["artifact"], transcript)
                    with self.assertRaisesRegex(
                        AdversarialMatrixError, "transcript source binding differs"
                    ):
                        self.validate()
        finally:
            self.fixture.rewrite_json(case["artifact"], original)

    def test_missing_attack_transcript_fails(self) -> None:
        self.document["cases"].pop()
        with self.assertRaisesRegex(AdversarialMatrixError, "every case"):
            self.validate()

    def test_transcript_authorization_outcome_cannot_be_declared(self) -> None:
        case, raw = self.transcript(0)
        raw["decision"]["accepted"] = not raw["decision"]["accepted"]
        self.fixture.rewrite_json(case["artifact"], raw)
        with self.assertRaisesRegex(AdversarialMatrixError, "decision differs"):
            self.validate()

    def test_transcript_exit_code_must_correspond_to_denial(self) -> None:
        case, raw = self.transcript(0)
        raw["exit_code"] = 1
        self.fixture.rewrite_json(case["artifact"], raw)
        with self.assertRaisesRegex(AdversarialMatrixError, "exit_code differs"):
            self.validate()

    def test_case_cannot_declare_a_different_source_category(self) -> None:
        self.document["cases"][0]["category"] = "identity"
        with self.assertRaisesRegex(AdversarialMatrixError, "entry category differs"):
            self.validate()

    def test_client_signature_evidence_must_match_binary(self) -> None:
        case, transcript = self.transcript(0)
        descriptor = transcript["client_signature_artifact"]
        path = self.root / descriptor["path"]
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["binary_sha256"] = "f" * 64
        self.fixture.rewrite_json(descriptor, raw)
        self.fixture.rewrite_json(case["artifact"], transcript)
        with self.assertRaisesRegex(AdversarialMatrixError, "transcript peer differs"):
            self.validate()

    def test_transcript_request_digest_cannot_differ_from_observation(self) -> None:
        first_case, first = self.transcript(0)
        second_case, second = self.transcript(1)
        self.assertNotEqual(first_case["id"], second_case["id"])
        second["request_sha256"] = first["request_sha256"]
        self.fixture.rewrite_json(second_case["artifact"], second)
        with self.assertRaisesRegex(AdversarialMatrixError, "request_sha256 differs"):
            self.validate()

    def test_transcript_candidate_binding_mismatch_fails(self) -> None:
        case, raw = self.transcript(0)
        raw["proof"]["candidate"]["app_manifest_sha256"] = "e" * 64
        self.fixture.rewrite_json(case["artifact"], raw)
        with self.assertRaisesRegex(AdversarialMatrixError, "source binding differs"):
            self.validate()

    def test_replayed_transcript_artifact_fails(self) -> None:
        self.document["cases"][1]["artifact"] = copy.deepcopy(
            self.document["cases"][0]["artifact"]
        )
        with self.assertRaisesRegex(AdversarialMatrixError, "reuses artifact"):
            self.validate()

    def test_handwritten_executed_field_is_rejected(self) -> None:
        self.document["cases"][0]["executed"] = True
        with self.assertRaisesRegex(AdversarialMatrixError, "unknown fields"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
