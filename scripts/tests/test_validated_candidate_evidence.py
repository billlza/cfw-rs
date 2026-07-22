from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.tests.test_release_runtime_evidence import fixture as runtime_fixture
from scripts.validated_candidate_evidence import (
    ValidatedCandidateError,
    validate_candidate_review,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ValidatedCandidateEvidenceTests(unittest.TestCase):
    def make_review(self, repository: Path) -> Path:
        base = repository / "target/candidates/0.4.0/validation/40000"
        signed = base / "signed"
        evidence = base / "evidence"
        review_root = repository / "target/candidates/0.4.0/review"
        signed.mkdir(parents=True)
        evidence.mkdir()
        review_root.mkdir()
        app_manifest = signed / "Clash for Mac.app.manifest.json"
        app_manifest.write_text(
            json.dumps(
                {
                    "metadata": {
                        "artifactKind": "notarized-validation-candidate-v1",
                        "buildNumber": "40000",
                        "version": "0.4.0",
                    }
                }
            ),
            encoding="utf-8",
        )
        notary = signed / "notarization.json"
        notary.write_text(json.dumps({"status": "Accepted", "id": "request-id"}), encoding="utf-8")
        runtime = evidence / "runtime-recovery.json"
        runtime_document = runtime_fixture()
        runtime_document["app_manifest_sha256"] = digest(app_manifest)
        runtime.write_text(json.dumps(runtime_document), encoding="utf-8")
        review = review_root / "validated-candidate.json"
        review.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "decision": "approved",
                    "reviewer": "Release Reviewer",
                    "reviewed_at": "2026-07-22T00:00:00Z",
                    "product": {"version": "0.4.0", "build_number": "40000"},
                    "candidate": {
                        "app_manifest_path": (
                            "target/candidates/0.4.0/validation/40000/signed/"
                            "Clash for Mac.app.manifest.json"
                        ),
                        "app_manifest_sha256": digest(app_manifest),
                        "notarization_result_path": (
                            "target/candidates/0.4.0/validation/40000/signed/notarization.json"
                        ),
                        "notarization_result_sha256": digest(notary),
                        "runtime_evidence_path": (
                            "target/candidates/0.4.0/validation/40000/evidence/runtime-recovery.json"
                        ),
                        "runtime_evidence_sha256": digest(runtime),
                    },
                }
            ),
            encoding="utf-8",
        )
        return review

    def test_final_build_must_be_newer_and_all_evidence_is_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            review = self.make_review(repository)
            result = validate_candidate_review(repository, review, "40001")
            self.assertEqual(result["product"]["build_number"], "40000")

    def test_same_final_build_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            review = self.make_review(repository)
            with self.assertRaisesRegex(ValueError, "strictly greater"):
                validate_candidate_review(repository, review, "40000")

    def test_runtime_evidence_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            review = self.make_review(repository)
            runtime = (
                repository
                / "target/candidates/0.4.0/validation/40000/evidence/runtime-recovery.json"
            )
            runtime.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValidatedCandidateError, "digest"):
                validate_candidate_review(repository, review, "40001")


if __name__ == "__main__":
    unittest.main()
