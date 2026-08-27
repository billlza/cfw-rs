from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest

from scripts import validated_candidate_evidence


REPOSITORY = Path(__file__).resolve().parents[2]


class RetiredValidatedCandidateEvidenceTests(unittest.TestCase):
    def test_module_exposes_no_legacy_validation_api(self) -> None:
        self.assertFalse(
            hasattr(validated_candidate_evidence, "validate_candidate_review")
        )

    def test_in_process_entrypoint_fails_explicitly(self) -> None:
        with self.assertRaisesRegex(SystemExit, "single frozen GA 40035"):
            validated_candidate_evidence.main([])

    def test_cli_rejects_old_review_arguments(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY / "scripts/validated_candidate_evidence.py"),
                "target/candidates/0.4.0/review/validated-candidate.json",
                "--final-build-number",
                "40035",
            ],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("validated-candidate evidence is retired", completed.stderr)


if __name__ == "__main__":
    unittest.main()
