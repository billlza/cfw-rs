from __future__ import annotations

from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from scripts.harness.physical_collector_request import initialize_context
from scripts.harness.raw_artifacts import parse_proof_binding
from scripts.physical_capture.policy import PhysicalCapturePolicyError
from scripts.physical_capture.proof import (
    PhysicalCaptureProofError,
    build_proof_material,
)
from scripts.tests.test_physical_collector_request import _candidate, _runner


class PhysicalCaptureProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.initialized_at = datetime(2026, 7, 29, 4, 0, tzinfo=timezone.utc)
        self.observed_at = datetime(2026, 7, 29, 5, 0, tzinfo=timezone.utc)
        self.runner = _runner()
        self.context = initialize_context(
            _candidate(),
            run_id="run-40021-macos15",
            clean_install_confirmed=True,
            runner=self.runner,
            observed_at=self.initialized_at,
        )
        self.nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T11:00:00Z",
        }

    def test_builds_exact_source_pinned_proof_after_reobservation(self) -> None:
        material = build_proof_material(
            self.context,
            self.nonce,
            runner=self.runner,
            observed_at=self.observed_at,
        )
        self.assertEqual(material.proof, parse_proof_binding(material.proof))
        self.assertEqual(material.proof["schema_version"], 3)
        self.assertEqual(material.proof["run_nonce"], "d" * 64)
        self.assertEqual(material.proof["candidate"]["build_number"], "40021")
        self.assertNotIn("built_at", material.proof["candidate"])
        self.assertEqual(
            material.nonce_issued_at,
            datetime(2026, 7, 29, 5, 0, tzinfo=timezone.utc),
        )

    def test_observation_must_complete_before_nonce_issue(self) -> None:
        material = build_proof_material(
            self.context,
            self.nonce,
            runner=self.runner,
            observed_at=self.observed_at,
        )
        material.require_observation_window(
            captured_at=datetime(2026, 7, 29, 4, 10, tzinfo=timezone.utc),
            completed_at=datetime(2026, 7, 29, 4, 20, tzinfo=timezone.utc),
        )
        for captured, completed in (
            (
                datetime(2026, 7, 29, 3, 59, tzinfo=timezone.utc),
                datetime(2026, 7, 29, 4, 20, tzinfo=timezone.utc),
            ),
            (
                datetime(2026, 7, 29, 4, 20, tzinfo=timezone.utc),
                datetime(2026, 7, 29, 5, 1, tzinfo=timezone.utc),
            ),
        ):
            with self.subTest(captured=captured, completed=completed), self.assertRaisesRegex(
                PhysicalCaptureProofError, "pre-nonce"
            ):
                material.require_observation_window(
                    captured_at=captured, completed_at=completed
                )

    def test_policy_and_environment_failures_are_one_explicit_domain_error(self) -> None:
        with patch(
            "scripts.physical_capture.proof.load_source_pinned_policy",
            side_effect=PhysicalCapturePolicyError("drift"),
        ), self.assertRaisesRegex(PhysicalCaptureProofError, "cannot be revalidated"):
            build_proof_material(
                self.context,
                self.nonce,
                runner=self.runner,
                observed_at=self.observed_at,
            )

        with self.assertRaisesRegex(PhysicalCaptureProofError, "cannot be revalidated"):
            build_proof_material(
                self.context,
                self.nonce,
                runner=_runner(macos_version="26.6", macos_build="25G72"),
                observed_at=self.observed_at,
            )


if __name__ == "__main__":
    unittest.main()
