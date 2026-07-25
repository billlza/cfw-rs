from __future__ import annotations

import copy
import unittest

from scripts.harness.adversarial_clients import (
    AdversarialMatrixError,
    REQUIRED_CASES,
    validate_adversarial_matrix,
)


def fixture() -> dict:
    cases = []
    for case_id, (category, client, denial_code, cleanup) in REQUIRED_CASES.items():
        cases.append(
            {
                "id": case_id,
                "category": category,
                "client": client,
                "executed": True,
                "outcome": "denied",
                "denial_code": denial_code,
                "cleanup": cleanup,
                "secret_observed": False,
            }
        )
    return {
        "schema_version": 1,
        "product": {"version": "0.4.0", "build_number": "40000"},
        "app_manifest_sha256": "a" * 64,
        "captured_at": "2026-07-22T00:00:00Z",
        "platform": {
            "architecture": "arm64",
            "macos_version": "15.0",
            "hardware_model": "Mac fixture",
            "clean_install": True,
        },
        "signing": {
            "team_id": "YKUPL7Z869",
            "allowed_client": {
                "signing_id": "com.bill.clashformac",
                "cdhash": "b" * 40,
                "designated_requirement_sha256": "c" * 64,
            },
            "denied_client": {
                "signing_id": "com.bill.clashformac.adversary",
                "cdhash": "d" * 40,
                "designated_requirement_sha256": "e" * 64,
            },
        },
        "baseline": {"client": "allowed", "executed": True, "authorized": True},
        "cases": cases,
    }


class AdversarialMatrixTests(unittest.TestCase):
    def test_complete_matrix_of_denials_passes(self) -> None:
        document = validate_adversarial_matrix(fixture())
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(len(document["cases"]), len(REQUIRED_CASES))

    def test_matrix_covers_every_required_attack_surface(self) -> None:
        categories = {meta[0] for meta in REQUIRED_CASES.values()}
        self.assertEqual(
            categories,
            {"identity", "replay", "journal", "protocol", "backpressure", "liveness", "secret"},
        )
        # Every secret-extraction surface named by Requirement 6.4 must be present.
        for surface in (
            "logs",
            "preferences",
            "journal",
            "crash-records",
            "snapshots",
            "evidence",
        ):
            self.assertIn(f"secret-extraction-{surface}", REQUIRED_CASES)

    def test_missing_case_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"] = value["cases"][:-1]
        with self.assertRaisesRegex(AdversarialMatrixError, "missing required cases"):
            validate_adversarial_matrix(value)

    def test_unexecuted_attack_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["executed"] = False
        with self.assertRaisesRegex(AdversarialMatrixError, "was not executed"):
            validate_adversarial_matrix(value)

    def test_attack_that_was_not_denied_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["outcome"] = "allowed"
        with self.assertRaisesRegex(AdversarialMatrixError, "attack succeeded"):
            validate_adversarial_matrix(value)

    def test_wrong_signature_binding_fails_closed(self) -> None:
        # Rebind an identity forgery to the allowed client rather than the denied one.
        value = copy.deepcopy(fixture())
        for case in value["cases"]:
            if case["id"] == "wrong-team-id":
                case["client"] = "allowed"
        with self.assertRaisesRegex(AdversarialMatrixError, "wrong client signature"):
            validate_adversarial_matrix(value)

    def test_observed_secret_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        for case in value["cases"]:
            if case["id"] == "secret-extraction-logs":
                case["secret_observed"] = True
        with self.assertRaisesRegex(AdversarialMatrixError, "observed secret material"):
            validate_adversarial_matrix(value)

    def test_wrong_denial_code_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["denial_code"] = "somethingElse"
        with self.assertRaisesRegex(AdversarialMatrixError, "denial_code differs"):
            validate_adversarial_matrix(value)

    def test_wrong_cleanup_outcome_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        for case in value["cases"]:
            if case["id"] == "authority-journal-truncation":
                case["cleanup"] = "off"
        with self.assertRaisesRegex(AdversarialMatrixError, "cleanup differs"):
            validate_adversarial_matrix(value)

    def test_baseline_positive_control_must_authorize(self) -> None:
        value = copy.deepcopy(fixture())
        value["baseline"]["authorized"] = False
        with self.assertRaisesRegex(AdversarialMatrixError, "was not authorized"):
            validate_adversarial_matrix(value)

    def test_clients_must_be_separately_signed(self) -> None:
        value = copy.deepcopy(fixture())
        value["signing"]["denied_client"]["cdhash"] = value["signing"]["allowed_client"]["cdhash"]
        with self.assertRaisesRegex(AdversarialMatrixError, "separately signed"):
            validate_adversarial_matrix(value)

    def test_denied_client_must_be_distinct_bundle(self) -> None:
        value = copy.deepcopy(fixture())
        value["signing"]["denied_client"]["signing_id"] = "com.bill.clashformac"
        with self.assertRaisesRegex(AdversarialMatrixError, "distinct same-Team bundle"):
            validate_adversarial_matrix(value)

    def test_wrong_team_id_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["signing"]["team_id"] = "AAAAAAAAAA"
        with self.assertRaisesRegex(AdversarialMatrixError, "team_id"):
            validate_adversarial_matrix(value)

    def test_non_clean_or_non_arm64_machine_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["platform"]["clean_install"] = False
        with self.assertRaisesRegex(AdversarialMatrixError, "clean Apple Silicon"):
            validate_adversarial_matrix(value)
        value = copy.deepcopy(fixture())
        value["platform"]["architecture"] = "x86_64"
        with self.assertRaisesRegex(AdversarialMatrixError, "clean Apple Silicon"):
            validate_adversarial_matrix(value)

    def test_duplicate_case_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"].append(copy.deepcopy(value["cases"][0]))
        with self.assertRaisesRegex(AdversarialMatrixError, "duplicate adversarial case"):
            validate_adversarial_matrix(value)

    def test_unknown_case_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        rogue = copy.deepcopy(value["cases"][0])
        rogue["id"] = "not-a-real-attack"
        value["cases"].append(rogue)
        with self.assertRaisesRegex(AdversarialMatrixError, "unknown adversarial case"):
            validate_adversarial_matrix(value)

    def test_symlink_matrix_file_fails_closed(self) -> None:
        import json
        import os
        import tempfile

        from scripts.harness.adversarial_clients import load_adversarial_matrix

        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, "matrix.json")
            with open(real, "w", encoding="utf-8") as handle:
                json.dump(fixture(), handle)
            link = os.path.join(tmp, "link.json")
            os.symlink(real, link)
            from pathlib import Path

            with self.assertRaisesRegex(AdversarialMatrixError, "non-symlink"):
                load_adversarial_matrix(Path(link))


if __name__ == "__main__":
    unittest.main()
