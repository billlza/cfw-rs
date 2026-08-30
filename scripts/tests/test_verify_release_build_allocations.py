from __future__ import annotations

import copy
import unittest

from scripts import verify_release_build_allocations as allocations


class ReleaseBuildAllocationTests(unittest.TestCase):
    def allocation_for_build(
        self,
        value: dict[str, object],
        build: str,
    ) -> dict[str, object]:
        records = value["allocations"]
        self.assertIsInstance(records, list)
        matches = [
            record
            for record in records
            if isinstance(record, dict) and record.get("build") == build
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def replace_allocation(
        self,
        value: dict[str, object],
        build: str,
        replacement: dict[str, object],
    ) -> None:
        record = self.allocation_for_build(value, build)
        record.clear()
        record.update(replacement)

    def test_active_identity_is_the_single_ga_build(self) -> None:
        identity = allocations.ACTIVE_RELEASE_IDENTITY
        self.assertEqual(identity.product_version, "0.4.0")
        self.assertEqual(identity.ga_build, "40037")
        allocations.verify_source_bindings(allocations.load_contract())

    def test_tracked_contract_matches_active_ga_and_retires_consumed_ga_builds(self) -> None:
        value = allocations.load_contract()
        allocations.validate_contract(value, expected_ga="40037")
        self.assertEqual(value["active_ga"], "40037")
        expected = {
            "40030": ("validation", "retired_unbuilt_policy_superseded"),
            "40031": (
                "ga",
                "retired_after_candidate_freeze_before_canonical_signing_output",
            ),
            "40032": (
                "ga",
                "retired_after_candidate_freeze_before_canonical_signing_output",
            ),
            "40033": (
                "ga",
                "retired_after_candidate_freeze_before_canonical_signing_output",
            ),
            "40034": (
                "ga",
                "retired_after_candidate_freeze_before_canonical_signing_output",
            ),
            "40035": (
                "ga",
                "retired_after_candidate_freeze_before_canonical_signing_output",
            ),
            "40036": (
                "ga",
                "retired_after_notarization_before_install",
            ),
            "40037": ("ga", "active_ga"),
        }
        for build, (role, status) in expected.items():
            with self.subTest(build=build):
                self.assertEqual(
                    self.allocation_for_build(value, build),
                    {"build": build, "role": role, "status": status},
                )

    def test_retired_40029_final_companion_cannot_be_reused_as_ga(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["active_ga"] = "40029"
        self.replace_allocation(
            value,
            "40029",
            {"build": "40029", "role": "ga", "status": "active_ga"},
        )
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(value, expected_ga="40029")

    def test_retired_40030_cannot_be_reactivated_or_reassigned(self) -> None:
        mutations = (
            {"build": "40030", "role": "ga", "status": "active_ga"},
            {
                "build": "40030",
                "role": "final",
                "status": "retired_unbuilt_policy_superseded",
            },
            {
                "build": "40030",
                "role": "validation",
                "status": "retired_unbuilt_reserved_final_companion",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract())
                self.replace_allocation(value, "40030", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "policy-superseded 40030 allocation changed",
                ):
                    allocations.validate_contract(value, expected_ga="40037")

    def test_retired_40031_cannot_be_reactivated_or_reassigned(self) -> None:
        mutations = (
            {"build": "40031", "role": "ga", "status": "active_ga"},
            {
                "build": "40031",
                "role": "validation",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
            {
                "build": "40031",
                "role": "ga",
                "status": "retired_unbuilt_policy_superseded",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract())
                self.replace_allocation(value, "40031", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_contract(value, expected_ga="40037")

    def test_retired_40032_cannot_be_reactivated_or_reassigned(self) -> None:
        mutations = (
            {"build": "40032", "role": "ga", "status": "active_ga"},
            {
                "build": "40032",
                "role": "validation",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
            {
                "build": "40032",
                "role": "ga",
                "status": "retired_unbuilt_policy_superseded",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract())
                self.replace_allocation(value, "40032", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_contract(value, expected_ga="40037")

    def test_retired_40033_cannot_be_reactivated_or_reassigned(self) -> None:
        mutations = (
            {"build": "40033", "role": "ga", "status": "active_ga"},
            {
                "build": "40033",
                "role": "validation",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
            {
                "build": "40033",
                "role": "ga",
                "status": "retired_unbuilt_policy_superseded",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract())
                self.replace_allocation(value, "40033", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_contract(value, expected_ga="40037")

    def test_retired_40034_cannot_be_reactivated_or_reassigned(self) -> None:
        mutations = (
            {"build": "40034", "role": "ga", "status": "active_ga"},
            {
                "build": "40034",
                "role": "validation",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
            {
                "build": "40034",
                "role": "ga",
                "status": "retired_unbuilt_policy_superseded",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract())
                self.replace_allocation(value, "40034", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_contract(value, expected_ga="40037")

    def test_retired_40035_cannot_be_reactivated_or_reassigned(self) -> None:
        mutations = (
            {"build": "40035", "role": "ga", "status": "active_ga"},
            {
                "build": "40035",
                "role": "validation",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
            {
                "build": "40035",
                "role": "ga",
                "status": "retired_unbuilt_policy_superseded",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract())
                self.replace_allocation(value, "40035", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_contract(value, expected_ga="40037")

    def test_retired_40036_cannot_be_reactivated_or_reassigned(self) -> None:
        mutations = (
            {"build": "40036", "role": "ga", "status": "active_ga"},
            {
                "build": "40036",
                "role": "validation",
                "status": "retired_after_notarization_before_install",
            },
            {
                "build": "40036",
                "role": "ga",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract())
                self.replace_allocation(value, "40036", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_contract(value, expected_ga="40037")

    def test_only_40037_can_be_the_single_active_ga(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"].append(
            {"build": "40037", "role": "ga", "status": "active_ga"}
        )
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "allocated more than once",
        ):
            allocations.validate_contract(value, expected_ga="40037")

        value = copy.deepcopy(allocations.load_contract())
        self.allocation_for_build(value, "40037")["role"] = "final"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "wrong role",
        ):
            allocations.validate_contract(value, expected_ga="40037")

    def test_active_ga_source_binding_cannot_drift(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["active_ga"] = "40030"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "differs from release source constants",
        ):
            allocations.validate_contract(value, expected_ga="40037")

    def test_allocation_history_cannot_omit_a_reserved_build(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        records = value["allocations"]
        self.assertIsInstance(records, list)
        value["allocations"] = [
            record
            for record in records
            if isinstance(record, dict) and record.get("build") != "40021"
        ]
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(value, expected_ga="40037")

    def test_non_string_role_is_a_stable_contract_error(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        self.allocation_for_build(value, "40021")["role"] = []
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "build 40021 role or status is invalid",
        ):
            allocations.validate_contract(value, expected_ga="40037")

    def test_retired_40026_status_cannot_be_rewritten(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        self.allocation_for_build(value, "40026")["status"] = "active_ga"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(value, expected_ga="40037")

    def test_retired_40028_status_cannot_be_rewritten(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        self.allocation_for_build(value, "40028")["status"] = "active_ga"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(value, expected_ga="40037")

    def test_allocation_history_rejects_records_after_the_active_ga(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        records = value["allocations"]
        self.assertIsInstance(records, list)
        records.append(
            {
                "build": "40038",
                "role": "ga",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            }
        )
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "must end with exactly one active GA allocation",
        ):
            allocations.validate_contract(value, expected_ga="40037")


if __name__ == "__main__":
    unittest.main()
