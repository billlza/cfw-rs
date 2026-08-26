from __future__ import annotations

import copy
import unittest

from scripts import verify_release_build_allocations as allocations


class ReleaseBuildAllocationTests(unittest.TestCase):
    def test_active_identity_is_the_single_ga_build(self) -> None:
        identity = allocations.ACTIVE_RELEASE_IDENTITY
        self.assertEqual(identity.product_version, "0.4.0")
        self.assertEqual(identity.ga_build, "40033")
        allocations.verify_source_bindings(allocations.load_contract())

    def test_tracked_contract_matches_active_ga_and_retires_consumed_ga_builds(self) -> None:
        value = allocations.load_contract()
        allocations.validate_contract(value, expected_ga="40033")
        self.assertEqual(value["active_ga"], "40033")
        self.assertEqual(
            value["allocations"][-4],
            {
                "build": "40030",
                "role": "validation",
                "status": "retired_unbuilt_policy_superseded",
            },
        )
        self.assertEqual(
            value["allocations"][-3],
            {
                "build": "40031",
                "role": "ga",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
        )
        self.assertEqual(
            value["allocations"][-2],
            {
                "build": "40032",
                "role": "ga",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
        )
        self.assertEqual(
            value["allocations"][-1],
            {"build": "40033", "role": "ga", "status": "active_ga"},
        )

    def test_retired_40029_final_companion_cannot_be_reused_as_ga(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["active_ga"] = "40029"
        value["allocations"][-5] = {
            "build": "40029",
            "role": "ga",
            "status": "active_ga",
        }
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
                value["allocations"][-4] = mutation
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "policy-superseded 40030 allocation changed",
                ):
                    allocations.validate_contract(value, expected_ga="40033")

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
                value["allocations"][-3] = mutation
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_contract(value, expected_ga="40033")

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
                value["allocations"][-2] = mutation
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_contract(value, expected_ga="40033")

    def test_only_40033_can_be_the_single_active_ga(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"].append(
            {"build": "40034", "role": "ga", "status": "active_ga"}
        )
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "exactly one active GA",
        ):
            allocations.validate_contract(value, expected_ga="40033")

        value = copy.deepcopy(allocations.load_contract())
        value["allocations"][-1]["role"] = "final"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "wrong role",
        ):
            allocations.validate_contract(value, expected_ga="40033")

    def test_active_ga_source_binding_cannot_drift(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["active_ga"] = "40030"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "differs from release source constants",
        ):
            allocations.validate_contract(value, expected_ga="40033")

    def test_allocation_history_cannot_omit_a_reserved_build(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"] = value["allocations"][5:]
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(value, expected_ga="40033")

    def test_non_string_role_is_a_stable_contract_error(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"][0]["role"] = []
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "build 40021 role or status is invalid",
        ):
            allocations.validate_contract(value, expected_ga="40033")

    def test_retired_40026_status_cannot_be_rewritten(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"][5]["status"] = "active_ga"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(value, expected_ga="40033")

    def test_retired_40028_status_cannot_be_rewritten(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"][7]["status"] = "active_ga"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(value, expected_ga="40033")


if __name__ == "__main__":
    unittest.main()
