from __future__ import annotations

import copy
import unittest

from scripts import verify_release_build_allocations as allocations


class ReleaseBuildAllocationTests(unittest.TestCase):
    def test_active_generation_is_the_single_release_pair(self) -> None:
        generation = allocations.ACTIVE_RELEASE_GENERATION
        self.assertEqual(generation.product_version, "0.4.0")
        self.assertEqual(generation.validation_build, "40030")
        self.assertEqual(generation.final_build, "40031")
        allocations.verify_source_bindings(allocations.load_contract())

    def test_tracked_contract_matches_active_release_pair(self) -> None:
        value = allocations.load_contract()
        allocations.validate_contract(
            value,
            expected_validation="40030",
            expected_final="40031",
        )

    def test_retired_40029_final_companion_cannot_be_reused_as_validation(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["active_pair"]["validation"] = "40029"
        value["active_pair"]["final"] = "40030"
        value["allocations"][-3] = {
            "build": "40029",
            "role": "validation",
            "status": "active",
        }
        value["allocations"][-2] = {
            "build": "40030",
            "role": "final",
            "status": "active",
        }
        value["allocations"].pop()
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(
                value,
                expected_validation="40029",
                expected_final="40030",
            )

    def test_allocation_history_cannot_omit_a_reserved_build(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"] = value["allocations"][5:]
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(
                value,
                expected_validation="40030",
                expected_final="40031",
            )

    def test_non_string_role_is_a_stable_contract_error(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"][0]["role"] = []
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "build 40021 role or status is invalid",
        ):
            allocations.validate_contract(
                value,
                expected_validation="40030",
                expected_final="40031",
            )

    def test_retired_40026_status_cannot_be_rewritten(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"][5]["status"] = "active"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(
                value,
                expected_validation="40030",
                expected_final="40031",
            )

    def test_retired_40028_status_cannot_be_rewritten(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"][7]["status"] = "active"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_contract(
                value,
                expected_validation="40030",
                expected_final="40031",
            )


if __name__ == "__main__":
    unittest.main()
