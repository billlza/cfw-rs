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
        self.assertEqual(identity.product_version, "0.5.0")
        self.assertEqual(identity.ga_build, "50027")
        allocations.verify_source_bindings(allocations.load_contract())
        allocations.verify_closed_ledgers()
        self.assertEqual(list(allocations.CLOSED_CONTRACT_PATHS), ["0.4.0"])
        self.assertEqual(allocations.main(), 0)

    def test_tracked_contract_matches_active_ga_and_retires_consumed_ga_builds(self) -> None:
        value = allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"])
        allocations.validate_closed_contract(value)
        self.assertIsNone(value["active_ga"])
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
            "40037": (
                "ga",
                "retired_after_candidate_freeze_before_canonical_signing_output",
            ),
            "40038": (
                "ga",
                "retired_after_candidate_freeze_before_canonical_signing_output",
            ),
            "40039": (
                "ga",
                "retired_product_change_notarization_outcome_unknown",
            ),
            "40040": (
                "ga",
                "retired_security_dependency_change_before_notarization",
            ),
            "40041": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40042": (
                "ga",
                "retired_after_notarization_before_install_lane_test_not_hermetic",
            ),
            "40043": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40044": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40045": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40046": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40047": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40048": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40049": ("ga", "retired_product_change_notarization_outcome_unknown"),
            "40050": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40053": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40056": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40057": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40058": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40059": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40060": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40061": (
                "ga",
                "retired_product_change_after_install_before_ga_runtime_acceptance",
            ),
            "40062": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40063": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40064": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40065": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40066": ("ga", "retired_after_notarization_before_install"),
            "40067": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40068": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40069": ("ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
            "40073": ("ga", "retired_superseded_by_next_product_version"),
        }
        for build, (role, status) in expected.items():
            with self.subTest(build=build):
                self.assertEqual(
                    self.allocation_for_build(value, build),
                    {"build": build, "role": role, "status": status},
                )

    def test_retired_40029_final_companion_cannot_be_reused_as_ga(self) -> None:
        value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
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
            allocations.validate_closed_contract(value)

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
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40030", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "policy-superseded 40030 allocation changed",
                ):
                    allocations.validate_closed_contract(value)

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
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40031", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

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
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40032", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

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
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40033", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

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
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40034", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

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
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40035", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

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
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40036", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40037_cannot_be_reactivated_or_reassigned(self) -> None:
        mutations = (
            {"build": "40037", "role": "ga", "status": "active_ga"},
            {
                "build": "40037",
                "role": "validation",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
            {
                "build": "40037",
                "role": "ga",
                "status": "retired_unbuilt_policy_superseded",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40037", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40038_cannot_be_reactivated_or_reassigned(self) -> None:
        mutations = (
            {"build": "40038", "role": "ga", "status": "active_ga"},
            {
                "build": "40038",
                "role": "validation",
                "status": (
                    "retired_after_candidate_freeze_before_canonical_signing_output"
                ),
            },
            {
                "build": "40038",
                "role": "ga",
                "status": "retired_unbuilt_policy_superseded",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40038", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40039_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40039", "role": "ga", "status": "active_ga"},
            {
                "build": "40039",
                "role": "validation",
                "status": "retired_product_change_notarization_outcome_unknown",
            },
            {
                "build": "40039",
                "role": "ga",
                "status": "retired_unbuilt_policy_superseded",
            },
            {
                "build": "40039",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40039", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40040_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40040", "role": "ga", "status": "active_ga"},
            {
                "build": "40040",
                "role": "validation",
                "status": "retired_security_dependency_change_before_notarization",
            },
            {
                "build": "40040",
                "role": "ga",
                "status": "retired_unbuilt_policy_superseded",
            },
            {
                "build": "40040",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40040", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40041_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40041", "role": "ga", "status": "active_ga"},
            {
                "build": "40041",
                "role": "validation",
                "status": "retired_product_change_after_install_before_ga_runtime_acceptance",
            },
            {
                "build": "40041",
                "role": "ga",
                "status": "retired_security_dependency_change_before_notarization",
            },
            {
                "build": "40041",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40041", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40042_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40042", "role": "ga", "status": "active_ga"},
            {
                "build": "40042",
                "role": "validation",
                "status": "retired_after_notarization_before_install_lane_test_not_hermetic",
            },
            {
                "build": "40042",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
            {
                "build": "40042",
                "role": "ga",
                "status": "retired_product_change_after_install_before_ga_runtime_acceptance",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40042", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40043_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40043", "role": "ga", "status": "active_ga"},
            {
                "build": "40043",
                "role": "validation",
                "status": "retired_product_change_after_install_before_ga_runtime_acceptance",
            },
            {
                "build": "40043",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
            {
                "build": "40043",
                "role": "ga",
                "status": "retired_after_notarization_before_install_lane_test_not_hermetic",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40043", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40044_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40044", "role": "ga", "status": "active_ga"},
            {
                "build": "40044",
                "role": "validation",
                "status": "retired_product_change_after_install_before_ga_runtime_acceptance",
            },
            {
                "build": "40044",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
            {
                "build": "40044",
                "role": "ga",
                "status": "retired_after_notarization_before_install_lane_test_not_hermetic",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40044", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40045_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40045", "role": "ga", "status": "active_ga"},
            {
                "build": "40045",
                "role": "validation",
                "status": "retired_product_change_after_install_before_ga_runtime_acceptance",
            },
            {
                "build": "40045",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
            {
                "build": "40045",
                "role": "ga",
                "status": "retired_after_notarization_before_install_lane_test_not_hermetic",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40045", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40046_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40046", "role": "ga", "status": "active_ga"},
            {
                "build": "40046",
                "role": "validation",
                "status": "retired_product_change_after_install_before_ga_runtime_acceptance",
            },
            {
                "build": "40046",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
            {
                "build": "40046",
                "role": "ga",
                "status": "retired_after_notarization_before_install_lane_test_not_hermetic",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40046", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40047_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40047", "role": "ga", "status": "active_ga"},
            {
                "build": "40047",
                "role": "validation",
                "status": "retired_product_change_after_install_before_ga_runtime_acceptance",
            },
            {
                "build": "40047",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
            {
                "build": "40047",
                "role": "ga",
                "status": "retired_after_notarization_before_install_lane_test_not_hermetic",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40047", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_retired_40048_cannot_be_reactivated_or_relabelled(self) -> None:
        mutations = (
            {"build": "40048", "role": "ga", "status": "active_ga"},
            {
                "build": "40048",
                "role": "validation",
                "status": "retired_product_change_after_install_before_ga_runtime_acceptance",
            },
            {
                "build": "40048",
                "role": "ga",
                "status": "retired_after_notarization_before_install",
            },
            {
                "build": "40048",
                "role": "ga",
                "status": "retired_after_notarization_before_install_lane_test_not_hermetic",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
                self.replace_allocation(value, "40048", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

    def test_closed_product_version_keeps_40073_retired(self) -> None:
        value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
        value["allocations"].append(
            {"build": "40073", "role": "ga", "status": "active_ga"}
        )
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "allocated more than once",
        ):
            allocations.validate_closed_contract(value)

        for mutation in (
            {"build": "40073", "role": "ga", "status": "active_ga"},
            {"build": "40073", "role": "final", "status": "retired_superseded_by_next_product_version"},
        ):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(
                    allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"])
                )
                self.replace_allocation(value, "40073", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed",
                ):
                    allocations.validate_closed_contract(value)

        value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
        value["active_ga"] = "40073"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "closed product version cannot have an active GA",
        ):
            allocations.validate_closed_contract(value)
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "product version is closed",
        ):
            allocations.validate_contract(value, expected_ga="40073")

        value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
        value["allocations"].append(
            {
                "build": "40074",
                "role": "ga",
                "status": "retired_after_candidate_freeze_before_canonical_signing_output",
            }
        )
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "outside its fixed record",
        ):
            allocations.validate_closed_contract(value)

    def test_previews_are_consumed_validation_lineages_before_the_single_active_ga(self) -> None:
        value = allocations.load_contract()
        allocations.validate_contract(value, expected_ga="50027")
        self.assertEqual(value["product_version"], "0.5.0")
        self.assertEqual(value["active_ga"], "50027")
        builds = [record["build"] for record in value["allocations"]]
        self.assertEqual(builds, [str(build) for build in range(50001, 50028)])
        for build in range(50001, 50026):
            with self.subTest(build=build):
                self.assertEqual(
                    self.allocation_for_build(value, str(build)),
                    {
                        "build": str(build),
                        "role": "validation",
                        "status": "retired_preview_validation_consumed",
                    },
                )
        # 50026 was frozen and consumed by a failed Developer ID signing attempt.
        self.assertEqual(
            self.allocation_for_build(value, "50026"),
            {
                "build": "50026",
                "role": "ga",
                "status": "retired_after_candidate_freeze_before_canonical_signing_output",
            },
        )
        self.assertEqual(
            self.allocation_for_build(value, "50027"),
            {"build": "50027", "role": "ga", "status": "active_ga"},
        )
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "product version is still active",
        ):
            allocations.validate_closed_contract(value)

    def test_a_consumed_preview_cannot_become_the_ga(self) -> None:
        for build in ("50001", "50025"):
            for mutation in (
                {"build": build, "role": "ga", "status": "active_ga"},
                {"build": build, "role": "ga", "status": "retired_preview_validation_consumed"},
                {"build": build, "role": "validation", "status": "retired_after_notarization_before_install"},
            ):
                with self.subTest(build=build, mutation=mutation):
                    value = copy.deepcopy(allocations.load_contract())
                    self.replace_allocation(value, build, mutation)
                    with self.assertRaisesRegex(
                        allocations.ReleaseBuildAllocationError,
                        "immutable retired allocation prefix changed",
                    ):
                        allocations.validate_contract(value, expected_ga="50027")

    def test_consumed_ga_50026_cannot_return_or_disappear(self) -> None:
        for mutation in (
            {"build": "50026", "role": "ga", "status": "active_ga"},
            {"build": "50026", "role": "ga", "status": "retired_after_notarization_before_install"},
            {"build": "50026", "role": "validation", "status": "retired_preview_validation_consumed"},
        ):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(allocations.load_contract())
                self.replace_allocation(value, "50026", mutation)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "retired GA allocations changed|immutable retired allocation prefix changed",
                ):
                    allocations.validate_contract(value, expected_ga="50027")
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"] = [
            record for record in value["allocations"] if record["build"] != "50026"
        ]
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "retired GA allocations changed"):
            allocations.validate_contract(value, expected_ga="50027")

    def test_only_50027_can_be_the_single_active_ga(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["allocations"].append(
            {"build": "50027", "role": "ga", "status": "active_ga"}
        )
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "allocated more than once",
        ):
            allocations.validate_contract(value, expected_ga="50027")

        value = copy.deepcopy(allocations.load_contract())
        self.allocation_for_build(value, "50027")["role"] = "final"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "wrong role",
        ):
            allocations.validate_contract(value, expected_ga="50027")

        value = copy.deepcopy(allocations.load_contract())
        self.allocation_for_build(value, "50027")["status"] = "retired_after_notarization_before_install"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "is allocated as retired_after_notarization_before_install",
        ):
            allocations.validate_contract(value, expected_ga="50027")

    def test_active_ga_source_binding_cannot_drift(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["active_ga"] = "50001"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "differs from release source constants",
        ):
            allocations.validate_contract(value, expected_ga="50027")
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "differs from the fixed successor",
        ):
            allocations.validate_contract(value, expected_ga="50001")

    def test_allocation_history_cannot_omit_a_reserved_build(self) -> None:
        for path, build in (
            (allocations.CLOSED_CONTRACT_PATHS["0.4.0"], "40021"),
            (allocations.CONTRACT_PATH, "50001"),
        ):
            with self.subTest(build=build):
                value = copy.deepcopy(allocations.load_contract(path))
                records = value["allocations"]
                self.assertIsInstance(records, list)
                value["allocations"] = [
                    record
                    for record in records
                    if isinstance(record, dict) and record.get("build") != build
                ]
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    "immutable retired allocation prefix changed",
                ):
                    if build == "40021":
                        allocations.validate_closed_contract(value)
                    else:
                        allocations.validate_contract(value, expected_ga="50027")

    def test_non_string_role_is_a_stable_contract_error(self) -> None:
        value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
        self.allocation_for_build(value, "40021")["role"] = []
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "build 40021 role or status is invalid",
        ):
            allocations.validate_closed_contract(value)

    def test_retired_40026_status_cannot_be_rewritten(self) -> None:
        value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
        self.allocation_for_build(value, "40026")["status"] = "active_ga"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_closed_contract(value)

    def test_retired_40028_status_cannot_be_rewritten(self) -> None:
        value = copy.deepcopy(allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS["0.4.0"]))
        self.allocation_for_build(value, "40028")["status"] = "active_ga"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "immutable retired allocation prefix changed",
        ):
            allocations.validate_closed_contract(value)

    def test_allocation_history_rejects_records_after_the_active_ga(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        records = value["allocations"]
        self.assertIsInstance(records, list)
        records.append(
            {
                "build": str(int(value["active_ga"]) + 1),
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
            allocations.validate_contract(value, expected_ga="50027")

    def test_a_ledger_of_an_unknown_product_version_is_rejected(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["product_version"] = "0.6.0"
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "allocation ledger identity is invalid",
        ):
            allocations.validate_contract(value, expected_ga="50027")


if __name__ == "__main__":
    unittest.main()
