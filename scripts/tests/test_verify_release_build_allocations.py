from __future__ import annotations

from contextlib import redirect_stderr
import copy
import dataclasses
import io
from pathlib import Path
import re
import sys
import tempfile
from typing import Final
import unittest
from unittest.mock import patch

from scripts import verify_release_build_allocations as allocations
from scripts.dormant_app_install import PredecessorProfile, SUPPORTED_PREDECESSORS
from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY, RELEASE_IDENTITY_PATH
from scripts.release_git import run_release_git
from scripts.repository_source_identity import RELEASE_PATHS
from scripts.tests.release_identity_fixture import (
    NEXT_GA_BUILD,
    next_patch,
    noncanonical,
    retired_ga_builds,
)


GA_BUILD: Final = ACTIVE_RELEASE_IDENTITY.ga_build


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
        self.assertIs(identity, ACTIVE_RELEASE_IDENTITY)
        self.assertEqual(allocations.load_contract()["active_ga"], identity.ga_build)
        allocations.verify_source_bindings(
            allocations.load_contract(),
            notes_directory=allocations.RETIREMENT_NOTES_DIRECTORY,
            predecessors=SUPPORTED_PREDECESSORS,
        )
        allocations.verify_closed_ledgers()
        self.assertEqual(
            set(allocations.CLOSED_CONTRACT_PATHS),
            set(allocations.POLICIES) - {allocations.PRODUCT_VERSION},
        )
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

    def test_a_consumed_preview_cannot_become_the_ga(self) -> None:
        path = allocations.CLOSED_CONTRACT_PATHS["0.5.0"]
        for build, _role, _status in (
            allocations.PREVIEW_VALIDATION_PREFIX[0],
            allocations.PREVIEW_VALIDATION_PREFIX[-1],
        ):
            for mutation in (
                {"build": build, "role": "ga", "status": "active_ga"},
                {"build": build, "role": "ga", "status": "retired_preview_validation_consumed"},
                {"build": build, "role": "validation", "status": "retired_after_notarization_before_install"},
            ):
                with self.subTest(build=build, mutation=mutation):
                    value = copy.deepcopy(allocations.load_contract(path))
                    self.replace_allocation(value, build, mutation)
                    with self.assertRaisesRegex(
                        allocations.ReleaseBuildAllocationError,
                        "immutable retired allocation prefix changed",
                    ):
                        allocations.validate_closed_contract(value)

    def test_allocation_history_cannot_omit_a_reserved_build(self) -> None:
        for version, build in (
            ("0.4.0", "40021"),
            ("0.5.0", allocations.PREVIEW_VALIDATION_PREFIX[0][0]),
        ):
            with self.subTest(build=build):
                value = copy.deepcopy(
                    allocations.load_contract(allocations.CLOSED_CONTRACT_PATHS[version])
                )
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
                    allocations.validate_closed_contract(value)

    def test_closed_0_5_0_keeps_its_published_ga(self) -> None:
        path = allocations.CLOSED_CONTRACT_PATHS["0.5.0"]
        published, role, status = allocations.PUBLISHED_GA_V050
        value = allocations.load_contract(path)
        allocations.validate_closed_contract(value)
        self.assertIsNone(value["active_ga"])
        self.assertEqual(value["allocations"][-1], {"build": published, "role": role, "status": status})
        self.assertEqual(
            [tuple(record.values()) for record in value["allocations"][-5:-1]],
            list(allocations.RETIRED_GA_ALLOCATIONS_V050),
        )
        for mutation, message in (
            ({"build": published, "role": "ga", "status": "active_ga"}, "published GA .* changed"),
            (
                {"build": published, "role": "ga", "status": allocations.RETIRED_GA_ALLOCATIONS_V050[-1][2]},
                "published GA .* changed",
            ),
            ({"build": published, "role": "final", "status": status}, "published GA .* changed"),
        ):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(value)
                self.replace_allocation(changed, published, mutation)
                with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, message):
                    allocations.validate_closed_contract(changed)
        removed = copy.deepcopy(value)
        del removed["allocations"][-1]
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "published GA allocation is absent"):
            allocations.validate_closed_contract(removed)
        reopened = copy.deepcopy(value)
        reopened["active_ga"] = published
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "cannot have an active GA"):
            allocations.validate_closed_contract(reopened)
        extended = copy.deepcopy(value)
        extended["allocations"].append(
            {
                "build": str(int(published) + 1),
                "role": "ga",
                "status": "retired_after_candidate_freeze_before_canonical_signing_output",
            }
        )
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "outside its fixed record"):
            allocations.validate_closed_contract(extended)

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


    def test_a_ledger_of_an_unknown_product_version_is_rejected(self) -> None:
        value = copy.deepcopy(allocations.load_contract())
        value["product_version"] = next_patch(allocations.PRODUCT_VERSION)
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "allocation ledger identity is invalid",
        ):
            allocations.validate_contract(value, expected_ga=GA_BUILD)


def synthetic_ledger(*ga_statuses: str) -> dict[str, object]:
    """The active version's fixed history, then GA allocations; the last is active."""
    policy = allocations.ACTIVE_POLICY
    fixed = (*policy.immutable_prefix, *(() if policy.superseded is None else (policy.superseded,)))
    records: list[dict[str, object]] = [
        {"build": build, "role": role, "status": status} for build, role, status in fixed
    ]
    first_ga = policy.first_build + len(fixed)
    for offset, status in enumerate(ga_statuses):
        records.append({"build": str(first_ga + offset), "role": "ga", "status": status})
    return {
        "active_ga": records[-1]["build"],
        "allocations": records,
        "document": allocations.DOCUMENT,
        "product_version": allocations.PRODUCT_VERSION,
    }


def published_ga_versions() -> dict[str, str]:
    """The GA build each closed product version published, with that version."""
    return {
        policy.published[0]: policy.product_version
        for policy in allocations.POLICIES.values()
        if policy.published is not None
    }


def retirement_note(build: str, status: str) -> str:
    return (
        f"# GA build {build} retirement\n\n"
        f"GA build {build} is permanently classified as\n"
        f"`{status}`. It must not be rebuilt, re-signed or reused.\n"
    )


FREEZE: Final = "retired_after_candidate_freeze_before_canonical_signing_output"
NOTARIZED: Final = "retired_after_notarization_before_install"
INSTALLED: Final = "retired_security_dependency_change_after_install_before_ga_runtime_acceptance"


class ActiveLedgerRuleTests(unittest.TestCase):
    """The active ledger rules on synthetic ledgers and notes directories."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.notes = Path(temporary.name)

    def write_notes(self, value: dict[str, object]) -> None:
        for record in value["allocations"][:-1]:
            if record["role"] == "ga":
                (self.notes / f"ga-build-{record['build']}-retirement.md").write_text(
                    retirement_note(record["build"], record["status"]), encoding="utf-8"
                )

    def ga_builds(self, value: dict[str, object]) -> list[str]:
        return [record["build"] for record in value["allocations"] if record["role"] == "ga"]

    def test_retired_ga_allocations_precede_the_one_active_tail(self) -> None:
        value = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        retired, active = self.ga_builds(value)[:-1], self.ga_builds(value)[-1]
        ledger = allocations.validate_contract(value, expected_ga=active)
        self.assertEqual(ledger.active_ga, active)
        self.assertEqual(ledger.product_version, allocations.PRODUCT_VERSION)
        self.assertEqual(ledger.first_build, allocations.ACTIVE_POLICY.first_build)
        self.assertEqual(ledger.retired_ga, ((retired[0], FREEZE), (retired[1], NOTARIZED)))
        self.assertEqual(ledger.builds, frozenset(record["build"] for record in value["allocations"]))
        first_active = synthetic_ledger("active_ga")
        self.assertEqual(
            allocations.validate_contract(
                first_active, expected_ga=first_active["active_ga"]
            ).retired_ga,
            (),
        )

    def test_the_active_ga_is_the_release_identity_and_the_last_record(self) -> None:
        value = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        retired, active = self.ga_builds(value)[0], self.ga_builds(value)[-1]
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError, "differs from the release identity"
        ):
            allocations.validate_contract(value, expected_ga=retired)
        drifted = copy.deepcopy(value)
        drifted["active_ga"] = retired
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError, f"active GA build {retired} is allocated as {FREEZE}"
        ):
            allocations.validate_contract(drifted, expected_ga=retired)
        noncanonical_ga = copy.deepcopy(value)
        noncanonical_ga["active_ga"] = noncanonical(active)
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "not canonical"):
            allocations.validate_contract(noncanonical_ga, expected_ga=noncanonical(active))
        wrong_role = copy.deepcopy(value)
        wrong_role["allocations"][-1]["role"] = "final"
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "wrong role"):
            allocations.validate_contract(wrong_role, expected_ga=active)
        unallocated = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        unallocated["active_ga"] = str(int(active) + 1)
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "is not allocated"):
            allocations.validate_contract(unallocated, expected_ga=str(int(active) + 1))

    def test_nothing_follows_the_active_ga_and_only_one_exists(self) -> None:
        value = synthetic_ledger(FREEZE, "active_ga", NOTARIZED)
        value["active_ga"] = self.ga_builds(value)[1]
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            "must end with exactly one active GA allocation",
        ):
            allocations.validate_contract(value, expected_ga=value["active_ga"])
        twice = synthetic_ledger(FREEZE, "active_ga", "active_ga")
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError, "exactly one active GA"
        ):
            allocations.validate_contract(twice, expected_ga=twice["active_ga"])

    def test_every_record_between_the_history_and_the_tail_is_a_retired_ga(self) -> None:
        for role, status in (
            ("validation", NOTARIZED),
            ("final", "retired_unbuilt_reserved_final_companion"),
        ):
            with self.subTest(role=role, status=status):
                value = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
                value["allocations"][-2].update(role=role, status=status)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    f"build {value['allocations'][-2]['build']} between the fixed history "
                    "and the active GA is not a retired GA allocation",
                ):
                    allocations.validate_contract(value, expected_ga=value["active_ga"])

    def test_the_ga_history_stays_gap_free(self) -> None:
        value = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        del value["allocations"][-2]
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "gap-free"):
            allocations.validate_contract(value, expected_ga=value["active_ga"])

    def test_the_history_starts_at_the_first_build_of_the_policy(self) -> None:
        # Replacing the first allocation instead of appending to it loses history.
        value = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        del value["allocations"][0]
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError, "immutable retired allocation prefix|gap-free"
        ):
            allocations.validate_contract(value, expected_ga=value["active_ga"])
        earlier = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        earlier["allocations"].insert(
            0,
            {
                "build": str(allocations.ACTIVE_POLICY.first_build - 1),
                "role": "ga",
                "status": FREEZE,
            },
        )
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError, "immutable retired allocation prefix|gap-free"
        ):
            allocations.validate_contract(earlier, expected_ga=earlier["active_ga"])

    def test_a_closed_product_ledger_is_never_the_active_ledger(self) -> None:
        for version, path in allocations.CLOSED_CONTRACT_PATHS.items():
            value = copy.deepcopy(allocations.load_contract(path))
            last = value["allocations"][-1]["build"]
            with self.subTest(version=version), self.assertRaisesRegex(
                allocations.ReleaseBuildAllocationError, "product version is closed"
            ):
                allocations.validate_contract(value, expected_ga=last)

    def test_every_retired_ga_has_its_exact_classification_note(self) -> None:
        value = synthetic_ledger(FREEZE, INSTALLED, "active_ga")
        self.write_notes(value)
        # Notes before the active ledger's first build belong to closed history.
        (self.notes / "ga-build-40031-retirement.md").write_text("closed history\n", encoding="utf-8")
        (self.notes / "validation-build-40021-retirement.md").write_text("other\n", encoding="utf-8")
        ledger = allocations.validate_contract(value, expected_ga=value["active_ga"])
        allocations.validate_retirement_notes(ledger, self.notes)

        retired = self.ga_builds(value)[0]
        note = self.notes / f"ga-build-{retired}-retirement.md"
        cases: tuple[tuple[str | bytes | None, str], ...] = (
            (None, f"retired GA build {retired} has no retirement note"),
            (retirement_note(retired, NOTARIZED), "does not classify"),
            (retirement_note(self.ga_builds(value)[1], FREEZE), "does not classify"),
            (retirement_note(retired, FREEZE) * 2, "does not classify"),
            # A backticked status elsewhere is not the classification sentence.
            (f"GA build {retired} is retired.\n`{FREEZE}`\n", "does not classify"),
            (b"\xff", "unreadable"),
            # A note drafted before the commit it names exists is not finished.
            (
                retirement_note(retired, FREEZE) + "Commit `@TOOLING_COMMIT@` fixes it.\n",
                "still holds the placeholder @TOOLING_COMMIT@",
            ),
        )
        original = note.read_bytes()
        for text, message in cases:
            with self.subTest(text=text):
                if text is None:
                    note.unlink()
                elif isinstance(text, bytes):
                    note.write_bytes(text)
                else:
                    note.write_text(text, encoding="utf-8")
                try:
                    with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, message):
                        allocations.validate_retirement_notes(ledger, self.notes)
                finally:
                    note.write_bytes(original)

    def test_a_rewritten_retired_status_contradicts_its_note(self) -> None:
        value = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        self.write_notes(value)
        value["allocations"][-2]["status"] = FREEZE
        ledger = allocations.validate_contract(value, expected_ga=value["active_ga"])
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "does not classify"):
            allocations.validate_retirement_notes(ledger, self.notes)

    def test_every_note_from_the_first_build_names_a_retired_ga(self) -> None:
        value = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        self.write_notes(value)
        ledger = allocations.validate_contract(value, expected_ga=value["active_ga"])
        active = value["active_ga"]
        # Below the first build, so no note of the ledger shares its name on a
        # case-insensitive volume.
        closed = str(ledger.first_build - 1)
        for name, message in (
            (f"ga-build-{active}-retirement.md", "at or above the active GA"),
            (f"ga-build-{int(active) + 1}-retirement.md", "at or above the active GA"),
            (f"ga-build-{noncanonical(active)}-retirement.md", "name is not canonical"),
            # A misspelt name on a case-insensitive volume is reported, not skipped.
            (f"GA-build-{closed}-retirement.md", "name is not canonical"),
            (f"ga-build-{closed}-retirement.MD", "name is not canonical"),
        ):
            with self.subTest(name=name):
                stray = self.notes / name
                stray.write_text(retirement_note(active, FREEZE), encoding="utf-8")
                try:
                    with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, message):
                        allocations.validate_retirement_notes(ledger, self.notes)
                finally:
                    stray.unlink()
        allocations.validate_retirement_notes(ledger, self.notes)
        # A note from the first build on names a retired GA allocation, never a
        # build of the ledger's fixed history.
        first_retired = ledger.retired_ga[0][0]
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError,
            f"ga-build-{first_retired}-retirement.md names no retired GA allocation",
        ):
            allocations.validate_retirement_notes(
                dataclasses.replace(ledger, retired_ga=ledger.retired_ga[1:]), self.notes
            )

    def test_unreadable_notes_fail_closed(self) -> None:
        value = synthetic_ledger(FREEZE, "active_ga")
        ledger = allocations.validate_contract(value, expected_ga=value["active_ga"])
        retired = self.ga_builds(value)[0]
        (self.notes / f"ga-build-{retired}-retirement.md").mkdir()
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "unreadable"):
            allocations.validate_retirement_notes(ledger, self.notes)
        first_active = synthetic_ledger("active_ga")
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError, "notes directory is unreadable"
        ):
            allocations.validate_retirement_notes(
                allocations.validate_contract(first_active, expected_ga=first_active["active_ga"]),
                self.notes / "missing",
            )

    def test_the_classification_sentence_opens_a_line_and_names_its_own_build(self) -> None:
        value = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        self.write_notes(value)
        ledger = allocations.validate_contract(value, expected_ga=value["active_ga"])
        older, newer = self.ga_builds(value)[0], self.ga_builds(value)[1]
        note = self.notes / f"ga-build-{newer}-retirement.md"
        # Quoting another build's classification does not reclassify this one.
        note.write_text(
            retirement_note(newer, NOTARIZED) + "\n" + retirement_note(older, FREEZE),
            encoding="utf-8",
        )
        allocations.validate_retirement_notes(ledger, self.notes)
        note.write_text(
            f"Note: GA build {newer} is permanently classified as `{NOTARIZED}`.\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "does not classify"):
            allocations.validate_retirement_notes(ledger, self.notes)

    def test_installed_ga_builds_are_registered_install_predecessors(self) -> None:
        value = synthetic_ledger(FREEZE, INSTALLED, "active_ga")
        installed, active = self.ga_builds(value)[1], value["active_ga"]
        version = allocations.PRODUCT_VERSION
        ledger = allocations.validate_contract(value, expected_ga=active)
        registered = PredecessorProfile(version, installed, "a" * 64)
        allocations.validate_predecessor_registry(ledger, {installed: registered})
        for registry in ({}, {installed: PredecessorProfile(next_patch(version), installed, "a" * 64)}):
            with self.subTest(registry=registry), self.assertRaisesRegex(
                allocations.ReleaseBuildAllocationError,
                f"installed GA build {installed} \\({INSTALLED}\\) is not a registered",
            ):
                allocations.validate_predecessor_registry(ledger, registry)
        # A retirement before installation needs no predecessor profile.
        before_install = synthetic_ledger(FREEZE, NOTARIZED, "active_ga")
        allocations.validate_predecessor_registry(
            allocations.validate_contract(before_install, expected_ga=before_install["active_ga"]),
            {},
        )

    def test_registered_builds_of_the_product_are_allocations_below_the_ga(self) -> None:
        value = synthetic_ledger(FREEZE, INSTALLED, "active_ga")
        installed, active = self.ga_builds(value)[1], value["active_ga"]
        version = allocations.PRODUCT_VERSION
        ledger = allocations.validate_contract(value, expected_ga=active)
        registered = {installed: PredecessorProfile(version, installed, "a" * 64)}
        allocations.validate_predecessor_registry(
            ledger,
            {
                **registered,
                # Another product version's lineage is outside this ledger.
                "40073": PredecessorProfile("0.4.0", "40073", "b" * 64),
            },
        )
        for build, message in (
            (active, "is not an allocated"),
            (str(int(active) + 1), "is not an allocated"),
            (str(ledger.first_build - 1), "is not an allocated"),
        ):
            with self.subTest(build=build), self.assertRaisesRegex(
                allocations.ReleaseBuildAllocationError, message
            ):
                allocations.validate_predecessor_registry(
                    ledger, {**registered, build: PredecessorProfile(version, build, "c" * 64)}
                )

    def test_a_registered_ga_build_was_retired_after_install(self) -> None:
        value = synthetic_ledger(FREEZE, NOTARIZED, INSTALLED, "active_ga")
        ledger = allocations.validate_contract(value, expected_ga=value["active_ga"])
        version = allocations.PRODUCT_VERSION
        freeze, notarized, installed = self.ga_builds(value)[:3]
        installed_profile = PredecessorProfile(version, installed, "a" * 64)
        allocations.validate_predecessor_registry(ledger, {installed: installed_profile})
        for build, status in ((freeze, FREEZE), (notarized, NOTARIZED)):
            with self.subTest(build=build), self.assertRaisesRegex(
                allocations.ReleaseBuildAllocationError,
                f"install predecessor {build} is a GA build retired as {status}",
            ):
                allocations.validate_predecessor_registry(
                    ledger,
                    {
                        installed: installed_profile,
                        build: PredecessorProfile(version, build, "b" * 64),
                    },
                )

    def test_installed_retirements_are_the_after_install_and_superseded_statuses(self) -> None:
        self.assertEqual(
            allocations.INSTALLED_GA_STATUSES,
            {
                "retired_product_change_after_install_before_ga_runtime_acceptance",
                "retired_security_dependency_change_after_install_before_ga_runtime_acceptance",
                "retired_superseded_by_next_product_version",
            },
        )
        self.assertLessEqual(allocations.INSTALLED_GA_STATUSES, allocations.STATUSES)


class LiveLedgerTests(unittest.TestCase):
    """The tracked ledger agrees with the identity file, its notes and the registry."""

    def test_live_ledger_ends_with_the_identity_build(self) -> None:
        value = allocations.load_contract()
        ledger = allocations.validate_contract(value, expected_ga=GA_BUILD)
        self.assertEqual(value["active_ga"], GA_BUILD)
        self.assertEqual(value["allocations"][-1], {"build": GA_BUILD, "role": "ga", "status": "active_ga"})
        self.assertEqual(
            [record["build"] for record in value["allocations"]],
            [str(build) for build in range(ledger.first_build, int(GA_BUILD) + 1)],
        )
        self.assertEqual(tuple(build for build, _ in ledger.retired_ga), retired_ga_builds())
        allocations.validate_retirement_notes(ledger, allocations.RETIREMENT_NOTES_DIRECTORY)
        allocations.validate_predecessor_registry(ledger, SUPPORTED_PREDECESSORS)
        self.assertIs(allocations.supported_predecessors(), SUPPORTED_PREDECESSORS)
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError, "product version is still active"
        ):
            allocations.validate_closed_contract(value)

    def test_a_rewritten_live_retired_status_contradicts_its_note(self) -> None:
        for retired in retired_ga_builds():
            with self.subTest(build=retired):
                value = copy.deepcopy(allocations.load_contract())
                record = next(
                    record for record in value["allocations"] if record["build"] == retired
                )
                record["status"] = next(
                    status
                    for status in sorted(allocations.STATUSES)
                    if status.startswith("retired_") and status != record["status"]
                )
                ledger = allocations.validate_contract(value, expected_ga=GA_BUILD)
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError, "does not classify"
                ):
                    allocations.validate_retirement_notes(
                        ledger, allocations.RETIREMENT_NOTES_DIRECTORY
                    )

    def test_the_gate_binds_the_notes_and_the_registry(self) -> None:
        # The identity names the GA allocated after a retired one, which needs
        # its retirement note.
        retired = synthetic_ledger(FREEZE, "active_ga")
        identity = dataclasses.replace(ACTIVE_RELEASE_IDENTITY, ga_build=retired["active_ga"])
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            allocations, "ACTIVE_RELEASE_IDENTITY", identity
        ), self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "has no retirement note"):
            allocations.verify_source_bindings(
                retired, notes_directory=Path(temporary), predecessors=SUPPORTED_PREDECESSORS
            )
        unallocated = {
            **SUPPORTED_PREDECESSORS,
            GA_BUILD: PredecessorProfile(allocations.PRODUCT_VERSION, GA_BUILD, "a" * 64),
        }
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "below the active GA"):
            allocations.verify_source_bindings(
                allocations.load_contract(),
                notes_directory=allocations.RETIREMENT_NOTES_DIRECTORY,
                predecessors=unallocated,
            )
        stderr = io.StringIO()
        with patch.object(
            allocations, "supported_predecessors", return_value=unallocated
        ), redirect_stderr(stderr):
            self.assertEqual(allocations.main(), 1)
        self.assertRegex(stderr.getvalue(), r"\Aerror: install predecessor .* below the active GA")
        published = published_ga_versions()
        unregistered = {
            build: profile
            for build, profile in SUPPORTED_PREDECESSORS.items()
            if build not in published
        }
        with self.assertRaisesRegex(
            allocations.ReleaseBuildAllocationError, "published GA build [0-9]+ is not a registered"
        ):
            allocations.verify_source_bindings(
                allocations.load_contract(),
                notes_directory=allocations.RETIREMENT_NOTES_DIRECTORY,
                predecessors=unregistered,
            )
        stderr = io.StringIO()
        with patch.object(
            allocations, "supported_predecessors", return_value=unregistered
        ), redirect_stderr(stderr):
            self.assertEqual(allocations.main(), 1)
        self.assertRegex(stderr.getvalue(), r"\Aerror: published GA build [0-9]+ is not a registered")

    def test_every_published_ga_is_a_registered_install_predecessor(self) -> None:
        published = published_ga_versions()
        self.assertTrue(published)
        allocations.validate_published_predecessors(SUPPORTED_PREDECESSORS)
        for build, version in published.items():
            for registry in (
                {other: profile for other, profile in SUPPORTED_PREDECESSORS.items() if other != build},
                {
                    **SUPPORTED_PREDECESSORS,
                    build: PredecessorProfile(next_patch(version), build, "a" * 64),
                },
            ):
                with self.subTest(build=build, registered=registry.get(build)), self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError,
                    f"published GA build {build} is not a registered {re.escape(version)} "
                    "install predecessor",
                ):
                    allocations.validate_published_predecessors(registry)

    def test_an_unimportable_registry_is_a_typed_gate_error(self) -> None:
        with patch.dict(sys.modules, {"scripts.dormant_app_install": None}):
            with self.assertRaisesRegex(
                allocations.ReleaseBuildAllocationError, "registry is unavailable"
            ) as raised:
                allocations.supported_predecessors()
        self.assertIsInstance(raised.exception.__cause__, ImportError)

    def test_live_retired_ga_builds_cannot_return_or_disappear(self) -> None:
        for build in retired_ga_builds():
            with self.subTest(build=build, mutation="reactivated"):
                value = copy.deepcopy(allocations.load_contract())
                next(r for r in value["allocations"] if r["build"] == build)["status"] = "active_ga"
                with self.assertRaisesRegex(
                    allocations.ReleaseBuildAllocationError, "exactly one active GA"
                ):
                    allocations.validate_contract(value, expected_ga=GA_BUILD)
            with self.subTest(build=build, mutation="removed"):
                value = copy.deepcopy(allocations.load_contract())
                value["allocations"] = [r for r in value["allocations"] if r["build"] != build]
                with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "gap-free"):
                    allocations.validate_contract(value, expected_ga=GA_BUILD)
        with self.assertRaisesRegex(allocations.ReleaseBuildAllocationError, "differs from the release identity"):
            allocations.validate_contract(allocations.load_contract(), expected_ga=NEXT_GA_BUILD)

    def test_policies_hold_history_but_no_active_build(self) -> None:
        self.assertFalse(allocations.ACTIVE_POLICY.closed)
        self.assertEqual(allocations.ACTIVE_POLICY.retired_ga, ())
        self.assertEqual(allocations.CONTRACT_RELATIVE_PATH, allocations.ACTIVE_POLICY.relative_path)
        self.assertEqual(allocations.CONTRACT_PATH, allocations.REPOSITORY_ROOT / allocations.CONTRACT_RELATIVE_PATH)
        self.assertNotIn("active_ga", {field.name for field in dataclasses.fields(allocations.LedgerPolicy)})
        self.assertIsNone(allocations.ACTIVE_POLICY.published)
        for version, policy in allocations.POLICIES.items():
            with self.subTest(version=version):
                self.assertEqual(policy.product_version, version)
                self.assertEqual(policy.closed, version != allocations.PRODUCT_VERSION)
                if policy.immutable_prefix:
                    self.assertEqual(policy.immutable_prefix[0][0], str(policy.first_build))

    def test_builds_increase_across_product_versions(self) -> None:
        # A GA install replaces the newest registered build below it, whatever
        # its product version, so each version allocates above every earlier one.
        policies = list(allocations.POLICIES.values())
        self.assertIs(policies[-1], allocations.ACTIVE_POLICY)
        for earlier, later in zip(policies, policies[1:]):
            with self.subTest(earlier=earlier.product_version, later=later.product_version):
                ledger = allocations.load_contract(allocations.REPOSITORY_ROOT / earlier.relative_path)
                self.assertLess(
                    max(int(record["build"]) for record in ledger["allocations"]), later.first_build
                )

    def test_every_ledger_file_has_a_policy(self) -> None:
        self.assertEqual(
            sorted(
                path.relative_to(allocations.REPOSITORY_ROOT)
                for path in (allocations.REPOSITORY_ROOT / "docs/release").glob(
                    "build-allocations-v*.json"
                )
            ),
            sorted(policy.relative_path for policy in allocations.POLICIES.values()),
        )


# The audit covers the reviewed release source closure except its documentation:
# the allocation ledger and the retirement notes live under docs/, and the
# guides record history and procedure in prose.
AUDIT_EXCLUDED_DOCUMENTATION_ROOT: Final = "docs/"
AUDIT_EXCLUDED_GUIDES: Final = frozenset({"CHANGELOG.md", "README.md", "RELEASE.md"})
# The allocation files inside the audited closure: the identity file names the
# active GA build and the install-predecessor registry names installed builds.
REGISTRY_FILE: Final = "scripts/dormant_app_install.py"
ALLOCATION_FILES: Final = frozenset(
    {
        RELEASE_IDENTITY_PATH.relative_to(allocations.REPOSITORY_ROOT).as_posix(),
        REGISTRY_FILE,
    }
)
# The ledger policies fix where each product version's history starts: for a
# version opened without earlier history, at its first GA allocation, which
# stays its first build after it retires.
POLICY_FILE: Final = "scripts/verify_release_build_allocations.py"
# A token of 16 or more hexadecimal characters is a digest or an object ID
# (a checksum, a pbxproj identifier), never a build name, even when a run of
# its digits equals a build.
HEX_TOKEN_RE: Final = re.compile(rb"\A[0-9A-Fa-f]{16,}\Z")
ALPHANUMERIC_TOKEN_RE: Final = re.compile(rb"[0-9A-Za-z]+")


def named_builds(data: bytes, builds: tuple[str, ...]) -> set[str]:
    """The builds that `data` names as whole numbers outside digest tokens.

    Digit boundaries, not word boundaries, delimit a build: `_<build>_`,
    `ga/<build>/` and `Installed<build>Identity` all name it, while a longer
    number does not.
    """

    pattern = re.compile(
        rb"(?<![0-9])(" + b"|".join(build.encode("ascii") for build in builds) + rb")(?![0-9])"
    )
    readable = ALPHANUMERIC_TOKEN_RE.sub(
        lambda token: b" " * len(token.group(0))
        if HEX_TOKEN_RE.fullmatch(token.group(0))
        else token.group(0),
        data,
    )
    return {match.decode("ascii") for match in pattern.findall(readable)}


def tracked_audited_files() -> dict[str, bytes]:
    """The committed and staged files of the audited closure, by repository path."""

    repository = allocations.REPOSITORY_ROOT
    listing = run_release_git(
        repository,
        ["ls-files", "-z", "--cached", "--", *RELEASE_PATHS],
        protected_roots=RELEASE_PATHS,
    )
    files: dict[str, bytes] = {}
    for raw in filter(None, listing.split(b"\0")):
        relative = raw.decode("utf-8")
        if (
            relative.startswith(AUDIT_EXCLUDED_DOCUMENTATION_ROOT)
            or relative in AUDIT_EXCLUDED_GUIDES
        ):
            continue
        files[relative] = (repository / relative).read_bytes()
    return files


def ga_role_ledger_builds() -> tuple[str, ...]:
    """Every GA-role build the active ledger has allocated, retired or active."""

    return tuple(
        record["build"]
        for record in allocations.load_contract()["allocations"]
        if record["role"] == "ga"
    )


class AllocationLiteralAuditTests(unittest.TestCase):
    """Only the allocation files may name a GA build or an installed tree."""

    def test_build_names_are_digit_bounded_and_skip_digest_tokens(self) -> None:
        build = GA_BUILD
        for named in (
            f"ga/{build}/signed",
            f"_{build}_",
            f"buildNumber={build}\n",
            f'"{build}"',
            f"Installed{build}ServiceIdentity",
            f"0x{build}",
        ):
            with self.subTest(named=named):
                self.assertEqual(named_builds(named.encode(), (build,)), {build})
        for unnamed in (
            f"1{build}",
            f"{build}1",
            f"{'a' * 11}{build}",
            f"0A7B74B72B8B36F{build}CE94",
            f"{'ab' * 8}{build}{'cd' * 8}",
        ):
            with self.subTest(unnamed=unnamed):
                self.assertEqual(named_builds(unnamed.encode(), (build,)), set())
        # A short hexadecimal token is a name, not a digest.
        self.assertEqual(named_builds(f"a{build}".encode(), (build,)), {build})

    def test_no_audited_file_outside_the_allocation_files_names_a_ga_build(self) -> None:
        builds = ga_role_ledger_builds()
        self.assertEqual(builds, (*retired_ga_builds(), GA_BUILD))
        files = tracked_audited_files()
        self.assertTrue(ALLOCATION_FILES <= set(files))
        named = {
            relative: sorted(found)
            for relative, data in files.items()
            if (found := named_builds(data, builds))
        }
        first_build = [str(allocations.ACTIVE_POLICY.first_build)]
        unexpected = {
            relative: found
            for relative, found in named.items()
            if relative not in ALLOCATION_FILES
            and not (relative == POLICY_FILE and found == first_build)
        }
        self.assertEqual(unexpected, {})
        identity_file = RELEASE_IDENTITY_PATH.relative_to(allocations.REPOSITORY_ROOT)
        self.assertEqual(named[identity_file.as_posix()], [GA_BUILD])

    def test_no_installed_tree_digest_appears_outside_the_registry(self) -> None:
        digests = {
            profile.tree_sha256.encode("ascii"): build
            for build, profile in SUPPORTED_PREDECESSORS.items()
        }
        self.assertTrue(digests)
        files = tracked_audited_files()
        self.assertTrue(all(digest in files[REGISTRY_FILE] for digest in digests))
        outside = {
            relative: sorted(build for digest, build in digests.items() if digest in data)
            for relative, data in files.items()
            if relative != REGISTRY_FILE
        }
        self.assertEqual({relative: found for relative, found in outside.items() if found}, {})


if __name__ == "__main__":
    unittest.main()
