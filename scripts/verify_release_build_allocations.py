#!/usr/bin/env python3
"""Verify that active CFM release builds never reuse an allocated identity."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

if __package__:
    from .release_build_identity import ACTIVE_RELEASE_IDENTITY
else:
    from release_build_identity import ACTIVE_RELEASE_IDENTITY

REPOSITORY_ROOT: Final = Path(__file__).resolve().parent.parent
DOCUMENT: Final = "cfm-release-build-allocation-v2"
PRODUCT_VERSION: Final = ACTIVE_RELEASE_IDENTITY.product_version
BUILD_PATTERN: Final = re.compile(r"\A[1-9][0-9]{4}\Z")
ROLES: Final = frozenset({"validation", "final", "ga"})
STATUSES: Final = frozenset(
    {
        "active_ga",
        "retired_after_notarization_before_install",
        "retired_after_notarization_before_install_preflight_protocol_incompatible",
        "retired_after_notarization_before_install_runtime_preflight_failed",
        "retired_after_notarization_before_install_runtime_preflight_toolchain_binding_mismatch",
        "retired_after_candidate_freeze_before_canonical_signing_output",
        "retired_product_change_notarization_outcome_unknown",
        "retired_security_dependency_change_before_notarization",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
        "retired_after_notarization_before_install_lane_test_not_hermetic",
        "retired_before_candidate_build_source_gate_contract_incomplete",
        "retired_unbuilt_policy_superseded",
        "retired_unbuilt_reserved_final_companion",
        "retired_superseded_by_next_product_version",
        "retired_preview_validation_consumed",
    }
)
IMMUTABLE_RETIRED_PREFIX: Final = (
    ("40021", "validation", "retired_after_notarization_before_install"),
    (
        "40022",
        "validation",
        "retired_after_notarization_before_install_preflight_protocol_incompatible",
    ),
    ("40023", "final", "retired_unbuilt_reserved_final_companion"),
    (
        "40024",
        "validation",
        "retired_after_notarization_before_install_runtime_preflight_failed",
    ),
    ("40025", "final", "retired_unbuilt_reserved_final_companion"),
    (
        "40026",
        "validation",
        "retired_after_notarization_before_install_runtime_preflight_toolchain_binding_mismatch",
    ),
    ("40027", "final", "retired_unbuilt_reserved_final_companion"),
    (
        "40028",
        "validation",
        "retired_before_candidate_build_source_gate_contract_incomplete",
    ),
    ("40029", "final", "retired_unbuilt_reserved_final_companion"),
)
POLICY_SUPERSEDED_ALLOCATION: Final = (
    "40030",
    "validation",
    "retired_unbuilt_policy_superseded",
)
RETIRED_GA_ALLOCATIONS: Final = (
    (
        "40031",
        "ga",
        "retired_after_candidate_freeze_before_canonical_signing_output",
    ),
    (
        "40032",
        "ga",
        "retired_after_candidate_freeze_before_canonical_signing_output",
    ),
    (
        "40033",
        "ga",
        "retired_after_candidate_freeze_before_canonical_signing_output",
    ),
    (
        "40034",
        "ga",
        "retired_after_candidate_freeze_before_canonical_signing_output",
    ),
    (
        "40035",
        "ga",
        "retired_after_candidate_freeze_before_canonical_signing_output",
    ),
    (
        "40036",
        "ga",
        "retired_after_notarization_before_install",
    ),
    (
        "40037",
        "ga",
        "retired_after_candidate_freeze_before_canonical_signing_output",
    ),
    (
        "40038",
        "ga",
        "retired_after_candidate_freeze_before_canonical_signing_output",
    ),
    (
        "40039",
        "ga",
        "retired_product_change_notarization_outcome_unknown",
    ),
    (
        "40040",
        "ga",
        "retired_security_dependency_change_before_notarization",
    ),
    (
        "40041",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40042",
        "ga",
        "retired_after_notarization_before_install_lane_test_not_hermetic",
    ),
    (
        "40043",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40044",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40045",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40046",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40047",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40048",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40049",
        "ga",
        "retired_product_change_notarization_outcome_unknown",
    ),
    (
        "40050",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40051",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40052",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40053",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40054",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40055",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40056",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),    (
        "40057",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40058",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40059",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40060",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40061",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40062",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40063",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40064",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40065",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40066",
        "ga",
        "retired_after_notarization_before_install",
    ),
    (
        "40067",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40068",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40069",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40070",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40071",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40072",
        "ga",
        "retired_product_change_after_install_before_ga_runtime_acceptance",
    ),
    (
        "40073",
        "ga",
        "retired_superseded_by_next_product_version",
    ),
)


PREVIEW_VALIDATION_PREFIX: Final = tuple(
    (str(build), "validation", "retired_preview_validation_consumed")
    for build in range(50001, 50026)
)

RETIRED_GA_ALLOCATIONS_V050: Final = (
    ("50026", "ga", "retired_after_candidate_freeze_before_canonical_signing_output"),
    ("50027", "ga", "retired_after_notarization_before_install"),
)


@dataclass(frozen=True)
class LedgerPolicy:
    """The fixed allocation history of one product version.

    A closed product version has no active GA: every allocation is retired and
    the ledger may only be read. The active product version ends its history
    with exactly one `active_ga` allocation.
    """

    product_version: str
    path: Path
    immutable_prefix: tuple[tuple[str, str, str], ...]
    superseded: tuple[str, str, str] | None
    retired_ga: tuple[tuple[str, str, str], ...]
    active_ga: str | None

    @property
    def closed(self) -> bool:
        return self.active_ga is None


POLICIES: Final = {
    "0.4.0": LedgerPolicy(
        "0.4.0",
        REPOSITORY_ROOT / "docs/release/build-allocations-v040.json",
        IMMUTABLE_RETIRED_PREFIX,
        POLICY_SUPERSEDED_ALLOCATION,
        RETIRED_GA_ALLOCATIONS,
        None,
    ),
    "0.5.0": LedgerPolicy(
        "0.5.0",
        REPOSITORY_ROOT / "docs/release/build-allocations-v050.json",
        PREVIEW_VALIDATION_PREFIX,
        None,
        RETIRED_GA_ALLOCATIONS_V050,
        "50028",
    ),
}
ACTIVE_POLICY: Final = POLICIES[PRODUCT_VERSION]
CONTRACT_RELATIVE_PATH: Final = Path("docs/release/build-allocations-v050.json")
CONTRACT_PATH: Final = ACTIVE_POLICY.path
CLOSED_CONTRACT_PATHS: Final = {
    version: policy.path for version, policy in POLICIES.items() if policy.closed
}


class ReleaseBuildAllocationError(ValueError):
    """The allocation ledger is malformed or conflicts with active source."""


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseBuildAllocationError(f"duplicate allocation field: {key}")
        result[key] = value
    return result


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, object]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseBuildAllocationError("allocation ledger is not valid JSON") from error
    if type(value) is not dict:
        raise ReleaseBuildAllocationError("allocation ledger must be an object")
    canonical = (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
        + b"\n"
    )
    if raw != canonical:
        raise ReleaseBuildAllocationError("allocation ledger is not canonical JSON")
    return value


def _exact_fields(value: dict[str, object], expected: frozenset[str], context: str) -> None:
    if frozenset(value) != expected:
        raise ReleaseBuildAllocationError(f"{context} fields are not exact")


def _parse_allocations(
    value: dict[str, object],
) -> tuple[LedgerPolicy, list[dict[str, object]], dict[str, dict[str, object]], list[int]]:
    _exact_fields(
        value,
        frozenset({"active_ga", "allocations", "document", "product_version"}),
        "allocation ledger",
    )
    product_version = value["product_version"]
    policy = POLICIES.get(product_version) if isinstance(product_version, str) else None
    if value["document"] != DOCUMENT or policy is None:
        raise ReleaseBuildAllocationError("allocation ledger identity is invalid")

    allocations = value["allocations"]
    if type(allocations) is not list or not allocations:
        raise ReleaseBuildAllocationError("allocations must be a non-empty array")
    records: dict[str, dict[str, object]] = {}
    ordered_builds: list[int] = []
    for index, record in enumerate(allocations):
        if type(record) is not dict:
            raise ReleaseBuildAllocationError(f"allocation {index} must be an object")
        _exact_fields(record, frozenset({"build", "role", "status"}), f"allocation {index}")
        build = record["build"]
        role = record["role"]
        status = record["status"]
        if not isinstance(build, str) or not BUILD_PATTERN.fullmatch(build):
            raise ReleaseBuildAllocationError(f"allocation {index} build is not canonical")
        if build in records:
            raise ReleaseBuildAllocationError(f"build {build} is allocated more than once")
        if (
            not isinstance(role, str)
            or not isinstance(status, str)
            or role not in ROLES
            or status not in STATUSES
        ):
            raise ReleaseBuildAllocationError(f"build {build} role or status is invalid")
        records[build] = record
        ordered_builds.append(int(build))
    return policy, allocations, records, ordered_builds


def _require_fixed_history(
    policy: LedgerPolicy, allocations: list[dict[str, object]]
) -> int:
    """Checks the immutable part of the history and returns the index after it."""
    observed_prefix = tuple(
        (record["build"], record["role"], record["status"])
        for record in allocations[: len(policy.immutable_prefix)]
    )
    if observed_prefix != policy.immutable_prefix:
        raise ReleaseBuildAllocationError("immutable retired allocation prefix changed")
    index = len(policy.immutable_prefix)
    if policy.superseded is not None:
        if index >= len(allocations):
            raise ReleaseBuildAllocationError("policy-superseded allocation is absent")
        superseded = allocations[index]
        if (
            superseded["build"],
            superseded["role"],
            superseded["status"],
        ) != policy.superseded:
            raise ReleaseBuildAllocationError(
                f"policy-superseded {policy.superseded[0]} allocation changed"
            )
        index += 1
    retired_ga_end = index + len(policy.retired_ga)
    if retired_ga_end > len(allocations):
        raise ReleaseBuildAllocationError("retired GA allocations are incomplete")
    observed_retired_ga = tuple(
        (record["build"], record["role"], record["status"])
        for record in allocations[index:retired_ga_end]
    )
    if observed_retired_ga != policy.retired_ga:
        raise ReleaseBuildAllocationError("retired GA allocations changed")
    return retired_ga_end


def _require_gap_free(policy: LedgerPolicy, ordered_builds: list[int]) -> None:
    expected_range = list(
        range(int(policy.immutable_prefix[0][0]), ordered_builds[-1] + 1)
    )
    if ordered_builds != expected_range:
        raise ReleaseBuildAllocationError("allocation history must be ordered and gap-free")


def _require_final_companions(records: dict[str, dict[str, object]]) -> None:
    for build, record in records.items():
        status = record["status"]
        if status == "retired_unbuilt_reserved_final_companion":
            predecessor = records.get(str(int(build) - 1))
            if record["role"] != "final" or predecessor is None:
                raise ReleaseBuildAllocationError(
                    f"retired final companion {build} has no allocated validation predecessor"
                )
            if predecessor["role"] != "validation" or not str(
                predecessor["status"]
            ).startswith("retired_"):
                raise ReleaseBuildAllocationError(
                    f"retired final companion {build} is not paired with a retired validation"
                )


def validate_contract(
    value: dict[str, object],
    *,
    expected_ga: str,
) -> None:
    """Validates the ledger of the active product version against its one GA."""
    policy, allocations, records, ordered_builds = _parse_allocations(value)
    if policy.closed:
        raise ReleaseBuildAllocationError("allocation ledger product version is closed")

    active_ga = value["active_ga"]
    if active_ga != expected_ga:
        raise ReleaseBuildAllocationError(
            "active GA build differs from release source constants"
        )
    if not isinstance(active_ga, str) or not BUILD_PATTERN.fullmatch(active_ga):
        raise ReleaseBuildAllocationError("active GA build is not canonical")
    if active_ga != policy.active_ga:
        raise ReleaseBuildAllocationError(
            "active GA allocation differs from the fixed successor"
        )

    retired_end = _require_fixed_history(policy, allocations)
    _require_gap_free(policy, ordered_builds)
    record = records.get(active_ga)
    if record is None:
        raise ReleaseBuildAllocationError(
            f"active GA build {active_ga} is not allocated"
        )
    if record["status"] != "active_ga":
        raise ReleaseBuildAllocationError(
            f"active GA build {active_ga} is allocated as {record['status']}"
        )
    if record["role"] != "ga":
        raise ReleaseBuildAllocationError(
            f"active GA build {active_ga} has the wrong role"
        )

    active_records = [
        build for build, candidate in records.items() if candidate["status"] == "active_ga"
    ]
    if active_records != [active_ga]:
        raise ReleaseBuildAllocationError("allocation ledger must have exactly one active GA")
    if len(allocations) != retired_end + 1:
        raise ReleaseBuildAllocationError(
            "allocation ledger must end with exactly one active GA allocation"
        )
    active_tail = allocations[retired_end]
    if (
        active_tail["build"],
        active_tail["role"],
        active_tail["status"],
    ) != (expected_ga, "ga", "active_ga"):
        raise ReleaseBuildAllocationError(
            "active GA allocation differs from the fixed successor"
        )
    _require_final_companions(records)


def validate_closed_contract(value: dict[str, object]) -> None:
    """Validates the read-only ledger of a closed product version."""
    policy, allocations, records, ordered_builds = _parse_allocations(value)
    if not policy.closed:
        raise ReleaseBuildAllocationError("allocation ledger product version is still active")
    retired_end = _require_fixed_history(policy, allocations)
    _require_gap_free(policy, ordered_builds)
    if value["active_ga"] is not None or any(
        record["status"] == "active_ga" for record in records.values()
    ):
        raise ReleaseBuildAllocationError("closed product version cannot have an active GA")
    if len(allocations) != retired_end:
        raise ReleaseBuildAllocationError(
            "closed allocation history has allocations outside its fixed record"
        )
    _require_final_companions(records)


def verify_source_bindings(value: dict[str, object]) -> None:
    validate_contract(value, expected_ga=ACTIVE_RELEASE_IDENTITY.ga_build)


def verify_closed_ledgers() -> None:
    for path in CLOSED_CONTRACT_PATHS.values():
        validate_closed_contract(load_contract(path))


def main() -> int:
    try:
        verify_source_bindings(load_contract())
        verify_closed_ledgers()
    except (OSError, ReleaseBuildAllocationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("release build allocation contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
