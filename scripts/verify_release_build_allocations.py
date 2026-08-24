#!/usr/bin/env python3
"""Verify that active CFM release builds never reuse an allocated identity."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Final

if __package__:
    from .release_build_identity import ACTIVE_RELEASE_GENERATION
else:
    from release_build_identity import ACTIVE_RELEASE_GENERATION

REPOSITORY_ROOT: Final = Path(__file__).resolve().parent.parent
CONTRACT_PATH: Final = REPOSITORY_ROOT / "docs/release/build-allocations-v040.json"
DOCUMENT: Final = "cfm-release-build-allocation-v1"
PRODUCT_VERSION: Final = ACTIVE_RELEASE_GENERATION.product_version
BUILD_PATTERN: Final = re.compile(r"\A[1-9][0-9]{4}\Z")
ROLES: Final = frozenset({"validation", "final"})
STATUSES: Final = frozenset(
    {
        "active",
        "retired_after_notarization_before_install",
        "retired_after_notarization_before_install_preflight_protocol_incompatible",
        "retired_after_notarization_before_install_runtime_preflight_failed",
        "retired_after_notarization_before_install_runtime_preflight_toolchain_binding_mismatch",
        "retired_before_candidate_build_source_gate_contract_incomplete",
        "retired_unbuilt_reserved_final_companion",
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


def validate_contract(
    value: dict[str, object],
    *,
    expected_validation: str,
    expected_final: str,
) -> None:
    _exact_fields(
        value,
        frozenset({"active_pair", "allocations", "document", "product_version"}),
        "allocation ledger",
    )
    if value["document"] != DOCUMENT or value["product_version"] != PRODUCT_VERSION:
        raise ReleaseBuildAllocationError("allocation ledger identity is invalid")

    pair = value["active_pair"]
    if type(pair) is not dict:
        raise ReleaseBuildAllocationError("active pair must be an object")
    _exact_fields(pair, frozenset({"validation", "final"}), "active pair")
    validation = pair["validation"]
    final = pair["final"]
    if validation != expected_validation or final != expected_final:
        raise ReleaseBuildAllocationError("active pair differs from release source constants")
    if not isinstance(validation, str) or not BUILD_PATTERN.fullmatch(validation):
        raise ReleaseBuildAllocationError("active validation build is not canonical")
    if not isinstance(final, str) or not BUILD_PATTERN.fullmatch(final):
        raise ReleaseBuildAllocationError("active final build is not canonical")

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

    observed_prefix = tuple(
        (record["build"], record["role"], record["status"])
        for record in allocations[: len(IMMUTABLE_RETIRED_PREFIX)]
    )
    if observed_prefix != IMMUTABLE_RETIRED_PREFIX:
        raise ReleaseBuildAllocationError("immutable retired allocation prefix changed")
    expected_range = list(
        range(int(IMMUTABLE_RETIRED_PREFIX[0][0]), ordered_builds[-1] + 1)
    )
    if ordered_builds != expected_range:
        raise ReleaseBuildAllocationError("allocation history must be ordered and gap-free")
    for role, build in (("validation", validation), ("final", final)):
        record = records.get(build)
        if record is None:
            raise ReleaseBuildAllocationError(f"active {role} build {build} is not allocated")
        if record["status"] != "active":
            raise ReleaseBuildAllocationError(
                f"active {role} build {build} is allocated as {record['status']}"
            )
        if record["role"] != role:
            raise ReleaseBuildAllocationError(f"active {role} build {build} has the wrong role")
    if int(final) != int(validation) + 1:
        raise ReleaseBuildAllocationError("active validation/final builds must be consecutive")

    active = {validation, final}
    for build, record in records.items():
        status = record["status"]
        if build not in active and status == "active":
            raise ReleaseBuildAllocationError(f"inactive build {build} is still marked active")
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


def verify_source_bindings(value: dict[str, object]) -> None:
    sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
    import dormant_app_install
    from publication import orchestrator

    validation = ACTIVE_RELEASE_GENERATION.validation_build
    final = ACTIVE_RELEASE_GENERATION.final_build
    installer_identity = (
        dormant_app_install.VERSION,
        dormant_app_install.BUILD_NUMBER,
        dormant_app_install.FINAL_BUILD_NUMBER,
    )
    orchestrator_identity = (
        orchestrator.PRODUCT_VERSION,
        orchestrator.VALIDATION_BUILD,
        orchestrator.FINAL_BUILD,
    )
    expected_identity = (PRODUCT_VERSION, validation, final)
    if installer_identity != expected_identity or orchestrator_identity != expected_identity:
        raise ReleaseBuildAllocationError("release entrypoints disagree on the active build pair")
    validate_contract(value, expected_validation=validation, expected_final=final)


def main() -> int:
    try:
        verify_source_bindings(load_contract())
    except (OSError, ReleaseBuildAllocationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("release build allocation contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
