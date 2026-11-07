#!/usr/bin/env python3
"""Verify that active CFM release builds never reuse an allocated identity."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

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
        "retired_security_dependency_change_after_install_before_ga_runtime_acceptance",
        # Installed, accepted and sealed for publication, then superseded by a
        # product change before anything was published.
        "retired_product_change_after_ga_runtime_acceptance_before_publication",
        "retired_after_notarization_before_install_lane_test_not_hermetic",
        "retired_before_candidate_build_source_gate_contract_incomplete",
        "retired_unbuilt_policy_superseded",
        "retired_unbuilt_reserved_final_companion",
        "retired_superseded_by_next_product_version",
        "retired_preview_validation_consumed",
        # The GA a closed product version published: official distribution
        # exposed it (docs/release/candidate-identity-lifecycle.md).
        "published",
    }
)
# GA retirements after the application was installed on the release Mac: each
# such build is the recorded predecessor whose journals a later install reads.
INSTALLED_GA_STATUSES: Final = frozenset(
    status for status in STATUSES if "_after_install_" in status
) | {
    "retired_product_change_after_ga_runtime_acceptance_before_publication",
    "retired_superseded_by_next_product_version",
}
# The fixed 0.4.0 history: the retired validation prefix, the build retired by
# policy and the retired GA allocations.
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


# The consumed 0.5.0 preview validation builds 50001 through 50025.
PREVIEW_VALIDATION_PREFIX: Final = tuple(
    (str(build), "validation", "retired_preview_validation_consumed")
    for build in range(50001, 50025 + 1)
)
# The 0.5.0 GA allocations retired before 50030 was published.
RETIRED_GA_ALLOCATIONS_V050: Final = (
    ("50026", "ga", "retired_after_candidate_freeze_before_canonical_signing_output"),
    ("50027", "ga", "retired_after_notarization_before_install"),
    (
        "50028",
        "ga",
        "retired_security_dependency_change_after_install_before_ga_runtime_acceptance",
    ),
    ("50029", "ga", "retired_product_change_after_install_before_ga_runtime_acceptance"),
)
PUBLISHED_GA_V050: Final = ("50030", "ga", "published")


@dataclass(frozen=True)
class LedgerPolicy:
    """The fixed allocation history of one product version.

    Every ledger starts at `first_build` and is gap-free from there. A closed
    product version has no active GA: its whole history, including every
    retired GA allocation and the GA it published, is fixed here and the
    ledger may only be read. The active product version fixes only the
    history before its GA allocations; the release identity file names its
    one active GA, and each retired GA allocation is bound by its retirement
    note instead.
    """

    product_version: str
    relative_path: Path
    first_build: int
    immutable_prefix: tuple[tuple[str, str, str], ...]
    superseded: tuple[str, str, str] | None
    retired_ga: tuple[tuple[str, str, str], ...]
    published: tuple[str, str, str] | None
    closed: bool


POLICIES: Final = {
    "0.4.0": LedgerPolicy(
        product_version="0.4.0",
        relative_path=Path("docs/release/build-allocations-v040.json"),
        first_build=40021,
        immutable_prefix=IMMUTABLE_RETIRED_PREFIX,
        superseded=POLICY_SUPERSEDED_ALLOCATION,
        retired_ga=RETIRED_GA_ALLOCATIONS,
        published=None,
        closed=True,
    ),
    "0.5.0": LedgerPolicy(
        product_version="0.5.0",
        relative_path=Path("docs/release/build-allocations-v050.json"),
        first_build=50001,
        immutable_prefix=PREVIEW_VALIDATION_PREFIX,
        superseded=None,
        retired_ga=RETIRED_GA_ALLOCATIONS_V050,
        published=PUBLISHED_GA_V050,
        closed=True,
    ),
    # Opened after 0.5.0 was published: its history starts with its first GA
    # allocation, so a ledger that loses a leading record is not gap-free.
    "0.5.1": LedgerPolicy(
        product_version="0.5.1",
        relative_path=Path("docs/release/build-allocations-v051.json"),
        first_build=51001,
        immutable_prefix=(),
        superseded=None,
        retired_ga=(),
        published=None,
        closed=False,
    ),
}
ACTIVE_POLICY: Final = POLICIES[PRODUCT_VERSION]
CONTRACT_RELATIVE_PATH: Final = ACTIVE_POLICY.relative_path
CONTRACT_PATH: Final = REPOSITORY_ROOT / CONTRACT_RELATIVE_PATH
CLOSED_CONTRACT_PATHS: Final = {
    version: REPOSITORY_ROOT / policy.relative_path
    for version, policy in POLICIES.items()
    if policy.closed
}
RETIREMENT_NOTES_RELATIVE: Final = Path("docs/release")
RETIREMENT_NOTES_DIRECTORY: Final = REPOSITORY_ROOT / RETIREMENT_NOTES_RELATIVE
# Case-insensitive so that a misspelt note on a case-insensitive volume is
# reported instead of being skipped.
RETIREMENT_NOTE_NAME_RE: Final = re.compile(
    r"\Aga-build-([0-9]+)-retirement\.md\Z", re.IGNORECASE
)
# The classification sentence opens a line; a note may quote another build's.
RETIREMENT_CLASSIFICATION_RE: Final = re.compile(
    r"^GA build ([0-9]+) is permanently classified as\s`([a-z_]+)`\.", re.MULTILINE
)
# A note drafted before a commit it names exists marks that commit's hash as
# `@NAME@`; a note in the tree must have every such hash filled in.
RETIREMENT_NOTE_PLACEHOLDER_RE: Final = re.compile(r"@[A-Z][A-Z0-9_]*@")


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
    if policy.published is None:
        return retired_ga_end
    if retired_ga_end >= len(allocations):
        raise ReleaseBuildAllocationError("published GA allocation is absent")
    published = allocations[retired_ga_end]
    if (published["build"], published["role"], published["status"]) != policy.published:
        raise ReleaseBuildAllocationError(
            f"published GA {policy.published[0]} allocation changed"
        )
    return retired_ga_end + 1


def _require_gap_free(policy: LedgerPolicy, ordered_builds: list[int]) -> None:
    expected_range = list(range(policy.first_build, ordered_builds[-1] + 1))
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


@dataclass(frozen=True)
class ActiveLedger:
    """The validated allocation ledger of the active product version."""

    product_version: str
    first_build: int
    active_ga: str
    builds: frozenset[str]
    retired_ga: tuple[tuple[str, str], ...]


class RegisteredPredecessor(Protocol):
    """The identity of one install-predecessor registry profile."""

    @property
    def product_version(self) -> str: ...

    @property
    def build_number(self) -> str: ...


def validate_contract(
    value: dict[str, object],
    *,
    expected_ga: str,
) -> ActiveLedger:
    """Validates the ledger of the active product version against its one GA.

    Every record after the fixed history is a GA allocation: the retired ones
    in allocation order, then the active GA as the one last record.
    """
    policy, allocations, records, ordered_builds = _parse_allocations(value)
    if policy.closed:
        raise ReleaseBuildAllocationError("allocation ledger product version is closed")

    active_ga = value["active_ga"]
    if active_ga != expected_ga:
        raise ReleaseBuildAllocationError(
            f"active GA build {active_ga} differs from the release identity {expected_ga}"
        )
    if not isinstance(active_ga, str) or not BUILD_PATTERN.fullmatch(active_ga):
        raise ReleaseBuildAllocationError("active GA build is not canonical")

    fixed_end = _require_fixed_history(policy, allocations)
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
    if allocations[-1] is not record:
        raise ReleaseBuildAllocationError(
            "allocation ledger must end with exactly one active GA allocation"
        )
    retired_ga = allocations[fixed_end:-1]
    for retired in retired_ga:
        if retired["role"] != "ga" or not str(retired["status"]).startswith("retired_"):
            raise ReleaseBuildAllocationError(
                f"build {retired['build']} between the fixed history and the active GA "
                "is not a retired GA allocation"
            )
    _require_final_companions(records)
    return ActiveLedger(
        product_version=policy.product_version,
        first_build=ordered_builds[0],
        active_ga=active_ga,
        builds=frozenset(records),
        retired_ga=tuple(
            (str(retired["build"]), str(retired["status"])) for retired in retired_ga
        ),
    )


def validate_retirement_notes(ledger: ActiveLedger, notes_directory: Path) -> None:
    """Binds every retired GA allocation to the classification of its note.

    Each retired GA build has ``ga-build-<n>-retirement.md`` whose one
    classification sentence states its exact ledger status, and every such
    note from the ledger's first build on names one of those retired builds.
    """
    retired = dict(ledger.retired_ga)
    for build, status in ledger.retired_ga:
        note = notes_directory / f"ga-build-{build}-retirement.md"
        try:
            text = note.read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise ReleaseBuildAllocationError(
                f"retired GA build {build} has no retirement note: {note}"
            ) from error
        except (OSError, UnicodeDecodeError) as error:
            raise ReleaseBuildAllocationError(
                f"retirement note is unreadable: {note}"
            ) from error
        classifications = [
            classified
            for classified_build, classified in RETIREMENT_CLASSIFICATION_RE.findall(text)
            if classified_build == build
        ]
        if classifications != [status]:
            raise ReleaseBuildAllocationError(
                f"retirement note does not classify GA build {build} exactly once "
                f"as `{status}`: {note}"
            )
        placeholder = RETIREMENT_NOTE_PLACEHOLDER_RE.search(text)
        if placeholder is not None:
            raise ReleaseBuildAllocationError(
                f"retirement note still holds the placeholder {placeholder.group(0)}: {note}"
            )
    try:
        names = sorted(entry.name for entry in notes_directory.iterdir())
    except OSError as error:
        raise ReleaseBuildAllocationError(
            f"retirement notes directory is unreadable: {notes_directory}"
        ) from error
    for name in names:
        match = RETIREMENT_NOTE_NAME_RE.fullmatch(name)
        if match is None:
            continue
        build = match.group(1)
        if (
            not BUILD_PATTERN.fullmatch(build)
            or name != f"ga-build-{build}-retirement.md"
        ):
            raise ReleaseBuildAllocationError(
                f"retirement note name is not canonical: {name}"
            )
        if int(build) < ledger.first_build:
            continue
        if int(build) >= int(ledger.active_ga):
            raise ReleaseBuildAllocationError(
                f"retirement note {name} names a build at or above the active GA "
                f"{ledger.active_ga}"
            )
        if build not in retired:
            raise ReleaseBuildAllocationError(
                f"retirement note {name} names no retired GA allocation"
            )


def validate_predecessor_registry(
    ledger: ActiveLedger, predecessors: Mapping[str, RegisteredPredecessor]
) -> None:
    """Requires the installed GA builds and the registry to name the same builds.

    A GA build retired after it was installed on the release Mac is the
    recorded predecessor of the next install, so allocating its successor
    without registering that profile fails here, before anything is signed.
    Conversely every registered build of this product version is an allocation
    below the active GA, and a registered GA build was retired after install.
    The registry keys its profiles by their own build numbers.
    """
    retired = dict(ledger.retired_ga)
    for build, status in ledger.retired_ga:
        if status not in INSTALLED_GA_STATUSES:
            continue
        profile = predecessors.get(build)
        if profile is None or profile.product_version != ledger.product_version:
            raise ReleaseBuildAllocationError(
                f"installed GA build {build} ({status}) is not a registered "
                f"{ledger.product_version} install predecessor"
            )
    for build, profile in predecessors.items():
        if profile.product_version != ledger.product_version:
            continue
        if build not in ledger.builds or int(build) >= int(ledger.active_ga):
            raise ReleaseBuildAllocationError(
                f"install predecessor {build} is not an allocated {ledger.product_version} "
                f"build below the active GA {ledger.active_ga}"
            )
        if build in retired and retired[build] not in INSTALLED_GA_STATUSES:
            raise ReleaseBuildAllocationError(
                f"install predecessor {build} is a GA build retired as {retired[build]}, "
                "which was never installed"
            )


def validate_published_predecessors(
    predecessors: Mapping[str, RegisteredPredecessor],
) -> None:
    """Requires the GA every closed product version published to be registered.

    A published GA was installed on the release Mac, and the first GA install
    of the next product version replaces it and archives its journals, so
    opening that version without registering the profile fails here, before
    anything is signed.
    """
    for policy in POLICIES.values():
        if policy.published is None:
            continue
        build = policy.published[0]
        profile = predecessors.get(build)
        if profile is None or profile.product_version != policy.product_version:
            raise ReleaseBuildAllocationError(
                f"published GA build {build} is not a registered "
                f"{policy.product_version} install predecessor"
            )


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


def verify_source_bindings(
    value: dict[str, object],
    *,
    notes_directory: Path,
    predecessors: Mapping[str, RegisteredPredecessor],
) -> None:
    """Binds the active ledger to the identity file, its notes and the registry.

    The registry must also hold the GA each closed product version published.
    """
    ledger = validate_contract(value, expected_ga=ACTIVE_RELEASE_IDENTITY.ga_build)
    validate_retirement_notes(ledger, notes_directory)
    validate_predecessor_registry(ledger, predecessors)
    validate_published_predecessors(predecessors)


def verify_closed_ledgers() -> None:
    for path in CLOSED_CONTRACT_PATHS.values():
        validate_closed_contract(load_contract(path))


def supported_predecessors() -> Mapping[str, RegisteredPredecessor]:
    """Load the install-predecessor registry when the gate runs.

    dormant_app_install imports candidate_freeze, which imports this module,
    so the registry cannot be imported while this module initializes.
    """
    try:
        if __package__:
            from .dormant_app_install import SUPPORTED_PREDECESSORS
        else:
            from dormant_app_install import SUPPORTED_PREDECESSORS
    except ImportError as error:
        raise ReleaseBuildAllocationError(
            f"install predecessor registry is unavailable: {error}"
        ) from error
    return SUPPORTED_PREDECESSORS


def main() -> int:
    try:
        verify_source_bindings(
            load_contract(),
            notes_directory=RETIREMENT_NOTES_DIRECTORY,
            predecessors=supported_predecessors(),
        )
        verify_closed_ledgers()
    except (OSError, ReleaseBuildAllocationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("release build allocation contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
