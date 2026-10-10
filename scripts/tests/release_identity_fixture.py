"""Neighbours of the active release identity for identity-relational tests.

Tests import ``ACTIVE_RELEASE_IDENTITY`` and ``ACTIVE_PREDECESSOR`` directly.
This module holds only values derived from them or from the live allocation
ledger, so a GA allocation never edits a test.
"""

from __future__ import annotations

from typing import Final

from scripts import verify_release_build_allocations as allocations
from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY


# The build the next GA allocation takes; never admitted while this GA is active.
NEXT_GA_BUILD: Final = str(int(ACTIVE_RELEASE_IDENTITY.ga_build) + 1)


def noncanonical(build: str) -> str:
    """The same integer with a leading zero, which no canonical check admits."""

    return f"0{build}"


def next_patch(version: str) -> str:
    """The following patch release of a ``major.minor.patch`` product version."""

    major, minor, patch = version.split(".")
    return f"{major}.{minor}.{int(patch) + 1}"


def retired_ga_builds() -> tuple[str, ...]:
    """The retired GA builds of the live active ledger, in allocation order."""

    ledger = allocations.validate_contract(
        allocations.load_contract(), expected_ga=ACTIVE_RELEASE_IDENTITY.ga_build
    )
    return tuple(build for build, _status in ledger.retired_ga)
