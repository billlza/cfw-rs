"""Publication review stages of the release driver and the shipped-release ledger.

The ledger ``~/.cfm-release-tooling/releases/shipped.json`` names, for every
release that passed remote verification, where its frozen artifact checkout
and its private review directory live. The next release carries the approved
component decisions of the newest shipped build forward from there
(scripts/publication/review_carryover.py). The driver appends an entry after
``verify-remote`` succeeds; ``cfm_release.sh shipped --add`` registers a
release that shipped before the driver existed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final, Sequence

from scripts.publication.common import PublicationError
from scripts.publication.review_carryover import (
    PENDING,
    REVIEWED,
    Release as ReviewRelease,
    compare,
    record_decisions,
    record_legal_review,
    shipped_decisions,
)
from scripts.release_build_identity import BuildIdentityError, canonical_build_version
from scripts.release_driver_context import (
    PREREQUISITE,
    RELEASE_HOME_RELATIVE,
    Context,
    DriverError,
    Release,
    path_present,
)

LEDGER_DOCUMENT: Final = "cfm-shipped-releases-v1"
LEDGER_FIELDS: Final = frozenset({"version", "build", "artifact", "review"})


def ledger_path(home: Path) -> Path:
    return home / RELEASE_HOME_RELATIVE / "shipped.json"


def read_ledger(home: Path) -> list[dict[str, Any]]:
    path = ledger_path(home)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    try:
        document = json.loads(data)
    except ValueError as error:
        raise DriverError(f"{path} is not JSON: {error}", PREREQUISITE) from error
    if not isinstance(document, dict) or document.get("document") != LEDGER_DOCUMENT:
        raise DriverError(f"{path} is not the shipped-release ledger", PREREQUISITE)
    releases = document.get("releases")
    if not isinstance(releases, list):
        raise DriverError(f"{path} lists no releases", PREREQUISITE)
    for entry in releases:
        if (
            not isinstance(entry, dict)
            or set(entry) != LEDGER_FIELDS
            or not all(isinstance(value, str) for value in entry.values())
        ):
            raise DriverError(f"{path} has a malformed entry: {entry!r}", PREREQUISITE)
        try:
            canonical_build_version(entry["build"], f"the build of a {path} entry")
        except BuildIdentityError as error:
            raise DriverError(str(error), PREREQUISITE) from error
    return releases


def _write_ledger(home: Path, releases: Sequence[dict[str, Any]]) -> None:
    path = ledger_path(home)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.pending")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"document": LEDGER_DOCUMENT, "releases": list(releases)}, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def add_shipped(home: Path, entry: ReviewRelease) -> None:
    """Register one shipped release after proving its approval chain."""

    try:
        shipped_decisions(entry)
    except (PublicationError, OSError, KeyError, TypeError, ValueError) as error:
        raise DriverError(f"the approval chain of {entry.version} build {entry.build} does not verify: {error}",
                          PREREQUISITE) from error
    releases = read_ledger(home)
    if any(item.get("build") == entry.build for item in releases):
        raise DriverError(f"build {entry.build} is already in the shipped-release ledger", PREREQUISITE)
    releases.append({
        "version": entry.version,
        "build": entry.build,
        "artifact": str(entry.artifact),
        "review": str(entry.review),
    })
    _write_ledger(home, sorted(releases, key=lambda item: int(item["build"])))


def shipped_predecessor(home: Path, build: str) -> ReviewRelease:
    releases = [item for item in read_ledger(home) if int(item["build"]) < int(build)]
    if not releases:
        raise DriverError(
            "no shipped release is registered; register the last one with "
            "`cfm_release.sh shipped --add VERSION BUILD ARTIFACT REVIEW`",
            PREREQUISITE,
        )
    newest = max(releases, key=lambda item: int(item["build"]))
    return ReviewRelease(newest["version"], newest["build"], Path(newest["artifact"]), Path(newest["review"]))


def review_release(release: Release) -> ReviewRelease:
    return ReviewRelease(release.version, release.build, release.artifact, release.review)


def run_component_review(context: Context) -> int:
    release = context.release
    if not path_present(release.stage_inputs / "component-review.json"):
        raise DriverError("the component review template is missing", PREREQUISITE)
    shipped = shipped_predecessor(context.machine.home, release.build)
    candidate = review_release(release)
    release.review.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        if not path_present(release.review / PENDING):
            summary = compare(shipped, candidate, release.operator, context.machine.home / ".cfm-release-tooling")
            print(json.dumps(summary, ensure_ascii=False, indent=1))
            if summary["review_kind"] == "complete":
                print(f"every manual decision carries over from {shipped.build}: {release.review / REVIEWED}")
                return 0
        record = record_decisions(candidate, input, print)
    except (PublicationError, EOFError) as error:
        raise DriverError(f"component review: {error}", PREREQUISITE) from error
    print(f"reviewed component input: {release.review / REVIEWED} ({record['reviewed_components_sha256']})")
    return 0


def run_legal_review(context: Context) -> int:
    release = context.release
    if not path_present(release.stage_inputs / "machine-closure.draft.json"):
        raise DriverError("the draft machine closure is missing", PREREQUISITE)
    shipped = shipped_predecessor(context.machine.home, release.build)
    try:
        approval = record_legal_review(shipped, review_release(release), input, print)
    except (PublicationError, EOFError) as error:
        raise DriverError(f"legal review: {error}", PREREQUISITE) from error
    print(f"legal review recorded for closure {approval['approved_closure_sha256']} by {approval['reviewer']}")
    return 0
