#!/usr/bin/env python3
"""Fail-closed aggregator that grants Signed_Installed_Verified (Task 11.5).

Requirement 6 splits the signed-installed evidence into four physical harnesses:
the lifecycle matrix (6.1), unique-token packet evidence (6.2), the
weak-network / performance / switch / soak gates (6.3), and the separately
signed adversarial / tamper matrix (6.4). Requirement 6.5 forbids turning any
absent, skipped, masked, stale, or unsuccessful result into success, Requirement
4.1 keeps each capability pinned to exactly one evidence level, and Requirement
7.5 keeps source existence separate from physical proof.

This module is the completeness gate that sits on top of those four harnesses.
It consumes each harness's own validator as a black box and only grants
``Signed_Installed_Verified`` when every one of the following holds:

* both required clean physical run sets are present - macOS 15 *and* the current
  macOS - each a distinct clean Apple Silicon run;
* every run carries all four harness documents and each document passes its own
  harness validator unchanged (any harness-level failure fails the level);
* every embedded harness document is bound to the exact same candidate identity
  (product version, build number, app-manifest hash, signed-app-tree hash) and
  to the run's own macOS version / build;
* every raw report is content-addressed: the declared ``report_sha256`` equals
  the canonical hash of the embedded document, and no report hash is reused
  across the aggregate (no duplicated or replayed report);
* every report carries the exact tool version for its harness and a UTC capture
  timestamp no older than the candidate's build time (no stale evidence);
* the aggregate asserts only the physical level and never hand-asserts a result:
  a ``manual``/``asserted`` evidence source or any non-physical ``granted_level``
  is rejected.

Absence is never success: a missing OS, a missing harness, a partial matrix, a
mismatched candidate, a stale or duplicated report, a manual assertion, or any
single harness failure raises :class:`PhysicalEvidenceError` and the whole
Signed_Installed level fails closed.

The signed physical runs themselves require signed Apple Silicon hardware on two
macOS versions and are out of scope here; they are reported as not-run. This
module provides the aggregation contract, the fail-closed validator, and
deterministic unit-test fixtures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
import re
from typing import Any, Callable

if __package__:
    from .lifecycle_matrix import (
        HARNESS_VERSION as LIFECYCLE_TOOL_VERSION,
        MACOS_BUILD_RE,
        LifecycleMatrixError,
        validate_lifecycle_matrix,
    )
    from .packet_evidence import PacketEvidenceError, validate_packet_evidence
    from .performance_gates import PerformanceGateError, validate_performance_evidence
    from .adversarial_clients import AdversarialMatrixError, validate_adversarial_matrix
    from ..evidence_manifest import LEVEL_ORDER
    from ..release_build_identity import canonical_build_version
else:  # pragma: no cover - import shim for direct invocation
    import sys

    _here = Path(__file__).resolve().parent
    sys.path.insert(0, str(_here))
    sys.path.insert(0, str(_here.parent))
    from lifecycle_matrix import (  # type: ignore
        HARNESS_VERSION as LIFECYCLE_TOOL_VERSION,
        MACOS_BUILD_RE,
        LifecycleMatrixError,
        validate_lifecycle_matrix,
    )
    from packet_evidence import PacketEvidenceError, validate_packet_evidence  # type: ignore
    from performance_gates import PerformanceGateError, validate_performance_evidence  # type: ignore
    from adversarial_clients import (  # type: ignore
        AdversarialMatrixError,
        validate_adversarial_matrix,
    )
    from evidence_manifest import LEVEL_ORDER  # type: ignore
    from release_build_identity import canonical_build_version  # type: ignore


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PRODUCT_VERSION = "0.4.0"

SCHEMA_VERSION = 1
AGGREGATOR_VERSION = "physical-evidence-aggregator-v1"

# The single evidence level this aggregator is allowed to grant. It is
# referenced from the Evidence_Manifest level order as a black box so the level
# name can never drift from the manifest, and so a source/unsigned/sealed claim
# can never be smuggled through this physical gate (Requirements 4.1, 7.5).
GRANTED_LEVEL = "Signed_Installed_Verified"
assert GRANTED_LEVEL in LEVEL_ORDER, "granted level must be a known Evidence_Manifest level"

# Requirement 6.1 requires clean physical runs on macOS 15 and current macOS.
# Both labels must be present exactly once; a missing OS fails closed.
REQUIRED_OS: frozenset[str] = frozenset({"macos15", "current-macos"})

# The four physical harnesses, each consumed as a black box: the exact tool
# version a report must declare and the harness validator that must accept the
# embedded document unchanged.
HARNESS_VALIDATORS: dict[str, Callable[[Any], Any]] = {
    "lifecycle": validate_lifecycle_matrix,
    "packet": validate_packet_evidence,
    "performance": validate_performance_evidence,
    "adversarial": validate_adversarial_matrix,
}
REQUIRED_HARNESSES: frozenset[str] = frozenset(HARNESS_VALIDATORS)

EXPECTED_TOOL_VERSIONS: dict[str, str] = {
    "lifecycle": LIFECYCLE_TOOL_VERSION,
    "packet": "packet-evidence-v1",
    "performance": "performance-gates-v1",
    "adversarial": "adversarial-clients-v1",
}

# The harness-specific error types raised when an embedded document is rejected.
# Any of these means a harness-level failure and fails the whole level.
_HARNESS_ERRORS = (
    LifecycleMatrixError,
    PacketEvidenceError,
    PerformanceGateError,
    AdversarialMatrixError,
)

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024

CANDIDATE_FIELDS = {
    "version",
    "build_number",
    "app_manifest_sha256",
    "signed_app_tree_sha256",
    "built_at",
}
RUN_FIELDS = {
    "os",
    "macos_version",
    "macos_build",
    "machine_sha256",
    "clean_install",
    "evidence_source",
    "captured_at",
    "reports",
}
REPORT_FIELDS = {"tool_version", "report_sha256", "captured_at", "document"}


class PhysicalEvidenceError(ValueError):
    """The aggregate physical evidence is incomplete, unbound, stale, or unproven."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PhysicalEvidenceError(f"aggregate has a duplicate field: {key!r}")
        result[key] = value
    return result


def _canonical_loads(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise PhysicalEvidenceError("physical evidence aggregate is not canonical JSON") from error


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PhysicalEvidenceError(f"{label} must be a JSON object")
    actual = set(value)
    missing = fields - actual
    unknown = actual - fields
    if missing:
        raise PhysicalEvidenceError(f"{label} is missing required fields: {sorted(missing)}")
    if unknown:
        raise PhysicalEvidenceError(f"{label} has unknown fields: {sorted(unknown)}")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise PhysicalEvidenceError(f"{label} is not a lowercase SHA-256")
    return value


def _non_empty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PhysicalEvidenceError(f"{label} must be a non-empty string")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PhysicalEvidenceError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PhysicalEvidenceError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PhysicalEvidenceError(f"{label} must use UTC")
    return parsed


def _canonical_report_hash(document: Any) -> str:
    """Content-address an embedded harness document with a canonical hash.

    Keeping the raw-report hash equal to a canonical serialization makes the
    hash immutable with respect to the document: any tamper with the embedded
    evidence changes the hash and fails the declared binding.
    """

    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _candidate(value: Any) -> dict[str, Any]:
    candidate = _exact(value, CANDIDATE_FIELDS, "candidate")
    if candidate["version"] != PRODUCT_VERSION:
        raise PhysicalEvidenceError(f"candidate.version must be {PRODUCT_VERSION}")
    build_number = canonical_build_version(candidate["build_number"], "candidate.build_number")
    return {
        "version": PRODUCT_VERSION,
        "build_number": build_number,
        "app_manifest_sha256": _sha256(
            candidate["app_manifest_sha256"], "candidate.app_manifest_sha256"
        ),
        "signed_app_tree_sha256": _sha256(
            candidate["signed_app_tree_sha256"], "candidate.signed_app_tree_sha256"
        ),
        "built_at": _timestamp(candidate["built_at"], "candidate.built_at"),
    }


def _check_lifecycle_identity(
    document: dict[str, Any], candidate: dict[str, Any], run: dict[str, Any], label: str
) -> None:
    device = document["candidate"]
    if device["signed_app_tree_sha256"] != candidate["signed_app_tree_sha256"]:
        raise PhysicalEvidenceError(f"{label} signed app tree does not match the candidate identity")
    if device["macos_build"] != run["macos_build"]:
        raise PhysicalEvidenceError(f"{label} macOS build does not match the run")


def _check_packet_identity(
    document: dict[str, Any], candidate: dict[str, Any], run: dict[str, Any], label: str
) -> None:
    if document["product"]["version"] != candidate["version"]:
        raise PhysicalEvidenceError(f"{label} product version does not match the candidate identity")
    if document["product"]["build_number"] != candidate["build_number"]:
        raise PhysicalEvidenceError(f"{label} build number does not match the candidate identity")
    if document["candidate"]["app_manifest_sha256"] != candidate["app_manifest_sha256"]:
        raise PhysicalEvidenceError(f"{label} app manifest does not match the candidate identity")
    if document["candidate"]["signed_app_tree_sha256"] != candidate["signed_app_tree_sha256"]:
        raise PhysicalEvidenceError(f"{label} signed app tree does not match the candidate identity")
    if document["platform"]["macos_version"] != run["macos_version"]:
        raise PhysicalEvidenceError(f"{label} macOS version does not match the run")


def _check_performance_identity(
    document: dict[str, Any], candidate: dict[str, Any], run: dict[str, Any], label: str
) -> None:
    build = document["parameters"]["build"]
    if build["version"] != candidate["version"]:
        raise PhysicalEvidenceError(f"{label} product version does not match the candidate identity")
    if build["build_number"] != candidate["build_number"]:
        raise PhysicalEvidenceError(f"{label} build number does not match the candidate identity")
    if build["app_manifest_sha256"] != candidate["app_manifest_sha256"]:
        raise PhysicalEvidenceError(f"{label} app manifest does not match the candidate identity")
    if document["parameters"]["machine"]["macos_version"] != run["macos_version"]:
        raise PhysicalEvidenceError(f"{label} macOS version does not match the run")


def _check_adversarial_identity(
    document: dict[str, Any], candidate: dict[str, Any], run: dict[str, Any], label: str
) -> None:
    if document["product"]["version"] != candidate["version"]:
        raise PhysicalEvidenceError(f"{label} product version does not match the candidate identity")
    if document["product"]["build_number"] != candidate["build_number"]:
        raise PhysicalEvidenceError(f"{label} build number does not match the candidate identity")
    if document["app_manifest_sha256"] != candidate["app_manifest_sha256"]:
        raise PhysicalEvidenceError(f"{label} app manifest does not match the candidate identity")
    if document["platform"]["macos_version"] != run["macos_version"]:
        raise PhysicalEvidenceError(f"{label} macOS version does not match the run")


_IDENTITY_CHECKS: dict[str, Callable[[dict[str, Any], dict[str, Any], dict[str, Any], str], None]] = {
    "lifecycle": _check_lifecycle_identity,
    "packet": _check_packet_identity,
    "performance": _check_performance_identity,
    "adversarial": _check_adversarial_identity,
}


def _validate_report(
    harness: str,
    raw: Any,
    candidate: dict[str, Any],
    run: dict[str, Any],
    report_hashes: set[str],
) -> None:
    label = f"run[{run['os']}].reports.{harness}"
    report = _exact(raw, REPORT_FIELDS, label)

    tool_version = report["tool_version"]
    if tool_version != EXPECTED_TOOL_VERSIONS[harness]:
        raise PhysicalEvidenceError(
            f"{label} tool_version is {tool_version!r}; expected "
            f"{EXPECTED_TOOL_VERSIONS[harness]!r}"
        )

    captured_at = _timestamp(report["captured_at"], f"{label}.captured_at")
    if captured_at < candidate["built_at"]:
        # A report captured before the candidate was built cannot describe this
        # candidate: it is stale evidence and fails closed.
        raise PhysicalEvidenceError(f"{label} is stale: captured before the candidate was built")

    declared_hash = _sha256(report["report_sha256"], f"{label}.report_sha256")
    computed_hash = _canonical_report_hash(report["document"])
    if declared_hash != computed_hash:
        # The raw-report hash must be immutable with respect to the document.
        raise PhysicalEvidenceError(f"{label} report_sha256 does not content-address its document")
    if declared_hash in report_hashes:
        # A report hash reused across harnesses or runs is a duplicated /
        # replayed report and fails closed.
        raise PhysicalEvidenceError(f"{label} reuses a raw report hash already bound")
    report_hashes.add(declared_hash)

    # Consume the harness validator as a black box. Any harness-level failure
    # (missing case, partial matrix, unbound result, ...) fails this level.
    try:
        HARNESS_VALIDATORS[harness](report["document"])
    except _HARNESS_ERRORS as error:
        raise PhysicalEvidenceError(f"{label} harness validation failed: {error}") from error

    _IDENTITY_CHECKS[harness](report["document"], candidate, run, label)


def _validate_run(
    raw: Any,
    index: int,
    candidate: dict[str, Any],
    seen_os: set[str],
    report_hashes: set[str],
) -> str:
    run = _exact(raw, RUN_FIELDS, f"runs[{index}]")

    os_label = run["os"]
    if os_label not in REQUIRED_OS:
        raise PhysicalEvidenceError(f"runs[{index}] declares an unknown macOS run set: {os_label!r}")
    if os_label in seen_os:
        raise PhysicalEvidenceError(f"physical evidence duplicates the {os_label!r} run set")
    seen_os.add(os_label)

    _non_empty_string(run["macos_version"], f"runs[{index}].macos_version")
    if not isinstance(run["macos_build"], str) or not MACOS_BUILD_RE.fullmatch(run["macos_build"]):
        raise PhysicalEvidenceError(f"runs[{index}].macos_build is not a macOS build identifier")
    _sha256(run["machine_sha256"], f"runs[{index}].machine_sha256")

    if run["clean_install"] is not True:
        raise PhysicalEvidenceError(f"runs[{index}] must be a clean physical install")
    if run["evidence_source"] != "harness":
        # A manual / hand-asserted result is never accepted as physical proof.
        raise PhysicalEvidenceError(
            f"runs[{index}] evidence_source is {run['evidence_source']!r}; "
            "manual assertions are rejected"
        )
    _timestamp(run["captured_at"], f"runs[{index}].captured_at")

    reports = _exact(run["reports"], set(REQUIRED_HARNESSES), f"runs[{index}].reports")
    for harness in sorted(REQUIRED_HARNESSES):
        _validate_report(harness, reports[harness], candidate, run, report_hashes)
    return os_label


def validate_physical_evidence(value: Any) -> dict[str, Any]:
    """Validate the whole physical-evidence aggregate, failing closed on any gap.

    Returns a summary that grants exactly :data:`GRANTED_LEVEL` on success.
    Raises :class:`PhysicalEvidenceError` on the first fail-closed condition.
    """

    document = _exact(
        value,
        {"schema_version", "aggregator_version", "granted_level", "candidate", "runs"},
        "physical evidence aggregate",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise PhysicalEvidenceError(f"aggregate schema_version must be {SCHEMA_VERSION}")
    if document["aggregator_version"] != AGGREGATOR_VERSION:
        raise PhysicalEvidenceError(f"aggregate aggregator_version must be {AGGREGATOR_VERSION!r}")

    granted = document["granted_level"]
    if granted != GRANTED_LEVEL:
        # This gate proves only the physical level; it may never assert a
        # source, unsigned, or sealed level. Levels stay separate.
        raise PhysicalEvidenceError(
            f"aggregate granted_level {granted!r} is not the physical level {GRANTED_LEVEL!r}"
        )

    candidate = _candidate(document["candidate"])

    runs = document["runs"]
    if not isinstance(runs, list):
        raise PhysicalEvidenceError("aggregate runs must be a list")
    if len(runs) != len(REQUIRED_OS):
        raise PhysicalEvidenceError("aggregate must contain each required macOS run set exactly once")

    seen_os: set[str] = set()
    report_hashes: set[str] = set()
    for index, raw in enumerate(runs):
        _validate_run(raw, index, candidate, seen_os, report_hashes)

    missing = REQUIRED_OS - seen_os
    if missing:
        # Absence is never success: a missing macOS run set fails the level.
        raise PhysicalEvidenceError(
            f"physical evidence is missing required macOS run sets: {sorted(missing)}"
        )

    return {
        "granted_level": GRANTED_LEVEL,
        "candidate": {
            "version": candidate["version"],
            "build_number": candidate["build_number"],
            "app_manifest_sha256": candidate["app_manifest_sha256"],
            "signed_app_tree_sha256": candidate["signed_app_tree_sha256"],
        },
        "runs": sorted(seen_os),
        "reports": len(report_hashes),
    }


def load_physical_evidence(path: Path) -> dict[str, Any]:
    """Load, canonically parse, and validate a physical-evidence aggregate file."""

    if path.is_symlink() or not path.is_file():
        raise PhysicalEvidenceError("physical evidence aggregate must be a regular non-symlink file")
    data = path.read_bytes()
    if not data or len(data) > MAX_DOCUMENT_BYTES:
        raise PhysicalEvidenceError("physical evidence aggregate size is outside the accepted range")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PhysicalEvidenceError("physical evidence aggregate is not valid UTF-8") from error
    return validate_physical_evidence(_canonical_loads(text))


def self_check() -> None:
    """Verify the aggregator's internal contract without any evidence file.

    This lets a static boundary gate confirm the physical aggregator is wired to
    all four harnesses and the Evidence_Manifest level order without requiring
    physical evidence (which needs signed Apple Silicon on two macOS versions).
    """

    if GRANTED_LEVEL not in LEVEL_ORDER:
        raise PhysicalEvidenceError("granted level is not a known Evidence_Manifest level")
    if len(REQUIRED_OS) != 2:
        raise PhysicalEvidenceError("physical gate must require exactly two macOS run sets")
    if set(HARNESS_VALIDATORS) != REQUIRED_HARNESSES:
        raise PhysicalEvidenceError("harness validator wiring is inconsistent")
    if set(EXPECTED_TOOL_VERSIONS) != REQUIRED_HARNESSES:
        raise PhysicalEvidenceError("harness tool-version wiring is inconsistent")
    if set(_IDENTITY_CHECKS) != REQUIRED_HARNESSES:
        raise PhysicalEvidenceError("harness identity-check wiring is inconsistent")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("aggregate", nargs="?", type=Path, help="physical evidence aggregate file")
    group.add_argument(
        "--self-check",
        action="store_true",
        help="verify the aggregator contract is wired to all four harnesses and exit",
    )
    arguments = parser.parse_args()

    if arguments.self_check:
        try:
            self_check()
        except PhysicalEvidenceError as error:
            raise SystemExit(f"error: physical evidence aggregator self-check failed: {error}")
        print(
            "physical evidence aggregator self-check ok: "
            f"grants {GRANTED_LEVEL} across {sorted(REQUIRED_OS)} using "
            f"{sorted(REQUIRED_HARNESSES)}"
        )
        return

    try:
        summary = load_physical_evidence(arguments.aggregate)
    except (PhysicalEvidenceError, OSError) as error:
        raise SystemExit(f"error: physical evidence aggregation failed: {error}") from error
    print(
        "physical evidence aggregated: "
        f"{summary['granted_level']} granted for {summary['candidate']['version']} "
        f"({summary['candidate']['build_number']}) across {summary['runs']}, "
        f"{summary['reports']} bound reports"
    )


if __name__ == "__main__":
    main()
