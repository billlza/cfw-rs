#!/usr/bin/env python3
"""Automated signed-installed lifecycle matrix harness (Task 11.1).

This module is the machine-readable half of the Signed_Installed_Verified
lifecycle gate required by Requirement 6.1. It declares the exact matrix of
lifecycle probes that a clean physical Apple Silicon run must exercise and a
strictly fail-closed validator for the raw results those probes emit.

Scope boundary: the *definitions* and the *result validator* live here and are
covered by deterministic unit tests using fixtures. The actual on-device runs
require signed Apple Silicon hardware, a notarizable app tree, at least two
login accounts, and privileged lifecycle control (login/logout/lock, Fast User
Switching, sleep/wake, reboot, and process kills). Those runs are out of scope
for this task and are reported as not-run.

Fail-closed contract (Requirements 4.1, 6.1, 6.5):

* Every probe in :data:`REQUIRED_PROBES` must appear exactly once. A missing
  probe is absence, and absence is never success.
* A probe contributes evidence only when its ``status`` is exactly
  ``"passed"``. ``skipped``, ``unavailable``, ``malformed``, ``timeout``,
  ``failed`` and every other value fail the whole level immediately.
* Every raw result binds to the exact signed app tree hash, Apple Silicon
  machine hash, macOS build, operation context, and a non-secret report hash.
  A missing or mismatched binding fails closed - a raw report can never be
  reused across candidates, machines, or operations.
* Parsing is canonical: duplicate JSON keys, unknown fields, and non-object
  documents are rejected before interpretation, so a malformed document can
  never be silently narrowed into a passing subset.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
# Realistic macOS build identifiers such as "24A335" or "23F79".
MACOS_BUILD_RE = re.compile(r"^[0-9]{2}[A-Z][0-9]{1,5}[a-z]?$")

SCHEMA_VERSION = 1
HARNESS_VERSION = "lifecycle-matrix-v1"

# The only architecture accepted by the Signed_Installed gate.
REQUIRED_ARCHITECTURE = "arm64"

# The only probe status that contributes evidence. Anything else - skipped,
# unavailable, masked, suppressed, timed-out, malformed, or unsuccessful -
# fails the associated evidence level (Requirement 6.5).
ACCEPTED_STATUS = "passed"

MAX_DOCUMENT_BYTES = 1 * 1024 * 1024


# The complete machine-readable lifecycle matrix. Each probe declares the
# category it belongs to and any structured attribute constraints its raw
# result must satisfy. The set is exhaustive for Requirement 6.1: inside-out
# signatures, exact Team ID, bundle identifiers, entitlements, provisioning,
# daemon registration approval and denial, System Extension approval / pending
# approval / restart, upgrade / replacement / downgrade refusal, install and
# uninstall cleanup, login / logout / lock, two-user Fast User Switching,
# concurrent starts, cancellation, sleep and wake, reboot recovery, and Host /
# Global Authority / ProxyAgent / Provider crashes.
#
# ``attributes`` maps the exact attribute keys a probe result must carry to a
# validator callable. A probe with no structured attributes must carry an empty
# ``attributes`` object, so extra fields cannot smuggle unaudited claims.
def _positive_int(minimum: int):
    def _check(value: Any, label: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise LifecycleMatrixError(f"{label} must be an integer >= {minimum}")
        return value

    return _check


PROBE_SPECS: dict[str, dict[str, Any]] = {
    # Signing, identity, entitlements, provisioning.
    "inside-out-signatures": {"category": "identity", "attributes": {}},
    "team-id": {"category": "identity", "attributes": {}},
    "bundle-identifiers": {"category": "identity", "attributes": {}},
    "entitlements": {"category": "identity", "attributes": {}},
    "provisioning": {"category": "identity", "attributes": {}},
    # Global Authority launchd daemon registration - both outcomes required.
    "daemon-registration-approval": {"category": "daemon", "attributes": {}},
    "daemon-registration-denial": {"category": "daemon", "attributes": {}},
    # System Extension activation lifecycle.
    "system-extension-approval": {"category": "system-extension", "attributes": {}},
    "system-extension-pending": {"category": "system-extension", "attributes": {}},
    "system-extension-restart": {"category": "system-extension", "attributes": {}},
    # Upgrade / replacement / downgrade.
    "upgrade": {"category": "packaging", "attributes": {}},
    "replacement": {"category": "packaging", "attributes": {}},
    "downgrade-refusal": {"category": "packaging", "attributes": {}},
    # Install / uninstall cleanup.
    "install-cleanup": {"category": "packaging", "attributes": {}},
    "uninstall-cleanup": {"category": "packaging", "attributes": {}},
    # Session lifecycle.
    "login": {"category": "session", "attributes": {}},
    "logout": {"category": "session", "attributes": {}},
    "lock": {"category": "session", "attributes": {}},
    # Fast User Switching requires at least two distinct users.
    "fast-user-switching": {
        "category": "session",
        "attributes": {"user_count": _positive_int(2)},
    },
    # Concurrency, cancellation, power, and recovery.
    "concurrent-starts": {
        "category": "concurrency",
        "attributes": {"concurrent_start_count": _positive_int(2)},
    },
    "cancellation": {"category": "concurrency", "attributes": {}},
    "sleep-wake": {"category": "power", "attributes": {}},
    "reboot-recovery": {"category": "power", "attributes": {}},
    # All four component crash cases.
    "host-crash": {"category": "crash", "attributes": {}},
    "global-authority-crash": {"category": "crash", "attributes": {}},
    "proxy-agent-crash": {"category": "crash", "attributes": {}},
    "provider-crash": {"category": "crash", "attributes": {}},
}

REQUIRED_PROBES: frozenset[str] = frozenset(PROBE_SPECS)

# The binding fields every raw probe result must carry and match against the
# candidate identity. ``operation_id``/``installation_id`` are identifiers,
# ``epoch``/``generation`` are integers, the rest are hashes/build strings.
BINDING_FIELDS = (
    "signed_app_tree_sha256",
    "machine_sha256",
    "macos_build",
    "operation_id",
    "installation_id",
    "epoch",
    "generation",
)


class LifecycleMatrixError(ValueError):
    """The lifecycle matrix evidence is incomplete, unbound, or malformed."""


def required_probe_ids() -> frozenset[str]:
    """Return the exact set of probe ids a signed-installed run must emit."""
    return REQUIRED_PROBES


def probe_matrix() -> dict[str, str]:
    """Return the machine-readable ``{probe_id: category}`` matrix."""
    return {probe: spec["category"] for probe, spec in PROBE_SPECS.items()}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LifecycleMatrixError(f"lifecycle matrix has a duplicate field: {key!r}")
        result[key] = value
    return result


def _canonical_loads(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise LifecycleMatrixError("lifecycle matrix is not canonical JSON") from error


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LifecycleMatrixError(f"{label} must be a JSON object")
    actual = set(value)
    missing = fields - actual
    unknown = actual - fields
    if missing:
        raise LifecycleMatrixError(f"{label} is missing required fields: {sorted(missing)}")
    if unknown:
        raise LifecycleMatrixError(f"{label} has unknown fields: {sorted(unknown)}")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise LifecycleMatrixError(f"{label} is not a lowercase SHA-256")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise LifecycleMatrixError(f"{label} is not a canonical identifier")
    return value


def _macos_build(value: Any, label: str) -> str:
    if not isinstance(value, str) or not MACOS_BUILD_RE.fullmatch(value):
        raise LifecycleMatrixError(f"{label} is not a macOS build identifier")
    return value


def _non_negative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise LifecycleMatrixError(f"{label} must be a non-negative integer")
    return value


def _positive_generation(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise LifecycleMatrixError(f"{label} must be a positive integer")
    return value


def _operation_context(value: Any) -> dict[str, Any]:
    context = _exact(
        value,
        {"operation_id", "installation_id", "epoch", "generation"},
        "operation_context",
    )
    return {
        "operation_id": _identifier(context["operation_id"], "operation_context.operation_id"),
        "installation_id": _identifier(
            context["installation_id"], "operation_context.installation_id"
        ),
        "epoch": _non_negative_int(context["epoch"], "operation_context.epoch"),
        "generation": _positive_generation(context["generation"], "operation_context.generation"),
    }


def _candidate(value: Any) -> dict[str, Any]:
    candidate = _exact(
        value,
        {
            "signed_app_tree_sha256",
            "machine_sha256",
            "macos_build",
            "architecture",
            "operation_context",
        },
        "candidate",
    )
    if candidate["architecture"] != REQUIRED_ARCHITECTURE:
        raise LifecycleMatrixError(
            f"candidate architecture must be {REQUIRED_ARCHITECTURE!r} (Apple Silicon)"
        )
    context = _operation_context(candidate["operation_context"])
    return {
        "signed_app_tree_sha256": _sha256(
            candidate["signed_app_tree_sha256"], "candidate.signed_app_tree_sha256"
        ),
        "machine_sha256": _sha256(candidate["machine_sha256"], "candidate.machine_sha256"),
        "macos_build": _macos_build(candidate["macos_build"], "candidate.macos_build"),
        "architecture": REQUIRED_ARCHITECTURE,
        "operation_id": context["operation_id"],
        "installation_id": context["installation_id"],
        "epoch": context["epoch"],
        "generation": context["generation"],
    }


def _validate_bindings(probe_id: str, raw: Any, candidate: dict[str, Any]) -> None:
    bindings = _exact(raw, set(BINDING_FIELDS), f"{probe_id}.bindings")
    _sha256(bindings["signed_app_tree_sha256"], f"{probe_id}.bindings.signed_app_tree_sha256")
    _sha256(bindings["machine_sha256"], f"{probe_id}.bindings.machine_sha256")
    _macos_build(bindings["macos_build"], f"{probe_id}.bindings.macos_build")
    _identifier(bindings["operation_id"], f"{probe_id}.bindings.operation_id")
    _identifier(bindings["installation_id"], f"{probe_id}.bindings.installation_id")
    _non_negative_int(bindings["epoch"], f"{probe_id}.bindings.epoch")
    _positive_generation(bindings["generation"], f"{probe_id}.bindings.generation")
    for field in BINDING_FIELDS:
        if bindings[field] != candidate[field]:
            # A stale signed tree, foreign machine, wrong build, or a different
            # operation context can never bind this raw result to the candidate.
            raise LifecycleMatrixError(
                f"{probe_id}.bindings.{field} does not match the candidate identity"
            )


def _validate_attributes(probe_id: str, raw: Any) -> None:
    checks = PROBE_SPECS[probe_id]["attributes"]
    attributes = _exact(raw, set(checks), f"{probe_id}.attributes")
    for key, check in checks.items():
        check(attributes[key], f"{probe_id}.attributes.{key}")


def _validate_probe(
    raw: Any,
    index: int,
    candidate: dict[str, Any],
    seen: set[str],
    report_hashes: set[str],
) -> str:
    probe = _exact(
        raw,
        {"id", "status", "report_sha256", "bindings", "attributes"},
        f"probes[{index}]",
    )
    probe_id = probe["id"]
    if not isinstance(probe_id, str) or probe_id not in PROBE_SPECS:
        raise LifecycleMatrixError(f"probes[{index}] has an unknown probe id: {probe_id!r}")
    if probe_id in seen:
        raise LifecycleMatrixError(f"lifecycle matrix repeats probe: {probe_id!r}")
    seen.add(probe_id)
    status = probe["status"]
    if status != ACCEPTED_STATUS:
        # unavailable / skipped / malformed / timeout / failed / masked / ...
        raise LifecycleMatrixError(
            f"{probe_id} status is {status!r}; only {ACCEPTED_STATUS!r} evidence is accepted"
        )
    report_sha256 = _sha256(probe["report_sha256"], f"{probe_id}.report_sha256")
    if report_sha256 in report_hashes:
        # Distinct probes must reference distinct raw reports so one artifact
        # cannot be replayed to cover multiple lifecycle cases.
        raise LifecycleMatrixError(f"{probe_id} reuses a raw report hash already bound")
    report_hashes.add(report_sha256)
    _validate_bindings(probe_id, probe["bindings"], candidate)
    _validate_attributes(probe_id, probe["attributes"])
    return probe_id


def validate_lifecycle_matrix(value: Any) -> dict[str, Any]:
    """Validate a parsed lifecycle matrix result document and return a summary.

    Raises :class:`LifecycleMatrixError` on the first fail-closed condition:
    a malformed document, an unknown/duplicate probe, a non-``passed`` status,
    a missing or mismatched binding, or an incomplete matrix.
    """
    document = _exact(
        value,
        {"schema_version", "harness_version", "candidate", "probes"},
        "lifecycle matrix",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise LifecycleMatrixError(f"lifecycle matrix schema_version must be {SCHEMA_VERSION}")
    if document["harness_version"] != HARNESS_VERSION:
        raise LifecycleMatrixError(
            f"lifecycle matrix harness_version must be {HARNESS_VERSION!r}"
        )
    candidate = _candidate(document["candidate"])

    probes = document["probes"]
    if not isinstance(probes, list) or not probes:
        raise LifecycleMatrixError("lifecycle matrix must declare at least one probe")
    if len(probes) > len(PROBE_SPECS):
        raise LifecycleMatrixError("lifecycle matrix declares more probes than the matrix defines")

    seen: set[str] = set()
    report_hashes: set[str] = set()
    for index, raw in enumerate(probes):
        _validate_probe(raw, index, candidate, seen, report_hashes)

    missing = REQUIRED_PROBES - seen
    if missing:
        # Absence is never success: an unavailable or skipped probe that never
        # emitted a result fails the entire Signed_Installed level.
        raise LifecycleMatrixError(
            f"lifecycle matrix is missing required probes: {sorted(missing)}"
        )
    return {"candidate": candidate, "probes": sorted(seen)}


def load_lifecycle_matrix(path: Path) -> dict[str, Any]:
    """Load, canonically parse, and validate a lifecycle matrix result file."""
    if path.is_symlink() or not path.is_file():
        raise LifecycleMatrixError("lifecycle matrix must be a regular non-symlink file")
    data = path.read_bytes()
    if not data or len(data) > MAX_DOCUMENT_BYTES:
        raise LifecycleMatrixError("lifecycle matrix size is outside the accepted range")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LifecycleMatrixError("lifecycle matrix is not valid UTF-8") from error
    return validate_lifecycle_matrix(_canonical_loads(text))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate an automated signed-installed lifecycle matrix result set."
    )
    parser.add_argument("results", type=Path)
    arguments = parser.parse_args()
    try:
        summary = load_lifecycle_matrix(arguments.results)
    except (LifecycleMatrixError, OSError) as error:
        raise SystemExit(f"error: lifecycle matrix validation failed: {error}") from error
    print(
        "lifecycle matrix verified: "
        f"{len(summary['probes'])}/{len(REQUIRED_PROBES)} probes bound to "
        f"{summary['candidate']['signed_app_tree_sha256'][:12]}"
    )


if __name__ == "__main__":
    main()
