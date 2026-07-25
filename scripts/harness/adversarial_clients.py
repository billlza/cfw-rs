#!/usr/bin/env python3
"""Separately-signed adversarial client / tamper harness for Signed_Installed_Verified.

This module owns the *definition* of the adversarial matrix that a physical,
signed on-device run must execute against Global_Authority, plus a fail-closed
validator that grades a captured result document.

Scope (task 11.4):
- Declare the complete adversarial matrix required by Requirement 6.4: identity
  predicate forgeries, inactive console user, replay/duplicate-redemption/cursor
  rollback, Authority_Journal truncation/tamper/symlink, oversize/deep/noncanonical
  protocol input, request floods and in-flight/event-queue saturation, heartbeat
  loss, Fast User Switching races, late callbacks, and secret-extraction surfaces
  (logs, preferences, journals, crash records, snapshots, evidence).
- Bind expected denial and cleanup outcomes to the exact separately-signed
  allowed-client and denied-client signatures and to the candidate app manifest.
- Fail closed: a missing fixture, an unexecuted attack case, a wrong signature
  binding, or a case whose attack was *not* denied (i.e. it succeeded) fails the
  Signed_Installed level immediately.

The signed on-device execution itself is out of scope here; this file provides the
harness definition, the result validator, and deterministic unit-test fixtures.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any

if __package__:
    from ..release_build_identity import canonical_build_version
else:  # pragma: no cover - import shim for direct invocation
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from release_build_identity import canonical_build_version


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CDHASH_RE = re.compile(r"^[0-9a-f]{40,64}$")
DENIAL_CODE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9]*$")

TEAM_ID = "YKUPL7Z869"
ALLOWED_SIGNING_ID = "com.bill.clashformac"

# Each attack case is bound to the exact client signature that must launch it and
# to the exact denial code + post-attack cleanup outcome the Authority must prove.
#   id -> (category, expected_client, expected_denial_code, expected_cleanup)
# expected_client is "denied" for identity forgeries launched from the separately
# signed adversary bundle, and "allowed" for misbehaviour launched from the
# correctly signed Host binary that the Authority must still refuse.
REQUIRED_CASES: dict[str, tuple[str, str, str, str]] = {
    # Identity predicate forgeries (launched from the denied adversary client).
    "wrong-team-id": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-bundle-identifier": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-designated-requirement": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-entitlement": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-uid": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-audit-session": ("identity", "denied", "unauthorizedPeer", "off"),
    "stale-pid-evidence": ("identity", "denied", "unauthorizedPeer", "off"),
    "stale-audit-evidence": ("identity", "denied", "unauthorizedPeer", "off"),
    "inactive-console-user": ("identity", "denied", "consoleUserMismatch", "off"),
    "same-team-unknown-bundle": ("identity", "denied", "unauthorizedPeer", "off"),
    # Replay / redemption attacks (launched from the correctly signed client).
    "replayed-operation": ("replay", "allowed", "replayRejected", "off"),
    "replayed-start-ticket": ("replay", "allowed", "ticketReplayRejected", "off"),
    "duplicate-redemption": ("replay", "allowed", "ticketAlreadyRedeemed", "off"),
    "replay-cursor-rollback": ("replay", "allowed", "replayRejected", "quarantined"),
    # Journal tamper / integrity attacks (must quarantine, never reset).
    "authority-journal-truncation": ("journal", "allowed", "journalIntegrityFailure", "quarantined"),
    "authority-journal-tamper": ("journal", "allowed", "journalIntegrityFailure", "quarantined"),
    "authority-journal-symlink": ("journal", "allowed", "journalIntegrityFailure", "quarantined"),
    # Protocol bounds attacks (rejected before state mutation).
    "oversize-message": ("protocol", "allowed", "protocolViolation", "off"),
    "deep-message": ("protocol", "allowed", "protocolViolation", "off"),
    "noncanonical-message": ("protocol", "allowed", "protocolViolation", "off"),
    # Backpressure / saturation attacks (explicit exhaustion, no drop of stop/revoke).
    "request-flood": ("backpressure", "allowed", "resourceExhausted", "off"),
    "in-flight-saturation": ("backpressure", "allowed", "resourceExhausted", "off"),
    "event-queue-saturation": ("backpressure", "allowed", "resourceExhausted", "off"),
    # Liveness / concurrency attacks.
    "heartbeat-loss": ("liveness", "allowed", "leaseRevoked", "off"),
    "fast-user-switching-race": ("liveness", "allowed", "leaseRevoked", "off"),
    "late-callback": ("liveness", "allowed", "staleOperation", "off"),
    # Secret-extraction surfaces (every surface must yield no secret bytes).
    "secret-extraction-logs": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-preferences": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-journal": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-crash-records": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-snapshots": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-evidence": ("secret", "allowed", "secretAbsent", "off"),
}

VALID_CLIENTS = {"allowed", "denied"}
VALID_CLEANUP = {"off", "quarantined"}
CASE_FIELDS = {
    "id",
    "category",
    "client",
    "executed",
    "outcome",
    "denial_code",
    "cleanup",
    "secret_observed",
}


class AdversarialMatrixError(ValueError):
    """The adversarial harness result is incomplete, unbound, or not fail-closed."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise AdversarialMatrixError(f"{label} fields differ: {actual}")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise AdversarialMatrixError(f"{label} is not a lowercase SHA-256")
    return value


def _cdhash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not CDHASH_RE.fullmatch(value):
        raise AdversarialMatrixError(f"{label} is not a lowercase code-directory hash")
    return value


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AdversarialMatrixError("captured_at must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise AdversarialMatrixError("captured_at is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise AdversarialMatrixError("captured_at must use UTC")
    return value


def _signing_identity(value: Any, label: str) -> dict[str, Any]:
    identity = _exact(
        value,
        {"signing_id", "cdhash", "designated_requirement_sha256"},
        label,
    )
    if not isinstance(identity["signing_id"], str) or not identity["signing_id"].strip():
        raise AdversarialMatrixError(f"{label}.signing_id is empty")
    _cdhash(identity["cdhash"], f"{label}.cdhash")
    _sha256(identity["designated_requirement_sha256"], f"{label}.designated_requirement_sha256")
    return identity


def _validate_signing(value: Any) -> dict[str, Any]:
    signing = _exact(value, {"team_id", "allowed_client", "denied_client"}, "signing")
    if signing["team_id"] != TEAM_ID:
        raise AdversarialMatrixError("signing.team_id is not the product Team ID")
    allowed = _signing_identity(signing["allowed_client"], "signing.allowed_client")
    denied = _signing_identity(signing["denied_client"], "signing.denied_client")
    if allowed["signing_id"] != ALLOWED_SIGNING_ID:
        raise AdversarialMatrixError("allowed client is not the signed Host identity")
    if denied["signing_id"] == ALLOWED_SIGNING_ID:
        raise AdversarialMatrixError("denied client must be a distinct same-Team bundle")
    if allowed["cdhash"] == denied["cdhash"]:
        raise AdversarialMatrixError("allowed and denied clients must be separately signed")
    return signing


def validate_adversarial_matrix(value: Any) -> dict[str, Any]:
    """Validate a captured adversarial matrix result document, failing closed."""
    document = _exact(
        value,
        {
            "schema_version",
            "product",
            "app_manifest_sha256",
            "captured_at",
            "platform",
            "signing",
            "baseline",
            "cases",
        },
        "adversarial matrix",
    )
    if document["schema_version"] != 1:
        raise AdversarialMatrixError("adversarial matrix schema_version must be 1")
    product = _exact(document["product"], {"version", "build_number"}, "product")
    if product["version"] != "0.4.0":
        raise AdversarialMatrixError("adversarial matrix is not for version 0.4.0")
    canonical_build_version(product["build_number"], "adversarial matrix build_number")
    _sha256(document["app_manifest_sha256"], "app_manifest_sha256")
    _timestamp(document["captured_at"])
    platform = _exact(
        document["platform"],
        {"architecture", "macos_version", "hardware_model", "clean_install"},
        "platform",
    )
    if platform["architecture"] != "arm64" or platform["clean_install"] is not True:
        raise AdversarialMatrixError("adversarial matrix requires a clean Apple Silicon machine")
    if not all(
        isinstance(platform[key], str) and platform[key].strip()
        for key in ("macos_version", "hardware_model")
    ):
        raise AdversarialMatrixError("adversarial platform identity is incomplete")

    _validate_signing(document["signing"])

    # Positive control: a correctly signed allowed client must be authorized. This
    # proves the harness can distinguish grant from denial, so a matrix of denials
    # is meaningful rather than a system that refuses everything unconditionally.
    baseline = _exact(document["baseline"], {"client", "executed", "authorized"}, "baseline")
    if baseline["client"] != "allowed":
        raise AdversarialMatrixError("baseline positive control must use the allowed client")
    if baseline["executed"] is not True:
        raise AdversarialMatrixError("baseline positive control was not executed (fail closed)")
    if baseline["authorized"] is not True:
        raise AdversarialMatrixError("baseline allowed client was not authorized (fail closed)")

    cases = document["cases"]
    if not isinstance(cases, list):
        raise AdversarialMatrixError("adversarial matrix cases must be a list")

    observed: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(cases):
        case = _exact(raw, CASE_FIELDS, f"cases[{index}]")
        case_id = case["id"]
        if case_id not in REQUIRED_CASES:
            raise AdversarialMatrixError(f"unknown adversarial case: {case_id!r}")
        if case_id in observed:
            raise AdversarialMatrixError(f"duplicate adversarial case: {case_id!r}")
        observed[case_id] = case

        category, expected_client, expected_code, expected_cleanup = REQUIRED_CASES[case_id]
        if case["category"] != category:
            raise AdversarialMatrixError(f"{case_id} category differs from the required matrix")
        if case["client"] not in VALID_CLIENTS:
            raise AdversarialMatrixError(f"{case_id} client is not a known signed identity")
        # Wrong signature binding fails closed.
        if case["client"] != expected_client:
            raise AdversarialMatrixError(
                f"{case_id} is bound to the wrong client signature: {case['client']!r}"
            )
        # An unexecuted attack case fails the level (fail closed).
        if case["executed"] is not True:
            raise AdversarialMatrixError(f"{case_id} attack was not executed (fail closed)")
        # A case that did not deny means the attack succeeded: fail closed.
        if case["outcome"] != "denied":
            raise AdversarialMatrixError(
                f"{case_id} was not denied (attack succeeded): {case['outcome']!r}"
            )
        code = case["denial_code"]
        if not isinstance(code, str) or not DENIAL_CODE_RE.fullmatch(code):
            raise AdversarialMatrixError(f"{case_id} denial_code is not a stable redacted code")
        if code != expected_code:
            raise AdversarialMatrixError(
                f"{case_id} denial_code differs: {code!r}, expected {expected_code!r}"
            )
        if case["cleanup"] not in VALID_CLEANUP:
            raise AdversarialMatrixError(f"{case_id} cleanup outcome is invalid")
        if case["cleanup"] != expected_cleanup:
            raise AdversarialMatrixError(
                f"{case_id} cleanup differs: {case['cleanup']!r}, expected {expected_cleanup!r}"
            )
        # No attack surface may ever reveal secret bytes, even when otherwise denied.
        if case["secret_observed"] is not False:
            raise AdversarialMatrixError(f"{case_id} observed secret material (fail closed)")

    missing = set(REQUIRED_CASES) - set(observed)
    if missing:
        raise AdversarialMatrixError(
            "adversarial matrix is missing required cases: " + ", ".join(sorted(missing))
        )
    return document


def load_adversarial_matrix(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise AdversarialMatrixError("adversarial matrix must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdversarialMatrixError("adversarial matrix is not valid UTF-8 JSON") from error
    return validate_adversarial_matrix(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("matrix", type=Path)
    arguments = parser.parse_args()
    try:
        document = load_adversarial_matrix(arguments.matrix)
    except (AdversarialMatrixError, OSError) as error:
        raise SystemExit(f"error: adversarial matrix failed: {error}") from error
    print(
        "adversarial matrix verified: "
        f"0.4.0 ({document['product']['build_number']}), "
        f"{len(document['cases'])} denied attack cases"
    )


if __name__ == "__main__":
    main()
