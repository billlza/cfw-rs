#!/usr/bin/env python3
"""Fail-closed validator for unique-token packet-evidence of a 0.4.0 candidate.

Requirement 6.2 requires unique-token ``Packet_Evidence`` for TCP over IPv4, TCP
over IPv6, UDP, QUIC, DNS A and AAAA through both resolver failover roles, LAN
bypass, included routes, excluded routes, stop cleanup, and IPv6-disabled
absence. The proof must be a packet capture or an independent server
observation; ``NEVPNStatus``, interface presence, localhost control traffic, or
component logs are never accepted as the sole proof of data-plane behavior.

Requirement 6.5 requires that any unavailable, skipped, malformed, or absent
capture fails the evidence level immediately. This module never converts
missing or ambiguous evidence into success: every deviation raises
``PacketEvidenceError`` and the associated evidence level fails closed.

The live capture requires a signed, installed candidate on real hardware and a
controlled network, which is out of scope for this harness. This module
implements the deterministic harness contract and the fail-closed validator so
that captured evidence can be verified reproducibly.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any

if __package__:
    from ..release_build_identity import canonical_build_version
else:  # pragma: no cover - direct-script execution fallback
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from release_build_identity import canonical_build_version


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PRODUCT_VERSION = "0.4.0"
MIN_TOKEN_LENGTH = 16
MIN_OBSERVATION_MS = 1_000

# Proof methods that constitute real data-plane evidence.
ALLOWED_METHODS = {"packet_capture", "server_observation"}
# Proof surfaces that Requirement 6.2 forbids as the sole proof of behavior.
REJECTED_METHODS = {
    "nevpn_status",
    "interface_presence",
    "localhost_control_traffic",
    "component_log",
}
# Vantage points that never prove real egress: loopback/control-plane surfaces.
REJECTED_VANTAGES = {
    "loopback",
    "localhost",
    "interface_presence",
    "nevpn_status",
    "component_log",
}


@dataclass(frozen=True)
class CaseSpec:
    """The fixed expectation for one required packet-evidence case."""

    protocol: str
    family: str
    resolver_role: str
    vantage: str
    token_observed: bool


# Every case Requirement 6.2 enumerates, with its exact required proof shape.
#
# Presence cases (token_observed=True) prove the data plane carried the unique
# token at a real vantage. Bypass/excluded cases prove the token egressed on the
# non-tunnel path (lan_segment/direct_wan) rather than merely trusting interface
# state. Absence cases (token_observed=False) require a real capture at the
# tunnel egress proving the token is absent -- not a NEVPNStatus/log assertion.
REQUIRED_CASES: dict[str, CaseSpec] = {
    "tcp-ipv4": CaseSpec("tcp", "ipv4", "none", "tunnel_egress", True),
    "tcp-ipv6": CaseSpec("tcp", "ipv6", "none", "tunnel_egress", True),
    "udp": CaseSpec("udp", "ipv4", "none", "tunnel_egress", True),
    "quic": CaseSpec("quic", "ipv4", "none", "tunnel_egress", True),
    "dns-a-primary": CaseSpec("dns", "ipv4", "primary", "independent_server", True),
    "dns-a-secondary": CaseSpec("dns", "ipv4", "secondary", "independent_server", True),
    "dns-aaaa-primary": CaseSpec("dns", "ipv6", "primary", "independent_server", True),
    "dns-aaaa-secondary": CaseSpec("dns", "ipv6", "secondary", "independent_server", True),
    "lan-bypass": CaseSpec("tcp", "ipv4", "none", "lan_segment", True),
    "included-routes": CaseSpec("tcp", "ipv4", "none", "tunnel_egress", True),
    "excluded-routes": CaseSpec("tcp", "ipv4", "none", "direct_wan", True),
    "stop-cleanup": CaseSpec("tcp", "ipv4", "none", "tunnel_egress", False),
    "ipv6-disabled-absence": CaseSpec("tcp", "ipv6", "none", "tunnel_egress", False),
}

ALLOWED_VANTAGES = {spec.vantage for spec in REQUIRED_CASES.values()}

CASE_FIELDS = {
    "id",
    "protocol",
    "family",
    "resolver_role",
    "token",
    "method",
    "vantage",
    "token_observed",
    "capture_sha256",
    "observation_ms",
    "captured_at",
    "candidate_app_manifest_sha256",
}


class PacketEvidenceError(ValueError):
    """Packet evidence is unavailable, malformed, mis-bound, or unproven."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise PacketEvidenceError(f"{label} fields differ: {actual}")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise PacketEvidenceError(f"{label} is not a lowercase SHA-256")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PacketEvidenceError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PacketEvidenceError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PacketEvidenceError(f"{label} must use UTC")
    return value


def _validate_case(
    raw: Any,
    index: int,
    candidate_manifest: str,
    tokens: set[str],
) -> str:
    case = _exact(raw, CASE_FIELDS, f"cases[{index}]")
    case_id = case["id"]
    if case_id not in REQUIRED_CASES:
        raise PacketEvidenceError(f"packet-evidence case is unknown: {case_id!r}")
    spec = REQUIRED_CASES[case_id]

    if case["protocol"] != spec.protocol:
        raise PacketEvidenceError(f"{case_id} protocol differs from the required case")
    if case["family"] != spec.family:
        raise PacketEvidenceError(f"{case_id} address family differs from the required case")
    if case["resolver_role"] != spec.resolver_role:
        raise PacketEvidenceError(f"{case_id} resolver role differs from the required case")

    method = case["method"]
    if method in REJECTED_METHODS:
        raise PacketEvidenceError(
            f"{case_id} relies on {method}, which is not accepted as sole packet proof"
        )
    if method not in ALLOWED_METHODS:
        raise PacketEvidenceError(f"{case_id} proof method is not a real capture or observation")

    vantage = case["vantage"]
    if vantage in REJECTED_VANTAGES:
        raise PacketEvidenceError(
            f"{case_id} vantage {vantage!r} cannot prove real data-plane egress"
        )
    if vantage not in ALLOWED_VANTAGES or vantage != spec.vantage:
        raise PacketEvidenceError(f"{case_id} vantage differs from the required proof point")

    token = case["token"]
    if not isinstance(token, str) or len(token) < MIN_TOKEN_LENGTH:
        raise PacketEvidenceError(f"{case_id} token is missing or too short to be unique")
    if token in tokens:
        raise PacketEvidenceError(f"{case_id} token is reused across cases")
    tokens.add(token)

    observed = case["token_observed"]
    if not isinstance(observed, bool):
        raise PacketEvidenceError(f"{case_id} token_observed must be boolean")
    if observed is not spec.token_observed:
        expectation = "present" if spec.token_observed else "absent"
        raise PacketEvidenceError(f"{case_id} token observation does not match the required {expectation} proof")

    # Absence proof still requires a real capture at a real vantage; a missing or
    # zero-length observation fails closed rather than passing by default.
    observation_ms = case["observation_ms"]
    if not isinstance(observation_ms, int) or isinstance(observation_ms, bool):
        raise PacketEvidenceError(f"{case_id} observation_ms must be an integer")
    if observation_ms < MIN_OBSERVATION_MS:
        raise PacketEvidenceError(f"{case_id} observation window is too short to prove behavior")

    _sha256(case["capture_sha256"], f"{case_id}.capture_sha256")
    _timestamp(case["captured_at"], f"{case_id}.captured_at")

    bound = case["candidate_app_manifest_sha256"]
    _sha256(bound, f"{case_id}.candidate_app_manifest_sha256")
    if bound != candidate_manifest:
        raise PacketEvidenceError(f"{case_id} is bound to a different candidate app manifest")

    return case_id


def validate_packet_evidence(value: Any) -> dict[str, Any]:
    """Validate a full packet-evidence document, failing closed on any gap."""

    document = _exact(
        value,
        {
            "schema_version",
            "product",
            "candidate",
            "platform",
            "captured_at",
            "cases",
        },
        "packet evidence",
    )
    if document["schema_version"] != 1:
        raise PacketEvidenceError("packet evidence schema_version must be 1")

    product = _exact(document["product"], {"version", "build_number"}, "product")
    if product["version"] != PRODUCT_VERSION:
        raise PacketEvidenceError("packet evidence is not for version 0.4.0")
    canonical_build_version(product["build_number"], "packet evidence build_number")

    candidate = _exact(
        document["candidate"],
        {"app_manifest_sha256", "signed_app_tree_sha256"},
        "candidate",
    )
    candidate_manifest = _sha256(candidate["app_manifest_sha256"], "candidate.app_manifest_sha256")
    _sha256(candidate["signed_app_tree_sha256"], "candidate.signed_app_tree_sha256")

    platform = _exact(
        document["platform"],
        {"architecture", "macos_version", "hardware_model", "clean_install"},
        "platform",
    )
    if platform["architecture"] != "arm64" or platform["clean_install"] is not True:
        raise PacketEvidenceError("packet evidence requires a clean Apple Silicon machine")
    if not all(
        isinstance(platform[key], str) and platform[key].strip()
        for key in ("macos_version", "hardware_model")
    ):
        raise PacketEvidenceError("packet evidence platform identity is incomplete")

    _timestamp(document["captured_at"], "captured_at")

    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(REQUIRED_CASES):
        raise PacketEvidenceError("packet evidence must contain each required case exactly once")

    observed_ids: set[str] = set()
    tokens: set[str] = set()
    for index, raw in enumerate(cases):
        case_id = _validate_case(raw, index, candidate_manifest, tokens)
        if case_id in observed_ids:
            raise PacketEvidenceError(f"packet-evidence case is duplicated: {case_id!r}")
        observed_ids.add(case_id)

    missing = set(REQUIRED_CASES) - observed_ids
    if missing:
        raise PacketEvidenceError(f"packet evidence is missing required cases: {sorted(missing)}")
    return document


def load_packet_evidence(path: Path) -> dict[str, Any]:
    """Load and validate packet evidence, failing closed on absence or symlinks."""

    if path.is_symlink() or not path.is_file():
        raise PacketEvidenceError("packet evidence must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PacketEvidenceError("packet evidence is not valid UTF-8 JSON") from error
    return validate_packet_evidence(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    arguments = parser.parse_args()
    try:
        document = load_packet_evidence(arguments.evidence)
    except (PacketEvidenceError, OSError) as error:
        raise SystemExit(f"error: packet evidence failed: {error}") from error
    print(
        "packet evidence verified: "
        f"0.4.0 ({document['product']['build_number']}), {len(document['cases'])} cases"
    )


if __name__ == "__main__":
    main()
