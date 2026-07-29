#!/usr/bin/env python3
"""Proof-to-byte validator for unique-token packet evidence.

Every case points at a bounded pcap/pcapng artifact beneath an explicit
evidence root. The validator reopens and hashes the file, parses packet records,
and recomputes presence or absence only inside a marker-bounded capture window.
Server/log/interface assertions are not accepted by this version.

Collector authenticity is verified by :mod:`physical_evidence_aggregator`; a
standalone check proves structure and bytes but does not grant a release level.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
import re
from typing import Any

if __package__:
    from .packet_capture import (
        PacketCaptureError,
        timestamp_fraction,
        validate_capture_tokens,
    )
    from .raw_artifacts import (
        ArtifactReader,
        RawArtifactError,
        exact_object,
        load_json_file,
        parse_proof_binding,
    )
else:  # pragma: no cover - direct-script import path
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from packet_capture import (  # type: ignore
        PacketCaptureError,
        timestamp_fraction,
        validate_capture_tokens,
    )
    from raw_artifacts import (  # type: ignore
        ArtifactReader,
        RawArtifactError,
        exact_object,
        load_json_file,
        parse_proof_binding,
    )


SCHEMA_VERSION = 2
HARNESS_VERSION = "packet-evidence-v2"
PRODUCT_VERSION = "0.4.0"
MAX_REPORT_BYTES = 1 * 1024 * 1024
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")


@dataclass(frozen=True)
class CaseSpec:
    protocol: str
    family: str
    resolver_role: str
    vantage: str
    token_observed: bool


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

CASE_FIELDS = {
    "id",
    "protocol",
    "family",
    "resolver_role",
    "vantage",
    "token",
    "window_start_token",
    "window_end_token",
    "token_observed",
    "observation_ms",
    "artifact",
}


class PacketEvidenceError(ValueError):
    """Packet evidence is malformed, byte-drifted, or behaviorally unproven."""


def _token(value: Any, label: str, seen: set[str]) -> bytes:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise PacketEvidenceError(f"{label} is not a bounded unique-token string")
    if any(value in existing or existing in value for existing in seen):
        raise PacketEvidenceError(f"{label} is reused or overlaps another packet token")
    seen.add(value)
    return value.encode("ascii")


def _platform(value: Any) -> dict[str, Any]:
    platform = exact_object(
        value,
        {"architecture", "macos_version", "hardware_model", "clean_install"},
        "platform",
    )
    if platform["architecture"] != "arm64" or platform["clean_install"] is not True:
        raise PacketEvidenceError("packet evidence requires a clean Apple Silicon machine")
    for field in ("macos_version", "hardware_model"):
        if not isinstance(platform[field], str) or not platform[field].strip():
            raise PacketEvidenceError(f"platform.{field} must be a non-empty string")
    return platform


def _validate(
    value: Any,
    artifacts: ArtifactReader,
) -> dict[str, Any]:
    document = exact_object(
        value,
        {
            "schema_version",
            "harness_version",
            "proof",
            "platform",
            "captured_at",
            "cases",
        },
        "packet evidence",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise PacketEvidenceError(f"packet evidence schema_version must be {SCHEMA_VERSION}")
    if document["harness_version"] != HARNESS_VERSION:
        raise PacketEvidenceError(
            f"packet evidence harness_version must be {HARNESS_VERSION!r}"
        )
    proof = parse_proof_binding(document["proof"])
    if proof["candidate"]["version"] != PRODUCT_VERSION:
        raise PacketEvidenceError("packet evidence is not for version 0.4.0")
    _platform(document["platform"])
    declared_start = timestamp_fraction(document["captured_at"])

    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(REQUIRED_CASES):
        raise PacketEvidenceError("packet evidence must contain each required case exactly once")
    seen_cases: set[str] = set()
    seen_tokens: set[str] = set()
    starts: list[Fraction] = []
    artifact_bindings: list[dict[str, Any]] = []
    for index, raw in enumerate(cases):
        case = exact_object(raw, CASE_FIELDS, f"cases[{index}]")
        case_id = case["id"]
        if not isinstance(case_id, str) or case_id not in REQUIRED_CASES:
            raise PacketEvidenceError(f"unknown packet-evidence case: {case_id!r}")
        if case_id in seen_cases:
            raise PacketEvidenceError(f"packet-evidence case is duplicated: {case_id!r}")
        seen_cases.add(case_id)
        spec = REQUIRED_CASES[case_id]
        for field in ("protocol", "family", "resolver_role", "vantage"):
            if case[field] != getattr(spec, field):
                raise PacketEvidenceError(f"{case_id} {field} differs from the required case")
        if case["token_observed"] is not spec.token_observed:
            expectation = "present" if spec.token_observed else "absent"
            raise PacketEvidenceError(
                f"{case_id} token_observed does not declare the required {expectation} proof"
            )
        observation_ms = case["observation_ms"]
        if not isinstance(observation_ms, int) or isinstance(observation_ms, bool):
            raise PacketEvidenceError(f"{case_id}.observation_ms must be an integer")
        token = _token(case["token"], f"{case_id}.token", seen_tokens)
        start_marker = _token(
            case["window_start_token"], f"{case_id}.window_start_token", seen_tokens
        )
        end_marker = _token(
            case["window_end_token"], f"{case_id}.window_end_token", seen_tokens
        )
        descriptor, capture = artifacts.read(
            case["artifact"],
            expected_kinds={"packet-pcap", "packet-pcapng"},
            label=f"{case_id}.artifact",
        )
        capture_proof = validate_capture_tokens(
            capture,
            descriptor.kind,
            token=token,
            start_marker=start_marker,
            end_marker=end_marker,
            expect_token=spec.token_observed,
            declared_observation_ms=observation_ms,
        )
        starts.append(capture_proof.started_at)
        artifact_bindings.append(
            {
                "subject": case_id,
                "descriptor": descriptor.as_dict(),
            }
        )
    if seen_cases != set(REQUIRED_CASES):
        raise PacketEvidenceError("packet evidence is missing a required case")
    if not starts or min(starts) != declared_start:
        raise PacketEvidenceError(
            "captured_at does not equal the earliest marker-bounded capture timestamp"
        )
    return {"document": document, "proof": proof, "artifacts": artifact_bindings}


def validate_packet_evidence(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    """Validate one v2 report and reopen every declared capture artifact."""

    try:
        return _validate(value, artifacts)
    except (RawArtifactError, PacketCaptureError) as error:
        raise PacketEvidenceError(str(error)) from error


def load_packet_evidence(path: Path, *, evidence_root: Path) -> dict[str, Any]:
    """Standalone byte/structure check; collector trust is checked by the aggregator."""

    try:
        value = load_json_file(path, maximum=MAX_REPORT_BYTES, label="packet report")
        with ArtifactReader(evidence_root) as artifacts:
            return validate_packet_evidence(value, artifacts)
    except RawArtifactError as error:
        raise PacketEvidenceError(str(error)) from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = load_packet_evidence(
            arguments.report, evidence_root=arguments.evidence_root
        )
    except (PacketEvidenceError, OSError) as error:
        raise SystemExit(f"error: packet evidence failed: {error}") from error
    print(
        "packet raw evidence structurally verified (collector signature not checked): "
        f"{len(result['artifacts'])} captures"
    )


if __name__ == "__main__":
    main()
