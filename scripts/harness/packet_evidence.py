#!/usr/bin/env python3
"""Proof-to-byte validator for unique-token packet evidence.

Every case points at a bounded pcap/pcapng artifact beneath an explicit
evidence root. The validator reopens and hashes the file, parses packet records,
and recomputes presence or absence only inside a marker-bounded capture window.
Unsigned server/log/interface assertions are not accepted by this version.

Collector authenticity is verified by :mod:`physical_evidence_aggregator`; a
standalone check proves structure and bytes but does not grant a release level.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import ipaddress
from pathlib import Path
import re
from typing import Any

if __package__:
    from .packet_capture import (
        ALLOWED_LINK_TYPES,
        PacketCaptureError,
        SUPPORTED_QUIC_VERSIONS,
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
        ALLOWED_LINK_TYPES,
        PacketCaptureError,
        SUPPORTED_QUIC_VERSIONS,
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


SCHEMA_VERSION = 3
HARNESS_VERSION = "packet-evidence-v3"
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
    "quic_version",
    "capture_filter_sha256",
    "capture_command_sha256",
    "send_command_sha256",
    "artifact",
    "provenance_artifact",
    "attempt_artifact",
}
PROVENANCE_FIELDS = {
    "schema_version",
    "proof",
    "case_id",
    "interface",
    "capture_point",
    "resolver_role",
    "capture_filter_sha256",
    "capture_command_sha256",
    "endpoint_set",
    "started_at",
    "completed_at",
    "signed_at",
    "quic_version",
}
INTERFACE_FIELDS = {"name", "index", "link_type"}
ENDPOINT_FIELDS = {"role", "address", "port", "transport"}
ATTEMPT_FIELDS = {
    "schema_version",
    "proof",
    "case_id",
    "token_sha256",
    "send_command_sha256",
    "capture_provenance_sha256",
    "endpoint_set",
    "started_at",
    "completed_at",
    "recorded_at",
    "exit_code",
    "bytes_submitted",
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


def _capture_provenance(
    value: Any,
    *,
    case_id: str,
    spec: CaseSpec,
    proof: dict[str, Any],
) -> dict[str, Any]:
    provenance = exact_object(value, PROVENANCE_FIELDS, f"{case_id}.capture_provenance")
    if provenance["schema_version"] != 1 or isinstance(
        provenance["schema_version"], bool
    ):
        raise PacketEvidenceError(f"{case_id} capture provenance schema_version must be 1")
    if parse_proof_binding(
        provenance["proof"], f"{case_id}.capture_provenance.proof"
    ) != proof:
        raise PacketEvidenceError(f"{case_id} capture provenance proof differs from its report")
    if provenance["case_id"] != case_id:
        raise PacketEvidenceError(f"{case_id} capture provenance case binding differs")
    if provenance["capture_point"] != spec.vantage:
        raise PacketEvidenceError(f"{case_id} capture point differs from the required vantage")
    if provenance["resolver_role"] != spec.resolver_role:
        raise PacketEvidenceError(f"{case_id} resolver role differs from the required case")
    for field in ("capture_filter_sha256", "capture_command_sha256"):
        value = provenance[field]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise PacketEvidenceError(f"{case_id} {field} is not a lowercase SHA-256")
    interface = exact_object(
        provenance["interface"], INTERFACE_FIELDS, f"{case_id}.capture_provenance.interface"
    )
    name = interface["name"]
    index = interface["index"]
    link_type = interface["link_type"]
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,31}", name)
        or not isinstance(index, int)
        or isinstance(index, bool)
        or not 1 <= index <= 2**31 - 1
        or not isinstance(link_type, int)
        or isinstance(link_type, bool)
        or link_type not in ALLOWED_LINK_TYPES
    ):
        raise PacketEvidenceError(f"{case_id} capture interface is invalid")
    endpoints = provenance["endpoint_set"]
    if not isinstance(endpoints, list) or len(endpoints) != 2:
        raise PacketEvidenceError(f"{case_id} endpoint_set must contain local and remote")
    parsed_endpoints: dict[str, dict[str, Any]] = {}
    expected_transport = "tcp" if spec.protocol == "tcp" else "udp"
    for endpoint_index, raw_endpoint in enumerate(endpoints):
        endpoint = exact_object(
            raw_endpoint,
            ENDPOINT_FIELDS,
            f"{case_id}.capture_provenance.endpoint_set[{endpoint_index}]",
        )
        role = endpoint["role"]
        if role not in {"local", "remote"} or role in parsed_endpoints:
            raise PacketEvidenceError(f"{case_id} endpoint role is unknown or duplicated")
        try:
            address = str(ipaddress.ip_address(endpoint["address"]))
        except (TypeError, ValueError) as error:
            raise PacketEvidenceError(f"{case_id} endpoint address is invalid") from error
        family = "ipv4" if ipaddress.ip_address(address).version == 4 else "ipv6"
        port = endpoint["port"]
        if (
            family != spec.family
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
            or endpoint["transport"] != expected_transport
        ):
            raise PacketEvidenceError(f"{case_id} endpoint family/port/transport is invalid")
        parsed_endpoints[role] = {
            "role": role,
            "address": address,
            "port": port,
            "transport": expected_transport,
        }
    if all(
        parsed_endpoints["local"][field] == parsed_endpoints["remote"][field]
        for field in ("address", "port", "transport")
    ):
        raise PacketEvidenceError(f"{case_id} local and remote endpoints must differ")
    if spec.protocol == "dns" and parsed_endpoints["remote"]["port"] != 53:
        raise PacketEvidenceError(f"{case_id} DNS resolver endpoint must use port 53")
    quic_version = provenance["quic_version"]
    if spec.protocol == "quic":
        if (
            not isinstance(quic_version, int)
            or isinstance(quic_version, bool)
            or quic_version not in SUPPORTED_QUIC_VERSIONS
        ):
            raise PacketEvidenceError(
                f"{case_id} capture provenance must bind QUIC v1 or v2"
            )
    elif quic_version is not None:
        raise PacketEvidenceError(f"{case_id} non-QUIC provenance declares a QUIC version")
    started_at = timestamp_fraction(provenance["started_at"])
    completed_at = timestamp_fraction(provenance["completed_at"])
    signed_at = timestamp_fraction(provenance["signed_at"])
    if not started_at < completed_at <= signed_at:
        raise PacketEvidenceError(f"{case_id} capture provenance timestamps are reversed")
    return {
        "interface": {"name": name, "index": index, "link_type": link_type},
        "local": parsed_endpoints["local"],
        "remote": parsed_endpoints["remote"],
        "capture_filter_sha256": provenance["capture_filter_sha256"],
        "capture_command_sha256": provenance["capture_command_sha256"],
        "quic_version": quic_version,
        "started_at": started_at,
        "completed_at": completed_at,
        "signed_at": signed_at,
    }


def _send_attempt(
    value: Any,
    *,
    case_id: str,
    proof: dict[str, Any],
    token: bytes,
    provenance: dict[str, Any],
    send_command_sha256: str,
    capture_provenance_sha256: str,
) -> tuple[Fraction, Fraction, Fraction]:
    attempt = exact_object(value, ATTEMPT_FIELDS, f"{case_id}.send_attempt")
    if attempt["schema_version"] != 1 or isinstance(attempt["schema_version"], bool):
        raise PacketEvidenceError(f"{case_id} send attempt schema_version must be 1")
    if parse_proof_binding(attempt["proof"], f"{case_id}.send_attempt.proof") != proof:
        raise PacketEvidenceError(f"{case_id} send attempt proof differs from its report")
    if attempt["case_id"] != case_id:
        raise PacketEvidenceError(f"{case_id} send attempt case binding differs")
    if attempt["token_sha256"] != hashlib.sha256(token).hexdigest():
        raise PacketEvidenceError(f"{case_id} send attempt token digest differs")
    if attempt["send_command_sha256"] != send_command_sha256:
        raise PacketEvidenceError(f"{case_id} send attempt command digest differs")
    if attempt["capture_provenance_sha256"] != capture_provenance_sha256:
        raise PacketEvidenceError(
            f"{case_id} send attempt capture-provenance binding differs"
        )
    endpoints = attempt["endpoint_set"]
    expected_endpoints = [provenance["local"], provenance["remote"]]
    if not isinstance(endpoints, list) or len(endpoints) != len(expected_endpoints):
        raise PacketEvidenceError(f"{case_id} send attempt endpoint_set is invalid")
    for index, expected in enumerate(expected_endpoints):
        endpoint = exact_object(
            endpoints[index], ENDPOINT_FIELDS, f"{case_id}.send_attempt.endpoint_set[{index}]"
        )
        if endpoint != expected:
            raise PacketEvidenceError(f"{case_id} send attempt endpoint tuple differs")
    if (
        not isinstance(attempt["exit_code"], int)
        or isinstance(attempt["exit_code"], bool)
        or attempt["exit_code"] != 0
        or not isinstance(attempt["bytes_submitted"], int)
        or isinstance(attempt["bytes_submitted"], bool)
        or attempt["bytes_submitted"] != len(token)
    ):
        raise PacketEvidenceError(
            f"{case_id} send attempt does not prove complete token submission"
        )
    started_at = timestamp_fraction(attempt["started_at"])
    completed_at = timestamp_fraction(attempt["completed_at"])
    recorded_at = timestamp_fraction(attempt["recorded_at"])
    if not (
        started_at
        < completed_at
        <= provenance["completed_at"]
        <= provenance["signed_at"]
        <= recorded_at
    ):
        raise PacketEvidenceError(
            f"{case_id} send attempt/capture receipt timestamps are not causal"
        )
    return started_at, completed_at, recorded_at


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
            "completed_at",
            "signed_at",
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
    completions: list[Fraction] = []
    signatures: list[Fraction] = []
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
        if spec.protocol == "quic" and any(
            len(value) > 20 for value in (token, start_marker, end_marker)
        ):
            raise PacketEvidenceError(f"{case_id} QUIC CID evidence tokens exceed 20 bytes")
        if spec.protocol == "quic":
            if (
                not isinstance(case["quic_version"], int)
                or isinstance(case["quic_version"], bool)
                or case["quic_version"] not in SUPPORTED_QUIC_VERSIONS
            ):
                raise PacketEvidenceError(f"{case_id} report must bind QUIC v1 or v2")
        elif case["quic_version"] is not None:
            raise PacketEvidenceError(f"{case_id} non-QUIC report declares a QUIC version")
        for field in (
            "capture_filter_sha256",
            "capture_command_sha256",
            "send_command_sha256",
        ):
            if not isinstance(case[field], str) or not re.fullmatch(
                r"[0-9a-f]{64}", case[field]
            ):
                raise PacketEvidenceError(f"{case_id} report {field} is not a SHA-256")
        if case["capture_command_sha256"] == case["send_command_sha256"]:
            raise PacketEvidenceError(
                f"{case_id} capture and send commands must be independently bound"
            )
        provenance_descriptor, provenance_document = artifacts.read_json(
            case["provenance_artifact"],
            expected_kind="packet-capture-provenance",
            label=f"{case_id}.provenance_artifact",
        )
        provenance = _capture_provenance(
            provenance_document,
            case_id=case_id,
            spec=spec,
            proof=proof,
        )
        if provenance["quic_version"] != case["quic_version"]:
            raise PacketEvidenceError(
                f"{case_id} report and capture provenance bind different QUIC versions"
            )
        if (
            provenance["capture_filter_sha256"] != case["capture_filter_sha256"]
            or provenance["capture_command_sha256"]
            != case["capture_command_sha256"]
        ):
            raise PacketEvidenceError(
                f"{case_id} report and capture provenance bind different capture commands"
            )
        descriptor, capture = artifacts.read(
            case["artifact"],
            expected_kinds={"packet-pcap", "packet-pcapng"},
            label=f"{case_id}.artifact",
        )
        capture_proof = validate_capture_tokens(
            capture,
            descriptor.kind,
            protocol=spec.protocol,
            family=spec.family,
            local_address=provenance["local"]["address"],
            local_port=provenance["local"]["port"],
            remote_address=provenance["remote"]["address"],
            remote_port=provenance["remote"]["port"],
            expected_link_type=provenance["interface"]["link_type"],
            expected_interface_name=provenance["interface"]["name"],
            expected_quic_version=provenance["quic_version"],
            token=token,
            start_marker=start_marker,
            end_marker=end_marker,
            expect_token=spec.token_observed,
            declared_observation_ms=observation_ms,
        )
        if (
            capture_proof.started_at != provenance["started_at"]
            or capture_proof.ended_at != provenance["completed_at"]
        ):
            raise PacketEvidenceError(
                f"{case_id} capture timestamps differ from signed provenance"
            )
        if spec.token_observed:
            if case["attempt_artifact"] is not None:
                raise PacketEvidenceError(
                    f"{case_id} presence proof must not carry an absence send attempt"
                )
        else:
            attempt_descriptor, attempt_document = artifacts.read_json(
                case["attempt_artifact"],
                expected_kind="packet-send-attempt",
                label=f"{case_id}.attempt_artifact",
            )
            attempt_started, attempt_completed, attempt_recorded = _send_attempt(
                attempt_document,
                case_id=case_id,
                proof=proof,
                token=token,
                provenance=provenance,
                send_command_sha256=case["send_command_sha256"],
                capture_provenance_sha256=provenance_descriptor.sha256,
            )
            if not (
                capture_proof.started_at
                <= attempt_started
                < attempt_completed
                <= capture_proof.ended_at
            ):
                raise PacketEvidenceError(
                    f"{case_id} send attempt is outside its marker-bounded capture window"
                )
            artifact_bindings.append(
                {
                    "subject": f"{case_id}:send-attempt",
                    "descriptor": attempt_descriptor.as_dict(),
                }
            )
            signatures.append(attempt_recorded)
        starts.append(capture_proof.started_at)
        completions.append(capture_proof.ended_at)
        signatures.append(provenance["signed_at"])
        artifact_bindings.append(
            {
                "subject": case_id,
                "descriptor": descriptor.as_dict(),
            }
        )
        artifact_bindings.append(
            {
                "subject": f"{case_id}:capture-provenance",
                "descriptor": provenance_descriptor.as_dict(),
            }
        )
    if seen_cases != set(REQUIRED_CASES):
        raise PacketEvidenceError("packet evidence is missing a required case")
    if not starts or min(starts) != declared_start:
        raise PacketEvidenceError(
            "captured_at does not equal the earliest marker-bounded capture timestamp"
        )
    declared_completed = timestamp_fraction(document["completed_at"])
    declared_signed = timestamp_fraction(document["signed_at"])
    if declared_completed != max(completions) or not max(signatures) <= declared_signed:
        raise PacketEvidenceError(
            "packet completed_at/signed_at do not cover every capture provenance record"
        )
    return {
        "document": document,
        "proof": proof,
        "started_at": min(starts),
        "completed_at": declared_completed,
        "artifacts": artifact_bindings,
    }


def validate_packet_evidence(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    """Validate one v3 report and reopen every declared capture artifact."""

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
        f"{len(result['artifacts'])} artifacts across {len(REQUIRED_CASES)} captures"
    )


if __name__ == "__main__":
    main()
