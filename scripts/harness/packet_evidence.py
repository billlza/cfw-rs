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
import calendar
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
import hashlib
import ipaddress
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

if __package__:
    from .physical_machine_identity import (
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from .packet_capture import (
        ALLOWED_LINK_TYPES,
        DLT_EN10MB,
        DLT_RAW,
        DNS_AAAA_ADDRESS,
        DNS_A_ADDRESS,
        DNS_TTL,
        PacketCaptureError,
        StagedCaptureEndpoint,
        SUPPORTED_QUIC_VERSIONS,
        timestamp_fraction,
        validate_staged_capture_tokens,
    )
    from .raw_artifacts import (
        ArtifactReader,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        load_json_file,
        parse_proof_binding,
    )
else:  # pragma: no cover - direct-script import path
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from physical_machine_identity import (  # type: ignore
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from packet_capture import (  # type: ignore
        ALLOWED_LINK_TYPES,
        DLT_EN10MB,
        DLT_RAW,
        DNS_AAAA_ADDRESS,
        DNS_A_ADDRESS,
        DNS_TTL,
        PacketCaptureError,
        StagedCaptureEndpoint,
        SUPPORTED_QUIC_VERSIONS,
        timestamp_fraction,
        validate_staged_capture_tokens,
    )
    from raw_artifacts import (  # type: ignore
        ArtifactReader,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        load_json_file,
        parse_proof_binding,
    )


SCHEMA_VERSION = 4
HARNESS_VERSION = "packet-evidence-v4"
PRODUCT_VERSION = "0.4.0"
MAX_REPORT_BYTES = 1 * 1024 * 1024
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
PRODUCT_OBSERVATION_PREFIX = "cfw-release-observation-v1 "
PRODUCT_OBSERVATION_DOCUMENT = "cfw-product-observation-event-v1"
PACKET_STATE_DOCUMENT = "cfw-packet-product-state-observation-v1"
PACKET_PROVENANCE_DOCUMENT = "cfw-packet-capture-provenance-v4"
PACKET_ATTEMPT_DOCUMENT = "cfw-packet-send-attempt-v4"
PRODUCT_LOG_SUBSYSTEM = "com.bill.clashformac"
PRODUCT_LOG_CATEGORY = "release-observation"
PRODUCT_LOG_PREDICATE = (
    'subsystem == "com.bill.clashformac" AND '
    'category == "release-observation" AND '
    'eventMessage BEGINSWITH "cfw-release-observation-v1 "'
)
INSTALLED_APP = "/Applications/Clash for Mac.app"
INSTALLED_EXECUTABLE = f"{INSTALLED_APP}/Contents/MacOS/clash-for-mac"
HOST_TEAM_ID = "YKUPL7Z869"
HOST_SIGNING_IDENTIFIER = "com.bill.clashformac"
PACKET_OWNER = "packet_tunnel_system_extension"
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_ABSENCE_WINDOW_MS = 30_000
REMOTE_CAPTURE_OFFLOAD_CONTEXT = "linux-gce-tx-checksum-offload-prestack-v1"
REMOTE_CAPTURE_SERVICE_ACCOUNT = (
    "packet-capture-client@cfw-release-evidence-20260730.iam.gserviceaccount.com"
)
REMOTE_CAPTURE_OS_LOGIN_PROFILE_ID = "116706315441516966425"
REMOTE_CAPTURE_POSIX_USERNAME = "sa_116706315441516966425"
PACKET_TRANSPORT_PORT = 44333
REMOTE_CAPTURE_SUDOERS_POLICY_SHA256 = (
    "a91c2bc91a294622d44f14e2cad653b9703fcf70afa42bf91e0248ef240c3411"
)
REMOTE_TCPDUMP_BINARY_SHA256 = (
    "c97881e39b54571829ec22b98cfa9c2348c7449a92fd761ebee7826b47ef4616"
)
REMOTE_CAPTURE_KNOWN_HOSTS_SHA256 = (
    "3741384531dbd24c65a2225386beae492bf92c61fdf2d5b90b57051d57be36ba"
)
TRANSPORT_ENDPOINT_IDENTITY_SHA256 = (
    "7e878c338d56a79e69f91d6c8d7091f8f524912c249e69ebb814b4ae91be76fa"
)
LAN_ENDPOINT_IDENTITY_SHA256 = (
    "c5e9e90cc7a4ec25bf27041373c3fd94e8a55096fb5227ad3a5156a8053dc2a6"
)
LAN_ENDPOINT_IDENTITY_FILE_SHA256 = (
    "bee82809982b4dc5cc0b5697f10077bfa88884f58eb152cce59a5109127d29a3"
)
IOS_LAN_CORE_DEVICE_SHA256 = (
    "a992e87636750487576c10f2ae66a9eb8e9a1b533ca720fd3dae047ef5f15ec0"
)
IOS_LAN_PROVISIONING_UDID_SHA256 = (
    "983e5e676afaca0eeb42cc86a9898270020a6e1b9db062226033b8c415851d76"
)
IOS_LAN_APP_TREE_SHA256 = (
    "9b70643066177cc6cf2b523411a50965a6c5f433aefcd91918ad2d7e8f371cc7"
)
IOS_LAN_EXECUTABLE_SHA256 = (
    "01d04a497d5a45a342db9986626055428929ff72a28dfcc9882eb8a9da19d1fe"
)
IOS_LAN_SOURCE_TREE_SHA256 = (
    "9dc014d685b1484d1a3bd31a9c58620d5fbb01e6efccf932024b1f30e57d5a60"
)
IOS_LAN_PROFILE_SHA256 = (
    "deed517ef2a944c19c1dae2207117fe520b8d48b4a3efd31af329682b626bc47"
)
IOS_LAN_ENTITLEMENTS_SHA256 = (
    "5ebda5445335b4bef0ff695cf4646a8377bc2e07b1e873ce4cdb6c8744dc1bbf"
)
IOS_LAN_SIGNING_CERTIFICATE_SHA256 = (
    "80ce3788e305d8d9321d6d8ec1dd9fdde12158de9203795f992706ae61d83a2b"
)
IOS_LAN_PROFILE_UUID = "B43F41C0-5487-47D8-9F39-FCDBDA8BA227"
DNS_REMOTE_CAPTURE_POLICIES: dict[str, dict[str, str]] = {
    "primary": {
        "identity_sha256": (
            "1bc00593e985d10b0ed0d38903166d78c5ec199682141007d6a792a19320526e"
        ),
        "project": "cfw-release-evidence-20260730",
        "zone": "asia-east1-c",
        "instance_name": "packet-dns-primary-v040",
        "instance_id": "3054958859983781235",
        "internal_ip": "10.42.40.3",
        "ipv4": "34.80.107.183",
        "ipv6": "2600:1900:4030:5afb:0:1::",
        "interface": "ens4",
        "host_key_bytes_sha256": (
            "a60f99db534de08424cd01d0d7c82de5b9f45b5770f9ca982de2b474381020e5"
        ),
    },
    "secondary": {
        "identity_sha256": (
            "839764c618e036098728f4dcd02f0f600c29cc17bc5e941fab1d6f2233d1805a"
        ),
        "project": "cfw-release-evidence-20260730",
        "zone": "asia-northeast1-b",
        "instance_name": "packet-dns-secondary-v040",
        "instance_id": "247293400913804658",
        "internal_ip": "10.42.41.2",
        "ipv4": "35.200.12.109",
        "ipv6": "2600:1900:4050:8de::",
        "interface": "ens4",
        "host_key_bytes_sha256": (
            "f4e28ed3f9d1fbeb71ddf4ec8894a521a0c84185f2728354e39316b3f9d29e06"
        ),
    },
}
TRANSPORT_ENDPOINT_ADDRESSES = {
    "ipv4": "35.194.216.98",
    "ipv6": "2600:1900:4030:5afb::",
}
TUNNEL_CAPTURE_LOCAL_ADDRESSES = {
    "ipv4": "198.18.64.1",
    "ipv6": "2001:2:0:64::1",
}
@dataclass(frozen=True)
class CaseSpec:
    protocol: str
    family: str
    resolver_role: str
    vantage: str
    token_observed: bool
    product_state: str

    @property
    def expected_mode(self) -> str:
        return "off" if self.product_state == "off" else "tunnel"

    @property
    def expected_phase(self) -> str:
        return "off" if self.expected_mode == "off" else "tunnel_active"

    @property
    def expected_ipv6_enabled(self) -> bool:
        return self.product_state == "active"


REQUIRED_CASES: dict[str, CaseSpec] = {
    "tcp-ipv4": CaseSpec("tcp", "ipv4", "none", "tunnel_egress", True, "active"),
    "tcp-ipv6": CaseSpec("tcp", "ipv6", "none", "tunnel_egress", True, "active"),
    "udp": CaseSpec("udp", "ipv4", "none", "tunnel_egress", True, "active"),
    "quic": CaseSpec("quic", "ipv4", "none", "tunnel_egress", True, "active"),
    "dns-a-primary": CaseSpec(
        "dns", "ipv4", "primary", "independent_server", True, "active"
    ),
    "dns-a-secondary": CaseSpec(
        "dns", "ipv4", "secondary", "independent_server", True, "active"
    ),
    "dns-aaaa-primary": CaseSpec(
        "dns", "ipv6", "primary", "independent_server", True, "active"
    ),
    "dns-aaaa-secondary": CaseSpec(
        "dns", "ipv6", "secondary", "independent_server", True, "active"
    ),
    "lan-bypass": CaseSpec(
        "tcp", "ipv4", "none", "lan_segment", True, "active"
    ),
    "included-routes": CaseSpec(
        "tcp", "ipv4", "none", "tunnel_egress", True, "active"
    ),
    "excluded-routes": CaseSpec(
        "tcp", "ipv4", "none", "direct_wan", True, "active"
    ),
    "stop-cleanup": CaseSpec(
        "tcp", "ipv4", "none", "tunnel_egress", False, "off"
    ),
    "ipv6-disabled-absence": CaseSpec(
        "tcp", "ipv6", "none", "tunnel_egress", False, "ipv6-disabled"
    ),
}

PACKET_STAGES = ("start", "target", "end")
CASE_STAGE_PLANS = MappingProxyType(
    {
        "tcp-ipv4": ("test", "test", "test"),
        "tcp-ipv6": ("test", "test", "test"),
        "udp": ("test", "test", "test"),
        "quic": ("test", "test", "test"),
        "dns-a-primary": ("test", "test", "test"),
        "dns-a-secondary": ("test", "test", "test"),
        "dns-aaaa-primary": ("test", "test", "test"),
        "dns-aaaa-secondary": ("test", "test", "test"),
        "lan-bypass": ("test", "test", "test"),
        "included-routes": ("test", "test", "test"),
        "excluded-routes": ("test", "test", "test"),
        "stop-cleanup": ("baseline", "test", "restored"),
        "ipv6-disabled-absence": ("baseline", "test", "restored"),
    }
)


def _private_lan_endpoint(value: object) -> str:
    if not isinstance(value, str):
        raise PacketEvidenceError(
            "controlled LAN endpoint must come from one iPhone ready receipt"
        )
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise PacketEvidenceError("controlled LAN endpoint is not IPv4") from error
    private_networks = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if str(address) != value or not any(address in network for network in private_networks):
        raise PacketEvidenceError(
            "controlled LAN endpoint is not canonical RFC1918 IPv4"
        )
    return value


def packet_capture_filter_argv(
    *,
    case_id: str,
    tokens: tuple[str, str, str],
    lan_endpoint_address: str | None = None,
) -> tuple[str, ...]:
    """Return the only local/remote BPF expression admitted for one case."""

    spec = REQUIRED_CASES.get(case_id)
    if spec is None or len(tokens) != 3 or any(TOKEN_RE.fullmatch(token) is None for token in tokens):
        raise PacketEvidenceError("packet capture filter input is not source-owned")
    if spec.protocol == "dns":
        return ("udp", "and", "port", "53")
    if case_id == "lan-bypass":
        remote_address = _private_lan_endpoint(lan_endpoint_address)
    else:
        if lan_endpoint_address is not None:
            raise PacketEvidenceError(
                "non-LAN capture filter declares a runtime LAN endpoint"
            )
        remote_address = TRANSPORT_ENDPOINT_ADDRESSES[spec.family]
    payload_offset = "tcp[((tcp[12] & 0xf0) >> 2):4]"
    if spec.protocol == "udp":
        payload_offset = "udp[8:4]"
    elif spec.protocol == "quic":
        payload_offset = "udp[14:4]"
    prefixes = [int.from_bytes(token.encode("ascii")[:4], "big") for token in tokens]
    if len(set(prefixes)) != len(prefixes):
        raise PacketEvidenceError("packet token BPF prefixes are not unique")
    token_clause = " or ".join(
        f"{payload_offset} = 0x{prefix:08x}" for prefix in prefixes
    )
    protocol = "tcp" if spec.protocol == "tcp" else "udp"
    clauses = [
        protocol,
        f"dst host {remote_address}",
        f"dst port {PACKET_TRANSPORT_PORT}",
    ]
    if case_id not in {"lan-bypass", "excluded-routes"}:
        clauses.insert(1, f"src host {TUNNEL_CAPTURE_LOCAL_ADDRESSES[spec.family]}")
    return (" and ".join(clauses) + f" and ({token_clause})",)

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
    "state_artifact",
    "restore_state_artifact",
    "provenance_artifact",
    "attempt_artifact",
}
PROVENANCE_FIELDS = {
    "schema_version",
    "document",
    "case_id",
    "state_observation_sha256",
    "capture_artifact_sha256",
    "endpoint_identity_sha256",
    "capture_device",
    "capture_point",
    "resolver_role",
    "capture_filter_argv",
    "capture_filter_sha256",
    "remote_key_generation_command",
    "remote_public_key_command",
    "remote_key_import_command",
    "remote_interface",
    "remote_interface_command",
    "capture_command",
    "capture_alive_at",
    "started_at",
    "completed_at",
    "quic_version",
    "remote_access",
    "capture_offload_context",
    "host_transaction",
}
CAPTURE_DEVICE_FIELDS = {"name", "link_type", "scope"}
HOST_TRANSACTION_FIELDS = {
    "session_id",
    "baseline",
    "baseline_observation_sequence",
    "test",
    "test_observation_sequence",
    "restore",
    "restore_observation_sequence",
    "candidate_observation_sequence",
}
HOST_SNAPSHOT_FIELDS = {
    "config_digest",
    "desired_mode",
    "generation",
    "ipv6_enabled",
    "owner",
    "phase",
    "ready",
}
INTERFACE_FIELDS = {"name", "index", "link_type", "flags"}
REMOTE_ACCESS_FIELDS = {
    "project",
    "zone",
    "instance_name",
    "instance_id",
    "internal_ip_address",
    "host_alias",
    "host_key_bytes_sha256",
    "service_account",
    "service_account_unique_id",
    "posix_username",
    "os_login_profile_id",
    "known_hosts_snapshot_path",
    "known_hosts_snapshot_sha256",
    "ssh_key_file_path",
    "ssh_key_file_path_sha256",
    "gcloud_path",
    "sudoers_policy_sha256",
    "tcpdump_binary_sha256",
    "private_key_size",
    "private_key_sha256",
    "public_key_sha256",
}
LAN_PEER_REMOTE_ACCESS_FIELDS = {
    "schema_version",
    "document",
    "evidence_role",
    "claim_eligible",
    "source_identity_sha256",
    "source_identity_file_sha256",
    "runtime_endpoint_source",
    "network",
    "admission",
    "before_capture",
    "after_capture",
    "cleanup",
}
LAN_PEER_NETWORK_FIELDS = {"interface_name", "ipv4", "listener_port", "transport"}
ENDPOINT_FIELDS = {"role", "address", "port", "transport"}
ATTEMPT_FIELDS = {
    "schema_version",
    "document",
    "case_id",
    "state_observation_sha256",
    "capture_provenance_sha256",
    "stages",
    "recorded_at",
    "absence_window_completed_at",
}
ATTEMPT_STAGE_FIELDS = {
    "stage",
    "host_stage",
    "token_sha256",
    "endpoint_set",
    "route_command",
    "interface_command",
    "interface",
    "command",
}
COMMAND_FIELDS = {
    "role",
    "argv",
    "argv_sha256",
    "started_at",
    "completed_at",
    "duration_ms",
    "exit_code",
    "stdout_size",
    "stdout_sha256",
    "stdout",
    "stderr_size",
    "stderr_sha256",
    "stderr",
}
STATE_OBSERVATION_FIELDS = {
    "schema_version",
    "document",
    "case_id",
    "log_entry",
    "query_command",
    "codesign_command",
    "signing_identity",
    "event",
}
LOG_ENTRY_FIELDS = {
    "timestamp",
    "processImagePath",
    "processID",
    "subsystem",
    "category",
    "eventMessage",
}
SIGNING_IDENTITY_FIELDS = {
    "executable",
    "team_id",
    "signing_identifier",
    "cdhash",
}
PRODUCT_EVENT_FIELDS = {
    "schema_version",
    "document",
    "component",
    "event",
    "sequence",
    "recorded_unix_ms",
    "process",
    "candidate",
    "payload",
}
PRODUCT_PAYLOAD_FIELDS = {"state"}
PRODUCT_PROCESS_FIELDS = {"pid", "start_unix_ms"}
PRODUCT_CANDIDATE_FIELDS = {"version", "build_number"}
PRODUCT_STATE_FIELDS = {
    "desired_mode",
    "generation",
    "config_digest",
    "phase",
    "owner",
    "ready",
    "ipv6_enabled",
}
SEND_RESULT_FIELDS = {
    "schema_version",
    "document",
    "case_id",
    "stage",
    "local_address",
    "local_port",
    "remote_address",
    "remote_port",
    "transport",
    "token_sha256",
    "bytes_submitted",
    "dns_result",
}
DNS_RESULT_FIELDS = {
    "trigger",
    "resolver_role",
    "requested_type",
    "query",
}
DNS_QUERY_RESULT_FIELDS = {"name", "token_sha256", "addresses"}

EXPECTED_PACKET_RAW_SUBJECTS = frozenset(
    subject
    for case_id in REQUIRED_CASES
    for subject in (
        case_id,
        f"{case_id}:product-state",
        f"{case_id}:capture-provenance",
        f"{case_id}:send-attempt",
    )
)
OPTIONAL_PACKET_RAW_SUBJECTS = frozenset(
    f"{case_id}:restore-state"
    for case_id, spec in REQUIRED_CASES.items()
    if not spec.token_observed
)


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
    if not isinstance(platform["macos_version"], str) or not platform[
        "macos_version"
    ].strip():
        raise PacketEvidenceError("platform.macos_version must be a non-empty string")
    try:
        validate_physical_hardware_model(platform["hardware_model"])
    except PhysicalMachineIdentityError as error:
        raise PacketEvidenceError("platform.hardware_model is invalid") from error
    return platform


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise PacketEvidenceError(f"{label} is not a lowercase SHA-256")
    return value


def _host_snapshot(value: Any, *, label: str) -> dict[str, Any]:
    snapshot = exact_object(value, HOST_SNAPSHOT_FIELDS, label)
    if (
        type(snapshot["generation"]) is not int
        or snapshot["generation"] <= 0
        or type(snapshot["ipv6_enabled"]) is not bool
        or type(snapshot["ready"]) is not bool
    ):
        raise PacketEvidenceError(f"{label} has non-exact scalar types")
    if snapshot["phase"] == "off":
        exact_state = (
            snapshot["desired_mode"] == "off"
            and snapshot["config_digest"] is None
            and snapshot["owner"] is None
            and snapshot["ready"] is False
            and snapshot["ipv6_enabled"] is False
        )
    elif snapshot["phase"] == "tunnel_active":
        exact_state = (
            snapshot["desired_mode"] == "tunnel"
            and isinstance(snapshot["config_digest"], str)
            and re.fullmatch(r"[0-9a-f]{64}", snapshot["config_digest"])
            is not None
            and snapshot["owner"] == "packet_tunnel_system_extension"
            and snapshot["ready"] is True
        )
    else:
        exact_state = False
    if not exact_state:
        raise PacketEvidenceError(f"{label} is not an exact Host state")
    return snapshot


def _log_timestamp_fraction(value: Any) -> Fraction:
    if not isinstance(value, str):
        raise PacketEvidenceError("Unified Log timestamp is not text")
    normalized = value.replace(" ", "T", 1)
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    elif re.search(r"[+-][0-9]{4}$", normalized):
        normalized = normalized[:-2] + ":" + normalized[-2:]
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise PacketEvidenceError("Unified Log timestamp is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PacketEvidenceError("Unified Log timestamp must use UTC")
    return Fraction(calendar.timegm(parsed.utctimetuple()), 1) + Fraction(
        parsed.microsecond, 1_000_000
    )


def _command(
    value: Any,
    *,
    label: str,
    expected_role: str,
    binary_stdout: tuple[int, str] | None = None,
) -> dict[str, Any]:
    command = exact_object(value, COMMAND_FIELDS, label)
    if command["role"] != expected_role:
        raise PacketEvidenceError(f"{label}.role differs from the source-pinned role")
    argv = command["argv"]
    if (
        not isinstance(argv, list)
        or not 1 <= len(argv) <= 64
        or any(
            not isinstance(argument, str)
            or not argument
            or "\x00" in argument
            or len(argument.encode("utf-8")) > 4096
            for argument in argv
        )
    ):
        raise PacketEvidenceError(f"{label}.argv is not a bounded argument vector")
    argv_sha256 = hashlib.sha256(canonical_json(argv)).hexdigest()
    if _sha256(command["argv_sha256"], f"{label}.argv_sha256") != argv_sha256:
        raise PacketEvidenceError(f"{label}.argv_sha256 differs from its exact argv")
    started_at = timestamp_fraction(command["started_at"])
    completed_at = timestamp_fraction(command["completed_at"])
    duration_ms = command["duration_ms"]
    if (
        not started_at < completed_at
        or type(duration_ms) is not int
        or duration_ms < 1
        or abs((completed_at - started_at) * 1000 - duration_ms) > 1000
    ):
        raise PacketEvidenceError(f"{label} timestamps/duration are not causal")
    if type(command["exit_code"]) is not int or command["exit_code"] != 0:
        raise PacketEvidenceError(f"{label} did not complete successfully")
    outputs: dict[str, str | None] = {}
    for stream in ("stdout", "stderr"):
        text = command[stream]
        if stream == "stdout" and binary_stdout is not None:
            expected_size, expected_sha256 = binary_stdout
            if (
                text is not None
                or type(command["stdout_size"]) is not int
                or command["stdout_size"] != expected_size
                or _sha256(command["stdout_sha256"], f"{label}.stdout_sha256")
                != expected_sha256
            ):
                raise PacketEvidenceError(
                    f"{label}.stdout does not bind the exact binary artifact"
                )
            outputs[stream] = None
            continue
        if not isinstance(text, str) or "\x00" in text:
            raise PacketEvidenceError(f"{label}.{stream} is not bounded UTF-8 text")
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_COMMAND_OUTPUT_BYTES:
            raise PacketEvidenceError(f"{label}.{stream} exceeds its byte bound")
        if type(command[f"{stream}_size"]) is not int or command[
            f"{stream}_size"
        ] != len(encoded):
            raise PacketEvidenceError(f"{label}.{stream}_size differs from its bytes")
        if _sha256(
            command[f"{stream}_sha256"], f"{label}.{stream}_sha256"
        ) != hashlib.sha256(encoded).hexdigest():
            raise PacketEvidenceError(f"{label}.{stream}_sha256 differs from its bytes")
        outputs[stream] = text
    return {
        "argv": tuple(argv),
        "argv_sha256": argv_sha256,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "stdout": outputs["stdout"],
        "stderr": outputs["stderr"],
    }


def _require_product_query(
    command: dict[str, Any],
    *,
    label: str,
    log_entry: dict[str, Any],
    event: dict[str, Any],
) -> None:
    argv = command["argv"]
    if (
        len(argv) != 13
        or argv[:8]
        != (
            "/usr/bin/log",
            "show",
            "--style",
            "ndjson",
            "--info",
            "--timezone",
            "UTC",
            "--start",
        )
        or argv[9] != "--end"
        or argv[11:] != ("--predicate", PRODUCT_LOG_PREDICATE)
    ):
        raise PacketEvidenceError(f"{label}.argv differs from the fixed Unified Log query")
    query_start = timestamp_fraction(argv[8])
    query_end = timestamp_fraction(argv[10])
    event_time = _log_timestamp_fraction(log_entry["timestamp"])
    if (
        command["stderr"]
        or not query_start <= event_time <= query_end <= command["completed_at"]
    ):
        raise PacketEvidenceError(f"{label} does not cover the retained product event")
    entries: list[dict[str, Any]] = []
    try:
        for line in command["stdout"].splitlines():
            if line.strip():
                value = load_json_bytes(line.encode("utf-8"), f"{label} entry")
                if not isinstance(value, dict):
                    raise TypeError("Unified Log entry is not an object")
                entries.append(value)
    except (RawArtifactError, TypeError, UnicodeError) as error:
        raise PacketEvidenceError(f"{label}.stdout is not strict NDJSON") from error
    candidates: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    for entry in entries:
        if not LOG_ENTRY_FIELDS <= set(entry):
            continue
        if (
            entry["processImagePath"] != INSTALLED_EXECUTABLE
            or entry["subsystem"] != PRODUCT_LOG_SUBSYSTEM
            or entry["category"] != PRODUCT_LOG_CATEGORY
            or not isinstance(entry["eventMessage"], str)
            or not entry["eventMessage"].startswith(PRODUCT_OBSERVATION_PREFIX)
        ):
            continue
        encoded = entry["eventMessage"][len(PRODUCT_OBSERVATION_PREFIX) :]
        try:
            candidate_event = load_json_bytes(
                encoded.encode("utf-8"), f"{label} Host event"
            )
            if canonical_json(candidate_event).decode("utf-8") != encoded:
                raise ValueError("event is not canonical")
            recorded = candidate_event["recorded_unix_ms"]
            candidate_time = _log_timestamp_fraction(entry["timestamp"])
        except (
            KeyError,
            TypeError,
            UnicodeEncodeError,
            ValueError,
            RawArtifactError,
        ) as error:
            raise PacketEvidenceError(
                f"{label}.stdout contains a malformed Host event"
            ) from error
        if (
            type(recorded) is not int
            or recorded < 1
            or not query_start <= candidate_time <= query_end
        ):
            raise PacketEvidenceError(
                f"{label}.stdout contains an out-of-range Host event"
            )
        candidates.append(
            (
                recorded,
                {field: entry[field] for field in LOG_ENTRY_FIELDS},
                candidate_event,
            )
        )
    if not candidates:
        raise PacketEvidenceError(
            f"{label}.stdout does not contain a Host product event"
        )
    latest_time = max(candidate[0] for candidate in candidates)
    latest = [candidate for candidate in candidates if candidate[0] == latest_time]
    try:
        latest_entry_matches = (
            len(latest) == 1
            and canonical_json(latest[0][1]) == canonical_json(log_entry)
            and canonical_json(latest[0][2]) == canonical_json(event)
        )
    except RawArtifactError as error:
        raise PacketEvidenceError(
            f"{label}.stdout contains a non-canonical Host event projection"
        ) from error
    if not latest_entry_matches:
        raise PacketEvidenceError(
            f"{label}.stdout does not bind the unique latest product event"
        )


def _require_codesign(
    command: dict[str, Any],
    *,
    label: str,
    identity: dict[str, Any],
) -> None:
    if command["argv"] != (
        "/usr/bin/codesign",
        "-d",
        "--verbose=4",
        INSTALLED_APP,
    ):
        raise PacketEvidenceError(f"{label}.argv differs from the fixed codesign query")
    output = command["stdout"] + command["stderr"]
    cdhashes = re.findall(r"^CDHash=([0-9a-f]{40})$", output, re.MULTILINE)
    required = (
        f"Executable={INSTALLED_EXECUTABLE}",
        f"Identifier={HOST_SIGNING_IDENTIFIER}",
        f"TeamIdentifier={HOST_TEAM_ID}",
        f"CDHash={identity['cdhash']}",
    )
    if (
        cdhashes != [identity["cdhash"]]
        or any(line not in output.splitlines() for line in required)
    ):
        raise PacketEvidenceError(f"{label} output differs from the installed Host identity")


def _product_state_observation(
    value: Any,
    *,
    case_id: str,
    spec: CaseSpec,
    candidate_identity: dict[str, Any],
    restored: bool = False,
) -> dict[str, Any]:
    observation = exact_object(
        value, STATE_OBSERVATION_FIELDS, f"{case_id}.product_state_observation"
    )
    if (
        type(observation["schema_version"]) is not int
        or observation["schema_version"] != 1
        or observation["document"] != PACKET_STATE_DOCUMENT
        or observation["case_id"] != case_id
    ):
        raise PacketEvidenceError(f"{case_id} product-state observation identity is invalid")
    log_entry = exact_object(
        observation["log_entry"], LOG_ENTRY_FIELDS, f"{case_id}.log_entry"
    )
    if (
        log_entry["processImagePath"] != INSTALLED_EXECUTABLE
        or log_entry["subsystem"] != PRODUCT_LOG_SUBSYSTEM
        or log_entry["category"] != PRODUCT_LOG_CATEGORY
        or type(log_entry["processID"]) is not int
        or log_entry["processID"] < 1
    ):
        raise PacketEvidenceError(f"{case_id} Unified Log source identity is invalid")
    event = exact_object(
        observation["event"], PRODUCT_EVENT_FIELDS, f"{case_id}.product_event"
    )
    try:
        encoded_event = canonical_json(event).decode("utf-8")
    except (RawArtifactError, UnicodeDecodeError) as error:
        raise PacketEvidenceError(f"{case_id} product event is not canonical JSON") from error
    if log_entry["eventMessage"] != PRODUCT_OBSERVATION_PREFIX + encoded_event:
        raise PacketEvidenceError(
            f"{case_id} product event differs from the exact Unified Log message"
        )
    if (
        type(event["schema_version"]) is not int
        or event["schema_version"] != 1
        or event["document"] != PRODUCT_OBSERVATION_DOCUMENT
        or event["component"] != "host"
        or event["event"] != "engine_snapshot"
        or type(event["sequence"]) is not int
        or event["sequence"] < 1
        or type(event["recorded_unix_ms"]) is not int
        or event["recorded_unix_ms"] < 1
    ):
        raise PacketEvidenceError(f"{case_id} product event identity/sequence is invalid")
    process = exact_object(
        event["process"], PRODUCT_PROCESS_FIELDS, f"{case_id}.product_event.process"
    )
    if (
        process["pid"] != log_entry["processID"]
        or type(process["start_unix_ms"]) is not int
        or not 1 <= process["start_unix_ms"] <= event["recorded_unix_ms"]
    ):
        raise PacketEvidenceError(f"{case_id} product process identity is invalid")
    recorded_at = Fraction(event["recorded_unix_ms"], 1000)
    if abs(_log_timestamp_fraction(log_entry["timestamp"]) - recorded_at) > 1:
        raise PacketEvidenceError(f"{case_id} product event/log timestamps disagree")
    candidate = exact_object(
        event["candidate"], PRODUCT_CANDIDATE_FIELDS, f"{case_id}.product_event.candidate"
    )
    if candidate != {
        "version": candidate_identity["version"],
        "build_number": candidate_identity["build_number"],
    }:
        raise PacketEvidenceError(f"{case_id} product event binds a different candidate")
    payload = exact_object(
        event["payload"], PRODUCT_PAYLOAD_FIELDS, f"{case_id}.product_event.payload"
    )
    state = exact_object(
        payload["state"], PRODUCT_STATE_FIELDS, f"{case_id}.product_event.state"
    )
    generation = state["generation"]
    if type(generation) is not int or generation < 0:
        raise PacketEvidenceError(f"{case_id} product generation is invalid")
    expected_mode = "tunnel" if restored else spec.expected_mode
    expected_phase = "tunnel_active" if restored else spec.expected_phase
    expected_ipv6_enabled = True if restored else spec.expected_ipv6_enabled
    if (
        state["desired_mode"] != expected_mode
        or state["phase"] != expected_phase
        or state["ipv6_enabled"] is not expected_ipv6_enabled
    ):
        raise PacketEvidenceError(f"{case_id} product state differs from its exact case")
    if expected_mode == "off":
        if (
            state["config_digest"] is not None
            or state["owner"] is not None
            or state["ready"] is not False
        ):
            raise PacketEvidenceError(f"{case_id} product state is not exact Off")
    elif (
        generation < 1
        or _sha256(state["config_digest"], f"{case_id}.state.config_digest")
        != state["config_digest"]
        or state["owner"] != PACKET_OWNER
        or state["ready"] is not True
    ):
        raise PacketEvidenceError(f"{case_id} product tunnel owner is not ready and exact")
    identity = exact_object(
        observation["signing_identity"],
        SIGNING_IDENTITY_FIELDS,
        f"{case_id}.signing_identity",
    )
    if (
        identity["executable"] != INSTALLED_EXECUTABLE
        or identity["team_id"] != HOST_TEAM_ID
        or identity["signing_identifier"] != HOST_SIGNING_IDENTIFIER
        or not isinstance(identity["cdhash"], str)
        or re.fullmatch(r"[0-9a-f]{40}", identity["cdhash"]) is None
    ):
        raise PacketEvidenceError(f"{case_id} installed Host signing identity is invalid")
    query = _command(
        observation["query_command"],
        label=f"{case_id}.product_query",
        expected_role="product-observation-log",
    )
    _require_product_query(
        query,
        label=f"{case_id}.product_query",
        log_entry=log_entry,
        event=event,
    )
    codesign = _command(
        observation["codesign_command"],
        label=f"{case_id}.codesign_query",
        expected_role="product-observation-codesign",
    )
    _require_codesign(
        codesign, label=f"{case_id}.codesign_query", identity=identity
    )
    if recorded_at > query["completed_at"]:
        raise PacketEvidenceError(f"{case_id} product observation postdates its query")
    if query["completed_at"] > codesign["started_at"]:
        raise PacketEvidenceError(
            f"{case_id} installed Host identity predates its product query"
        )
    return {
        "recorded_at": recorded_at,
        "observed_at": max(query["completed_at"], codesign["completed_at"]),
        "sequence": event["sequence"],
        "process": (process["pid"], process["start_unix_ms"]),
        "state": state,
    }




def _network_interface(value: Any, label: str) -> dict[str, Any]:
    interface = exact_object(value, INTERFACE_FIELDS, label)
    if (
        not isinstance(interface["name"], str)
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,31}", interface["name"])
        is None
        or type(interface["index"]) is not int
        or not 1 <= interface["index"] <= 2**31 - 1
        or type(interface["link_type"]) is not int
        or interface["link_type"] not in ALLOWED_LINK_TYPES
        or not isinstance(interface["flags"], list)
        or not interface["flags"]
        or len(set(interface["flags"])) != len(interface["flags"])
        or any(
            not isinstance(flag, str)
            or re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", flag) is None
            for flag in interface["flags"]
        )
        or not {"UP", "RUNNING"} <= set(interface["flags"])
    ):
        raise PacketEvidenceError(f"{label} is invalid")
    return interface


def _capture_device(value: Any, *, label: str) -> dict[str, Any]:
    device = exact_object(value, CAPTURE_DEVICE_FIELDS, label)
    if (
        not isinstance(device["name"], str)
        or not device["name"]
        or not isinstance(device["scope"], str)
        or not device["scope"]
        or type(device["link_type"]) is not int
    ):
        raise PacketEvidenceError(f"{label} has non-exact field types")
    return device


def _require_interface_output(
    command: dict[str, Any],
    interface: dict[str, Any],
    *,
    case_id: str,
    label: str,
    remote: bool,
) -> None:
    first = command["stdout"].splitlines()[0] if command["stdout"] else ""
    name = interface["name"]
    if remote:
        match = re.fullmatch(
            rf"{re.escape(name)}: flags=[0-9a-fA-F]+<([^>]+)>\s+"
            r"mtu [0-9]+(?:\s+.*)?",
            first,
        )
        index_match = re.search(r"(?:^|\s)index ([0-9]+)(?:\s|$)", first)
        observed_index = int(index_match.group(1)) if index_match else None
    else:
        match = re.fullmatch(
            rf"{re.escape(name)}: flags=[0-9a-fA-F]+<([^>]+)> "
            r"mtu [0-9]+ index ([0-9]+)(?: .*)?",
            first,
        )
        observed_index = int(match.group(2)) if match else None
    if (
        match is None
        or match.group(1).split(",") != interface["flags"]
        or observed_index is None
        or observed_index != interface["index"]
    ):
        raise PacketEvidenceError(f"{case_id} {label} output differs")


def _ios_command_receipt(
    value: Any, *, label: str, expected_role: str | None = None
) -> dict[str, Any]:
    receipt = exact_object(
        value,
        {
            "role",
            "argv_sha256",
            "started_at",
            "completed_at",
            "duration_ms",
            "exit_code",
            "stdout_size",
            "stdout_sha256",
            "stderr_size",
            "stderr_sha256",
        },
        label,
    )
    started = timestamp_fraction(receipt["started_at"])
    completed = timestamp_fraction(receipt["completed_at"])
    if (
        not isinstance(receipt["role"], str)
        or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", receipt["role"]) is None
        or expected_role is not None
        and receipt["role"] != expected_role
        or _sha256(receipt["argv_sha256"], f"{label}.argv_sha256")
        != receipt["argv_sha256"]
        or type(receipt["duration_ms"]) is not int
        or receipt["duration_ms"] < 0
        or type(receipt["exit_code"]) is not int
        or receipt["exit_code"] != 0
        or any(
            type(receipt[field]) is not int or receipt[field] < 0
            for field in ("stdout_size", "stderr_size")
        )
        or any(
            _sha256(receipt[field], f"{label}.{field}") != receipt[field]
            for field in ("stdout_sha256", "stderr_sha256")
        )
        or started > completed
    ):
        raise PacketEvidenceError(f"{label} command receipt differs")
    return receipt


def _ios_copy_receipt(
    value: Any, *, label: str, expected_role: str
) -> dict[str, Any]:
    receipt = exact_object(
        value,
        {"command", "envelope_sha256", "receipt_sha256", "receipt_size"},
        label,
    )
    _ios_command_receipt(
        receipt["command"], label=f"{label}.command", expected_role=expected_role
    )
    if (
        _sha256(receipt["envelope_sha256"], f"{label}.envelope_sha256")
        != receipt["envelope_sha256"]
        or _sha256(receipt["receipt_sha256"], f"{label}.receipt_sha256")
        != receipt["receipt_sha256"]
        or type(receipt["receipt_size"]) is not int
        or not 1 <= receipt["receipt_size"] <= 64 * 1024
    ):
        raise PacketEvidenceError(f"{label} copied receipt differs")
    return receipt


def _validate_lan_peer_provenance(
    value: Any, *, case_id: str
) -> dict[str, Any]:
    access = exact_object(
        value, LAN_PEER_REMOTE_ACCESS_FIELDS, f"{case_id}.remote_access"
    )
    network = exact_object(
        access["network"], LAN_PEER_NETWORK_FIELDS, f"{case_id}.remote_access.network"
    )
    peer_ipv4 = _private_lan_endpoint(network["ipv4"])
    admission = exact_object(
        access["admission"],
        {
            "schema_version",
            "document",
            "evidence_role",
            "claim_eligible",
            "source_identity_sha256",
            "source_identity_file_sha256",
            "device",
            "artifact",
            "preflight",
            "installation",
            "primer",
            "session",
            "process",
            "network",
            "listener",
            "admitted_at",
        },
        f"{case_id}.remote_access.admission",
    )
    before = exact_object(
        access["before_capture"],
        {
            "schema_version",
            "document",
            "claim_eligible",
            "session_id",
            "process_id",
            "peer_ipv4",
            "listener_port",
            "process_inventory",
            "process_inventory_sha256",
            "ready_copy",
            "observed_at",
        },
        f"{case_id}.remote_access.before_capture",
    )
    after = exact_object(
        access["after_capture"],
        {
            "schema_version",
            "document",
            "claim_eligible",
            "session_id",
            "process_id",
            "peer_ipv4",
            "listener_port",
            "result_copy",
            "result_sha256",
            "result_status",
            "sender_server_bindings",
            "process_inventory",
            "process_inventory_sha256",
            "ready_copy",
            "observed_at",
        },
        f"{case_id}.remote_access.after_capture",
    )
    cleanup = exact_object(
        access["cleanup"],
        {
            "schema_version",
            "document",
            "claim_eligible",
            "outcome",
            "capture_state",
            "session_id",
            "process_id",
            "termination",
            "uninstall",
        },
        f"{case_id}.remote_access.cleanup",
    )
    session_id = _sha256(before["session_id"], f"{case_id}.lan.session_id")
    process_id = before["process_id"]
    if (
        access["schema_version"] != 1
        or access["document"] != "cfm-ios-packet-lan-peer-provenance-v1"
        or access["evidence_role"] != "server_observation_only"
        or access["claim_eligible"] is not False
        or access["source_identity_sha256"] != LAN_ENDPOINT_IDENTITY_SHA256
        or access["source_identity_file_sha256"]
        != LAN_ENDPOINT_IDENTITY_FILE_SHA256
        or access["runtime_endpoint_source"]
        != "cfm-ios-packet-lan-peer-ready-v1"
        or network
        != {
            "interface_name": "en0",
            "ipv4": peer_ipv4,
            "listener_port": PACKET_TRANSPORT_PORT,
            "transport": "tcp4",
        }
        or type(process_id) is not int
        or not 1 <= process_id < 2**31
    ):
        raise PacketEvidenceError(f"{case_id} iPhone LAN peer identity differs")

    device = exact_object(
        admission["device"],
        {
            "core_device_identifier_sha256",
            "provisioning_udid_sha256",
            "product_type",
            "os_version",
            "os_build",
            "inventory_connection_state",
            "inventory_preparedness_state",
            "device_list_receipt_sha256",
            "device_list_command",
            "device_details_receipt_sha256",
            "device_details_command",
            "lock_receipt_sha256",
            "lock_command",
        },
        f"{case_id}.lan.admission.device",
    )
    inventory_state_is_valid = (
        device["inventory_connection_state"] == "connected"
        and device["inventory_preparedness_state"] == 7
    ) or (
        device["inventory_connection_state"] == "disconnected"
        and device["inventory_preparedness_state"] is None
    )
    if not inventory_state_is_valid:
        raise PacketEvidenceError(
            f"{case_id} iPhone LAN peer inventory bootstrap state differs"
        )
    artifact = exact_object(
        admission["artifact"],
        {
            "app_tree_sha256",
            "executable_sha256",
            "source_tree_sha256",
            "profile_sha256",
            "entitlements_sha256",
            "signing_certificate_sha256",
            "validation",
        },
        f"{case_id}.lan.admission.artifact",
    )
    preflight = exact_object(
        admission["preflight"],
        {
            "app_inventory_sha256",
            "process_inventory_sha256",
            "app_inventory_command",
            "process_inventory_command",
            "app_absent",
            "process_absent",
        },
        f"{case_id}.lan.admission.preflight",
    )
    installation = exact_object(
        admission["installation"],
        {
            "install_intent_sha256",
            "install_receipt_sha256",
            "post_install_app_inventory_sha256",
            "install_command",
            "post_install_app_inventory_command",
        },
        f"{case_id}.lan.admission.installation",
    )
    primer = exact_object(
        admission["primer"],
        {
            "pre_launch_lock_receipt_sha256",
            "pre_launch_lock_command",
            "launch_receipt_sha256",
            "launch_command",
            "process_inventory_sha256",
            "process_inventory_command",
            "receipt_copy",
            "cleanup",
        },
        f"{case_id}.lan.admission.primer",
    )
    admitted_session = exact_object(
        admission["session"],
        {"session_id", "session_sha256", "copy_receipt_sha256", "copy_command"},
        f"{case_id}.lan.admission.session",
    )
    admitted_process = exact_object(
        admission["process"],
        {
            "pre_launch_lock_receipt_sha256",
            "pre_launch_lock_command",
            "process_id",
            "launch_receipt_sha256",
            "launch_command",
            "process_inventory_sha256",
            "process_inventory_command",
            "ready_copy",
        },
        f"{case_id}.lan.admission.process",
    )
    validation = exact_object(
        artifact["validation"],
        {
            "profile_decode",
            "keychain_certificate",
            "signature_verify",
            "signature_details",
            "signature_entitlements",
            "architectures",
            "build_version",
            "cdhash",
            "profile_uuid",
        },
        f"{case_id}.lan.admission.artifact.validation",
    )
    for field, role in {
        "profile_decode": "ios-peer-profile-decode",
        "keychain_certificate": "ios-peer-keychain-certificate",
        "signature_verify": "ios-peer-codesign-verify",
        "signature_details": "ios-peer-codesign-details",
        "signature_entitlements": "ios-peer-codesign-entitlements",
        "architectures": "ios-peer-executable-architectures",
        "build_version": "ios-peer-executable-build-version",
    }.items():
        _ios_command_receipt(
            validation[field],
            label=f"{case_id}.lan.artifact.validation.{field}",
            expected_role=role,
        )
    if (
        admission["schema_version"] != 1
        or admission["document"] != "cfm-ios-packet-lan-peer-admission-v1"
        or admission["evidence_role"] != "server_observation_only"
        or admission["claim_eligible"] is not False
        or admission["source_identity_sha256"] != LAN_ENDPOINT_IDENTITY_SHA256
        or admission["source_identity_file_sha256"]
        != LAN_ENDPOINT_IDENTITY_FILE_SHA256
        or device["core_device_identifier_sha256"] != IOS_LAN_CORE_DEVICE_SHA256
        or device["provisioning_udid_sha256"]
        != IOS_LAN_PROVISIONING_UDID_SHA256
        or device["product_type"] != "iPhone17,1"
        or device["os_version"] != "26.5"
        or device["os_build"] != "23F77"
        or artifact["app_tree_sha256"] != IOS_LAN_APP_TREE_SHA256
        or artifact["executable_sha256"] != IOS_LAN_EXECUTABLE_SHA256
        or artifact["source_tree_sha256"] != IOS_LAN_SOURCE_TREE_SHA256
        or artifact["profile_sha256"] != IOS_LAN_PROFILE_SHA256
        or artifact["entitlements_sha256"] != IOS_LAN_ENTITLEMENTS_SHA256
        or artifact["signing_certificate_sha256"]
        != IOS_LAN_SIGNING_CERTIFICATE_SHA256
        or validation["profile_uuid"] != IOS_LAN_PROFILE_UUID
        or not isinstance(validation["cdhash"], str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", validation["cdhash"])
        is None
        or preflight["app_absent"] is not True
        or preflight["process_absent"] is not True
        or admitted_session["session_id"] != session_id
        or admitted_process["process_id"] != process_id
        or admission["network"] != {"interface_name": "en0", "ipv4": peer_ipv4}
        or admission["listener"] != {"port": PACKET_TRANSPORT_PORT, "transport": "tcp4"}
    ):
        raise PacketEvidenceError(f"{case_id} iPhone admission is not source-bound")
    timestamp_fraction(admission["admitted_at"])
    for value, label, role in (
        (device["device_list_command"], "device_list", "ios-peer-device-list"),
        (device["device_details_command"], "device_details", "ios-peer-device-details"),
        (device["lock_command"], "lock", "ios-peer-lock-state"),
        (preflight["app_inventory_command"], "preflight_apps", "ios-peer-app-inventory"),
        (
            preflight["process_inventory_command"],
            "preflight_processes",
            "ios-peer-process-inventory",
        ),
        (installation["install_command"], "install", "ios-peer-install"),
        (
            installation["post_install_app_inventory_command"],
            "post_install_apps",
            "ios-peer-app-inventory",
        ),
        (
            primer["pre_launch_lock_command"],
            "primer_pre_launch_lock",
            "ios-peer-lock-state",
        ),
        (primer["launch_command"], "primer_launch", "ios-peer-primer-launch"),
        (
            primer["process_inventory_command"],
            "primer_processes",
            "ios-peer-process-inventory",
        ),
        (admitted_session["copy_command"], "session_copy", "ios-peer-packet-lan-session-copy"),
        (
            admitted_process["pre_launch_lock_command"],
            "packet_pre_launch_lock",
            "ios-peer-lock-state",
        ),
        (admitted_process["launch_command"], "packet_launch", "ios-peer-packet-lan-launch"),
        (
            admitted_process["process_inventory_command"],
            "packet_processes",
            "ios-peer-process-inventory",
        ),
    ):
        _ios_command_receipt(
            value, label=f"{case_id}.lan.admission.{label}", expected_role=role
        )
    _ios_copy_receipt(
        primer["receipt_copy"],
        label=f"{case_id}.lan.admission.primer.receipt_copy",
        expected_role="ios-peer-primer-result-copy",
    )
    primer_cleanup = exact_object(
        primer["cleanup"],
        {
            "process_inventory",
            "process_inventory_sha256",
            "primer_copy",
            "terminate_command",
            "terminate_receipt_sha256",
            "process_id",
            "post_terminate_process_inventory",
            "post_terminate_process_inventory_sha256",
        },
        f"{case_id}.lan.admission.primer.cleanup",
    )
    _ios_command_receipt(
        primer_cleanup["process_inventory"],
        label=f"{case_id}.lan.primer.cleanup.process_inventory",
        expected_role="ios-peer-process-inventory",
    )
    _ios_copy_receipt(
        primer_cleanup["primer_copy"],
        label=f"{case_id}.lan.primer.cleanup.primer_copy",
        expected_role="ios-peer-primer-result-copy",
    )
    _ios_command_receipt(
        primer_cleanup["terminate_command"],
        label=f"{case_id}.lan.primer.cleanup.terminate",
        expected_role="ios-peer-primer-terminate",
    )
    _ios_command_receipt(
        primer_cleanup["post_terminate_process_inventory"],
        label=f"{case_id}.lan.primer.cleanup.post_inventory",
        expected_role="ios-peer-process-inventory",
    )
    if (
        type(primer_cleanup["process_id"]) is not int
        or not 1 <= primer_cleanup["process_id"] < 2**31
    ):
        raise PacketEvidenceError(f"{case_id} primer cleanup PID differs")
    for value, label in (
        (primer_cleanup["process_inventory_sha256"], "primer cleanup inventory"),
        (primer_cleanup["terminate_receipt_sha256"], "primer terminate receipt"),
        (
            primer_cleanup["post_terminate_process_inventory_sha256"],
            "primer post-terminate inventory",
        ),
    ):
        _sha256(value, f"{case_id}.lan.{label}")
    _ios_copy_receipt(
        admitted_process["ready_copy"],
        label=f"{case_id}.lan.admission.process.ready_copy",
        expected_role="ios-peer-packet-lan-ready-copy",
    )
    for value, label in (
        (device["device_list_receipt_sha256"], "device list receipt"),
        (device["device_details_receipt_sha256"], "device details receipt"),
        (device["lock_receipt_sha256"], "lock receipt"),
        (preflight["app_inventory_sha256"], "preflight app inventory"),
        (preflight["process_inventory_sha256"], "preflight process inventory"),
        (installation["install_intent_sha256"], "install intent"),
        (installation["install_receipt_sha256"], "install receipt"),
        (
            installation["post_install_app_inventory_sha256"],
            "post-install app inventory",
        ),
        (primer["pre_launch_lock_receipt_sha256"], "primer pre-launch lock"),
        (primer["launch_receipt_sha256"], "primer launch receipt"),
        (primer["process_inventory_sha256"], "primer process inventory"),
        (admitted_session["session_sha256"], "session receipt"),
        (admitted_session["copy_receipt_sha256"], "session copy receipt"),
        (
            admitted_process["pre_launch_lock_receipt_sha256"],
            "packet pre-launch lock",
        ),
        (admitted_process["launch_receipt_sha256"], "packet launch receipt"),
        (admitted_process["process_inventory_sha256"], "packet process inventory"),
    ):
        _sha256(value, f"{case_id}.lan.{label}")

    before_inventory = _ios_command_receipt(
        before["process_inventory"],
        label=f"{case_id}.lan.before.process_inventory",
        expected_role="ios-peer-process-inventory",
    )
    del before_inventory
    _ios_copy_receipt(
        before["ready_copy"],
        label=f"{case_id}.lan.before.ready_copy",
        expected_role="ios-peer-packet-lan-ready-copy",
    )
    after_inventory = _ios_command_receipt(
        after["process_inventory"],
        label=f"{case_id}.lan.after.process_inventory",
        expected_role="ios-peer-process-inventory",
    )
    del after_inventory
    _ios_copy_receipt(
        after["result_copy"],
        label=f"{case_id}.lan.after.result_copy",
        expected_role="ios-peer-packet-lan-result-copy",
    )
    _ios_copy_receipt(
        after["ready_copy"],
        label=f"{case_id}.lan.after.ready_copy",
        expected_role="ios-peer-packet-lan-ready-copy",
    )
    if (
        before["schema_version"] != 1
        or before["document"] != "cfm-ios-packet-lan-peer-before-capture-v1"
        or before["claim_eligible"] is not False
        or after["schema_version"] != 1
        or after["document"] != "cfm-ios-packet-lan-peer-after-capture-v1"
        or after["claim_eligible"] is not False
        or after["result_status"] != "closed"
        or any(
            value != expected
            for value, expected in (
                (before["session_id"], session_id),
                (after["session_id"], session_id),
                (before["process_id"], process_id),
                (after["process_id"], process_id),
                (before["peer_ipv4"], peer_ipv4),
                (after["peer_ipv4"], peer_ipv4),
                (before["listener_port"], PACKET_TRANSPORT_PORT),
                (after["listener_port"], PACKET_TRANSPORT_PORT),
            )
        )
    ):
        raise PacketEvidenceError(f"{case_id} iPhone capture binding differs")
    for value, label in (
        (before["process_inventory_sha256"], "before process inventory"),
        (after["process_inventory_sha256"], "after process inventory"),
        (after["result_sha256"], "result receipt"),
    ):
        _sha256(value, f"{case_id}.lan.{label}")
    timestamp_fraction(before["observed_at"])
    timestamp_fraction(after["observed_at"])

    bindings = after["sender_server_bindings"]
    if not isinstance(bindings, list) or len(bindings) != len(PACKET_STAGES):
        raise PacketEvidenceError(f"{case_id} iPhone sender/server bindings differ")
    normalized_bindings: list[dict[str, Any]] = []
    local_addresses: set[str] = set()
    local_ports: set[int] = set()
    for index, stage in enumerate(PACKET_STAGES):
        binding = exact_object(
            bindings[index],
            {
                "stage",
                "token_sha256",
                "local_address",
                "local_port",
                "remote_address",
                "remote_port",
                "bytes_received",
                "eof_observed",
            },
            f"{case_id}.lan.binding.{stage}",
        )
        local_address = _private_lan_endpoint(binding["local_address"])
        if (
            binding["stage"] != stage
            or _sha256(binding["token_sha256"], f"{case_id}.lan.{stage}.token")
            != binding["token_sha256"]
            or type(binding["local_port"]) is not int
            or not 49_152 <= binding["local_port"] <= 65_535
            or binding["remote_address"] != peer_ipv4
            or binding["remote_port"] != PACKET_TRANSPORT_PORT
            or binding["bytes_received"] != 20
            or binding["eof_observed"] is not True
        ):
            raise PacketEvidenceError(f"{case_id} iPhone {stage} binding differs")
        local_addresses.add(local_address)
        local_ports.add(binding["local_port"])
        normalized_bindings.append(binding)
    if len(local_addresses) != 1 or len(local_ports) != len(PACKET_STAGES):
        raise PacketEvidenceError(f"{case_id} iPhone client endpoint drifted")

    termination = exact_object(
        cleanup["termination"],
        {
            "process_inventory",
            "process_inventory_sha256",
            "ready_copy",
            "terminate_command",
            "terminate_receipt_sha256",
            "process_id",
            "post_terminate_process_inventory",
            "post_terminate_process_inventory_sha256",
        },
        f"{case_id}.lan.cleanup.termination",
    )
    uninstall = exact_object(
        cleanup["uninstall"],
        {
            "uninstall_command",
            "uninstall_receipt_sha256",
            "final_app_inventory",
            "final_app_inventory_sha256",
            "final_process_inventory",
            "final_process_inventory_sha256",
            "app_absent",
            "process_absent",
        },
        f"{case_id}.lan.cleanup.uninstall",
    )
    for value, label, role in (
        (
            termination["process_inventory"],
            "cleanup_process_inventory",
            "ios-peer-process-inventory",
        ),
        (termination["terminate_command"], "terminate", "ios-peer-terminate"),
        (
            termination["post_terminate_process_inventory"],
            "post_terminate_process_inventory",
            "ios-peer-process-inventory",
        ),
        (uninstall["uninstall_command"], "uninstall", "ios-peer-uninstall"),
        (
            uninstall["final_app_inventory"],
            "final_app_inventory",
            "ios-peer-app-inventory",
        ),
        (
            uninstall["final_process_inventory"],
            "final_process_inventory",
            "ios-peer-process-inventory",
        ),
    ):
        _ios_command_receipt(
            value, label=f"{case_id}.lan.cleanup.{label}", expected_role=role
        )
    _ios_copy_receipt(
        termination["ready_copy"],
        label=f"{case_id}.lan.cleanup.ready_copy",
        expected_role="ios-peer-packet-lan-ready-copy",
    )
    for value, label in (
        (termination["process_inventory_sha256"], "cleanup process inventory"),
        (termination["terminate_receipt_sha256"], "terminate receipt"),
        (
            termination["post_terminate_process_inventory_sha256"],
            "post-terminate process inventory",
        ),
        (uninstall["uninstall_receipt_sha256"], "uninstall receipt"),
        (uninstall["final_app_inventory_sha256"], "final app inventory"),
        (uninstall["final_process_inventory_sha256"], "final process inventory"),
    ):
        _sha256(value, f"{case_id}.lan.cleanup.{label}")
    if (
        cleanup["schema_version"] != 1
        or cleanup["document"] != "cfm-ios-packet-lan-peer-cleanup-v1"
        or cleanup["claim_eligible"] is not False
        or cleanup["outcome"] != "capture-complete"
        or cleanup["capture_state"] != "capture-validated"
        or cleanup["session_id"] != session_id
        or cleanup["process_id"] != process_id
        or termination["process_id"] != process_id
        or uninstall["app_absent"] is not True
        or uninstall["process_absent"] is not True
    ):
        raise PacketEvidenceError(f"{case_id} iPhone cleanup is incomplete")
    return {
        "peer_ipv4": peer_ipv4,
        "session_id": session_id,
        "process_id": process_id,
        "sender_server_bindings": normalized_bindings,
    }


def _capture_provenance_v4(
    value: Any,
    *,
    case_id: str,
    spec: CaseSpec,
    state_observation_sha256: str,
    capture_artifact_sha256: str,
    capture_artifact_size: int,
) -> dict[str, Any]:
    provenance = exact_object(value, PROVENANCE_FIELDS, f"{case_id}.capture_provenance")
    if (
        type(provenance["schema_version"]) is not int
        or provenance["schema_version"] != 4
        or provenance["document"] != PACKET_PROVENANCE_DOCUMENT
        or provenance["case_id"] != case_id
        or provenance["state_observation_sha256"] != state_observation_sha256
        or provenance["capture_artifact_sha256"] != capture_artifact_sha256
    ):
        raise PacketEvidenceError(f"{case_id} capture provenance identity differs")
    endpoint_identity = _sha256(
        provenance["endpoint_identity_sha256"],
        f"{case_id}.endpoint_identity_sha256",
    )
    expected_identity = (
        DNS_REMOTE_CAPTURE_POLICIES[spec.resolver_role]["identity_sha256"]
        if spec.protocol == "dns"
        else LAN_ENDPOINT_IDENTITY_SHA256
        if case_id == "lan-bypass"
        else TRANSPORT_ENDPOINT_IDENTITY_SHA256
    )
    if endpoint_identity != expected_identity:
        raise PacketEvidenceError(f"{case_id} endpoint identity differs")
    host = exact_object(
        provenance["host_transaction"],
        HOST_TRANSACTION_FIELDS,
        f"{case_id}.host_transaction",
    )
    snapshots = {
        name: _host_snapshot(
            host[name], label=f"{case_id}.host_transaction.{name}"
        )
        for name in ("baseline", "test", "restore")
    }
    sequences = [
        host["baseline_observation_sequence"],
        host["test_observation_sequence"],
        host["restore_observation_sequence"],
    ]
    if (
        not isinstance(host["session_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", host["session_id"]) is None
        or any(type(sequence) is not int or sequence < 1 for sequence in sequences)
        or not sequences[0] < sequences[1] < sequences[2]
        or type(host["candidate_observation_sequence"]) is not int
        or host["candidate_observation_sequence"] != sequences[1]
        or snapshots["baseline"]["phase"] != "tunnel_active"
        or snapshots["baseline"]["ipv6_enabled"] is not True
        or not snapshots["baseline"]["generation"]
        < snapshots["test"]["generation"]
        < snapshots["restore"]["generation"]
        or {
            key: value
            for key, value in snapshots["baseline"].items()
            if key != "generation"
        }
        != {
            key: value
            for key, value in snapshots["restore"].items()
            if key != "generation"
        }
    ):
        raise PacketEvidenceError(f"{case_id} Host transaction is not exact/causal")
    if (
        provenance["capture_point"] != spec.vantage
        or provenance["resolver_role"] != spec.resolver_role
    ):
        raise PacketEvidenceError(f"{case_id} capture point/resolver role differs")
    device = _capture_device(
        provenance["capture_device"], label=f"{case_id}.capture_device"
    )
    filter_argv = provenance["capture_filter_argv"]
    if (
        not isinstance(filter_argv, list)
        or not 1 <= len(filter_argv) <= 32
        or any(
            not isinstance(argument, str)
            or not argument
            or "\x00" in argument
            or len(argument.encode("utf-8")) > 4096
            for argument in filter_argv
        )
    ):
        raise PacketEvidenceError(f"{case_id} capture filter is not bounded")
    filter_sha256 = hashlib.sha256(canonical_json(filter_argv)).hexdigest()
    if provenance["capture_filter_sha256"] != filter_sha256:
        raise PacketEvidenceError(f"{case_id} capture filter digest differs")
    quic_version = provenance["quic_version"]
    if spec.protocol == "quic":
        if type(quic_version) is not int or quic_version not in SUPPORTED_QUIC_VERSIONS:
            raise PacketEvidenceError(f"{case_id} QUIC version is invalid")
    elif quic_version is not None:
        raise PacketEvidenceError(f"{case_id} non-QUIC capture declares QUIC")
    remote_fields = (
        "remote_key_generation_command",
        "remote_public_key_command",
        "remote_key_import_command",
        "remote_interface",
        "remote_interface_command",
        "remote_access",
        "capture_offload_context",
    )
    lan_peer: dict[str, Any] | None = None
    if spec.protocol == "dns":
        policy = DNS_REMOTE_CAPTURE_POLICIES[spec.resolver_role]
        if device != {
            "name": policy["interface"],
            "link_type": DLT_EN10MB,
            "scope": "exact-remote-interface",
        }:
            raise PacketEvidenceError(f"{case_id} remote capture device differs")
        access = exact_object(
            provenance["remote_access"], REMOTE_ACCESS_FIELDS, f"{case_id}.remote_access"
        )
        fixed_access = {
            "project": policy["project"],
            "zone": policy["zone"],
            "instance_name": policy["instance_name"],
            "instance_id": policy["instance_id"],
            "internal_ip_address": policy["internal_ip"],
            "host_alias": f"compute.{policy['instance_id']}",
            "host_key_bytes_sha256": policy["host_key_bytes_sha256"],
            "service_account": REMOTE_CAPTURE_SERVICE_ACCOUNT,
            "service_account_unique_id": REMOTE_CAPTURE_OS_LOGIN_PROFILE_ID,
            "posix_username": REMOTE_CAPTURE_POSIX_USERNAME,
            "os_login_profile_id": REMOTE_CAPTURE_OS_LOGIN_PROFILE_ID,
            "sudoers_policy_sha256": REMOTE_CAPTURE_SUDOERS_POLICY_SHA256,
            "tcpdump_binary_sha256": REMOTE_TCPDUMP_BINARY_SHA256,
        }
        if any(access[field] != expected for field, expected in fixed_access.items()):
            raise PacketEvidenceError(f"{case_id} remote capture identity differs")
        key_path = access["ssh_key_file_path"]
        known_hosts = access["known_hosts_snapshot_path"]
        private_size = access["private_key_size"]
        if (
            not isinstance(key_path, str)
            or not Path(key_path).is_absolute()
            or not key_path.endswith("/packet-capture-rsa3072")
            or not isinstance(known_hosts, str)
            or not Path(known_hosts).is_absolute()
            or not known_hosts.endswith("/scripts/physical_capture/packet_known_hosts")
            or access["gcloud_path"] != "/opt/homebrew/bin/gcloud"
            or type(private_size) is not int
            or not 1 <= private_size <= 16 * 1024
            or access["known_hosts_snapshot_sha256"]
            != REMOTE_CAPTURE_KNOWN_HOSTS_SHA256
            or access["ssh_key_file_path_sha256"]
            != hashlib.sha256(key_path.encode()).hexdigest()
        ):
            raise PacketEvidenceError(f"{case_id} remote key/tool path is invalid")
        keygen = _command(
            provenance["remote_key_generation_command"],
            label=f"{case_id}.remote_key_generation_command",
            expected_role="packet-remote-key-generate",
            binary_stdout=(
                private_size,
                _sha256(access["private_key_sha256"], "private key digest"),
            ),
        )
        public = _command(
            provenance["remote_public_key_command"],
            label=f"{case_id}.remote_public_key_command",
            expected_role="packet-remote-public-key",
        )
        key_import = _command(
            provenance["remote_key_import_command"],
            label=f"{case_id}.remote_key_import_command",
            expected_role="packet-remote-key-import",
        )
        public_digest = _sha256(access["public_key_sha256"], "public key digest")
        if (
            keygen["argv"]
            != (
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:3072",
            )
            or re.fullmatch(r"[.+*\n]*", keygen["stderr"] or "") is None
            or public["argv"] != ("/usr/bin/ssh-keygen", "-y", "-f", key_path)
            or public["stderr"]
            or re.fullmatch(r"ssh-rsa [A-Za-z0-9+/]+={0,2}\n", public["stdout"] or "")
            is None
            or hashlib.sha256(public["stdout"].encode("ascii")).hexdigest()
            != public_digest
        ):
            raise PacketEvidenceError(f"{case_id} ephemeral SSH key receipt differs")
        expected_import = (
            access["gcloud_path"], "--verbosity=error", "--quiet", "compute",
            "os-login", "ssh-keys", "add", "--project", policy["project"],
            f"--impersonate-service-account={REMOTE_CAPTURE_SERVICE_ACCOUNT}",
            f"--key-file={key_path}.pub", "--ttl=2m", "--format=value(loginProfile.name)",
        )
        if (
            key_import["argv"] != expected_import
            or key_import["stdout"] != f"{REMOTE_CAPTURE_OS_LOGIN_PROFILE_ID}\n"
            or key_import["stderr"]
        ):
            raise PacketEvidenceError(f"{case_id} OS Login key import differs")
        remote_interface = _network_interface(
            provenance["remote_interface"], f"{case_id}.remote_interface"
        )
        interface_command = _command(
            provenance["remote_interface_command"],
            label=f"{case_id}.remote_interface_command",
            expected_role="packet-interface-observation",
        )
        capture_command = _command(
            provenance["capture_command"],
            label=f"{case_id}.capture_command",
            expected_role="packet-remote-capture",
            binary_stdout=(capture_artifact_size, capture_artifact_sha256),
        )
        if (
            remote_interface["name"] != policy["interface"]
            or remote_interface["link_type"] != DLT_EN10MB
            or interface_command["stderr"]
            or provenance["capture_offload_context"]
            != REMOTE_CAPTURE_OFFLOAD_CONTEXT
        ):
            raise PacketEvidenceError(f"{case_id} remote interface differs")
        _require_interface_output(
            interface_command, remote_interface,
            case_id=case_id, label="remote-interface", remote=True,
        )
        _require_remote_capture_commands(
            case_id=case_id, policy=policy, access=access,
            key_path=key_path, known_hosts=known_hosts,
            interface_command=interface_command, capture_command=capture_command,
        )
        if not (
            keygen["completed_at"] <= public["started_at"]
            < public["completed_at"] <= key_import["started_at"]
            < key_import["completed_at"] <= interface_command["started_at"]
            < interface_command["completed_at"] <= capture_command["started_at"]
        ):
            raise PacketEvidenceError(f"{case_id} remote setup timeline is not causal")
    else:
        if case_id == "lan-bypass":
            if device != {
                "name": "pktap,all", "link_type": DLT_RAW,
                "scope": "all-interfaces-source-filtered-raw",
            } or any(
                provenance[field] is not None
                for field in remote_fields
                if field not in {"remote_access", "capture_offload_context"}
            ) or provenance["capture_offload_context"] != (
                "ios-coredevice-localnetwork-packet-peer-v1"
            ):
                raise PacketEvidenceError(f"{case_id} local capture policy differs")
            lan_peer = _validate_lan_peer_provenance(
                provenance["remote_access"], case_id=case_id
            )
        elif device != {
            "name": "pktap,all", "link_type": DLT_RAW,
            "scope": "all-interfaces-source-filtered-raw",
        } or any(provenance[field] is not None for field in remote_fields):
            raise PacketEvidenceError(f"{case_id} local capture policy differs")
        capture_command = _command(
            provenance["capture_command"],
            label=f"{case_id}.capture_command",
            expected_role="packet-capture",
            binary_stdout=(capture_artifact_size, capture_artifact_sha256),
        )
        count = 2 if not spec.token_observed else 3
        expected = (
            "/usr/sbin/tcpdump", "-i", "pktap,all", "-y", "RAW", "-n",
            "-U", "-s", "0", "-c", str(count), "-w", "-", *filter_argv,
        )
        diagnostics = (
            "tcpdump: listening on pktap,all, link-type RAW (Raw IP), "
            "snapshot length 262144 bytes\n"
            f"{count} packets captured\n{count} packets received by filter\n"
            "0 packets dropped by kernel\n"
        )
        if capture_command["argv"] != expected or capture_command["stderr"] != diagnostics:
            raise PacketEvidenceError(f"{case_id} local capture receipt differs")
    started_at = timestamp_fraction(provenance["started_at"])
    completed_at = timestamp_fraction(provenance["completed_at"])
    alive_at = timestamp_fraction(provenance["capture_alive_at"])
    if not (
        capture_command["started_at"] < alive_at
        <= started_at < completed_at <= capture_command["completed_at"]
    ):
        raise PacketEvidenceError(f"{case_id} capture timeline is not causal")
    return {
        "capture_device": device,
        "capture_filter_argv": filter_argv,
        "capture_filter_sha256": filter_sha256,
        "capture_command_sha256": capture_command["argv_sha256"],
        "endpoint_identity_sha256": endpoint_identity,
        "quic_version": quic_version,
        "capture_alive_at": alive_at,
        "command_completed_at": capture_command["completed_at"],
        "started_at": started_at,
        "completed_at": completed_at,
        "host_transaction": {**host, **snapshots},
        "lan_peer": lan_peer,
    }


def _require_remote_capture_commands(
    *,
    case_id: str,
    policy: dict[str, str],
    access: dict[str, Any],
    key_path: str,
    known_hosts: str,
    interface_command: dict[str, Any],
    capture_command: dict[str, Any],
) -> None:
    prefix = (
        access["gcloud_path"], "--verbosity=error", "--quiet", "compute", "ssh",
        f"{REMOTE_CAPTURE_POSIX_USERNAME}@{policy['instance_name']}", "--zone",
        policy["zone"], "--project", policy["project"], "--tunnel-through-iap",
        f"--impersonate-service-account={REMOTE_CAPTURE_SERVICE_ACCOUNT}",
        f"--ssh-key-file={key_path}", "--plain",
    )
    tail = (
        "--", "-T", "-F", "/dev/null", "-i", key_path, "-o", "CheckHostIP=no",
        "-o", "HashKnownHosts=no", "-o", f"HostKeyAlias={access['host_alias']}",
        "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o",
        f"UserKnownHostsFile={known_hosts}", "-o", "BatchMode=yes", "-o",
        "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "-o",
        "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ConnectTimeout=15",
        "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=10", "-o",
        "ServerAliveCountMax=2", "-o", "ProxyUseFdpass=no",
    )
    interface_text = f"/sbin/ifconfig -v {policy['interface']}"
    capture_text = (
        f"sudo -n /usr/bin/tcpdump -i {policy['interface']} -n -U -s 0 "
        "-c 6 -w - udp and port 53"
    )
    diagnostics = (
        f"tcpdump: listening on {policy['interface']}, link-type EN10MB "
        "(Ethernet), snapshot length 262144 bytes\n"
        "6 packets captured\n6 packets received by filter\n"
        "0 packets dropped by kernel\n"
    )
    if (
        interface_command["argv"] != (*prefix, f"--command={interface_text}", *tail)
        or capture_command["argv"] != (*prefix, f"--command={capture_text}", *tail)
        or capture_command["stderr"] != diagnostics
    ):
        raise PacketEvidenceError(f"{case_id} remote capture command differs")


def validate_packet_state_observation(
    value: Any,
    *,
    case_id: str,
    candidate: Any,
    restored: bool = False,
) -> dict[str, Any]:
    """Validate one proof-free product event before manifest publication."""

    if case_id not in REQUIRED_CASES:
        raise PacketEvidenceError("product-state observation case is not source-pinned")
    identity = exact_object(
        candidate,
        {"version", "build_number"},
        "product-state observation candidate",
    )
    return _product_state_observation(
        value,
        case_id=case_id,
        spec=REQUIRED_CASES[case_id],
        candidate_identity=identity,
        restored=restored,
    )




def _stage_endpoint_set(
    value: Any,
    *,
    case_id: str,
    stage: str,
    spec: CaseSpec,
    lan_endpoint_address: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 2:
        raise PacketEvidenceError(f"{case_id}.{stage} endpoint_set is invalid")
    parsed: dict[str, dict[str, Any]] = {}
    transport = "tcp" if spec.protocol == "tcp" else "udp"
    for index, raw in enumerate(value):
        endpoint = exact_object(
            raw, ENDPOINT_FIELDS, f"{case_id}.{stage}.endpoint_set[{index}]"
        )
        role = endpoint["role"]
        if role not in {"local", "remote"} or role in parsed:
            raise PacketEvidenceError(f"{case_id}.{stage} endpoint role differs")
        try:
            address = str(ipaddress.ip_address(endpoint["address"]))
        except (TypeError, ValueError) as error:
            raise PacketEvidenceError(
                f"{case_id}.{stage} endpoint address is invalid"
            ) from error
        expected_version = 4 if spec.family == "ipv4" else 6
        if (
            ipaddress.ip_address(address).version != expected_version
            or type(endpoint["port"]) is not int
            or not 1 <= endpoint["port"] <= 65535
            or endpoint["transport"] != transport
        ):
            raise PacketEvidenceError(f"{case_id}.{stage} endpoint tuple is invalid")
        parsed[role] = {
            "role": role,
            "address": address,
            "port": endpoint["port"],
            "transport": transport,
        }
    local, remote = parsed["local"], parsed["remote"]
    if local == remote or not 49152 <= local["port"] <= 65535:
        raise PacketEvidenceError(f"{case_id}.{stage} local endpoint is invalid")
    expected_remote = (
        DNS_REMOTE_CAPTURE_POLICIES[spec.resolver_role][spec.family]
        if spec.protocol == "dns"
        else _private_lan_endpoint(lan_endpoint_address)
        if case_id == "lan-bypass"
        else TRANSPORT_ENDPOINT_ADDRESSES[spec.family]
    )
    expected_port = 53 if spec.protocol == "dns" else PACKET_TRANSPORT_PORT
    if remote["address"] != expected_remote or remote["port"] != expected_port:
        raise PacketEvidenceError(f"{case_id}.{stage} remote endpoint differs")
    return local, remote


def _ifconfig_addresses(stdout: str, family: str) -> set[str]:
    prefix = "inet " if family == "ipv4" else "inet6 "
    addresses: set[str] = set()
    for line in stdout.splitlines()[1:]:
        stripped = line.strip()
        if not stripped.startswith(prefix):
            continue
        text = stripped[len(prefix) :].split()[0].split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(text)
        except ValueError as error:
            raise PacketEvidenceError("ifconfig address is invalid") from error
        expected_version = 4 if family == "ipv4" else 6
        if parsed.version == expected_version and not parsed.is_link_local:
            addresses.add(str(parsed))
    return addresses


def _send_attempt_v4(
    value: Any,
    *,
    case_id: str,
    spec: CaseSpec,
    tokens: tuple[str, str, str],
    provenance: dict[str, Any],
    state_observation_sha256: str,
    capture_provenance_sha256: str,
) -> dict[str, Any]:
    attempt = exact_object(value, ATTEMPT_FIELDS, f"{case_id}.send_attempt")
    if (
        type(attempt["schema_version"]) is not int
        or attempt["schema_version"] != 4
        or attempt["document"] != PACKET_ATTEMPT_DOCUMENT
        or attempt["case_id"] != case_id
        or attempt["state_observation_sha256"] != state_observation_sha256
        or attempt["capture_provenance_sha256"] != capture_provenance_sha256
    ):
        raise PacketEvidenceError(f"{case_id} send attempt identity/binding differs")
    stages = attempt["stages"]
    if not isinstance(stages, list) or len(stages) != len(PACKET_STAGES):
        raise PacketEvidenceError(f"{case_id} send attempt stage count differs")
    expected_host_stages = CASE_STAGE_PLANS[case_id]
    normalized: list[dict[str, Any]] = []
    prior_completed: Fraction | None = None
    for index, stage_name in enumerate(PACKET_STAGES):
        stage = exact_object(
            stages[index], ATTEMPT_STAGE_FIELDS, f"{case_id}.stages[{index}]"
        )
        token_text = tokens[index]
        token = token_text.encode("ascii")
        if (
            stage["stage"] != stage_name
            or stage["host_stage"] != expected_host_stages[index]
            or stage["token_sha256"] != hashlib.sha256(token).hexdigest()
        ):
            raise PacketEvidenceError(f"{case_id}.{stage_name} stage identity differs")
        lan_peer = provenance.get("lan_peer")
        lan_endpoint_address = (
            lan_peer.get("peer_ipv4")
            if isinstance(lan_peer, dict) and case_id == "lan-bypass"
            else None
        )
        local, remote = _stage_endpoint_set(
            stage["endpoint_set"],
            case_id=case_id,
            stage=stage_name,
            spec=spec,
            lan_endpoint_address=lan_endpoint_address,
        )
        route = _command(
            stage["route_command"],
            label=f"{case_id}.{stage_name}.route_command",
            expected_role="packet-route-observation",
        )
        interface_command = _command(
            stage["interface_command"],
            label=f"{case_id}.{stage_name}.interface_command",
            expected_role="packet-send-interface-observation",
        )
        interfaces = re.findall(
            r"^\s*interface:\s*(\S+)\s*$", route["stdout"], re.MULTILINE
        )
        if route["argv"] != (
            "/sbin/route", "-n", "get", remote["address"]
        ) or len(interfaces) != 1:
            raise PacketEvidenceError(f"{case_id}.{stage_name} route differs")
        interface = _network_interface(
            stage["interface"], f"{case_id}.{stage_name}.interface"
        )
        if (
            interface["name"] != interfaces[0]
            or interface_command["argv"]
            != ("/sbin/ifconfig", "-v", interface["name"])
            or route["stderr"]
            or interface_command["stderr"]
        ):
            raise PacketEvidenceError(f"{case_id}.{stage_name} interface differs")
        _require_interface_output(
            interface_command,
            interface,
            case_id=case_id,
            label=f"{stage_name}-interface",
            remote=False,
        )
        direct = (
            case_id in {"lan-bypass", "excluded-routes"}
            or case_id in {"stop-cleanup", "ipv6-disabled-absence"}
            and stage_name == "target"
        )
        if (
            (direct and interface["name"].startswith("utun"))
            or (not direct and not interface["name"].startswith("utun"))
            or interface["link_type"] != (DLT_EN10MB if direct else 0)
        ):
            raise PacketEvidenceError(f"{case_id}.{stage_name} route policy differs")
        if spec.protocol != "dns" and local["address"] not in _ifconfig_addresses(
            interface_command["stdout"], spec.family
        ):
            raise PacketEvidenceError(f"{case_id}.{stage_name} local address differs")
        command = _command(
            stage["command"],
            label=f"{case_id}.{stage_name}.send_command",
            expected_role=f"packet-send-{spec.protocol}-{stage_name}",
        )
        helper = Path(command["argv"][4]) if len(command["argv"]) > 4 else Path()
        socket_arguments = (
            ()
            if spec.protocol == "dns"
            else (
                "--local-address", local["address"], "--local-port", "0",
                "--remote-address", remote["address"], "--remote-port",
                str(remote["port"]),
            )
        )
        absence_ms = (
            "3000"
            if case_id in {"stop-cleanup", "ipv6-disabled-absence"}
            and stage_name == "target"
            else "0"
        )
        expected_tail = (
            "--case", case_id, "--stage", stage_name, "--protocol", spec.protocol,
            "--family", spec.family, "--resolver-role", spec.resolver_role,
            *socket_arguments, "--token", token_text, "--quic-version",
            str(provenance["quic_version"] or 0), "--absence-window-ms", absence_ms,
        )
        if (
            command["argv"][:4] != ("/usr/bin/python3", "-I", "-S", "-B")
            or not helper.is_absolute()
            or not helper.as_posix().endswith("/scripts/physical_capture/packet_sender.py")
            or command["argv"][5:] != expected_tail
            or command["stderr"]
        ):
            raise PacketEvidenceError(f"{case_id}.{stage_name} send argv differs")
        try:
            result = exact_object(
                load_json_bytes(
                    command["stdout"].encode("utf-8"),
                    f"{case_id}.{stage_name}.send_result",
                ),
                SEND_RESULT_FIELDS,
                f"{case_id}.{stage_name}.send_result",
            )
        except (RawArtifactError, UnicodeEncodeError) as error:
            raise PacketEvidenceError(
                f"{case_id}.{stage_name} send result is not JSON"
            ) from error
        if canonical_json(result).decode("utf-8") + "\n" != command["stdout"]:
            raise PacketEvidenceError(
                f"{case_id}.{stage_name} send result is not canonical JSON with LF"
            )
        if (
            type(result["schema_version"]) is not int
            or type(result["bytes_submitted"]) is not int
            or any(
                port is not None and type(port) is not int
                for port in (result["local_port"], result["remote_port"])
            )
        ):
            raise PacketEvidenceError(
                f"{case_id}.{stage_name} send result has non-exact numeric types"
            )
        dns_result = result["dns_result"]
        if spec.protocol == "dns":
            dns = exact_object(
                dns_result, DNS_RESULT_FIELDS, f"{case_id}.{stage_name}.dns_result"
            )
            query = exact_object(
                dns["query"], DNS_QUERY_RESULT_FIELDS,
                f"{case_id}.{stage_name}.dns_query",
            )
            expected_answer = DNS_A_ADDRESS if spec.family == "ipv4" else DNS_AAAA_ADDRESS
            if dns != {
                "trigger": "getaddrinfo",
                "resolver_role": spec.resolver_role,
                "requested_type": "A" if spec.family == "ipv4" else "AAAA",
                "query": query,
            } or query != {
                "name": f"{token_text}.evidence.test",
                "token_sha256": hashlib.sha256(token).hexdigest(),
                "addresses": [expected_answer],
            }:
                raise PacketEvidenceError(f"{case_id}.{stage_name} DNS result differs")
            expected_local = expected_remote = expected_port = None
            transport = "resolver"
        else:
            if dns_result is not None:
                raise PacketEvidenceError(f"{case_id}.{stage_name} carries DNS result")
            expected_local, expected_remote, expected_port = (
                local["address"], remote["address"], remote["port"]
            )
            transport = remote["transport"]
        expected_result = {
            "schema_version": 2,
            "document": "cfw-packet-send-stage-result-v2",
            "case_id": case_id,
            "stage": stage_name,
            "local_address": expected_local,
            "local_port": None if spec.protocol == "dns" else local["port"],
            "remote_address": expected_remote,
            "remote_port": expected_port,
            "transport": transport,
            "token_sha256": hashlib.sha256(token).hexdigest(),
            "bytes_submitted": len(token),
            "dns_result": dns_result,
        }
        if result != expected_result:
            raise PacketEvidenceError(f"{case_id}.{stage_name} send result differs")
        if case_id == "lan-bypass":
            if not isinstance(lan_peer, dict):
                raise PacketEvidenceError(
                    f"{case_id}.{stage_name} lacks iPhone server provenance"
                )
            server_bindings = lan_peer.get("sender_server_bindings")
            if (
                not isinstance(server_bindings, list)
                or len(server_bindings) != len(PACKET_STAGES)
            ):
                raise PacketEvidenceError(
                    f"{case_id}.{stage_name} iPhone server bindings differ"
                )
            server = server_bindings[index]
            if (
                server["stage"] != stage_name
                or server["token_sha256"] != result["token_sha256"]
                or server["local_address"] != local["address"]
                or server["local_port"] != local["port"]
                or server["remote_address"] != remote["address"]
                or server["remote_port"] != remote["port"]
                or server["bytes_received"] != result["bytes_submitted"]
                or server["eof_observed"] is not True
            ):
                raise PacketEvidenceError(
                    f"{case_id}.{stage_name} sender/iPhone binding differs"
                )
        if not (
            route["completed_at"] <= interface_command["started_at"]
            < interface_command["completed_at"] <= command["started_at"]
            < command["completed_at"]
        ):
            raise PacketEvidenceError(f"{case_id}.{stage_name} command timeline differs")
        if prior_completed is not None and prior_completed > route["started_at"]:
            raise PacketEvidenceError(f"{case_id} sender stages overlap")
        prior_completed = command["completed_at"]
        if absence_ms == "3000" and command["completed_at"] - command["started_at"] < 3:
            raise PacketEvidenceError(f"{case_id} absence interval is too short")
        normalized.append(
            {
                "stage": stage_name,
                "host_stage": stage["host_stage"],
                "local": local,
                "remote": remote,
                "interface": interface,
                "route_started_at": route["started_at"],
                "started_at": command["started_at"],
                "completed_at": command["completed_at"],
                "command_sha256": command["argv_sha256"],
            }
        )
    recorded_at = timestamp_fraction(attempt["recorded_at"])
    if prior_completed is None or recorded_at < prior_completed:
        raise PacketEvidenceError(f"{case_id} send attempt recording is not causal")
    absence = attempt["absence_window_completed_at"]
    if spec.token_observed:
        if absence is not None:
            raise PacketEvidenceError(f"{case_id} presence attempt declares absence")
        absence_at = None
    else:
        absence_at = timestamp_fraction(absence)
        if absence_at != normalized[1]["completed_at"]:
            raise PacketEvidenceError(f"{case_id} absence completion differs")
    if spec.protocol != "dns" and len(
        {(stage["local"]["address"], stage["local"]["port"]) for stage in normalized}
    ) != 3:
        raise PacketEvidenceError(f"{case_id} sender stage tuples are reused")
    return {
        "stages": normalized,
        "recorded_at": recorded_at,
        "absence_completed_at": absence_at,
        "command_sha256": hashlib.sha256(
            canonical_json([stage["command_sha256"] for stage in normalized])
        ).hexdigest(),
    }


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
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
    ):
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
    seen_product_events: set[tuple[int, int, int]] = set()
    seen_host_sessions: set[str] = set()
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
        if not 1 <= observation_ms <= MAX_ABSENCE_WINDOW_MS:
            raise PacketEvidenceError(
                f"{case_id} observation window is outside its fixed bound"
            )
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
        state_descriptor, state_document = artifacts.read_json(
            case["state_artifact"],
            expected_kind="packet-product-state-observation",
            label=f"{case_id}.state_artifact",
        )
        state_observation = _product_state_observation(
            state_document,
            case_id=case_id,
            spec=spec,
            candidate_identity=proof["candidate"],
        )
        state_event_identity = (
            state_observation["process"][0],
            state_observation["process"][1],
            state_observation["sequence"],
        )
        if state_event_identity in seen_product_events:
            raise PacketEvidenceError("packet cases reuse one product-state event")
        seen_product_events.add(state_event_identity)
        descriptor, capture = artifacts.read(
            case["artifact"],
            expected_kinds={"packet-pcap", "packet-pcapng"},
            label=f"{case_id}.artifact",
        )
        provenance_descriptor, provenance_document = artifacts.read_json(
            case["provenance_artifact"],
            expected_kind="packet-capture-provenance",
            label=f"{case_id}.provenance_artifact",
        )
        provenance = _capture_provenance_v4(
            provenance_document,
            case_id=case_id,
            spec=spec,
            state_observation_sha256=state_descriptor.sha256,
            capture_artifact_sha256=descriptor.sha256,
            capture_artifact_size=descriptor.size,
        )
        host_transaction = provenance["host_transaction"]
        host_session = host_transaction["session_id"]
        if host_session in seen_host_sessions:
            raise PacketEvidenceError("packet cases reuse one Host transaction session")
        seen_host_sessions.add(host_session)
        if (
            host_transaction["test"] != state_observation["state"]
            or host_transaction["test_observation_sequence"]
            != state_observation["sequence"]
        ):
            raise PacketEvidenceError(
                f"{case_id} product observation differs from Host transaction"
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
        expected_filter = packet_capture_filter_argv(
            case_id=case_id,
            tokens=(
                case["window_start_token"],
                case["token"],
                case["window_end_token"],
            ),
            lan_endpoint_address=(
                provenance["lan_peer"]["peer_ipv4"]
                if case_id == "lan-bypass"
                and isinstance(provenance["lan_peer"], dict)
                else None
            ),
        )
        if provenance["capture_filter_argv"] != list(expected_filter):
            raise PacketEvidenceError(f"{case_id} capture filter differs from tokens")
        attempt_descriptor, attempt_document = artifacts.read_json(
            case["attempt_artifact"],
            expected_kind="packet-send-attempt",
            label=f"{case_id}.attempt_artifact",
        )
        attempt = _send_attempt_v4(
            attempt_document,
            case_id=case_id,
            spec=spec,
            tokens=(
                case["window_start_token"],
                case["token"],
                case["window_end_token"],
            ),
            provenance=provenance,
            state_observation_sha256=state_descriptor.sha256,
            capture_provenance_sha256=provenance_descriptor.sha256,
        )
        if attempt["command_sha256"] != case["send_command_sha256"]:
            raise PacketEvidenceError(
                f"{case_id} report and send attempt bind different commands"
            )
        capture_proof = validate_staged_capture_tokens(
            capture,
            descriptor.kind,
            protocol=spec.protocol,
            family=spec.family,
            endpoints=tuple(
                StagedCaptureEndpoint(
                    stage=stage["stage"],
                    local_address=stage["local"]["address"],
                    local_port=stage["local"]["port"],
                    remote_address=stage["remote"]["address"],
                    remote_port=stage["remote"]["port"],
                )
                for stage in attempt["stages"]
            ),
            expected_link_type=provenance["capture_device"]["link_type"],
            expected_interface_name=provenance["capture_device"]["name"],
            expected_quic_version=provenance["quic_version"],
            token=token,
            start_marker=start_marker,
            end_marker=end_marker,
            expect_token=spec.token_observed,
            declared_observation_ms=observation_ms,
        )
        expected_packet_count = (
            6 if spec.protocol == "dns" else 3 if spec.token_observed else 2
        )
        if (
            capture_proof.total_record_count != expected_packet_count
        ):
            raise PacketEvidenceError(
                f"{case_id} capture bytes differ from the fixed tcpdump receipt count"
            )
        if (
            capture_proof.started_at != provenance["started_at"]
            or capture_proof.ended_at != provenance["completed_at"]
        ):
            raise PacketEvidenceError(
                f"{case_id} capture timestamps differ from retained provenance"
            )
        if spec.protocol == "dns":
            if (
                capture_proof.dns_response_count != 3
                or capture_proof.dns_answer_type
                != ("A" if spec.family == "ipv4" else "AAAA")
                or capture_proof.dns_answer_address
                != (DNS_A_ADDRESS if spec.family == "ipv4" else DNS_AAAA_ADDRESS)
                or capture_proof.dns_ttl != DNS_TTL
                or _sha256(
                    capture_proof.dns_responses_sha256,
                    f"{case_id}.pcap.dns_responses_sha256",
                )
                != capture_proof.dns_responses_sha256
            ):
                raise PacketEvidenceError(
                    f"{case_id} remote pcap lacks exact upstream DNS query/response proof"
                )
        elif any(
            value is not None
            for value in (
                capture_proof.dns_response_count,
                capture_proof.dns_answer_type,
                capture_proof.dns_answer_address,
                capture_proof.dns_ttl,
                capture_proof.dns_responses_sha256,
            )
        ):
            raise PacketEvidenceError(f"{case_id} non-DNS pcap carries DNS proof")
        start_stage, target_stage, end_stage = attempt["stages"]
        if not (
            start_stage["started_at"]
            <= capture_proof.start_event_started_at
            <= capture_proof.start_event_ended_at
            <= start_stage["completed_at"]
            and end_stage["started_at"]
            <= capture_proof.end_event_started_at
            <= capture_proof.end_event_ended_at
            <= end_stage["completed_at"]
        ):
            raise PacketEvidenceError(
                f"{case_id} marker packets are not caused by their retained sends"
            )
        if spec.token_observed:
            if (
                capture_proof.target_started_at is None
                or capture_proof.target_ended_at is None
                or not target_stage["started_at"]
                <= capture_proof.target_started_at
                <= capture_proof.target_ended_at
                <= target_stage["completed_at"]
            ):
                raise PacketEvidenceError(
                    f"{case_id} target packet is not caused by the retained target send"
                )
        elif (
            capture_proof.target_started_at is not None
            or capture_proof.target_ended_at is not None
        ):
            raise PacketEvidenceError(
                f"{case_id} absence capture retained a target event"
            )
        if not (
            provenance["capture_alive_at"] <= start_stage["route_started_at"]
            <= start_stage["started_at"]
            <= capture_proof.started_at <= start_stage["completed_at"]
            and target_stage["started_at"] <= target_stage["completed_at"]
            and end_stage["started_at"] <= capture_proof.ended_at
            <= end_stage["completed_at"] <= provenance["command_completed_at"]
            <= attempt["recorded_at"]
        ):
            raise PacketEvidenceError(f"{case_id} staged capture timeline is not causal")
        if CASE_STAGE_PLANS[case_id] == ("test", "test", "test") and not (
            provenance["capture_alive_at"]
            <= state_observation["recorded_at"]
            <= state_observation["observed_at"]
            <= start_stage["route_started_at"]
        ):
            raise PacketEvidenceError(f"{case_id} test observation does not precede sends")
        if CASE_STAGE_PLANS[case_id] == ("baseline", "test", "restored") and not (
            start_stage["completed_at"]
            <= state_observation["recorded_at"]
            <= state_observation["observed_at"]
            <= target_stage["route_started_at"]
        ):
            raise PacketEvidenceError(f"{case_id} test state is not marker-bounded")
        restore_descriptor = None
        restore_observation = None
        if spec.token_observed:
            if case["restore_state_artifact"] is not None:
                raise PacketEvidenceError(
                    f"{case_id} presence proof must not carry a restore observation"
                )
        elif case["restore_state_artifact"] is None:
            raise PacketEvidenceError(
                f"{case_id} absence proof requires exact restored product state"
            )
        else:
            restore_descriptor, restore_document = artifacts.read_json(
                case["restore_state_artifact"],
                expected_kind="packet-product-state-observation",
                label=f"{case_id}.restore_state_artifact",
            )
            restore_observation = _product_state_observation(
                restore_document,
                case_id=case_id,
                spec=spec,
                candidate_identity=proof["candidate"],
                restored=True,
            )
            restore_event_identity = (
                restore_observation["process"][0],
                restore_observation["process"][1],
                restore_observation["sequence"],
            )
            if restore_event_identity in seen_product_events:
                raise PacketEvidenceError("packet cases reuse one product-state event")
            seen_product_events.add(restore_event_identity)
            if (
                host_transaction["restore"] != restore_observation["state"]
                or host_transaction["restore_observation_sequence"]
                != restore_observation["sequence"]
            ):
                raise PacketEvidenceError(
                    f"{case_id} restored product observation differs from Host transaction"
                )
            same_process = (
                restore_observation["process"] == state_observation["process"]
            )
            if not (
                attempt["absence_completed_at"]
                < restore_observation["recorded_at"]
                <= restore_observation["observed_at"]
                <= end_stage["route_started_at"]
                and (
                    not same_process
                    or restore_observation["sequence"]
                    > state_observation["sequence"]
                )
            ):
                raise PacketEvidenceError(
                    f"{case_id} restore/re-enable observation is not causal"
                )
            artifact_bindings.append(
                {
                    "subject": f"{case_id}:restore-state",
                    "descriptor": restore_descriptor.as_dict(),
                }
            )
        artifact_bindings.append(
            {
                "subject": f"{case_id}:send-attempt",
                "descriptor": attempt_descriptor.as_dict(),
            }
        )
        artifact_bindings.append(
            {
                "subject": f"{case_id}:product-state",
                "descriptor": state_descriptor.as_dict(),
            }
        )
        completion = attempt["recorded_at"]
        if restore_observation is not None:
            completion = max(completion, restore_observation["observed_at"])
        completions.append(completion)
        starts.append(capture_proof.started_at)
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
    if declared_completed != max(completions) or declared_completed > declared_signed:
        raise PacketEvidenceError(
            "packet completed_at/signed_at do not cover every retained observation"
        )
    subjects = {binding["subject"] for binding in artifact_bindings}
    if len(subjects) != len(artifact_bindings):
        raise PacketEvidenceError("packet raw evidence repeats a subject")
    if not EXPECTED_PACKET_RAW_SUBJECTS <= subjects or not subjects <= (
        EXPECTED_PACKET_RAW_SUBJECTS | OPTIONAL_PACKET_RAW_SUBJECTS
    ):
        raise PacketEvidenceError("packet raw evidence subject set is incomplete or unknown")
    return {
        "document": document,
        "proof": proof,
        "started_at": min(starts),
        "completed_at": declared_completed,
        "artifacts": artifact_bindings,
    }


def validate_packet_evidence(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    """Validate one v4 report and reopen every pre-nonce raw artifact."""

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
