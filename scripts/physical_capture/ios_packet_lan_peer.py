"""Strict receipts for the test-only iOS Packet LAN peer mode.

The peer result is a server-side observation, never a standalone Packet pass.
The Packet joint verifier must bind it to the Host state transaction, sender
receipts, route observations, and pcap before any release claim is eligible.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import re
import secrets
from typing import Final, Mapping, Sequence

from scripts.harness.raw_artifacts import canonical_json, exact_object

from .ios_transport_peer import (
    BUNDLE_IDENTIFIER,
    IOSPeerContractError,
    MAX_JSON_BYTES,
    MAX_PID,
    _load_canonical_document,
    _parse_timestamp,
    _require_digest,
    _validate_controlled_wifi_network,
)


SCHEMA_VERSION: Final = 1
SESSION_DOCUMENT: Final = "cfm-ios-packet-lan-peer-session-v1"
READY_DOCUMENT: Final = "cfm-ios-packet-lan-peer-ready-v1"
RESULT_DOCUMENT: Final = "cfm-ios-packet-lan-peer-result-v1"
EVIDENCE_ROLE: Final = "server_observation_only"
LAUNCH_ARGUMENT: Final = "--cfm-packet-lan-run-v1"
DIRECTORY_NAME: Final = "CFMPacketLanPeer"
DEVICE_DIRECTORY: Final = f"Documents/{DIRECTORY_NAME}"
SESSION_FILE_NAME: Final = "session.json"
READY_FILE_NAME: Final = "ready.json"
RESULT_FILE_NAME: Final = "result.json"
CASE_ID: Final = "lan-bypass"
LISTENER_PORT: Final = 44_333
TRANSPORT: Final = "tcp4"
TOKEN_BYTES: Final = 20
MAXIMUM_SESSION_SECONDS: Final = 15 * 60
FAILURE_FINALIZATION_GRACE_SECONDS: Final = 10
STAGES: Final = ("start", "target", "end")

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{19}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SESSION_FIELDS = {
    "schema_version",
    "document",
    "session_id",
    "case_id",
    "created_at",
    "expires_at",
    "listener_port",
    "stage_token_sha256",
}
_TOKEN_DIGEST_FIELDS = set(STAGES)
_READY_FIELDS = {
    "schema_version",
    "document",
    "evidence_role",
    "claim_eligible",
    "session_id",
    "bundle_identifier",
    "process_id",
    "started_at",
    "expires_at",
    "network",
    "listener",
    "session_file_removed",
}
_LISTENER_FIELDS = {"port", "transport"}
_RESULT_FIELDS = {
    "schema_version",
    "document",
    "evidence_role",
    "claim_eligible",
    "session_id",
    "ready_sha256",
    "bundle_identifier",
    "process_id",
    "completed_at",
    "status",
    "failure_phase",
    "failure_reason",
    "network",
    "listener",
    "listener_closed",
    "session_file_removed",
    "connections",
}
_CONNECTION_FIELDS = {
    "stage",
    "admission_sequence",
    "token_sha256",
    "bytes_received",
    "eof_observed",
    "peer_ipv4",
    "peer_port",
}
_FAILURE_PHASE_BY_REASON = {
    "application_lifecycle_requested": "application_lifecycle",
    "connection_overlap": "connection_admission",
    "extra_connection": "connection_admission",
    "connection_deadline_expired": "payload_delivery",
    "connection_terminated": "payload_delivery",
    "payload_invalid": "payload_delivery",
    "client_endpoint_invalid": "payload_delivery",
    "session_deadline_expired": "session_deadline",
    "listener_runtime_failed": "listener_runtime",
    "network_identity_changed": "listener_runtime",
    "listener_shutdown_failed": "listener_shutdown",
}


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise IOSPeerContractError(
            "ios_packet_lan_time_invalid",
            "packet LAN time must be timezone-aware",
        )
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical(value: Mapping[str, object]) -> bytes:
    data = canonical_json(dict(value)) + b"\n"
    if len(data) > MAX_JSON_BYTES:
        raise IOSPeerContractError(
            "ios_packet_lan_session_invalid",
            "packet LAN session exceeds the fixed JSON bound",
        )
    return data


def _token(value: object, stage: str) -> bytes:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise IOSPeerContractError(
            "ios_packet_lan_token_invalid",
            f"packet LAN {stage} token is not canonical",
        )
    encoded = value.encode("ascii")
    if len(encoded) != TOKEN_BYTES or encoded[:1] != stage[:1].encode("ascii"):
        raise IOSPeerContractError(
            "ios_packet_lan_token_invalid",
            f"packet LAN {stage} token has the wrong stage binding",
        )
    return encoded


def create_session(*, tokens: Sequence[str], now: datetime) -> bytes:
    """Create one fresh packet-only session without retaining raw tokens."""

    if now.tzinfo is None or now.utcoffset() is None:
        raise IOSPeerContractError(
            "ios_packet_lan_time_invalid",
            "packet LAN creation time must be timezone-aware",
        )
    if not isinstance(tokens, (tuple, list)) or len(tokens) != len(STAGES):
        raise IOSPeerContractError(
            "ios_packet_lan_token_invalid",
            "packet LAN session requires exactly three source-owned tokens",
        )
    encoded = [_token(value, stage) for stage, value in zip(STAGES, tokens)]
    if len(set(encoded)) != len(encoded):
        raise IOSPeerContractError(
            "ios_packet_lan_token_invalid",
            "packet LAN stage tokens are not unique",
        )
    created = now.astimezone(timezone.utc)
    session_id = hashlib.sha256(
        b"cfm-ios-packet-lan-session-v1\0" + secrets.token_bytes(32)
    ).hexdigest()
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "document": SESSION_DOCUMENT,
        "session_id": session_id,
        "case_id": CASE_ID,
        "created_at": _timestamp(created),
        "expires_at": _timestamp(
            created + timedelta(seconds=MAXIMUM_SESSION_SECONDS)
        ),
        "listener_port": LISTENER_PORT,
        "stage_token_sha256": {
            stage: hashlib.sha256(payload).hexdigest()
            for stage, payload in zip(STAGES, encoded)
        },
    }
    data = _canonical(document)
    validate_session(data, now=now)
    return data


def validate_session(data: bytes, *, now: datetime) -> dict[str, object]:
    document = _load_canonical_document(
        data, _SESSION_FIELDS, "iOS packet LAN session"
    )
    try:
        digests = exact_object(
            document["stage_token_sha256"],
            _TOKEN_DIGEST_FIELDS,
            "iOS packet LAN token digests",
        )
    except (TypeError, ValueError) as error:
        raise IOSPeerContractError(
            "ios_packet_lan_session_invalid",
            "packet LAN token digest fields differ",
        ) from error
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
        or document["document"] != SESSION_DOCUMENT
        or document["case_id"] != CASE_ID
        or type(document["listener_port"]) is not int
        or document["listener_port"] != LISTENER_PORT
        or not isinstance(document["session_id"], str)
        or _SHA256.fullmatch(document["session_id"]) is None
        or any(
            not isinstance(digests[stage], str)
            or _SHA256.fullmatch(digests[stage]) is None
            for stage in STAGES
        )
        or len(set(digests.values())) != len(STAGES)
    ):
        raise IOSPeerContractError(
            "ios_packet_lan_session_invalid",
            "packet LAN session identity differs",
        )
    created = _parse_timestamp(document["created_at"], "packet LAN creation")
    expires = _parse_timestamp(document["expires_at"], "packet LAN expiry")
    if now.tzinfo is None or now.utcoffset() is None:
        raise IOSPeerContractError(
            "ios_packet_lan_time_invalid",
            "packet LAN validation time must be timezone-aware",
        )
    current = now.astimezone(timezone.utc)
    if (
        not created <= current < expires
        or (expires - created).total_seconds() > MAXIMUM_SESSION_SECONDS
    ):
        raise IOSPeerContractError(
            "ios_packet_lan_session_expired",
            "packet LAN session is stale or exceeds its lifetime",
        )
    return document


def _listener(value: object, *, label: str) -> dict[str, object]:
    try:
        listener = exact_object(value, _LISTENER_FIELDS, label)
    except (TypeError, ValueError) as error:
        raise IOSPeerContractError(
            "ios_packet_lan_receipt_invalid",
            f"{label} fields differ",
        ) from error
    if listener != {"port": LISTENER_PORT, "transport": TRANSPORT}:
        raise IOSPeerContractError(
            "ios_packet_lan_receipt_invalid",
            f"{label} policy differs",
        )
    return listener


def validate_ready(
    data: bytes,
    *,
    session: Mapping[str, object],
    now: datetime,
) -> dict[str, object]:
    document = _load_canonical_document(
        data, _READY_FIELDS, "iOS packet LAN ready receipt"
    )
    expected_session_id = session.get("session_id")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
        or document["document"] != READY_DOCUMENT
        or document["evidence_role"] != EVIDENCE_ROLE
        or document["claim_eligible"] is not False
        or document["session_id"] != expected_session_id
        or document["bundle_identifier"] != BUNDLE_IDENTIFIER
        or type(document["process_id"]) is not int
        or not 1 <= document["process_id"] <= MAX_PID
        or document["expires_at"] != session.get("expires_at")
        or document["session_file_removed"] is not True
    ):
        raise IOSPeerContractError(
            "ios_packet_lan_ready_invalid",
            "packet LAN ready identity differs",
        )
    _require_digest(expected_session_id, "packet LAN session ID")
    created = _parse_timestamp(session.get("created_at"), "packet LAN creation")
    started = _parse_timestamp(document["started_at"], "packet LAN ready time")
    expires = _parse_timestamp(document["expires_at"], "packet LAN expiry")
    if now.tzinfo is None or now.utcoffset() is None:
        raise IOSPeerContractError(
            "ios_packet_lan_time_invalid",
            "packet LAN validation time must be timezone-aware",
        )
    current = now.astimezone(timezone.utc)
    if not created <= started <= current < expires:
        raise IOSPeerContractError(
            "ios_packet_lan_ready_expired",
            "packet LAN ready receipt is stale or out of order",
        )
    _validate_controlled_wifi_network(
        document["network"],
        label="iOS packet LAN network",
        error_code="ios_packet_lan_ready_invalid",
    )
    _listener(document["listener"], label="iOS packet LAN listener")
    return document


def _private_ipv4(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise IOSPeerContractError(
            "ios_packet_lan_result_invalid", f"{label} is not IPv4"
        )
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise IOSPeerContractError(
            "ios_packet_lan_result_invalid", f"{label} is not IPv4"
        ) from error
    controlled_networks = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if not any(address in network for network in controlled_networks):
        raise IOSPeerContractError(
            "ios_packet_lan_result_invalid", f"{label} is outside RFC1918"
        )
    return str(address)


def validate_result(
    data: bytes,
    *,
    session: Mapping[str, object],
    ready: Mapping[str, object],
) -> dict[str, object]:
    document = _load_canonical_document(
        data, _RESULT_FIELDS, "iOS packet LAN result receipt"
    )
    ready_bytes = canonical_json(dict(ready)) + b"\n"
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
        or document["document"] != RESULT_DOCUMENT
        or document["evidence_role"] != EVIDENCE_ROLE
        or document["claim_eligible"] is not False
        or document["session_id"] != session.get("session_id")
        or document["ready_sha256"] != hashlib.sha256(ready_bytes).hexdigest()
        or document["bundle_identifier"] != BUNDLE_IDENTIFIER
        or type(document["process_id"]) is not int
        or document["process_id"] != ready.get("process_id")
        or document["network"] != ready.get("network")
        or document["listener"] != ready.get("listener")
        or document["listener_closed"] is not True
        or document["session_file_removed"] is not True
        or not isinstance(document["status"], str)
        or document["status"] not in {"closed", "failed"}
        or not isinstance(document["failure_phase"], str)
        or not isinstance(document["failure_reason"], str)
        or not isinstance(document["connections"], list)
        or len(document["connections"]) > len(STAGES)
    ):
        raise IOSPeerContractError(
            "ios_packet_lan_result_invalid",
            "packet LAN result identity differs",
        )
    _require_digest(document["ready_sha256"], "packet LAN ready digest")
    _listener(document["listener"], label="iOS packet LAN result listener")
    network = _validate_controlled_wifi_network(
        document["network"],
        label="iOS packet LAN result network",
        error_code="ios_packet_lan_result_invalid",
    )
    started = _parse_timestamp(ready.get("started_at"), "packet LAN ready time")
    completed = _parse_timestamp(document["completed_at"], "packet LAN completion")
    expires = _parse_timestamp(ready.get("expires_at"), "packet LAN expiry")
    if completed < started:
        raise IOSPeerContractError(
            "ios_packet_lan_result_invalid",
            "packet LAN completion precedes readiness",
        )
    try:
        digests = exact_object(
            session.get("stage_token_sha256"),
            _TOKEN_DIGEST_FIELDS,
            "packet LAN session token digests",
        )
    except (TypeError, ValueError) as error:
        raise IOSPeerContractError(
            "ios_packet_lan_result_invalid",
            "packet LAN session token digests differ",
        ) from error
    peers: set[str] = set()
    ports: set[int] = set()
    for index, value in enumerate(document["connections"]):
        try:
            connection = exact_object(
                value,
                _CONNECTION_FIELDS,
                f"packet LAN connection {index + 1}",
            )
        except (TypeError, ValueError) as error:
            raise IOSPeerContractError(
                "ios_packet_lan_result_invalid",
                "packet LAN connection fields differ",
            ) from error
        stage = STAGES[index]
        peer = _private_ipv4(connection["peer_ipv4"], label="packet LAN peer")
        port = connection["peer_port"]
        if (
            connection["stage"] != stage
            or type(connection["admission_sequence"]) is not int
            or connection["admission_sequence"] != index + 1
            or connection["token_sha256"] != digests[stage]
            or type(connection["bytes_received"]) is not int
            or connection["bytes_received"] != TOKEN_BYTES
            or connection["eof_observed"] is not True
            or peer == network["ipv4"]
            or type(port) is not int
            or not 49_152 <= port <= 65_535
        ):
            raise IOSPeerContractError(
                "ios_packet_lan_result_invalid",
                "packet LAN connection observation differs",
            )
        peers.add(peer)
        ports.add(port)
    if len(peers) > 1 or len(ports) != len(document["connections"]):
        raise IOSPeerContractError(
            "ios_packet_lan_result_invalid",
            "packet LAN client identity drifted across stages",
        )
    if document["status"] == "closed":
        coherent = (
            document["failure_phase"] == "none"
            and document["failure_reason"] == "none"
            and len(document["connections"]) == len(STAGES)
            and completed <= expires
        )
    else:
        reason = document["failure_reason"]
        coherent = (
            reason in _FAILURE_PHASE_BY_REASON
            and document["failure_phase"] == _FAILURE_PHASE_BY_REASON[reason]
            and completed
            <= expires + timedelta(seconds=FAILURE_FINALIZATION_GRACE_SECONDS)
        )
    if not coherent:
        raise IOSPeerContractError(
            "ios_packet_lan_result_invalid",
            "packet LAN result status is incoherent",
        )
    return document


__all__ = [
    "CASE_ID",
    "DEVICE_DIRECTORY",
    "DIRECTORY_NAME",
    "EVIDENCE_ROLE",
    "FAILURE_FINALIZATION_GRACE_SECONDS",
    "LAUNCH_ARGUMENT",
    "LISTENER_PORT",
    "MAXIMUM_SESSION_SECONDS",
    "READY_DOCUMENT",
    "READY_FILE_NAME",
    "RESULT_DOCUMENT",
    "RESULT_FILE_NAME",
    "SCHEMA_VERSION",
    "SESSION_DOCUMENT",
    "SESSION_FILE_NAME",
    "STAGES",
    "TOKEN_BYTES",
    "TRANSPORT",
    "create_session",
    "validate_ready",
    "validate_result",
    "validate_session",
]
