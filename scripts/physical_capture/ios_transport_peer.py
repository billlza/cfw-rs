"""Closed command and receipt contract for the test-only iOS transport peer.

This module deliberately does not execute ``devicectl``.  It builds the exact
command specifications that a later physical-capture transaction may execute
and validates the peer's canonical receipts.  Keeping planning pure lets the
source and failure paths be tested without installing an app or changing a
device.

The peer is validation infrastructure, not an iOS CFM product.  Its dedicated
Packet-LAN mode is consumed only through the versioned iPhone adapter and
Packet-v4 joint evidence contract; transport receipts remain separate and
server-only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

from scripts.harness.raw_artifacts import canonical_json, exact_object, load_json_bytes

from .execution import CommandSpec

SCHEMA_VERSION: Final = 1
RESULT_SCHEMA_VERSION: Final = 5
SESSION_DOCUMENT: Final = "cfm-ios-transport-peer-session-v1"
READY_DOCUMENT: Final = "cfm-ios-transport-peer-ready-v1"
RESULT_DOCUMENT: Final = "cfm-ios-transport-peer-result-v5"
PRIMER_RESULT_DOCUMENT: Final = "cfm-ios-transport-peer-primer-result-v1"
BUNDLE_IDENTIFIER: Final = "com.bill.cfm.physical-transport-peer"
APP_EXECUTABLE: Final = "CFMPhysicalTransportPeer"
PRIMER_LAUNCH_ARGUMENT: Final = "--cfm-local-network-primer-v1"
TRANSPORT_RUN_ARGUMENT: Final = "--cfm-transport-run-v1"
PRIMER_MODE: Final = "local_network_permission_primer"
SESSION_DIRECTORY_NAME: Final = "CFMTransportPeer"
DEVICE_SESSION_DIRECTORY: Final = f"Documents/{SESSION_DIRECTORY_NAME}"
PRIMER_DIRECTORY_NAME: Final = "CFMTransportPrimer"
DEVICE_PRIMER_DIRECTORY: Final = f"Documents/{PRIMER_DIRECTORY_NAME}"
SESSION_FILE_NAME: Final = "session.json"
CERTIFICATE_FILE_NAME: Final = "certificate.der"
PRIVATE_KEY_FILE_NAME: Final = "private-key.x963"
READY_FILE_NAME: Final = "ready.json"
RESULT_FILE_NAME: Final = "result.json"
PRIMER_RESULT_FILE_NAME: Final = "primer-result.json"
PRIMER_PORT: Final = 44332
TCP_SINK_PORT: Final = 44333
TLS13_ECHO_PORT: Final = 44334
QUIC_ECHO_PORT: Final = 44335
TLS_ALPN: Final = "cfm-transport-peer-tls/1"
QUIC_ALPN: Final = "cfm-transport-peer-quic/1"
PRIMER_BONJOUR_NAME: Final = "CFM Transport Primer"
PRIMER_BONJOUR_TYPE: Final = "_cfm-primer._tcp"
PRIMER_BONJOUR_DOMAIN: Final = "local."
XCRUN: Final = Path("/usr/bin/xcrun")
COMMAND_TIMEOUT_SECONDS: Final = 30.0
INSTALL_TIMEOUT_SECONDS: Final = 120.0
COPY_TIMEOUT_SECONDS: Final = 60.0
MAX_JSON_BYTES: Final = 64 * 1024
MAX_PID: Final = 2**31 - 1
MAX_CONNECTIONS: Final = 8
MAX_PAYLOAD_BYTES: Final = 64
MAX_SESSION_SECONDS: Final = 15 * 60
UNKNOWN_LAUNCH_SERVICES_IDENTIFIER: Final = "unknown"

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_PROVISIONING_UDID = re.compile(r"^(?:[0-9A-F]{8}-[0-9A-F]{16}|[0-9A-F]{40})$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_SESSION_FIELDS = {
    "schema_version",
    "document",
    "session_id",
    "created_at",
    "expires_at",
    "certificate_sha256",
    "private_key_sha256",
}
_READY_FIELDS = {
    "schema_version",
    "document",
    "session_id",
    "bundle_identifier",
    "process_id",
    "started_at",
    "expires_at",
    "certificate_sha256",
    "network",
    "listeners",
}
_NETWORK_FIELDS = {"interface_name", "ipv4"}
_LISTENER_FIELDS = {"port", "transport", "alpn"}
_PRIMER_RESULT_FIELDS = {
    "schema_version",
    "document",
    "mode",
    "claim_eligible",
    "bundle_identifier",
    "process_id",
    "started_at",
    "service_registered_at",
    "listener_ready_at",
    "listener_cancelled_at",
    "service_registered",
    "listener_ready",
    "listener_cancelled",
    "network",
    "listener",
}
_PRIMER_LISTENER_FIELDS = {
    "port",
    "transport",
    "bonjour_name",
    "bonjour_type",
    "bonjour_domain",
}
_RESULT_FIELDS = {
    "schema_version",
    "document",
    "evidence_role",
    "claim_eligible",
    "session_id",
    "certificate_sha256",
    "bundle_identifier",
    "process_id",
    "completed_at",
    "status",
    "failure_phase",
    "failed_service",
    "failure_reason",
    "phase_reached",
    "blocking_service",
    "blocking_phase",
    "blocking_admission_sequence",
    "incoming_admission_sequence",
    "incoming_matches_blocker_object",
    "blocking_quic_stream_identifier",
    "listeners_closed",
    "identity_files_removed",
    "connections",
}
_CONNECTION_FIELDS = {
    "tcp_sink",
    "tls13_echo",
    "quic_echo",
}
_CONNECTION_RESULT_FIELDS = {
    "accepted",
    "evidence_disposition",
    "bytes_received",
    "bytes_sent",
    "control_bytes_received",
    "control_bytes_submitted",
    "delivery_confirmation_completion",
    "peer_terminal_observed",
    "delivery_acknowledgement_final_context_observed",
    "transport",
    "tls_version",
    "cipher_suite",
    "alpn",
    "early_data_accepted",
    "payload_sha256",
}
_RESULT_STATUSES = {"closed", "pair_required", "failed"}
_EVIDENCE_DISPOSITIONS = {"accepted", "pair_required", "unobserved"}
_CONFIRMATION_COMPLETIONS = {"processed", "failed", "unobserved"}
_FAILURE_PHASES = {
    "none",
    "application_lifecycle",
    "listener_setup",
    "listener_runtime",
    "ready_publication",
    "session_deadline",
    "connection_admission",
    "delivery_evidence",
    "completion_validation",
    "listener_shutdown",
    "identity_cleanup",
}
_FAILED_SERVICES = {
    "none",
    "runtime",
    "tcp_sink",
    "tls13_echo",
    "quic_echo",
}
_FAILURE_REASONS = {
    "none",
    "application_lifecycle_requested",
    "listener_setup_failed",
    "listener_runtime_failed",
    "unexpected_listener_cancellation",
    "ready_publication_failed",
    "session_deadline_expired",
    "connection_deadline_expired",
    "connection_admission_overlap",
    "echo_runtime_state_conflict",
    "echo_send_failed",
    "acknowledgement_receive_failed",
    "acknowledgement_invalid",
    "acknowledgement_not_final",
    "delivery_callback_out_of_order",
    "delivery_callback_conflict",
    "unexpected_trailing_bytes",
    "connection_overlap",
    "completion_evidence_invalid",
    "completion_overlap",
    "completion_payload_invalid",
    "listener_shutdown_deadline",
    "identity_cleanup_failed",
}
_PHASES_REACHED = {
    "application_started",
    "listener_setup",
    "listeners_ready",
    "connection_accepted",
    "security_ready",
    "payload_received",
    "echo_completed",
    "acknowledgement_received",
    "delivery_confirmation_submitted",
    "delivery_evidence_observed",
    "completion_resolved",
    "listener_shutdown",
    "identity_cleanup",
    "completed",
}
_PHASE_RANKS = {
    phase: rank
    for rank, phase in enumerate(
        (
            "application_started",
            "listener_setup",
            "listeners_ready",
            "connection_accepted",
            "security_ready",
            "payload_received",
            "echo_completed",
            "acknowledgement_received",
            "delivery_confirmation_submitted",
            "delivery_evidence_observed",
            "completion_resolved",
            "listener_shutdown",
            "identity_cleanup",
            "completed",
        )
    )
}
_RUNTIME_FAILURE_REASONS = {
    "application_lifecycle_requested",
    "listener_setup_failed",
    "ready_publication_failed",
    "session_deadline_expired",
    "listener_shutdown_deadline",
    "identity_cleanup_failed",
}
_SECURE_DELIVERY_FAILURE_REASONS = {
    "echo_runtime_state_conflict",
    "echo_send_failed",
    "acknowledgement_receive_failed",
    "acknowledgement_invalid",
    "acknowledgement_not_final",
    "delivery_callback_out_of_order",
    "delivery_callback_conflict",
    "unexpected_trailing_bytes",
    "connection_overlap",
}
_SERVICE_FAILURE_REASONS = {
    "listener_runtime_failed",
    "unexpected_listener_cancellation",
    "connection_deadline_expired",
    "connection_admission_overlap",
    "completion_overlap",
    "completion_payload_invalid",
}
_ANY_SCOPED_FAILURE_REASONS = {"completion_evidence_invalid"}


class IOSPeerContractError(RuntimeError):
    """The iOS peer plan or receipt is unsafe, stale, or malformed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sha256_domain(domain: bytes, value: str) -> str:
    return hashlib.sha256(domain + value.encode("ascii", errors="strict")).hexdigest()


def transport_payload_receipt_sha256(service: str, session_id: str) -> str:
    """Hash the exact session-derived payload bytes recorded by both peers."""

    domains = {
        "tcp_sink": b"cfm-ios-transport-peer-tcp-payload-v1\0",
        "tls13_echo": b"cfm-ios-transport-peer-tls-payload-v1\0",
        "quic_echo": b"cfm-ios-transport-peer-quic-payload-v1\0",
    }
    if service not in domains or not isinstance(session_id, str):
        raise IOSPeerContractError(
            "ios_peer_result_invalid", "transport payload identity is invalid"
        )
    try:
        session_bytes = bytes.fromhex(session_id)
    except ValueError as error:
        raise IOSPeerContractError(
            "ios_peer_result_invalid", "transport payload session ID is invalid"
        ) from error
    if _HEX_64.fullmatch(session_id) is None or len(session_bytes) != 32:
        raise IOSPeerContractError(
            "ios_peer_result_invalid", "transport payload session ID is invalid"
        )
    payload = hashlib.sha256(domains[service] + session_bytes).digest()
    return hashlib.sha256(payload).hexdigest()


def _canonical_device_identifier(value: str) -> str:
    if not isinstance(value, str):
        raise IOSPeerContractError(
            "ios_peer_device_invalid", "iOS peer device identifier must be a string"
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise IOSPeerContractError(
            "ios_peer_device_invalid", "iOS peer device identifier is not one UUID"
        ) from error
    canonical = str(parsed).upper()
    if value != canonical:
        raise IOSPeerContractError(
            "ios_peer_device_invalid", "iOS peer device identifier is not canonical"
        )
    return canonical


def _canonical_provisioning_udid(value: str) -> str:
    if not isinstance(value, str) or _PROVISIONING_UDID.fullmatch(value) is None:
        raise IOSPeerContractError(
            "ios_peer_provisioning_udid_invalid",
            "iOS peer provisioning UDID is not one canonical physical-device UDID",
        )
    return value


def _require_launch_services_identifier(value: object) -> str:
    if value == UNKNOWN_LAUNCH_SERVICES_IDENTIFIER:
        # CoreDevice 642.9.1 can emit this exact sentinel even after a fresh
        # inventory has observed the installed app. It means the optional
        # Launch Services synchronization token is unavailable; it is never
        # passed back to ``devicectl process launch`` as though it were one.
        return value
    if not isinstance(value, str) or not 4 <= len(value) <= 4096:
        raise IOSPeerContractError(
            "ios_peer_launch_services_identifier_invalid",
            "iOS peer Launch Services identifier is outside the fixed bound",
        )
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IOSPeerContractError(
            "ios_peer_launch_services_identifier_invalid",
            "iOS peer Launch Services identifier is not canonical base64",
        ) from error
    if not decoded or base64.b64encode(decoded).decode("ascii") != value:
        raise IOSPeerContractError(
            "ios_peer_launch_services_identifier_invalid",
            "iOS peer Launch Services identifier is not canonical base64",
        )
    return value


def _require_remote_executable_path(value: object) -> str:
    expected_suffix = f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}"
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or not value.endswith(expected_suffix)
        or "\x00" in value
        or "//" in value
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise IOSPeerContractError(
            "ios_peer_process_invalid",
            "iOS peer executable path is not the fixed remote app executable",
        )
    return value


def _require_private_destination(
    path: Path, *, expected_name: str, allow_role_suffix: bool = False
) -> None:
    stem = expected_name.removesuffix(".json")
    accepted_name = (
        re.fullmatch(
            rf"{re.escape(stem)}(?:-[a-z][a-z0-9-]{{0,31}})?\.json",
            path.name if isinstance(path, Path) else "",
        )
        if allow_role_suffix
        else path.name == expected_name
        if isinstance(path, Path)
        else False
    )
    if not isinstance(path, Path) or not path.is_absolute() or not accepted_name:
        raise IOSPeerContractError(
            "ios_peer_output_path_invalid", "iOS peer output destination is not fixed"
        )
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise IOSPeerContractError(
            "ios_peer_output_path_invalid", "iOS peer output parent is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or path.parent.is_symlink()
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise IOSPeerContractError(
            "ios_peer_output_path_invalid",
            "iOS peer output parent is not a collector-owned private directory",
        )
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise IOSPeerContractError(
            "ios_peer_output_path_invalid", "iOS peer output destination is unavailable"
        ) from error
    raise IOSPeerContractError(
        "ios_peer_output_path_invalid",
        "iOS peer output destination must not exist before the command",
    )


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise IOSPeerContractError(
            "ios_peer_digest_invalid", f"{label} must be one lowercase SHA-256"
        )
    return value


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise IOSPeerContractError(
            "ios_peer_time_invalid", f"{label} is not a canonical UTC timestamp"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise IOSPeerContractError(
            "ios_peer_time_invalid", f"{label} is not a real UTC timestamp"
        ) from error
    return parsed


def _load_canonical_document(
    data: bytes, fields: set[str], label: str
) -> dict[str, object]:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_JSON_BYTES:
        raise IOSPeerContractError(
            "ios_peer_receipt_invalid", f"{label} size is outside the fixed bound"
        )
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise IOSPeerContractError(
            "ios_peer_receipt_invalid",
            f"{label} is not one newline-terminated document",
        )
    try:
        document = exact_object(load_json_bytes(data, label), fields, label)
    except (TypeError, ValueError) as error:
        raise IOSPeerContractError(
            "ios_peer_receipt_invalid",
            f"{label} has unknown, missing, or invalid fields",
        ) from error
    if canonical_json(document) + b"\n" != data:
        raise IOSPeerContractError(
            "ios_peer_receipt_invalid", f"{label} is not canonical JSON"
        )
    return document


def _validate_controlled_wifi_network(
    value: object, *, label: str, error_code: str
) -> dict[str, object]:
    try:
        network = exact_object(value, _NETWORK_FIELDS, label)
        address = ipaddress.IPv4Address(network["ipv4"])
    except (TypeError, ValueError) as error:
        raise IOSPeerContractError(
            error_code, f"{label} is not one exact canonical IPv4 object"
        ) from error
    controlled_networks = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if (
        network["interface_name"] != "en0"
        or network["ipv4"] != str(address)
        or not any(address in subnet for subnet in controlled_networks)
    ):
        raise IOSPeerContractError(
            error_code, f"{label} differs from the fixed Wi-Fi IPv4 policy"
        )
    return network


@dataclass(frozen=True, slots=True)
class IOSPeerDevice:
    """Separate CoreDevice and provisioning selectors for one physical iPhone."""

    core_device_identifier: str
    core_device_identifier_sha256: str
    provisioning_udid: str
    provisioning_udid_sha256: str

    def __post_init__(self) -> None:
        core_device_identifier = _canonical_device_identifier(
            self.core_device_identifier
        )
        provisioning_udid = _canonical_provisioning_udid(self.provisioning_udid)
        expected_core = _sha256_domain(
            b"cfm-ios-transport-peer-core-device-v1\x00", core_device_identifier
        )
        expected_provisioning = _sha256_domain(
            b"cfm-ios-transport-peer-provisioning-udid-v1\x00", provisioning_udid
        )
        if (
            self.core_device_identifier_sha256 != expected_core
            or self.provisioning_udid_sha256 != expected_provisioning
        ):
            raise IOSPeerContractError(
                "ios_peer_device_invalid",
                "iOS peer device hashes do not bind both explicit selectors",
            )


@dataclass(frozen=True, slots=True)
class IOSPeerArtifact:
    """The exact signed test app selected for a later physical transaction."""

    app_path: Path
    executable_sha256: str
    app_tree_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.app_path, Path)
            or not self.app_path.is_absolute()
            or self.app_path.name != f"{APP_EXECUTABLE}.app"
            or self.app_path.is_symlink()
        ):
            raise IOSPeerContractError(
                "ios_peer_artifact_invalid",
                "iOS peer app path is not the fixed absolute bundle",
            )
        _require_digest(self.executable_sha256, "iOS peer executable digest")
        _require_digest(self.app_tree_sha256, "iOS peer app-tree digest")


@dataclass(frozen=True, slots=True)
class IOSPeerPreflight:
    """Proof that this exact test bundle was absent before the owned install."""

    device_identifier_sha256: str
    app_inventory_receipt_sha256: str
    process_inventory_receipt_sha256: str
    observed_at: str
    app_absent: bool
    process_absent: bool

    def __post_init__(self) -> None:
        _require_digest(
            self.device_identifier_sha256, "iOS peer preflight device digest"
        )
        _require_digest(
            self.app_inventory_receipt_sha256, "iOS peer app-inventory receipt digest"
        )
        _require_digest(
            self.process_inventory_receipt_sha256,
            "iOS peer process-inventory receipt digest",
        )
        _parse_timestamp(self.observed_at, "iOS peer preflight observation")
        if self.app_absent is not True or self.process_absent is not True:
            raise IOSPeerContractError(
                "ios_peer_preexisting_app",
                "the iOS peer app or executable already existed before this transaction",
            )


@dataclass(frozen=True, slots=True)
class IOSPeerInstallationOwnership:
    """Receipt-bound authority to operate on, and later remove, one owned app."""

    device_identifier_sha256: str
    app_tree_sha256: str
    install_receipt_sha256: str
    app_inventory_receipt_sha256: str
    launch_services_identifier: str
    installed_at: str

    def __post_init__(self) -> None:
        _require_digest(self.device_identifier_sha256, "iOS peer install device digest")
        _require_digest(self.app_tree_sha256, "iOS peer installed app-tree digest")
        _require_digest(self.install_receipt_sha256, "iOS peer install receipt digest")
        _require_digest(
            self.app_inventory_receipt_sha256,
            "iOS peer post-install app-inventory receipt digest",
        )
        _require_launch_services_identifier(self.launch_services_identifier)
        _parse_timestamp(self.installed_at, "iOS peer install time")


@dataclass(frozen=True, slots=True)
class IOSPeerCleanupOnlyInstallationOwnership:
    """Uninstall-only authority after an ambiguous owned install attempt."""

    device_identifier_sha256: str
    app_tree_sha256: str
    preflight_app_inventory_receipt_sha256: str
    install_intent_event_sha256: str
    post_intent_app_inventory_receipt_sha256: str
    installation_path: str
    observed_at: str

    def __post_init__(self) -> None:
        _require_digest(self.device_identifier_sha256, "cleanup-only device digest")
        _require_digest(self.app_tree_sha256, "cleanup-only app-tree digest")
        _require_digest(
            self.preflight_app_inventory_receipt_sha256,
            "cleanup-only preflight inventory digest",
        )
        _require_digest(
            self.install_intent_event_sha256, "cleanup-only install intent digest"
        )
        _require_digest(
            self.post_intent_app_inventory_receipt_sha256,
            "cleanup-only post-intent inventory digest",
        )
        expected_suffix = f"/{APP_EXECUTABLE}.app"
        if (
            not isinstance(self.installation_path, str)
            or not self.installation_path.startswith("/")
            or not self.installation_path.endswith(expected_suffix)
            or "//" in self.installation_path
            or any(part in {".", ".."} for part in self.installation_path.split("/"))
        ):
            raise IOSPeerContractError(
                "ios_peer_cleanup_install_ownership_invalid",
                "cleanup-only installation path is invalid",
            )
        _parse_timestamp(self.observed_at, "cleanup-only install observation")


@dataclass(frozen=True, slots=True)
class IOSPeerPrimerProcessOwnership:
    """Primer launch, full-inventory, and canonical receipt binding."""

    device_identifier_sha256: str
    app_tree_sha256: str
    process_id: int
    launch_services_identifier: str
    executable_path: str
    launch_receipt_sha256: str
    process_inventory_receipt_sha256: str
    primer_receipt_sha256: str

    def __post_init__(self) -> None:
        _require_digest(
            self.device_identifier_sha256, "iOS primer process device digest"
        )
        _require_digest(self.app_tree_sha256, "iOS primer process app-tree digest")
        _require_launch_services_identifier(self.launch_services_identifier)
        _require_remote_executable_path(self.executable_path)
        _require_digest(self.launch_receipt_sha256, "iOS primer launch receipt digest")
        _require_digest(
            self.process_inventory_receipt_sha256,
            "iOS primer process-inventory receipt digest",
        )
        _require_digest(
            self.primer_receipt_sha256, "iOS primer lifecycle receipt digest"
        )
        if type(self.process_id) is not int or not 1 <= self.process_id <= MAX_PID:
            raise IOSPeerContractError(
                "ios_peer_primer_process_invalid",
                "iOS primer process ID is outside the fixed bound",
            )


@dataclass(frozen=True, slots=True)
class IOSPeerPrimerProcessCleanupAuthority:
    """Fresh full-inventory authority for the primer's exact PID only."""

    process: IOSPeerPrimerProcessOwnership
    revalidated_process_inventory_receipt_sha256: str
    revalidated_primer_receipt_sha256: str
    observed_at: str

    def __post_init__(self) -> None:
        if type(self.process) is not IOSPeerPrimerProcessOwnership:
            raise IOSPeerContractError(
                "ios_peer_primer_cleanup_authority_invalid",
                "iOS primer cleanup lacks typed process ownership",
            )
        _require_digest(
            self.revalidated_process_inventory_receipt_sha256,
            "iOS primer cleanup inventory receipt digest",
        )
        _require_digest(
            self.revalidated_primer_receipt_sha256,
            "iOS primer cleanup lifecycle receipt digest",
        )
        if self.revalidated_primer_receipt_sha256 != self.process.primer_receipt_sha256:
            raise IOSPeerContractError(
                "ios_peer_primer_cleanup_authority_invalid",
                "iOS primer cleanup receipt no longer identifies the process",
            )
        _parse_timestamp(self.observed_at, "iOS primer cleanup observation")


@dataclass(frozen=True, slots=True)
class PrimerStoppedOwnership:
    """Proof that one owned primer PID was terminated and is now absent."""

    process: IOSPeerPrimerProcessOwnership
    terminate_receipt_sha256: str
    post_terminate_process_inventory_receipt_sha256: str
    stopped_at: str
    process_absent: bool

    def __post_init__(self) -> None:
        if type(self.process) is not IOSPeerPrimerProcessOwnership:
            raise IOSPeerContractError(
                "ios_peer_primer_stopped_invalid",
                "stopped primer lacks typed process ownership",
            )
        _require_digest(
            self.terminate_receipt_sha256, "iOS primer terminate receipt digest"
        )
        _require_digest(
            self.post_terminate_process_inventory_receipt_sha256,
            "iOS primer stopped process-inventory receipt digest",
        )
        _parse_timestamp(self.stopped_at, "iOS primer stopped observation")
        if self.process_absent is not True:
            raise IOSPeerContractError(
                "ios_peer_primer_stopped_invalid",
                "iOS primer exact PID absence is unproven",
            )


@dataclass(frozen=True, slots=True)
class IOSPeerProcessOwnership:
    """Launch, full-inventory, and ready-receipt binding for one generation."""

    device_identifier_sha256: str
    app_tree_sha256: str
    session_id: str
    process_id: int
    launch_services_identifier: str
    executable_path: str
    launch_receipt_sha256: str
    process_inventory_receipt_sha256: str
    ready_receipt_sha256: str

    def __post_init__(self) -> None:
        _require_digest(self.device_identifier_sha256, "iOS peer process device digest")
        _require_digest(self.app_tree_sha256, "iOS peer process app-tree digest")
        _require_digest(self.session_id, "iOS peer process session ID")
        _require_launch_services_identifier(self.launch_services_identifier)
        _require_remote_executable_path(self.executable_path)
        _require_digest(self.launch_receipt_sha256, "iOS peer launch receipt digest")
        _require_digest(
            self.process_inventory_receipt_sha256,
            "iOS peer launched process-inventory receipt digest",
        )
        _require_digest(self.ready_receipt_sha256, "iOS peer ready receipt digest")
        if type(self.process_id) is not int or not 1 <= self.process_id <= MAX_PID:
            raise IOSPeerContractError(
                "ios_peer_process_invalid",
                "iOS peer process ID is outside the fixed bound",
            )


@dataclass(frozen=True, slots=True)
class IOSPeerProcessCleanupAuthority:
    """Fresh full-inventory authority for exceptional exact-PID cleanup only."""

    process: IOSPeerProcessOwnership
    revalidated_process_inventory_receipt_sha256: str
    revalidated_ready_receipt_sha256: str
    observed_at: str

    def __post_init__(self) -> None:
        if type(self.process) is not IOSPeerProcessOwnership:
            raise IOSPeerContractError(
                "ios_peer_cleanup_authority_invalid",
                "iOS peer cleanup authority lacks exact process ownership",
            )
        _require_digest(
            self.revalidated_process_inventory_receipt_sha256,
            "iOS peer cleanup inventory receipt digest",
        )
        _require_digest(
            self.revalidated_ready_receipt_sha256,
            "iOS peer cleanup ready receipt digest",
        )
        if self.revalidated_ready_receipt_sha256 != self.process.ready_receipt_sha256:
            raise IOSPeerContractError(
                "ios_peer_cleanup_authority_invalid",
                "iOS peer cleanup ready receipt no longer identifies the launch generation",
            )
        _parse_timestamp(self.observed_at, "iOS peer cleanup observation")


def device_identifier_sha256(identifier: str) -> str:
    """Return the domain-separated hash for the CoreDevice UUID."""

    canonical = _canonical_device_identifier(identifier)
    return _sha256_domain(b"cfm-ios-transport-peer-core-device-v1\x00", canonical)


def provisioning_udid_sha256(identifier: str) -> str:
    """Return the distinct domain-separated hash for the provisioning UDID."""

    canonical = _canonical_provisioning_udid(identifier)
    return _sha256_domain(b"cfm-ios-transport-peer-provisioning-udid-v1\x00", canonical)


def _command(
    role: str,
    *arguments: str,
    cwd: Path,
    timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
    final_arguments: tuple[str, ...] = (),
) -> CommandSpec:
    return CommandSpec(
        role=role,
        argv=(
            str(XCRUN),
            "devicectl",
            *arguments,
            "--quiet",
            "--timeout",
            str(int(timeout_seconds)),
            *final_arguments,
        ),
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        stdout_limit=MAX_JSON_BYTES,
        stderr_limit=64 * 1024,
    )


def device_inventory_command(repository: Path, json_output: Path) -> CommandSpec:
    """Build the sole reviewed device-list command used for hashed selection."""

    if (
        not isinstance(repository, Path)
        or not repository.is_absolute()
        or repository.is_symlink()
        or not repository.is_dir()
    ):
        raise IOSPeerContractError(
            "ios_peer_repository_invalid", "iOS peer repository root is unavailable"
        )
    _require_private_destination(json_output, expected_name="device-list.json")
    return _command(
        "ios-peer-device-list",
        "list",
        "devices",
        "--omit-deprecated-fields-in-json",
        "--json-output",
        str(json_output),
        cwd=repository,
    )


@dataclass(frozen=True, slots=True)
class IOSPeerCommandPlan:
    """Pure factory for the sole reviewed ``devicectl`` command surface."""

    repository: Path
    device: IOSPeerDevice
    artifact: IOSPeerArtifact

    def __post_init__(self) -> None:
        if (
            not isinstance(self.repository, Path)
            or not self.repository.is_absolute()
            or self.repository.is_symlink()
            or not self.repository.is_dir()
        ):
            raise IOSPeerContractError(
                "ios_peer_repository_invalid", "iOS peer repository root is unavailable"
            )

    def _json_destination(self, path: Path, *, role: str) -> str:
        _require_private_destination(
            path, expected_name=f"{role}.json", allow_role_suffix=True
        )
        return str(path)

    def device_details(self, json_output: Path) -> CommandSpec:
        return _command(
            "ios-peer-device-details",
            "device",
            "info",
            "details",
            "--device",
            self.device.core_device_identifier,
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role="device-details"),
            cwd=self.repository,
        )

    def lock_state(self, json_output: Path) -> CommandSpec:
        return _command(
            "ios-peer-lock-state",
            "device",
            "info",
            "lockState",
            "--device",
            self.device.core_device_identifier,
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role="lock-state"),
            cwd=self.repository,
        )

    def app_inventory(self, json_output: Path) -> CommandSpec:
        return _command(
            "ios-peer-app-inventory",
            "device",
            "info",
            "apps",
            "--device",
            self.device.core_device_identifier,
            "--bundle-id",
            BUNDLE_IDENTIFIER,
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role="app-inventory"),
            cwd=self.repository,
        )

    def _require_preflight(self, preflight: IOSPeerPreflight) -> None:
        if (
            type(preflight) is not IOSPeerPreflight
            or preflight.device_identifier_sha256
            != self.device.core_device_identifier_sha256
        ):
            raise IOSPeerContractError(
                "ios_peer_preflight_invalid",
                "iOS peer preflight does not bind this device",
            )

    def _require_installation(self, ownership: IOSPeerInstallationOwnership) -> None:
        if (
            type(ownership) is not IOSPeerInstallationOwnership
            or ownership.device_identifier_sha256
            != self.device.core_device_identifier_sha256
            or ownership.app_tree_sha256 != self.artifact.app_tree_sha256
        ):
            raise IOSPeerContractError(
                "ios_peer_install_ownership_invalid",
                "iOS peer install ownership does not bind this app and device",
            )

    def _require_cleanup_only_installation(
        self, ownership: IOSPeerCleanupOnlyInstallationOwnership
    ) -> None:
        if (
            type(ownership) is not IOSPeerCleanupOnlyInstallationOwnership
            or ownership.device_identifier_sha256
            != self.device.core_device_identifier_sha256
            or ownership.app_tree_sha256 != self.artifact.app_tree_sha256
        ):
            raise IOSPeerContractError(
                "ios_peer_cleanup_install_ownership_invalid",
                "cleanup-only ownership does not bind this app and device",
            )

    def _require_process(self, ownership: IOSPeerProcessOwnership) -> None:
        if (
            type(ownership) is not IOSPeerProcessOwnership
            or ownership.device_identifier_sha256
            != self.device.core_device_identifier_sha256
            or ownership.app_tree_sha256 != self.artifact.app_tree_sha256
        ):
            raise IOSPeerContractError(
                "ios_peer_process_ownership_invalid",
                "iOS peer process ownership does not bind this app and device",
            )

    def _require_primer_process(self, ownership: IOSPeerPrimerProcessOwnership) -> None:
        if (
            type(ownership) is not IOSPeerPrimerProcessOwnership
            or ownership.device_identifier_sha256
            != self.device.core_device_identifier_sha256
            or ownership.app_tree_sha256 != self.artifact.app_tree_sha256
        ):
            raise IOSPeerContractError(
                "ios_peer_primer_process_invalid",
                "iOS primer process ownership does not bind this app and device",
            )

    def _require_primer_stopped(self, ownership: PrimerStoppedOwnership) -> None:
        if type(ownership) is not PrimerStoppedOwnership:
            raise IOSPeerContractError(
                "ios_peer_primer_stopped_invalid",
                "session copy requires typed stopped-primer ownership",
            )
        self._require_primer_process(ownership.process)

    def install(self, preflight: IOSPeerPreflight, json_output: Path) -> CommandSpec:
        self._require_preflight(preflight)
        return _command(
            "ios-peer-install",
            "device",
            "install",
            "app",
            "--device",
            self.device.core_device_identifier,
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role="install"),
            cwd=self.repository,
            timeout_seconds=INSTALL_TIMEOUT_SECONDS,
            final_arguments=(str(self.artifact.app_path),),
        )

    def copy_session_to_device(
        self,
        ownership: PrimerStoppedOwnership,
        host_session_directory: Path,
        json_output: Path,
    ) -> CommandSpec:
        return self._copy_session_directory_to_device(
            ownership=ownership,
            host_session_directory=host_session_directory,
            json_output=json_output,
            expected_name=SESSION_DIRECTORY_NAME,
            device_directory=DEVICE_SESSION_DIRECTORY,
            role="session-copy",
            error_code="ios_peer_session_directory_invalid",
            error_message="iOS peer session directory is not the fixed real directory",
        )

    def copy_packet_lan_session_to_device(
        self,
        ownership: PrimerStoppedOwnership,
        host_session_directory: Path,
        json_output: Path,
    ) -> CommandSpec:
        from .ios_packet_lan_peer import DEVICE_DIRECTORY, DIRECTORY_NAME

        return self._copy_session_directory_to_device(
            ownership=ownership,
            host_session_directory=host_session_directory,
            json_output=json_output,
            expected_name=DIRECTORY_NAME,
            device_directory=DEVICE_DIRECTORY,
            role="packet-lan-session-copy",
            error_code="ios_peer_packet_lan_directory_invalid",
            error_message=(
                "iOS packet LAN session directory is not the fixed real directory"
            ),
        )

    def _copy_session_directory_to_device(
        self,
        *,
        ownership: PrimerStoppedOwnership,
        host_session_directory: Path,
        json_output: Path,
        expected_name: str,
        device_directory: str,
        role: str,
        error_code: str,
        error_message: str,
    ) -> CommandSpec:
        self._require_primer_stopped(ownership)
        if (
            not isinstance(host_session_directory, Path)
            or not host_session_directory.is_absolute()
            or host_session_directory.name != expected_name
            or host_session_directory.is_symlink()
            or not host_session_directory.is_dir()
        ):
            raise IOSPeerContractError(error_code, error_message)
        return _command(
            f"ios-peer-{role}",
            "device",
            "copy",
            "to",
            "--device",
            self.device.core_device_identifier,
            "--source",
            str(host_session_directory),
            "--destination",
            device_directory,
            "--domain-type",
            "appDataContainer",
            "--domain-identifier",
            BUNDLE_IDENTIFIER,
            "--remove-existing-content",
            "false",
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role=role),
            cwd=self.repository,
            timeout_seconds=COPY_TIMEOUT_SECONDS,
        )

    def _launch_application(
        self,
        ownership: IOSPeerInstallationOwnership,
        json_output: Path,
        *,
        role: str,
        launch_argument: str,
    ) -> CommandSpec:
        self._require_installation(ownership)
        from .ios_packet_lan_peer import LAUNCH_ARGUMENT as PACKET_LAN_LAUNCH_ARGUMENT

        if launch_argument not in {
            PRIMER_LAUNCH_ARGUMENT,
            TRANSPORT_RUN_ARGUMENT,
            PACKET_LAN_LAUNCH_ARGUMENT,
        }:
            raise IOSPeerContractError(
                "ios_peer_launch_argument_invalid",
                "iOS peer launch argument is outside the closed mode set",
            )
        persistent_identifier_arguments = (
            ()
            if ownership.launch_services_identifier
            == UNKNOWN_LAUNCH_SERVICES_IDENTIFIER
            else (
                "--launch-persistent-identifier",
                ownership.launch_services_identifier,
            )
        )
        return _command(
            role,
            "device",
            "process",
            "launch",
            "--device",
            self.device.core_device_identifier,
            "--activate",
            *persistent_identifier_arguments,
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role=role.removeprefix("ios-peer-")),
            cwd=self.repository,
            final_arguments=(BUNDLE_IDENTIFIER, launch_argument),
        )

    def launch_primer(
        self, ownership: IOSPeerInstallationOwnership, json_output: Path
    ) -> CommandSpec:
        return self._launch_application(
            ownership,
            json_output,
            role="ios-peer-primer-launch",
            launch_argument=PRIMER_LAUNCH_ARGUMENT,
        )

    def launch_transport(
        self, ownership: IOSPeerInstallationOwnership, json_output: Path
    ) -> CommandSpec:
        return self._launch_application(
            ownership,
            json_output,
            role="ios-peer-transport-launch",
            launch_argument=TRANSPORT_RUN_ARGUMENT,
        )

    def launch_packet_lan(
        self, ownership: IOSPeerInstallationOwnership, json_output: Path
    ) -> CommandSpec:
        from .ios_packet_lan_peer import LAUNCH_ARGUMENT

        return self._launch_application(
            ownership,
            json_output,
            role="ios-peer-packet-lan-launch",
            launch_argument=LAUNCH_ARGUMENT,
        )

    def process_inventory(self, json_output: Path) -> CommandSpec:
        return _command(
            "ios-peer-process-inventory",
            "device",
            "info",
            "processes",
            "--device",
            self.device.core_device_identifier,
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role="process-inventory"),
            cwd=self.repository,
        )

    def copy_receipt_from_device(
        self,
        ownership: IOSPeerInstallationOwnership | IOSPeerProcessOwnership,
        name: str,
        destination: Path,
        json_output: Path,
    ) -> CommandSpec:
        return self._copy_mode_receipt_from_device(
            ownership=ownership,
            name=name,
            destination=destination,
            json_output=json_output,
            ready_name=READY_FILE_NAME,
            result_name=RESULT_FILE_NAME,
            device_directory=DEVICE_SESSION_DIRECTORY,
            role_prefix="",
            error_code="ios_peer_receipt_path_invalid",
            error_message="iOS peer receipt name is not reviewed",
        )

    def copy_packet_lan_receipt_from_device(
        self,
        ownership: IOSPeerInstallationOwnership | IOSPeerProcessOwnership,
        name: str,
        destination: Path,
        json_output: Path,
    ) -> CommandSpec:
        from .ios_packet_lan_peer import (
            DEVICE_DIRECTORY,
            READY_FILE_NAME as PACKET_READY_FILE_NAME,
            RESULT_FILE_NAME as PACKET_RESULT_FILE_NAME,
        )

        return self._copy_mode_receipt_from_device(
            ownership=ownership,
            name=name,
            destination=destination,
            json_output=json_output,
            ready_name=PACKET_READY_FILE_NAME,
            result_name=PACKET_RESULT_FILE_NAME,
            device_directory=DEVICE_DIRECTORY,
            role_prefix="packet-lan-",
            error_code="ios_peer_packet_lan_receipt_path_invalid",
            error_message="iOS packet LAN receipt name is not reviewed",
        )

    def _copy_mode_receipt_from_device(
        self,
        *,
        ownership: IOSPeerInstallationOwnership | IOSPeerProcessOwnership,
        name: str,
        destination: Path,
        json_output: Path,
        ready_name: str,
        result_name: str,
        device_directory: str,
        role_prefix: str,
        error_code: str,
        error_message: str,
    ) -> CommandSpec:
        if name not in {ready_name, result_name}:
            raise IOSPeerContractError(error_code, error_message)
        if type(ownership) is IOSPeerInstallationOwnership:
            if name != ready_name:
                raise IOSPeerContractError(
                    error_code,
                    "installation ownership may copy only the initial ready receipt",
                )
            self._require_installation(ownership)
        elif type(ownership) is IOSPeerProcessOwnership:
            self._require_process(ownership)
        else:
            raise IOSPeerContractError(
                error_code,
                "receipt copy lacks installation or process ownership",
            )
        _require_private_destination(destination, expected_name=name)
        role = f"{role_prefix}{name.removesuffix('.json')}-copy"
        return _command(
            f"ios-peer-{role}",
            "device",
            "copy",
            "from",
            "--device",
            self.device.core_device_identifier,
            "--source",
            f"{device_directory}/{name}",
            "--destination",
            str(destination),
            "--domain-type",
            "appDataContainer",
            "--domain-identifier",
            BUNDLE_IDENTIFIER,
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role=role),
            cwd=self.repository,
            timeout_seconds=COPY_TIMEOUT_SECONDS,
        )

    def copy_primer_receipt(
        self,
        ownership: IOSPeerInstallationOwnership,
        destination: Path,
        json_output: Path,
    ) -> CommandSpec:
        self._require_installation(ownership)
        _require_private_destination(destination, expected_name=PRIMER_RESULT_FILE_NAME)
        return _command(
            "ios-peer-primer-result-copy",
            "device",
            "copy",
            "from",
            "--device",
            self.device.core_device_identifier,
            "--source",
            f"{DEVICE_PRIMER_DIRECTORY}/{PRIMER_RESULT_FILE_NAME}",
            "--destination",
            str(destination),
            "--domain-type",
            "appDataContainer",
            "--domain-identifier",
            BUNDLE_IDENTIFIER,
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role="primer-result-copy"),
            cwd=self.repository,
            timeout_seconds=COPY_TIMEOUT_SECONDS,
        )

    def terminate(
        self,
        authority: IOSPeerProcessCleanupAuthority,
        json_output: Path,
    ) -> CommandSpec:
        if type(authority) is not IOSPeerProcessCleanupAuthority:
            raise IOSPeerContractError(
                "ios_peer_cleanup_authority_invalid",
                "iOS peer terminate requires fresh full-inventory authority",
            )
        self._require_process(authority.process)
        return _command(
            "ios-peer-terminate",
            "device",
            "process",
            "terminate",
            "--device",
            self.device.core_device_identifier,
            "--pid",
            str(authority.process.process_id),
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role="terminate"),
            cwd=self.repository,
        )

    def terminate_primer(
        self,
        authority: IOSPeerPrimerProcessCleanupAuthority,
        json_output: Path,
    ) -> CommandSpec:
        if type(authority) is not IOSPeerPrimerProcessCleanupAuthority:
            raise IOSPeerContractError(
                "ios_peer_primer_cleanup_authority_invalid",
                "iOS primer terminate requires fresh exact-process authority",
            )
        self._require_primer_process(authority.process)
        return _command(
            "ios-peer-primer-terminate",
            "device",
            "process",
            "terminate",
            "--device",
            self.device.core_device_identifier,
            "--pid",
            str(authority.process.process_id),
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role="primer-terminate"),
            cwd=self.repository,
        )

    def uninstall(
        self,
        ownership: IOSPeerInstallationOwnership
        | IOSPeerCleanupOnlyInstallationOwnership,
        json_output: Path,
    ) -> CommandSpec:
        if type(ownership) is IOSPeerInstallationOwnership:
            self._require_installation(ownership)
        elif type(ownership) is IOSPeerCleanupOnlyInstallationOwnership:
            self._require_cleanup_only_installation(ownership)
        else:
            raise IOSPeerContractError(
                "ios_peer_install_ownership_invalid",
                "uninstall requires normal or cleanup-only owned installation",
            )
        return _command(
            "ios-peer-uninstall",
            "device",
            "uninstall",
            "app",
            "--device",
            self.device.core_device_identifier,
            "--omit-deprecated-fields-in-json",
            "--json-output",
            self._json_destination(json_output, role="uninstall"),
            cwd=self.repository,
            final_arguments=(BUNDLE_IDENTIFIER,),
        )


def validate_primer_receipt(
    data: bytes, *, expected_process_id: int, now: datetime
) -> dict[str, object]:
    """Validate one fresh, canonical, fully closed primer lifecycle receipt."""

    if type(expected_process_id) is not int or not 1 <= expected_process_id <= MAX_PID:
        raise IOSPeerContractError(
            "ios_peer_primer_process_invalid",
            "expected iOS primer process ID is outside the fixed bound",
        )
    document = _load_canonical_document(
        data, _PRIMER_RESULT_FIELDS, "iOS local-network primer receipt"
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
        or document["document"] != PRIMER_RESULT_DOCUMENT
        or document["mode"] != PRIMER_MODE
        or document["claim_eligible"] is not False
        or document["bundle_identifier"] != BUNDLE_IDENTIFIER
        or type(document["process_id"]) is not int
        or document["process_id"] != expected_process_id
        or document["service_registered"] is not True
        or document["listener_ready"] is not True
        or document["listener_cancelled"] is not True
    ):
        raise IOSPeerContractError(
            "ios_peer_primer_invalid",
            "iOS local-network primer identity or lifecycle proof differs",
        )
    started = _parse_timestamp(document["started_at"], "iOS primer start")
    registered = _parse_timestamp(
        document["service_registered_at"], "iOS primer service registration"
    )
    ready = _parse_timestamp(document["listener_ready_at"], "iOS primer listener ready")
    cancelled = _parse_timestamp(
        document["listener_cancelled_at"], "iOS primer listener cancellation"
    )
    if now.tzinfo is None or now.utcoffset() is None:
        raise IOSPeerContractError(
            "ios_peer_time_invalid", "iOS primer validation time must be timezone-aware"
        )
    current = now.astimezone(timezone.utc)
    if (
        not started <= registered <= cancelled
        or not started <= ready <= cancelled
        or cancelled > current
        or (current - started).total_seconds() > MAX_SESSION_SECONDS
    ):
        raise IOSPeerContractError(
            "ios_peer_primer_stale",
            "iOS local-network primer lifecycle is stale or out of order",
        )
    _validate_controlled_wifi_network(
        document["network"],
        label="iOS primer network",
        error_code="ios_peer_primer_invalid",
    )
    try:
        listener = exact_object(
            document["listener"], _PRIMER_LISTENER_FIELDS, "iOS primer listener"
        )
    except (TypeError, ValueError) as error:
        raise IOSPeerContractError(
            "ios_peer_primer_invalid",
            "iOS primer listener has unknown or missing fields",
        ) from error
    if type(listener["port"]) is not int or listener != {
        "port": PRIMER_PORT,
        "transport": "tcp4",
        "bonjour_name": PRIMER_BONJOUR_NAME,
        "bonjour_type": PRIMER_BONJOUR_TYPE,
        "bonjour_domain": PRIMER_BONJOUR_DOMAIN,
    }:
        raise IOSPeerContractError(
            "ios_peer_primer_invalid",
            "iOS primer listener differs from the fixed Bonjour policy",
        )
    return document


def validate_session_document(data: bytes, *, now: datetime) -> dict[str, object]:
    document = _load_canonical_document(data, _SESSION_FIELDS, "iOS peer session")
    if (
        document["schema_version"] != SCHEMA_VERSION
        or document["document"] != SESSION_DOCUMENT
    ):
        raise IOSPeerContractError(
            "ios_peer_session_invalid", "iOS peer session schema or document differs"
        )
    if (
        not isinstance(document["session_id"], str)
        or _HEX_64.fullmatch(document["session_id"]) is None
    ):
        raise IOSPeerContractError(
            "ios_peer_session_invalid", "iOS peer session ID is not one lowercase nonce"
        )
    created = _parse_timestamp(document["created_at"], "iOS peer session creation")
    expires = _parse_timestamp(document["expires_at"], "iOS peer session expiry")
    if now.tzinfo is None or now.utcoffset() is None:
        raise IOSPeerContractError(
            "ios_peer_time_invalid", "iOS peer validation time must be timezone-aware"
        )
    current = now.astimezone(timezone.utc)
    if (
        not created <= current < expires
        or (expires - created).total_seconds() > 15 * 60
    ):
        raise IOSPeerContractError(
            "ios_peer_session_expired",
            "iOS peer session is stale or exceeds its lifetime",
        )
    _require_digest(document["certificate_sha256"], "iOS peer certificate digest")
    _require_digest(document["private_key_sha256"], "iOS peer private-key digest")
    return document


def _validate_listener(
    value: object, *, label: str, port: int, transport: str, alpn: str | None
) -> dict[str, object]:
    try:
        listener = exact_object(value, _LISTENER_FIELDS, label)
    except (TypeError, ValueError) as error:
        raise IOSPeerContractError(
            "ios_peer_ready_invalid", f"{label} has unknown or missing fields"
        ) from error
    if listener != {"port": port, "transport": transport, "alpn": alpn}:
        raise IOSPeerContractError(
            "ios_peer_ready_invalid", f"{label} differs from the fixed transport policy"
        )
    return listener


def validate_ready_receipt(
    data: bytes,
    *,
    expected_session_id: str,
    expected_certificate_sha256: str,
    now: datetime,
) -> dict[str, object]:
    document = _load_canonical_document(data, _READY_FIELDS, "iOS peer ready receipt")
    if (
        document["schema_version"] != SCHEMA_VERSION
        or document["document"] != READY_DOCUMENT
        or document["session_id"] != expected_session_id
        or document["bundle_identifier"] != BUNDLE_IDENTIFIER
        or document["certificate_sha256"] != expected_certificate_sha256
        or type(document["process_id"]) is not int
        or not 1 <= document["process_id"] <= MAX_PID
    ):
        raise IOSPeerContractError(
            "ios_peer_ready_invalid", "iOS peer ready receipt identity differs"
        )
    _require_digest(expected_session_id, "expected iOS peer session ID")
    _require_digest(expected_certificate_sha256, "expected iOS peer certificate digest")
    started = _parse_timestamp(document["started_at"], "iOS peer start")
    expires = _parse_timestamp(document["expires_at"], "iOS peer expiry")
    if now.tzinfo is None or now.utcoffset() is None:
        raise IOSPeerContractError(
            "ios_peer_time_invalid", "iOS peer validation time must be timezone-aware"
        )
    current = now.astimezone(timezone.utc)
    if (
        not started <= current < expires
        or (expires - started).total_seconds() > 15 * 60
    ):
        raise IOSPeerContractError(
            "ios_peer_ready_expired", "iOS peer ready receipt is stale"
        )
    try:
        listeners = exact_object(
            document["listeners"],
            {"tcp_sink", "tls13_echo", "quic_echo"},
            "iOS peer listeners",
        )
    except (TypeError, ValueError) as error:
        raise IOSPeerContractError(
            "ios_peer_ready_invalid",
            "iOS peer listeners have unknown or missing fields",
        ) from error
    _validate_controlled_wifi_network(
        document["network"],
        label="iOS peer network",
        error_code="ios_peer_ready_invalid",
    )
    _validate_listener(
        listeners["tcp_sink"],
        label="iOS TCP sink",
        port=TCP_SINK_PORT,
        transport="tcp4",
        alpn=None,
    )
    _validate_listener(
        listeners["tls13_echo"],
        label="iOS TLS echo",
        port=TLS13_ECHO_PORT,
        transport="tls13-tcp4",
        alpn=TLS_ALPN,
    )
    _validate_listener(
        listeners["quic_echo"],
        label="iOS QUIC echo",
        port=QUIC_ECHO_PORT,
        transport="quic-tls13",
        alpn=QUIC_ALPN,
    )
    return document


def validate_result_receipt(
    data: bytes,
    *,
    expected_session_id: str,
    expected_certificate_sha256: str,
    expected_process_id: int,
) -> dict[str, object]:
    document = _load_canonical_document(data, _RESULT_FIELDS, "iOS peer result receipt")
    if (
        document["schema_version"] != RESULT_SCHEMA_VERSION
        or document["document"] != RESULT_DOCUMENT
        or document["evidence_role"] != "server_observation_only"
        or document["claim_eligible"] is not False
        or document["session_id"] != expected_session_id
        or document["certificate_sha256"] != expected_certificate_sha256
        or document["bundle_identifier"] != BUNDLE_IDENTIFIER
        or document["process_id"] != expected_process_id
        or not isinstance(document["status"], str)
        or document["status"] not in _RESULT_STATUSES
        or not isinstance(document["failure_phase"], str)
        or document["failure_phase"] not in _FAILURE_PHASES
        or not isinstance(document["failed_service"], str)
        or document["failed_service"] not in _FAILED_SERVICES
        or not isinstance(document["failure_reason"], str)
        or document["failure_reason"] not in _FAILURE_REASONS
        or not isinstance(document["phase_reached"], str)
        or document["phase_reached"] not in _PHASES_REACHED
        or type(document["listeners_closed"]) is not bool
        or type(document["identity_files_removed"]) is not bool
    ):
        raise IOSPeerContractError(
            "ios_peer_result_invalid", "iOS peer result receipt identity differs"
        )
    _require_digest(expected_session_id, "expected iOS peer session ID")
    _require_digest(expected_certificate_sha256, "expected iOS peer certificate")
    if type(expected_process_id) is not int or not 1 <= expected_process_id <= MAX_PID:
        raise IOSPeerContractError(
            "ios_peer_process_invalid", "expected iOS peer process ID is invalid"
        )
    _parse_timestamp(document["completed_at"], "iOS peer completion")
    blocking_service = document["blocking_service"]
    blocking_phase = document["blocking_phase"]
    blocking_admission_sequence = document["blocking_admission_sequence"]
    incoming_admission_sequence = document["incoming_admission_sequence"]
    incoming_matches_blocker_object = document["incoming_matches_blocker_object"]
    blocking_quic_stream_identifier = document["blocking_quic_stream_identifier"]
    required_overlap_values = (
        blocking_service,
        blocking_phase,
        blocking_admission_sequence,
        incoming_admission_sequence,
        incoming_matches_blocker_object,
    )
    overlap_observation_present = all(
        value is not None for value in required_overlap_values
    )
    if (
        overlap_observation_present
        != (document["failure_reason"] == "connection_admission_overlap")
        or not overlap_observation_present
        and any(value is not None for value in required_overlap_values)
        or not overlap_observation_present
        and blocking_quic_stream_identifier is not None
    ):
        raise IOSPeerContractError(
            "ios_peer_result_invalid",
            "iOS peer admission overlap observation is incomplete",
        )
    if overlap_observation_present:
        if (
            not isinstance(blocking_service, str)
            or blocking_service not in _CONNECTION_FIELDS
            or not isinstance(blocking_phase, str)
            or blocking_phase not in _PHASE_RANKS
        ):
            raise IOSPeerContractError(
                "ios_peer_result_invalid",
                "iOS peer admission overlap blocker is incoherent",
            )
        blocking_phase_rank = _PHASE_RANKS[blocking_phase]
        if (
            not _PHASE_RANKS["connection_accepted"]
            <= blocking_phase_rank
            <= _PHASE_RANKS["delivery_evidence_observed"]
            or type(blocking_admission_sequence) is not int
            or type(incoming_admission_sequence) is not int
            or type(incoming_matches_blocker_object) is not bool
            or not 0 < blocking_admission_sequence < incoming_admission_sequence
            or incoming_admission_sequence > MAX_CONNECTIONS
            or incoming_matches_blocker_object
            and blocking_service != document["failed_service"]
            or blocking_quic_stream_identifier is not None
            and (
                type(blocking_quic_stream_identifier) is not int
                or not 0 <= blocking_quic_stream_identifier < 2**62
                or blocking_service != "quic_echo"
                or blocking_phase_rank < _PHASE_RANKS["security_ready"]
            )
        ):
            raise IOSPeerContractError(
                "ios_peer_result_invalid",
                "iOS peer admission overlap observation is incoherent",
            )
    try:
        connections = exact_object(
            document["connections"], _CONNECTION_FIELDS, "iOS peer connection results"
        )
    except (TypeError, ValueError) as error:
        raise IOSPeerContractError(
            "ios_peer_result_invalid", "iOS peer connection results differ"
        ) from error
    total_accepted = 0
    for service in sorted(_CONNECTION_FIELDS):
        try:
            outcome = exact_object(
                connections[service],
                _CONNECTION_RESULT_FIELDS,
                f"iOS peer {service} result",
            )
        except (TypeError, ValueError) as error:
            raise IOSPeerContractError(
                "ios_peer_result_invalid", f"iOS peer {service} result differs"
            ) from error
        accepted = outcome["accepted"]
        evidence_disposition = outcome["evidence_disposition"]
        bytes_received = outcome["bytes_received"]
        bytes_sent = outcome["bytes_sent"]
        control_bytes_received = outcome["control_bytes_received"]
        control_bytes_submitted = outcome["control_bytes_submitted"]
        confirmation_completion = outcome["delivery_confirmation_completion"]
        peer_terminal_observed = outcome["peer_terminal_observed"]
        acknowledgement_final_context_observed = outcome[
            "delivery_acknowledgement_final_context_observed"
        ]
        transport = outcome["transport"]
        tls_version = outcome["tls_version"]
        cipher_suite = outcome["cipher_suite"]
        alpn = outcome["alpn"]
        early_data_accepted = outcome["early_data_accepted"]
        payload_sha256 = outcome["payload_sha256"]
        if (
            type(accepted) is not int
            or accepted not in {0, 1}
            or not isinstance(evidence_disposition, str)
            or evidence_disposition not in _EVIDENCE_DISPOSITIONS
            or type(bytes_received) is not int
            or bytes_received < 0
            or type(bytes_sent) is not int
            or bytes_sent < 0
            or type(control_bytes_received) is not int
            or control_bytes_received < 0
            or type(control_bytes_submitted) is not int
            or control_bytes_submitted < 0
            or (
                confirmation_completion is not None
                and (
                    not isinstance(confirmation_completion, str)
                    or confirmation_completion not in _CONFIRMATION_COMPLETIONS
                )
            )
            or type(peer_terminal_observed) is not bool
            or type(acknowledgement_final_context_observed) is not bool
            or (transport is not None and not isinstance(transport, str))
            or (
                payload_sha256 is not None
                and (
                    not isinstance(payload_sha256, str)
                    or _HEX_64.fullmatch(payload_sha256) is None
                )
            )
        ):
            raise IOSPeerContractError(
                "ios_peer_result_invalid", f"iOS peer {service} counters are invalid"
            )
        expected_payload_sha256 = transport_payload_receipt_sha256(
            service, expected_session_id
        )
        observation_is_resolved = evidence_disposition in {
            "accepted",
            "pair_required",
        }
        digest_is_coherent = (
            payload_sha256 == expected_payload_sha256
            if observation_is_resolved
            else payload_sha256 is None
        )
        if service == "tcp_sink":
            accepted_tcp = evidence_disposition == "accepted"
            byte_counts_are_coherent = (
                evidence_disposition != "pair_required"
                and accepted == int(accepted_tcp)
                and bytes_received == (32 if accepted_tcp else 0)
                and bytes_sent == 0
                and control_bytes_received == 0
                and control_bytes_submitted == 0
                and confirmation_completion is None
                and peer_terminal_observed is accepted_tcp
                and acknowledgement_final_context_observed is False
                and transport == ("tcp4" if accepted_tcp else None)
                and tls_version is None
                and cipher_suite is None
                and alpn is None
                and early_data_accepted is None
            )
        else:
            expected_transport = (
                "tls13-tcp4" if service == "tls13_echo" else "quic-tls13"
            )
            expected_alpn = TLS_ALPN if service == "tls13_echo" else QUIC_ALPN
            if evidence_disposition == "pair_required":
                completion_is_coherent = accepted == 0 and confirmation_completion in {
                    "processed",
                    "failed",
                    "unobserved",
                }
            elif evidence_disposition == "unobserved":
                completion_is_coherent = (
                    accepted == 0 and confirmation_completion is None
                )
            else:
                completion_is_coherent = False
            byte_counts_are_coherent = (
                completion_is_coherent
                and bytes_received == (32 if observation_is_resolved else 0)
                and bytes_sent == (34 if observation_is_resolved else 0)
                and control_bytes_received == int(observation_is_resolved)
                and control_bytes_submitted == int(observation_is_resolved)
                and peer_terminal_observed is False
                and acknowledgement_final_context_observed is observation_is_resolved
                and transport
                == (expected_transport if observation_is_resolved else None)
                and (
                    observation_is_resolved
                    and tls_version == 0x0304
                    and type(cipher_suite) is int
                    and 0x1301 <= cipher_suite <= 0x1305
                    and alpn == expected_alpn
                    and early_data_accepted is False
                    or not observation_is_resolved
                    and tls_version is None
                    and cipher_suite is None
                    and alpn is None
                    and early_data_accepted is None
                )
            )
        if not digest_is_coherent or not byte_counts_are_coherent:
            raise IOSPeerContractError(
                "ios_peer_result_invalid",
                f"iOS peer {service} counters are internally inconsistent",
            )
        total_accepted += accepted
    if total_accepted > MAX_CONNECTIONS:
        raise IOSPeerContractError(
            "ios_peer_result_invalid",
            "iOS peer result exceeds the session connection bound",
        )
    dispositions = {
        service: connections[service]["evidence_disposition"]
        for service in _CONNECTION_FIELDS
    }
    cleanup_is_complete = (
        document["listeners_closed"] is True
        and document["identity_files_removed"] is True
    )
    admission_failure_is_coherent = (
        document["failure_reason"] == "connection_admission_overlap"
    ) == (document["failure_phase"] == "connection_admission")
    failure_binding_is_coherent = (
        document["failure_reason"] in _RUNTIME_FAILURE_REASONS
        and document["failed_service"] == "runtime"
        or document["failure_reason"] in _SECURE_DELIVERY_FAILURE_REASONS
        and document["failed_service"] in {"tls13_echo", "quic_echo"}
        or document["failure_reason"] in _SERVICE_FAILURE_REASONS
        and document["failed_service"] in _CONNECTION_FIELDS
        or document["failure_reason"] in _ANY_SCOPED_FAILURE_REASONS
        and document["failed_service"] != "none"
    )
    status_is_coherent = (
        document["status"] == "closed"
        and document["failure_phase"] == "none"
        and document["failed_service"] == "none"
        and document["failure_reason"] == "none"
        and document["phase_reached"] == "completed"
        and cleanup_is_complete
        and all(value == "accepted" for value in dispositions.values())
        or document["status"] == "pair_required"
        and document["failure_phase"] == "none"
        and document["failed_service"] == "none"
        and document["failure_reason"] == "none"
        and document["phase_reached"] == "completed"
        and cleanup_is_complete
        and all(
            value in {"accepted", "pair_required"} for value in dispositions.values()
        )
        and any(value == "pair_required" for value in dispositions.values())
        or document["status"] == "failed"
        and document["failure_phase"] != "none"
        and document["failed_service"] != "none"
        and document["failure_reason"] != "none"
        and document["phase_reached"] != "completed"
        and failure_binding_is_coherent
        and admission_failure_is_coherent
    )
    if not status_is_coherent:
        raise IOSPeerContractError(
            "ios_peer_cleanup_unproven",
            "iOS peer result status, evidence, or cleanup proof is incoherent",
        )
    return document


__all__ = [
    "APP_EXECUTABLE",
    "BUNDLE_IDENTIFIER",
    "CERTIFICATE_FILE_NAME",
    "PRIMER_BONJOUR_DOMAIN",
    "PRIMER_BONJOUR_NAME",
    "PRIMER_BONJOUR_TYPE",
    "PRIMER_LAUNCH_ARGUMENT",
    "PRIMER_MODE",
    "PRIMER_PORT",
    "PRIMER_RESULT_DOCUMENT",
    "PRIMER_RESULT_FILE_NAME",
    "PRIVATE_KEY_FILE_NAME",
    "QUIC_ALPN",
    "QUIC_ECHO_PORT",
    "READY_FILE_NAME",
    "RESULT_FILE_NAME",
    "SESSION_DIRECTORY_NAME",
    "SESSION_DOCUMENT",
    "SESSION_FILE_NAME",
    "TCP_SINK_PORT",
    "TLS13_ECHO_PORT",
    "TLS_ALPN",
    "TRANSPORT_RUN_ARGUMENT",
    "IOSPeerArtifact",
    "IOSPeerCleanupOnlyInstallationOwnership",
    "IOSPeerCommandPlan",
    "IOSPeerContractError",
    "IOSPeerDevice",
    "IOSPeerInstallationOwnership",
    "IOSPeerPreflight",
    "IOSPeerPrimerProcessCleanupAuthority",
    "IOSPeerPrimerProcessOwnership",
    "IOSPeerProcessCleanupAuthority",
    "IOSPeerProcessOwnership",
    "PrimerStoppedOwnership",
    "device_identifier_sha256",
    "provisioning_udid_sha256",
    "transport_payload_receipt_sha256",
    "validate_primer_receipt",
    "validate_ready_receipt",
    "validate_result_receipt",
    "validate_session_document",
]
