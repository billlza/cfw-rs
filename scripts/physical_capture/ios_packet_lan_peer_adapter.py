"""Fail-closed lifecycle adapter for the test-only iPhone Packet LAN peer.

The source identity contains only domain-separated device hashes.  Every run
discovers the matching physical iPhone from a fresh CoreDevice inventory,
revalidates the signed arm64 test bundle, proves that the bundle and process
were absent, and then owns the complete install/primer/session/process/cleanup
lifecycle.  Raw device selectors remain inside a private temporary workspace
and never enter Packet provenance.

The iPhone receipt is server-side support evidence only.  A Packet claim is
eligible only after the enclosing Packet validator reconciles it with the
three source-owned sender receipts, the pcap marker window, Host state, and the
exact cleanup receipt.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import threading
import time
from typing import Callable, Final, Mapping, Protocol, Sequence

from scripts.harness.raw_artifacts import (
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
)

from .execution import CommandResult, CommandSpec, ProbeExecutionError, command_sha256
from .ios_packet_lan_peer import (
    CASE_ID,
    DEVICE_DIRECTORY,
    DIRECTORY_NAME,
    EVIDENCE_ROLE,
    LISTENER_PORT,
    READY_DOCUMENT,
    READY_FILE_NAME,
    RESULT_DOCUMENT,
    RESULT_FILE_NAME,
    SESSION_DOCUMENT,
    SESSION_FILE_NAME,
    STAGES,
    TOKEN_BYTES,
    TRANSPORT,
    create_session,
    validate_ready,
    validate_result,
    validate_session,
)
from .ios_transport_peer import (
    APP_EXECUTABLE,
    BUNDLE_IDENTIFIER,
    PRIMER_RESULT_FILE_NAME,
    IOSPeerArtifact,
    IOSPeerCleanupOnlyInstallationOwnership,
    IOSPeerCommandPlan,
    IOSPeerContractError,
    IOSPeerDevice,
    IOSPeerInstallationOwnership,
    IOSPeerPreflight,
    IOSPeerPrimerProcessOwnership,
    IOSPeerProcessOwnership,
    PrimerStoppedOwnership,
    device_identifier_sha256,
    device_inventory_command,
    provisioning_udid_sha256,
)
from .ios_transport_peer_lab import (
    AppInventory,
    DeviceAdmission,
    DevicectlRuntime,
    IOSPeerLabError,
    IOSPeerPacketLanSessionMaterial,
    IOSPeerProvisioningProfile,
    IOSPeerSigningCommandPlan,
    IOSPeerSigningInputs,
    ProcessInventory,
    authorize_cleanup_only_installation_from_preflight,
    authorize_packet_lan_process_cleanup,
    authorize_primer_process_cleanup,
    bind_packet_lan_process,
    bind_primer_process,
    bind_stopped_primer,
    build_preflight,
    inspect_ios_peer_artifact,
    minimal_entitlements_plist,
    parse_app_inventory,
    parse_decoded_provisioning_profile,
    parse_device_admission,
    parse_devicectl_envelope,
    parse_install_receipt,
    parse_lock_state,
    parse_packet_lan_launch_receipt,
    parse_packet_lan_session_copy_receipt,
    parse_packet_lan_terminate_receipt,
    parse_primer_launch_receipt,
    parse_primer_terminate_receipt,
    parse_process_inventory,
    parse_uninstall_receipt,
    validate_codesign_details,
    validate_copied_receipt,
    validate_embedded_profile,
    validate_executable_architectures,
    validate_executable_build_version,
    validate_keychain_certificate_pem,
    validate_packet_lan_session_material,
    validate_profile_source_unchanged,
    validate_signed_entitlements,
    verify_post_uninstall_absence,
)


REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[2]
SOURCE_IDENTITY_PATH: Final = Path(__file__).with_name(
    "ios_packet_lan_peer_identity.json"
)
SOURCE_IDENTITY_FILE_SHA256: Final = (
    "bee82809982b4dc5cc0b5697f10077bfa88884f58eb152cce59a5109127d29a3"
)
SOURCE_IDENTITY_DOCUMENT: Final = "cfm-ios-packet-lan-peer-source-identity-v1"
IDENTITY_DOCUMENT: Final = "cfm-ios-packet-lan-peer-identity-v1"
ADMISSION_DOCUMENT: Final = "cfm-ios-packet-lan-peer-admission-v1"
BEFORE_CAPTURE_DOCUMENT: Final = "cfm-ios-packet-lan-peer-before-capture-v1"
AFTER_CAPTURE_DOCUMENT: Final = "cfm-ios-packet-lan-peer-after-capture-v1"
CLEANUP_DOCUMENT: Final = "cfm-ios-packet-lan-peer-cleanup-v1"
PROVENANCE_DOCUMENT: Final = "cfm-ios-packet-lan-peer-provenance-v1"
SCHEMA_VERSION: Final = 1
MAX_SOURCE_IDENTITY_BYTES: Final = 64 * 1024
MAX_PRIVATE_FILE_BYTES: Final = 2 * 1024 * 1024
PRIMER_SETTLE_SECONDS: Final = 45.0
ADMISSION_LOCK_PATH: Final = Path("/private/tmp/cfm-ios-packet-lan-admission.lock")

SOURCE_TREE_PATHS: Final = (
    "project.yml",
    "Info.plist",
    "CFMPhysicalTransportPeerIOS.xcodeproj/project.pbxproj",
    (
        "CFMPhysicalTransportPeerIOS.xcodeproj/project.xcworkspace/"
        "contents.xcworkspacedata"
    ),
    (
        "CFMPhysicalTransportPeerIOS.xcodeproj/xcshareddata/xcschemes/"
        "CFMPhysicalTransportPeer.xcscheme"
    ),
    "App/AppDelegate.swift",
    "Sources/TransportPeerCore/PacketLanPeerContract.swift",
    "Sources/TransportPeerCore/PacketLanPeerIdentity.swift",
    "Sources/TransportPeerCore/PacketLanPeerRuntime.swift",
    "Sources/TransportPeerCore/PeerContract.swift",
    "Sources/TransportPeerCore/PeerIdentity.swift",
    "Sources/TransportPeerCore/PeerNetworkIdentity.swift",
    "Sources/TransportPeerCore/PeerRuntime.swift",
    "Sources/TransportPeerCore/PeerStreamProtocol.swift",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1_UPPER = re.compile(r"^[0-9A-F]{40}$")
_TEAM = re.compile(r"^[A-Z0-9]{10}$")
_SOURCE_LOCK = threading.Lock()


class IOSPacketLanPeerError(RuntimeError):
    """The iPhone Packet LAN peer cannot be admitted or proven safe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.cleanup_code: str | None = None

    def attach_cleanup_context(self, error: BaseException) -> None:
        self.cleanup_code = getattr(error, "code", "ios_packet_lan_cleanup_unexpected")
        self.add_note(
            "iPhone Packet LAN cleanup also failed "
            f"[{self.cleanup_code}]: {type(error).__name__}"
        )


class IOSPacketLanPeerRunner(Protocol):
    def run_command(self, spec: CommandSpec) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class IOSPacketLanPeerSourceIdentity:
    file_sha256: str
    identity_sha256: str
    identity: Mapping[str, object]
    core_device_identifier_sha256: str
    provisioning_udid_sha256: str
    product_type: str
    os_version: str
    os_build: str
    artifact_path: Path
    app_tree_sha256: str
    executable_sha256: str
    source_tree_sha256: str
    profile_path: Path
    profile_sha256: str
    profile_uuid: str
    entitlements_path: Path
    entitlements_sha256: str
    keychain_path: Path
    signing_identity_sha1: str
    signing_identity_label: str
    signing_certificate_sha256: str
    team_identifier: str
    devicectl_runtime: DevicectlRuntime

    def as_identity(self) -> dict[str, object]:
        return copy.deepcopy(dict(self.identity))


@dataclass(frozen=True, slots=True)
class _DeviceSelection:
    device: IOSPeerDevice
    receipt_sha256: str
    product_type: str
    os_version: str
    os_build: str
    inventory_connection_state: str
    inventory_preparedness_state: int | None


@dataclass(frozen=True, slots=True)
class _ArtifactValidation:
    artifact: IOSPeerArtifact
    profile: IOSPeerProvisioningProfile
    receipts: Mapping[str, object]


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", f"{label} is not one SHA-256"
        )
    return value


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_time_invalid", "adapter time is not timezone-aware"
        )
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _strict_object(value: object, fields: set[str], label: str) -> dict[str, object]:
    try:
        return exact_object(value, fields, label)
    except RawArtifactError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", f"{label} fields differ"
        ) from error


def _resolve_repository_path(value: object, *, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", f"{label} is not a repository path"
        )
    path = REPOSITORY_ROOT.joinpath(*value.split("/"))
    try:
        # The checked-in source identity describes release artifacts that do not
        # exist in a fresh checkout yet. Resolve the ancestors that exist at this
        # import boundary so an already-present symlink escape is rejected, but
        # do not require a generated target directory. The release workspace is
        # owner-controlled and quiescent; later artifact boundaries reopen and
        # validate the actual app, profile, and entitlements.
        resolved_parent = path.parent.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", f"{label} parent cannot be resolved"
        ) from error
    if REPOSITORY_ROOT not in (resolved_parent, *resolved_parent.parents):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", f"{label} escapes the repository"
        )
    return path


def _source_tree_sha256() -> str:
    tool_root = REPOSITORY_ROOT / "tools/physical-transport-peer-ios"
    entries: list[dict[str, object]] = []
    for relative in SOURCE_TREE_PATHS:
        path = tool_root.joinpath(*relative.split("/"))
        try:
            metadata = path.lstat()
            data = path.read_bytes()
            after = path.lstat()
        except OSError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_source_tree_invalid",
                f"iOS peer source member is unavailable: {relative}",
            ) from error
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_mode & 0o022
            or not data
            or identity(metadata) != identity(after)
        ):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_source_tree_invalid",
                f"iOS peer source member is unsafe: {relative}",
            )
        entries.append(
            {
                "path": relative,
                "mode": stat.S_IMODE(metadata.st_mode),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return hashlib.sha256(canonical_json(entries)).hexdigest()


def load_source_identity() -> IOSPacketLanPeerSourceIdentity:
    """Load the source document without trusting deployment artifacts yet."""

    try:
        metadata = SOURCE_IDENTITY_PATH.lstat()
        data = SOURCE_IDENTITY_PATH.read_bytes()
        after = SOURCE_IDENTITY_PATH.lstat()
    except OSError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", "iOS peer source identity is unavailable"
        ) from error
    identity_tuple = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if (
        SOURCE_IDENTITY_PATH.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
        or not 1 <= len(data) <= MAX_SOURCE_IDENTITY_BYTES
        or identity_tuple(metadata) != identity_tuple(after)
        or hashlib.sha256(data).hexdigest() != SOURCE_IDENTITY_FILE_SHA256
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", "iOS peer source identity pin differs"
        )
    try:
        root = exact_object(
            load_json_bytes(data, "iOS Packet LAN peer source identity"),
            {"schema_version", "document", "identity_sha256", "identity"},
            "iOS Packet LAN peer source identity",
        )
        identity = exact_object(
            root["identity"],
            {
                "schema_version",
                "document",
                "role",
                "platform",
                "device",
                "control",
                "artifact",
                "network",
                "session",
            },
            "iOS Packet LAN peer identity",
        )
        device = exact_object(
            identity["device"],
            {
                "core_device_identifier_sha256",
                "provisioning_udid_sha256",
                "product_type",
                "os_version",
                "os_build",
                "device_family",
            },
            "iOS Packet LAN peer device identity",
        )
        control = exact_object(
            identity["control"],
            {
                "devicectl_version",
                "json_version",
                "transport",
                "authentication",
                "tunnel_transport",
            },
            "iOS Packet LAN peer control identity",
        )
        artifact = exact_object(
            identity["artifact"],
            {
                "relative_path",
                "bundle_identifier",
                "app_tree_sha256",
                "executable_sha256",
                "source_tree_sha256",
                "team_identifier",
                "signing_identity_sha1",
                "signing_identity_label",
                "signing_certificate_sha256",
                "profile_uuid",
                "profile_relative_path",
                "profile_sha256",
                "entitlements_relative_path",
                "entitlements_sha256",
                "keychain_path",
                "architecture",
                "minimum_os",
                "device_family",
            },
            "iOS Packet LAN peer artifact identity",
        )
        network = exact_object(
            identity["network"],
            {
                "interface_name",
                "address_source",
                "address_scope",
                "listener_port",
                "transport",
            },
            "iOS Packet LAN peer network identity",
        )
        session = exact_object(
            identity["session"],
            {
                "document",
                "ready_document",
                "result_document",
                "stage_count",
                "token_bytes",
                "claim_eligible",
            },
            "iOS Packet LAN peer session identity",
        )
    except (RawArtifactError, TypeError, ValueError) as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", "iOS peer source identity is malformed"
        ) from error

    identity_sha256 = _require_sha256(root["identity_sha256"], "identity digest")
    core_digest = _require_sha256(
        device["core_device_identifier_sha256"], "CoreDevice selector digest"
    )
    udid_digest = _require_sha256(
        device["provisioning_udid_sha256"], "provisioning selector digest"
    )
    digest_fields = (
        "app_tree_sha256",
        "executable_sha256",
        "source_tree_sha256",
        "signing_certificate_sha256",
        "profile_sha256",
        "entitlements_sha256",
    )
    for field in digest_fields:
        _require_sha256(artifact[field], f"artifact {field}")
    runtime = DevicectlRuntime(control["devicectl_version"], control["json_version"])
    keychain_path = Path(artifact["keychain_path"])
    if (
        type(root["schema_version"]) is not int
        or root["schema_version"] != SCHEMA_VERSION
        or root["document"] != SOURCE_IDENTITY_DOCUMENT
        or hashlib.sha256(canonical_json(identity)).hexdigest() != identity_sha256
        or type(identity["schema_version"]) is not int
        or identity["schema_version"] != SCHEMA_VERSION
        or identity["document"] != IDENTITY_DOCUMENT
        or identity["role"] != "packet-lan-peer"
        or identity["platform"] != "iOS"
        or not isinstance(device["product_type"], str)
        or re.fullmatch(r"iPhone[0-9]+,[0-9]+", device["product_type"]) is None
        or not isinstance(device["os_version"], str)
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", device["os_version"]) is None
        or not isinstance(device["os_build"], str)
        or re.fullmatch(r"[0-9]+[A-Z][A-Za-z0-9]+", device["os_build"]) is None
        or type(device["device_family"]) is not int
        or device["device_family"] != 1
        or control["transport"] != "localNetwork"
        or control["authentication"] != "manualPairing"
        or control["tunnel_transport"] != "tcp"
        or artifact["bundle_identifier"] != BUNDLE_IDENTIFIER
        or not isinstance(artifact["team_identifier"], str)
        or _TEAM.fullmatch(artifact["team_identifier"]) is None
        or not isinstance(artifact["signing_identity_sha1"], str)
        or _SHA1_UPPER.fullmatch(artifact["signing_identity_sha1"]) is None
        or not isinstance(artifact["signing_identity_label"], str)
        or not 1 <= len(artifact["signing_identity_label"]) <= 256
        or not isinstance(artifact["profile_uuid"], str)
        or artifact["architecture"] != "arm64"
        or artifact["minimum_os"] != "17.0"
        or type(artifact["device_family"]) is not int
        or artifact["device_family"] != 1
        or not keychain_path.is_absolute()
        or network
        != {
            "interface_name": "en0",
            "address_source": READY_DOCUMENT,
            "address_scope": "rfc1918-ipv4",
            "listener_port": LISTENER_PORT,
            "transport": TRANSPORT,
        }
        or session
        != {
            "document": SESSION_DOCUMENT,
            "ready_document": READY_DOCUMENT,
            "result_document": RESULT_DOCUMENT,
            "stage_count": len(STAGES),
            "token_bytes": TOKEN_BYTES,
            "claim_eligible": False,
        }
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", "iOS peer source identity policy differs"
        )
    return IOSPacketLanPeerSourceIdentity(
        file_sha256=SOURCE_IDENTITY_FILE_SHA256,
        identity_sha256=identity_sha256,
        identity=copy.deepcopy(identity),
        core_device_identifier_sha256=core_digest,
        provisioning_udid_sha256=udid_digest,
        product_type=device["product_type"],
        os_version=device["os_version"],
        os_build=device["os_build"],
        artifact_path=_resolve_repository_path(
            artifact["relative_path"], label="app bundle"
        ),
        app_tree_sha256=artifact["app_tree_sha256"],
        executable_sha256=artifact["executable_sha256"],
        source_tree_sha256=artifact["source_tree_sha256"],
        profile_path=_resolve_repository_path(
            artifact["profile_relative_path"], label="provisioning profile"
        ),
        profile_sha256=artifact["profile_sha256"],
        profile_uuid=artifact["profile_uuid"],
        entitlements_path=_resolve_repository_path(
            artifact["entitlements_relative_path"], label="signing entitlements"
        ),
        entitlements_sha256=artifact["entitlements_sha256"],
        keychain_path=keychain_path,
        signing_identity_sha1=artifact["signing_identity_sha1"],
        signing_identity_label=artifact["signing_identity_label"],
        signing_certificate_sha256=artifact["signing_certificate_sha256"],
        team_identifier=artifact["team_identifier"],
        devicectl_runtime=runtime,
    )


def validate_static_source_identity(
    source: IOSPacketLanPeerSourceIdentity,
) -> dict[str, str]:
    """Reopen non-device inputs before a release or physical-run boundary."""

    if type(source) is not IOSPacketLanPeerSourceIdentity:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", "static source identity is not typed"
        )
    current = load_source_identity()
    if not _same_source_identity(current, source):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_changed",
            "iOS Packet LAN source identity changed after import",
        )
    source_tree_sha256 = _source_tree_sha256()
    try:
        artifact = inspect_ios_peer_artifact(source.artifact_path)
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_artifact_invalid", "signed iOS peer app is invalid"
        ) from error
    profile = _read_stable_file(
        source.profile_path, maximum=MAX_PRIVATE_FILE_BYTES, private=False
    )
    entitlements = _read_stable_file(
        source.entitlements_path, maximum=64 * 1024, private=False
    )
    if (
        source_tree_sha256 != source.source_tree_sha256
        or artifact.app_tree_sha256 != source.app_tree_sha256
        or artifact.executable_sha256 != source.executable_sha256
        or hashlib.sha256(profile).hexdigest() != source.profile_sha256
        or hashlib.sha256(entitlements).hexdigest() != source.entitlements_sha256
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_static_identity_stale",
            "iOS Packet LAN source, app, profile, or entitlements pin differs",
        )
    return {
        "source_identity_file_sha256": source.file_sha256,
        "source_identity_sha256": source.identity_sha256,
        "source_tree_sha256": source_tree_sha256,
        "app_tree_sha256": artifact.app_tree_sha256,
        "executable_sha256": artifact.executable_sha256,
        "profile_sha256": source.profile_sha256,
        "entitlements_sha256": source.entitlements_sha256,
    }


def _read_stable_file(path: Path, *, maximum: int, private: bool) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_private_file_invalid", "private output is unavailable"
        ) from error
    try:
        before = os.fstat(descriptor)
        initial_mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or before.st_mode & 0o022
            or private
            and initial_mode not in {0o600, 0o644}
            or not 1 <= before.st_size <= maximum
        ):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_private_file_invalid", "private output metadata differs"
            )
        if private and initial_mode == 0o644:
            try:
                parent = path.parent.lstat()
            except OSError as error:
                raise IOSPacketLanPeerError(
                    "ios_packet_lan_private_file_invalid",
                    "private output parent is unavailable",
                ) from error
            if (
                path.parent.is_symlink()
                or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) != 0o700
            ):
                raise IOSPacketLanPeerError(
                    "ios_packet_lan_private_file_invalid",
                    "0644 output is not enclosed by the exact private directory",
                )
            original_identity = (before.st_dev, before.st_ino, before.st_size)
            try:
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            except OSError as error:
                raise IOSPacketLanPeerError(
                    "ios_packet_lan_private_file_invalid",
                    "CoreDevice output mode could not be tightened",
                ) from error
            before = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size) != original_identity
                or stat.S_IMODE(before.st_mode) != 0o600
            ):
                raise IOSPacketLanPeerError(
                    "ios_packet_lan_private_file_invalid",
                    "CoreDevice output identity changed while tightening mode",
                )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 128 * 1024))
            if not chunk:
                raise IOSPacketLanPeerError(
                    "ios_packet_lan_private_file_invalid", "private output was truncated"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_private_file_invalid", "private output grew"
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_private_file_invalid", "private output changed"
        )
    return b"".join(chunks)


def _write_private_file(path: Path, data: bytes) -> None:
    if not isinstance(data, bytes) or not data:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_private_file_invalid", "private output bytes are empty"
        )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            written = 0
            while written < len(data):
                count = os.write(descriptor, data[written:])
                if count <= 0:
                    raise OSError("short private-file write")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_private_file_invalid", "private output could not be written"
        ) from error


def _command_receipt(result: CommandResult, spec: CommandSpec) -> dict[str, object]:
    if (
        type(result) is not CommandResult
        or result.role != spec.role
        or result.argv_sha256 != command_sha256(spec.argv)
        or type(result.exit_code) is not int
        or result.exit_code != 0
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_command_invalid", "fixed command result differs from its spec"
        )
    return {
        "role": spec.role,
        "argv_sha256": result.argv_sha256,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "duration_ms": result.duration_ms,
        "exit_code": result.exit_code,
        "stdout_size": len(result.stdout),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_size": len(result.stderr),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    }


def _run(
    runner: IOSPacketLanPeerRunner, spec: CommandSpec
) -> tuple[CommandResult, dict[str, object]]:
    try:
        result = runner.run_command(spec)
    except ProbeExecutionError as error:
        failure = error.result
        if (
            type(failure) is CommandResult
            and failure.role == spec.role
            and failure.argv_sha256 == command_sha256(spec.argv)
        ):
            context = (
                f"exit_code={failure.exit_code}, "
                f"stdout_sha256={hashlib.sha256(failure.stdout).hexdigest()}, "
                f"stderr_sha256={hashlib.sha256(failure.stderr).hexdigest()}"
            )
        else:
            context = "bounded failure result unavailable"
        raise IOSPacketLanPeerError(
            "ios_packet_lan_command_failed",
            f"fixed command failed: {spec.role}; {context}",
        ) from error
    except Exception as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_command_failed", f"fixed command failed: {spec.role}"
        ) from error
    return result, _command_receipt(result, spec)


def _allowed_object(
    value: object,
    *,
    required: set[str],
    optional: set[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_device_inventory_invalid", f"{label} is not an object"
        )
    keys = set(value)
    if not required <= keys or keys - required - optional:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_device_inventory_invalid", f"{label} fields differ"
        )
    return value


def _parse_device_selection(
    data: bytes,
    *,
    spec: CommandSpec,
    source: IOSPacketLanPeerSourceIdentity,
) -> _DeviceSelection:
    try:
        result, receipt_sha256 = parse_devicectl_envelope(
            data,
            spec=spec,
            runtime=source.devicectl_runtime,
            command_type="devicectl.list.devices",
        )
        result = exact_object(result, {"devices"}, "CoreDevice device list")
    except (IOSPeerLabError, RawArtifactError) as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_device_inventory_invalid",
            "CoreDevice device inventory envelope differs",
        ) from error
    values = result["devices"]
    if not isinstance(values, list) or not 1 <= len(values) <= 64:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_device_inventory_invalid",
            "CoreDevice device inventory count is outside the fixed bound",
        )
    candidates: list[tuple[IOSPeerDevice, dict[str, object]]] = []
    for index, value in enumerate(values):
        item = _allowed_object(
            value,
            required={
                "capabilities",
                "identifier",
                "properties",
                "propertyDisplayNames",
                "visibilityClass",
            },
            optional=set(),
            label=f"CoreDevice device {index}",
        )
        properties = _allowed_object(
            item["properties"],
            required={"connection", "hardware", "software", "state"},
            optional=set(),
            label=f"CoreDevice device {index} properties",
        )
        hardware = _allowed_object(
            properties["hardware"],
            required={
                "cpuType",
                "deviceType",
                "hasActionButton",
                "marketingName",
                "platform",
                "productType",
                "reality",
                "supportedBiometrics",
                "supportedCPUTypes",
                "supportsSiri",
                "udid",
            },
            optional={
                "cpuCount",
                "ecid",
                "internalStorageCapacity",
                "serialNumber",
                "supportedDeviceFamilies",
                "thinningProductType",
            },
            label=f"CoreDevice device {index} hardware",
        )
        connection = _allowed_object(
            properties["connection"],
            required={
                "authenticationType",
                "lastConnectionDate",
                "pairingState",
                "state",
                "transportType",
            },
            optional={
                "screenViewingURL",
                "tunnelIPAddressString",
                "tunnelTransportProtocol",
            },
            label=f"CoreDevice device {index} connection",
        )
        software = _allowed_object(
            properties["software"],
            required={"osBuildVersions", "osVersionNumber"},
            optional={"supportsCheckedAllocations"},
            label=f"CoreDevice device {index} software",
        )
        state = _allowed_object(
            properties["state"],
            required={"bootState", "name"},
            optional={
                "developerModeStatus",
                "preparednessState",
                "visibilityClass",
            },
            label=f"CoreDevice device {index} state",
        )
        if not (
            hardware["platform"] == "iOS"
            and hardware["reality"] == "physical"
            and hardware["deviceType"] == "iPhone"
        ):
            continue
        identifier = item["identifier"]
        provisioning_udid = hardware["udid"]
        if not isinstance(identifier, str) or not isinstance(provisioning_udid, str):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_device_inventory_invalid",
                "physical iPhone selectors are not strings",
            )
        try:
            core_digest = device_identifier_sha256(identifier)
            udid_digest = provisioning_udid_sha256(provisioning_udid)
        except IOSPeerContractError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_device_inventory_invalid",
                "physical iPhone selectors are non-canonical",
            ) from error
        if not (
            hmac.compare_digest(core_digest, source.core_device_identifier_sha256)
            and hmac.compare_digest(udid_digest, source.provisioning_udid_sha256)
        ):
            continue
        try:
            device = IOSPeerDevice(
                identifier,
                core_digest,
                provisioning_udid,
                udid_digest,
            )
        except IOSPeerContractError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_device_inventory_invalid",
                "selected iPhone selectors do not bind their hashes",
            ) from error
        candidates.append(
            (
                device,
                {
                    "item": item,
                    "hardware": hardware,
                    "connection": connection,
                    "software": software,
                    "state": state,
                },
            )
        )
    if len(candidates) != 1:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_device_selection_invalid",
            "fresh CoreDevice inventory does not contain exactly one hash-matched iPhone",
        )
    device, selected = candidates[0]
    hardware = selected["hardware"]
    connection = selected["connection"]
    software = selected["software"]
    state = selected["state"]
    build = _allowed_object(
        software["osBuildVersions"],
        required={"buildVersion", "supplementalBuildVersion"},
        optional=set(),
        label="selected iPhone OS build",
    )
    build_version = _allowed_object(
        build["buildVersion"],
        required={
            "majorLetterComponent",
            "majorNumberComponent",
            "name",
            "revisionVersion",
            "trainProgram",
            "updateNumberComponent",
        },
        optional=set(),
        label="selected iPhone primary build version",
    )
    supplemental_build = _allowed_object(
        build["supplementalBuildVersion"],
        required={
            "majorLetterComponent",
            "majorNumberComponent",
            "name",
            "revisionVersion",
            "trainProgram",
            "updateNumberComponent",
        },
        optional=set(),
        label="selected iPhone supplemental build version",
    )
    build_revision = _allowed_object(
        build_version["revisionVersion"],
        required={"components", "originalComponentsCount", "stringValue"},
        optional=set(),
        label="selected iPhone build revision",
    )
    version = _allowed_object(
        software["osVersionNumber"],
        required={"components", "originalComponentsCount", "stringValue"},
        optional=set(),
        label="selected iPhone OS version",
    )
    cpu = _allowed_object(
        hardware["cpuType"],
        required={"subtype", "type"},
        optional=set(),
        label="selected iPhone CPU",
    )
    developer = _allowed_object(
        state.get("developerModeStatus"),
        required={"enabled"},
        optional=set(),
        label="selected iPhone developer mode",
    )
    enabled = _allowed_object(
        developer["enabled"],
        required={"mode"},
        optional=set(),
        label="selected iPhone developer mode value",
    )
    inventory_connection_state = connection.get("state")
    inventory_preparedness_state = state.get("preparednessState")
    inventory_state_is_valid = (
        inventory_connection_state == "connected"
        and inventory_preparedness_state == 7
    ) or (
        inventory_connection_state == "disconnected"
        and inventory_preparedness_state is None
    )
    if (
        selected["item"]["visibilityClass"] != "default"
        or hardware.get("productType") != source.product_type
        or hardware.get("supportedDeviceFamilies") != [1]
        or cpu.get("type") != 16_777_228
        or connection.get("authenticationType") != "manualPairing"
        or connection.get("pairingState") != "paired"
        or not inventory_state_is_valid
        or connection.get("transportType") != "localNetwork"
        or state.get("bootState") != "booted"
        or enabled.get("mode") != 1
        or version.get("stringValue") != source.os_version
        or build_version != supplemental_build
        or build_version.get("name") != source.os_build
        or build_version.get("trainProgram") != "iOS"
        or type(build_version.get("majorNumberComponent")) is not int
        or not isinstance(build_version.get("majorLetterComponent"), str)
        or type(build_version.get("updateNumberComponent")) is not int
        or not isinstance(build_revision.get("components"), list)
        or not build_revision["components"]
        or any(type(component) is not int for component in build_revision["components"])
        or type(build_revision.get("originalComponentsCount")) is not int
        or build_revision["originalComponentsCount"]
        != len(build_revision["components"])
        or not isinstance(build_revision.get("stringValue"), str)
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_device_selection_invalid",
            "hash-matched iPhone public identity or inventory state differs from source",
        )
    return _DeviceSelection(
        device=device,
        receipt_sha256=receipt_sha256,
        product_type=source.product_type,
        os_version=source.os_version,
        os_build=source.os_build,
        inventory_connection_state=inventory_connection_state,
        inventory_preparedness_state=inventory_preparedness_state,
    )


def _validate_artifact(
    *,
    runner: IOSPacketLanPeerRunner,
    source: IOSPacketLanPeerSourceIdentity,
    device: IOSPeerDevice,
    workspace: Path,
    now: datetime,
) -> _ArtifactValidation:
    if _source_tree_sha256() != source.source_tree_sha256:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_tree_stale",
            "iOS peer source tree differs from the source identity",
        )
    try:
        artifact = inspect_ios_peer_artifact(source.artifact_path)
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_artifact_invalid", "signed iOS peer app is invalid"
        ) from error
    if (
        artifact.app_tree_sha256 != source.app_tree_sha256
        or artifact.executable_sha256 != source.executable_sha256
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_artifact_stale",
            "signed iOS peer app differs from its source identity",
        )
    try:
        signing_inputs = IOSPeerSigningInputs(
            profile_path=source.profile_path,
            profile_sha256=source.profile_sha256,
            keychain_path=source.keychain_path,
            signing_identity_sha1=source.signing_identity_sha1,
            signing_identity_label=source.signing_identity_label,
            signing_certificate_sha256=source.signing_certificate_sha256,
            team_identifier=source.team_identifier,
        )
        plan = IOSPeerSigningCommandPlan(REPOSITORY_ROOT, artifact, signing_inputs)
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_signing_invalid", "iOS signing inputs are invalid"
        ) from error
    signing_dir = workspace / "signing"
    signing_dir.mkdir(mode=0o700)
    decoded_profile = signing_dir / "decoded-profile.plist"
    receipts: dict[str, object] = {}

    decode_spec = plan.decode_profile(decoded_profile)
    decode_result, receipts["profile_decode"] = _run(runner, decode_spec)
    if decode_result.stdout or decode_result.stderr:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_signing_invalid", "profile decoder emitted output"
        )
    decoded = _read_stable_file(
        decoded_profile, maximum=MAX_PRIVATE_FILE_BYTES, private=False
    )
    try:
        profile = parse_decoded_provisioning_profile(
            decoded, inputs=signing_inputs, device=device, now=now
        )
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_signing_invalid", "provisioning profile is invalid"
        ) from error
    if profile.uuid != source.profile_uuid:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_signing_invalid", "provisioning profile UUID differs"
        )

    entitlements = _read_stable_file(
        source.entitlements_path, maximum=64 * 1024, private=False
    )
    if (
        hashlib.sha256(entitlements).hexdigest() != source.entitlements_sha256
        or entitlements != minimal_entitlements_plist(profile)
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_signing_invalid", "signing entitlements source differs"
        )

    certificate_spec = plan.export_keychain_certificate()
    certificate_result, receipts["keychain_certificate"] = _run(
        runner, certificate_spec
    )
    if certificate_result.stderr:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_signing_invalid", "certificate export emitted stderr"
        )
    validate_keychain_certificate_pem(certificate_result.stdout, inputs=signing_inputs)

    verify_spec = plan.verify_signature()
    verify_result, receipts["signature_verify"] = _run(runner, verify_spec)
    if verify_result.stdout:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_signing_invalid", "codesign verification emitted stdout"
        )

    details_spec = plan.signature_details()
    details_result, receipts["signature_details"] = _run(runner, details_spec)
    if details_result.stdout or not details_result.stderr:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_signing_invalid", "codesign details stream differs"
        )
    cdhash = validate_codesign_details(details_result.stderr, inputs=signing_inputs)

    entitlements_spec = plan.signature_entitlements()
    entitlements_result, receipts["signature_entitlements"] = _run(
        runner, entitlements_spec
    )
    if not entitlements_result.stdout:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_signing_invalid", "signed entitlements are absent"
        )
    validate_signed_entitlements(entitlements_result.stdout, profile=profile)

    architectures_spec = plan.executable_architectures()
    architectures_result, receipts["architectures"] = _run(
        runner, architectures_spec
    )
    if architectures_result.stderr:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_artifact_invalid", "lipo emitted stderr"
        )
    validate_executable_architectures(architectures_result.stdout)

    build_spec = plan.executable_build_version()
    build_result, receipts["build_version"] = _run(runner, build_spec)
    if build_result.stderr:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_artifact_invalid", "vtool emitted stderr"
        )
    validate_executable_build_version(build_result.stdout)
    validate_profile_source_unchanged(signing_inputs)
    validate_embedded_profile(artifact, inputs=signing_inputs)
    receipts["cdhash"] = cdhash
    receipts["profile_uuid"] = profile.uuid
    return _ArtifactValidation(artifact, profile, receipts)


def _acquire_admission_lock() -> int:
    if not _SOURCE_LOCK.acquire(blocking=False):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_admission_busy",
            "another iPhone Packet LAN admission is active in this process",
        )
    descriptor = -1
    try:
        descriptor = os.open(
            ADMISSION_LOCK_PATH,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_admission_lock_invalid",
                "cross-process iPhone admission lock metadata differs",
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_admission_busy",
                "another process owns the iPhone Packet LAN admission",
            ) from error
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        _SOURCE_LOCK.release()
        raise


def _release_admission_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
        _SOURCE_LOCK.release()


def _remove_workspace_after_creation_failure(path: Path) -> None:
    """Remove only the empty, newly-owned workspace shape created below."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (
        path.parent != Path("/private/tmp")
        or not path.name.startswith("cfm-ios-packet-lan-")
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_workspace_cleanup_failed",
            "new private workspace ownership differs during rollback",
        )
    device_directory = path / "device-json"
    try:
        device_metadata = device_directory.lstat()
    except FileNotFoundError:
        pass
    else:
        if (
            device_directory.is_symlink()
            or not stat.S_ISDIR(device_metadata.st_mode)
            or device_metadata.st_uid != os.geteuid()
        ):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_workspace_cleanup_failed",
                "new device workspace ownership differs during rollback",
            )
        device_directory.rmdir()
    path.rmdir()


def _create_workspace() -> Path:
    path = Path(
        tempfile.mkdtemp(prefix="cfm-ios-packet-lan-", dir="/private/tmp")
    ).resolve()
    try:
        metadata = path.lstat()
        if (
            path.parent != Path("/private/tmp")
            or not path.name.startswith("cfm-ios-packet-lan-")
            or path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_workspace_invalid", "private workspace metadata differs"
            )
        (path / "device-json").mkdir(mode=0o700)
        return path
    except BaseException as error:
        try:
            _remove_workspace_after_creation_failure(path)
        except BaseException as cleanup_error:
            if isinstance(error, Exception):
                error.add_note(
                    "new private workspace rollback also failed: "
                    f"{type(cleanup_error).__name__}"
                )
        raise


def _remove_workspace(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_workspace_cleanup_failed",
            "private workspace cannot be inspected for cleanup",
        ) from error
    if (
        path.parent != Path("/private/tmp")
        or not path.name.startswith("cfm-ios-packet-lan-")
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_workspace_cleanup_failed",
            "private workspace no longer has its exact owned identity",
        )
    try:
        shutil.rmtree(path)
    except OSError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_workspace_cleanup_failed",
            "private workspace removal failed",
        ) from error


class _TransactionContext:
    def __init__(
        self,
        *,
        runner: IOSPacketLanPeerRunner,
        source: IOSPacketLanPeerSourceIdentity,
        workspace: Path,
        device: IOSPeerDevice,
        artifact: IOSPeerArtifact,
    ) -> None:
        self.runner = runner
        self.source = source
        self.workspace = workspace
        self.device = device
        self.artifact = artifact
        self.plan = IOSPeerCommandPlan(REPOSITORY_ROOT, device, artifact)
        self._sequence = 0

    def json_path(self, name: str) -> Path:
        path = self.workspace / "device-json" / name
        if path.exists() or path.is_symlink():
            raise IOSPacketLanPeerError(
                "ios_packet_lan_workspace_invalid", "command JSON path already exists"
            )
        return path

    def receipt_path(self, name: str, label: str) -> Path:
        if name not in {READY_FILE_NAME, RESULT_FILE_NAME, PRIMER_RESULT_FILE_NAME}:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_receipt_invalid", "receipt name is outside the closed set"
            )
        self._sequence += 1
        directory = self.workspace / f"receipt-{self._sequence:02d}-{label}"
        directory.mkdir(mode=0o700)
        return directory / name

    def run_json(
        self, spec: CommandSpec, output: Path
    ) -> tuple[bytes, dict[str, object]]:
        result, receipt = _run(self.runner, spec)
        if result.stdout or result.stderr:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_devicectl_output_invalid",
                f"{spec.role} emitted an unreviewed stream",
            )
        return (
            _read_stable_file(output, maximum=MAX_PRIVATE_FILE_BYTES, private=True),
            receipt,
        )

    def prove_unlocked(self, suffix: str) -> tuple[str, dict[str, object]]:
        output = self.json_path(f"lock-state-{suffix}.json")
        spec = self.plan.lock_state(output)
        data, command = self.run_json(spec, output)
        try:
            receipt_sha256 = parse_lock_state(
                data,
                spec=spec,
                runtime=self.source.devicectl_runtime,
                device=self.device,
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_device_locked",
                f"selected iPhone is not unlocked at {suffix}",
            ) from error
        return receipt_sha256, command

    def app_inventory(self, suffix: str) -> tuple[AppInventory, dict[str, object]]:
        output = self.json_path(f"app-inventory-{suffix}.json")
        spec = self.plan.app_inventory(output)
        data, receipt = self.run_json(spec, output)
        try:
            return (
                parse_app_inventory(
                    data,
                    spec=spec,
                    runtime=self.source.devicectl_runtime,
                    device=self.device,
                ),
                receipt,
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_app_inventory_invalid",
                "iPhone app inventory is invalid",
            ) from error

    def process_inventory(
        self, suffix: str
    ) -> tuple[ProcessInventory, dict[str, object]]:
        output = self.json_path(f"process-inventory-{suffix}.json")
        spec = self.plan.process_inventory(output)
        data, receipt = self.run_json(spec, output)
        try:
            return (
                parse_process_inventory(
                    data,
                    spec=spec,
                    runtime=self.source.devicectl_runtime,
                    device=self.device,
                ),
                receipt,
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_process_inventory_invalid",
                "iPhone process inventory is invalid",
            ) from error

    def copy_receipt(
        self,
        *,
        ownership: IOSPeerInstallationOwnership | IOSPeerProcessOwnership,
        name: str,
        suffix: str,
        primer: bool = False,
    ) -> tuple[bytes, dict[str, object]]:
        destination = self.receipt_path(name, suffix)
        json_name = (
            f"primer-result-copy-{suffix}.json"
            if primer
            else f"packet-lan-{name.removesuffix('.json')}-copy-{suffix}.json"
        )
        output = self.json_path(json_name)
        if primer:
            if type(ownership) is not IOSPeerInstallationOwnership:
                raise IOSPacketLanPeerError(
                    "ios_packet_lan_receipt_invalid",
                    "primer copy lacks installation ownership",
                )
            spec = self.plan.copy_primer_receipt(ownership, destination, output)
            expected_source = f"Documents/CFMTransportPrimer/{name}"
        else:
            spec = self.plan.copy_packet_lan_receipt_from_device(
                ownership, name, destination, output
            )
            expected_source = f"{DEVICE_DIRECTORY}/{name}"
        envelope, command_receipt = self.run_json(spec, output)
        try:
            result, envelope_sha256 = parse_devicectl_envelope(
                envelope,
                spec=spec,
                runtime=self.source.devicectl_runtime,
                command_type="devicectl.device.copy.from",
            )
            result = exact_object(
                result,
                {
                    "destination",
                    "deviceIdentifier",
                    "domain",
                    "domainIdentifier",
                    "source",
                },
                "CoreDevice receipt copy",
            )
        except (IOSPeerLabError, RawArtifactError) as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_receipt_copy_invalid",
                "CoreDevice receipt-copy envelope differs",
            ) from error
        if result != {
            "destination": destination.as_uri(),
            "deviceIdentifier": self.device.core_device_identifier,
            "domain": "appDataContainer",
            "domainIdentifier": BUNDLE_IDENTIFIER,
            "source": expected_source,
        }:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_receipt_copy_invalid",
                "CoreDevice receipt-copy tuple differs",
            )
        try:
            verified = validate_copied_receipt(destination, expected_name=name)
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_receipt_copy_invalid",
                "copied iPhone receipt is not a private stable file",
            ) from error
        return verified.data, {
            "command": command_receipt,
            "envelope_sha256": envelope_sha256,
            "receipt_sha256": verified.sha256,
            "receipt_size": verified.size,
        }


def _write_install_intent(
    context: _TransactionContext,
    *,
    preflight: IOSPeerPreflight,
    spec: CommandSpec,
    recorded_at: datetime,
) -> str:
    value = {
        "schema_version": SCHEMA_VERSION,
        "document": "cfm-ios-packet-lan-install-intent-v1",
        "device_identifier_sha256": context.device.core_device_identifier_sha256,
        "app_tree_sha256": context.artifact.app_tree_sha256,
        "preflight_app_inventory_sha256": preflight.app_inventory_receipt_sha256,
        "preflight_process_inventory_sha256": (
            preflight.process_inventory_receipt_sha256
        ),
        "install_argv_sha256": command_sha256(spec.argv),
        "recorded_at": _timestamp(recorded_at),
    }
    data = canonical_json(value) + b"\n"
    _write_private_file(context.workspace / "install-intent.json", data)
    return hashlib.sha256(data).hexdigest()


def _session_material(
    workspace: Path,
    *,
    tokens: Sequence[str],
    now: datetime,
) -> tuple[bytes, Mapping[str, object], IOSPeerPacketLanSessionMaterial]:
    session_data = create_session(tokens=tokens, now=now)
    session = validate_session(session_data, now=now)
    directory = workspace / DIRECTORY_NAME
    directory.mkdir(mode=0o700)
    _write_private_file(directory / SESSION_FILE_NAME, session_data)
    try:
        material = validate_packet_lan_session_material(
            directory,
            expected_session_id=session["session_id"],
            now=now,
        )
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_session_material_invalid",
            "packet LAN session material is invalid",
        ) from error
    return session_data, session, material


def _terminate_packet_process(
    context: _TransactionContext,
    *,
    installation: IOSPeerInstallationOwnership,
    ownership: IOSPeerProcessOwnership,
    session_data: bytes,
    material: IOSPeerPacketLanSessionMaterial,
    suffix: str,
    now: datetime,
) -> dict[str, object]:
    inventory, inventory_command = context.process_inventory(f"{suffix}-terminate")
    fresh_ready, ready_copy = context.copy_receipt(
        ownership=ownership,
        name=READY_FILE_NAME,
        suffix=f"{suffix}-terminate",
    )
    try:
        authority = authorize_packet_lan_process_cleanup(
            ownership=ownership,
            fresh_inventory=inventory,
            fresh_ready_receipt=fresh_ready,
            session_document=session_data,
            material=material,
            observed_at=now,
        )
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_cleanup_authority_invalid",
            "fresh iPhone inventory cannot authorize exact Packet PID cleanup",
        ) from error
    output = context.json_path(f"terminate-{suffix}.json")
    spec = context.plan.terminate(authority, output)
    data, terminate_command = context.run_json(spec, output)
    try:
        termination = parse_packet_lan_terminate_receipt(
            data,
            spec=spec,
            runtime=context.source.devicectl_runtime,
            device=context.device,
            authority=authority,
        )
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_terminate_invalid",
            "iPhone Packet PID termination receipt differs",
        ) from error
    post_inventory, post_command = context.process_inventory(f"{suffix}-stopped")
    if any(
        process.process_id == ownership.process_id
        or process.executable_path == ownership.executable_path
        for process in post_inventory.processes
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_terminate_invalid",
            "terminated iPhone Packet process remains in fresh inventory",
        )
    return {
        "process_inventory": inventory_command,
        "process_inventory_sha256": inventory.receipt_sha256,
        "ready_copy": ready_copy,
        "terminate_command": terminate_command,
        "terminate_receipt_sha256": termination.receipt_sha256,
        "process_id": termination.process_id,
        "post_terminate_process_inventory": post_command,
        "post_terminate_process_inventory_sha256": post_inventory.receipt_sha256,
    }


def _terminate_primer_process(
    context: _TransactionContext,
    *,
    installation: IOSPeerInstallationOwnership,
    ownership: IOSPeerPrimerProcessOwnership,
    suffix: str,
    now: datetime,
) -> tuple[PrimerStoppedOwnership, dict[str, object]]:
    inventory, inventory_command = context.process_inventory(f"{suffix}-terminate")
    fresh_primer, primer_copy = context.copy_receipt(
        ownership=installation,
        name=PRIMER_RESULT_FILE_NAME,
        suffix=f"{suffix}-terminate",
        primer=True,
    )
    try:
        authority = authorize_primer_process_cleanup(
            ownership=ownership,
            fresh_inventory=inventory,
            fresh_primer_receipt=fresh_primer,
            device=context.device,
            observed_at=now,
        )
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_primer_cleanup_invalid",
            "fresh iPhone inventory cannot authorize exact primer PID cleanup",
        ) from error
    output = context.json_path(f"primer-terminate-{suffix}.json")
    spec = context.plan.terminate_primer(authority, output)
    data, terminate_command = context.run_json(spec, output)
    try:
        termination = parse_primer_terminate_receipt(
            data,
            spec=spec,
            runtime=context.source.devicectl_runtime,
            device=context.device,
            authority=authority,
        )
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_primer_terminate_invalid",
            "iPhone primer PID termination receipt differs",
        ) from error
    post_inventory, post_command = context.process_inventory(f"{suffix}-stopped")
    try:
        stopped = bind_stopped_primer(
            authority=authority,
            termination=termination,
            post_terminate_inventory=post_inventory,
            device=context.device,
            observed_at=now,
        )
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_primer_terminate_invalid",
            "iPhone primer stopped proof is invalid",
        ) from error
    return stopped, {
        "process_inventory": inventory_command,
        "process_inventory_sha256": inventory.receipt_sha256,
        "primer_copy": primer_copy,
        "terminate_command": terminate_command,
        "terminate_receipt_sha256": termination.receipt_sha256,
        "process_id": termination.process_id,
        "post_terminate_process_inventory": post_command,
        "post_terminate_process_inventory_sha256": post_inventory.receipt_sha256,
    }


def _uninstall_and_verify(
    context: _TransactionContext,
    *,
    installation: IOSPeerInstallationOwnership
    | IOSPeerCleanupOnlyInstallationOwnership,
    ownership: IOSPeerProcessOwnership | IOSPeerPrimerProcessOwnership | None,
    suffix: str,
) -> dict[str, object]:
    output = context.json_path(f"uninstall-{suffix}.json")
    spec = context.plan.uninstall(installation, output)
    data, uninstall_command = context.run_json(spec, output)
    try:
        observation = parse_uninstall_receipt(
            data,
            spec=spec,
            runtime=context.source.devicectl_runtime,
            device=context.device,
            installation=installation,
        )
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_uninstall_invalid",
            "owned iPhone test-app uninstall receipt differs",
        ) from error
    app_inventory, app_command = context.app_inventory(f"{suffix}-final")
    process_inventory, process_command = context.process_inventory(f"{suffix}-final")
    try:
        app_sha256, process_sha256 = verify_post_uninstall_absence(
            app_inventory=app_inventory,
            process_inventory=process_inventory,
            device=context.device,
            ownership=ownership,
        )
    except IOSPeerLabError as error:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_cleanup_unproven",
            "owned iPhone test app or process remains after uninstall",
        ) from error
    return {
        "uninstall_command": uninstall_command,
        "uninstall_receipt_sha256": observation.receipt_sha256,
        "final_app_inventory": app_command,
        "final_app_inventory_sha256": app_sha256,
        "final_process_inventory": process_command,
        "final_process_inventory_sha256": process_sha256,
        "app_absent": True,
        "process_absent": True,
    }


def _cleanup_known_installation(
    context: _TransactionContext,
    *,
    installation: IOSPeerInstallationOwnership
    | IOSPeerCleanupOnlyInstallationOwnership,
    packet_ownership: IOSPeerProcessOwnership | None,
    primer_ownership: IOSPeerPrimerProcessOwnership | None,
    session_data: bytes | None,
    material: IOSPeerPacketLanSessionMaterial | None,
    suffix: str,
    now: datetime,
) -> dict[str, object]:
    termination: dict[str, object] | None = None
    termination_error: BaseException | None = None
    typed_ownership: IOSPeerProcessOwnership | IOSPeerPrimerProcessOwnership | None = (
        packet_ownership if packet_ownership is not None else primer_ownership
    )
    if packet_ownership is not None:
        if (
            type(installation) is not IOSPeerInstallationOwnership
            or session_data is None
            or material is None
        ):
            termination_error = IOSPacketLanPeerError(
                "ios_packet_lan_cleanup_authority_invalid",
                "Packet cleanup lacks installation or session ownership",
            )
        else:
            try:
                termination = _terminate_packet_process(
                    context,
                    installation=installation,
                    ownership=packet_ownership,
                    session_data=session_data,
                    material=material,
                    suffix=suffix,
                    now=now,
                )
            except BaseException as error:
                termination_error = error
    elif primer_ownership is not None:
        if type(installation) is not IOSPeerInstallationOwnership:
            termination_error = IOSPacketLanPeerError(
                "ios_packet_lan_cleanup_authority_invalid",
                "primer cleanup lacks installation ownership",
            )
        else:
            try:
                _stopped, termination = _terminate_primer_process(
                    context,
                    installation=installation,
                    ownership=primer_ownership,
                    suffix=suffix,
                    now=now,
                )
            except BaseException as error:
                termination_error = error
    uninstall = _uninstall_and_verify(
        context,
        installation=installation,
        ownership=typed_ownership,
        suffix=suffix,
    )
    if termination_error is not None:
        if isinstance(termination_error, Exception):
            termination_error.add_note(
                "owned app uninstall and final absence succeeded after exact-PID "
                "termination could not be proven"
            )
        raise termination_error
    return {"termination": termination, "uninstall": uninstall}


def _reconcile_sender_and_server(
    *,
    stages: Sequence[Mapping[str, object]],
    result: Mapping[str, object],
    peer_ipv4: str,
) -> list[dict[str, object]]:
    connections = result.get("connections")
    if (
        not isinstance(stages, (tuple, list))
        or len(stages) != len(STAGES)
        or not isinstance(connections, list)
        or len(connections) != len(STAGES)
    ):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_joint_evidence_invalid",
            "sender or server stage count differs",
        )
    reconciled: list[dict[str, object]] = []
    source_addresses: set[str] = set()
    source_ports: set[int] = set()
    for index, stage_name in enumerate(STAGES):
        sender = stages[index]
        server = connections[index]
        if not isinstance(sender, Mapping) or not isinstance(server, dict):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_joint_evidence_invalid",
                "sender or server stage is not an object",
            )
        endpoints = sender.get("endpoint_set")
        if (
            sender.get("stage") != stage_name
            or not isinstance(sender.get("token_sha256"), str)
            or _SHA256.fullmatch(sender["token_sha256"]) is None
            or not isinstance(endpoints, list)
            or len(endpoints) != 2
            or not all(isinstance(item, dict) for item in endpoints)
        ):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_joint_evidence_invalid",
                "sender stage identity or endpoints differ",
            )
        local, remote = endpoints
        local_address = local.get("address")
        local_port = local.get("port")
        try:
            parsed_local = ipaddress.IPv4Address(local_address)
        except (ipaddress.AddressValueError, TypeError) as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_joint_evidence_invalid",
                "sender local endpoint is not canonical IPv4",
            ) from error
        if (
            local
            != {
                "role": "local",
                "address": str(parsed_local),
                "port": local_port,
                "transport": "tcp",
            }
            or type(local_port) is not int
            or not 49_152 <= local_port <= 65_535
            or remote
            != {
                "role": "remote",
                "address": peer_ipv4,
                "port": LISTENER_PORT,
                "transport": "tcp",
            }
            or server.get("stage") != stage_name
            or server.get("admission_sequence") != index + 1
            or server.get("token_sha256") != sender["token_sha256"]
            or server.get("bytes_received") != TOKEN_BYTES
            or server.get("eof_observed") is not True
            or server.get("peer_ipv4") != str(parsed_local)
            or server.get("peer_port") != local_port
        ):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_joint_evidence_invalid",
                "sender and iPhone server observations do not bind one connection",
            )
        source_addresses.add(str(parsed_local))
        source_ports.add(local_port)
        reconciled.append(
            {
                "stage": stage_name,
                "token_sha256": sender["token_sha256"],
                "local_address": str(parsed_local),
                "local_port": local_port,
                "remote_address": peer_ipv4,
                "remote_port": LISTENER_PORT,
                "bytes_received": TOKEN_BYTES,
                "eof_observed": True,
            }
        )
    if len(source_addresses) != 1 or len(source_ports) != len(STAGES):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_joint_evidence_invalid",
            "Mac source address drifted or source ports were reused",
        )
    return reconciled


class IOSPacketLanPeerLease:
    """One installed and running iPhone peer with mandatory exact cleanup."""

    def __init__(
        self,
        *,
        context: _TransactionContext,
        lock_descriptor: int,
        installation: IOSPeerInstallationOwnership,
        ownership: IOSPeerProcessOwnership,
        session_data: bytes,
        session: Mapping[str, object],
        material: IOSPeerPacketLanSessionMaterial,
        ready_data: bytes,
        ready: Mapping[str, object],
        admission: Mapping[str, object],
        time_source: Callable[[], datetime],
        sleeper: Callable[[float], None],
    ) -> None:
        self._context = context
        self._lock_descriptor = lock_descriptor
        self._installation = installation
        self._ownership = ownership
        self._session_data = session_data
        self._session = copy.deepcopy(dict(session))
        self._material = material
        self._ready_data = ready_data
        self._ready = copy.deepcopy(dict(ready))
        self._admission = copy.deepcopy(dict(admission))
        self._time_source = time_source
        self._sleeper = sleeper
        self._state = "admitted"
        self._released = False

    @property
    def peer_ipv4(self) -> str:
        network = self._ready["network"]
        if not isinstance(network, dict) or not isinstance(network.get("ipv4"), str):
            raise IOSPacketLanPeerError(
                "ios_packet_lan_lease_invalid", "ready network is unavailable"
            )
        return network["ipv4"]

    @property
    def listener_port(self) -> int:
        return LISTENER_PORT

    @property
    def is_closed(self) -> bool:
        return self._state == "closed"

    def as_document(self) -> dict[str, object]:
        if self._state not in {"admitted", "capture-ready", "capture-validated"}:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_lease_state_invalid",
                f"admission document is unavailable from {self._state}",
            )
        return copy.deepcopy(self._admission)

    def revalidate_before_capture(self) -> dict[str, object]:
        if self._state != "admitted":
            raise IOSPacketLanPeerError(
                "ios_packet_lan_lease_state_invalid",
                f"before-capture validation cannot run from {self._state}",
            )
        observed_at = self._time_source()
        inventory, inventory_command = self._context.process_inventory(
            "packet-before-capture"
        )
        fresh_ready, ready_copy = self._context.copy_receipt(
            ownership=self._ownership,
            name=READY_FILE_NAME,
            suffix="before-capture",
        )
        try:
            authority = authorize_packet_lan_process_cleanup(
                ownership=self._ownership,
                fresh_inventory=inventory,
                fresh_ready_receipt=fresh_ready,
                session_document=self._session_data,
                material=self._material,
                observed_at=observed_at,
            )
            ready = validate_ready(
                fresh_ready, session=self._session, now=observed_at
            )
        except (IOSPeerLabError, IOSPeerContractError) as error:
            self._state = "poisoned"
            raise IOSPacketLanPeerError(
                "ios_packet_lan_before_capture_invalid",
                "iPhone Packet process or ready receipt drifted before capture",
            ) from error
        if (
            hashlib.sha256(fresh_ready).hexdigest()
            != hashlib.sha256(self._ready_data).hexdigest()
            or ready["network"] != self._ready["network"]
            or authority.process.process_id != self._ownership.process_id
        ):
            self._state = "poisoned"
            raise IOSPacketLanPeerError(
                "ios_packet_lan_before_capture_invalid",
                "iPhone Packet launch generation changed before capture",
            )
        document = {
            "schema_version": SCHEMA_VERSION,
            "document": BEFORE_CAPTURE_DOCUMENT,
            "claim_eligible": False,
            "session_id": self._material.session_id,
            "process_id": self._ownership.process_id,
            "peer_ipv4": self.peer_ipv4,
            "listener_port": LISTENER_PORT,
            "process_inventory": inventory_command,
            "process_inventory_sha256": inventory.receipt_sha256,
            "ready_copy": ready_copy,
            "observed_at": _timestamp(observed_at),
        }
        self._state = "capture-ready"
        return document

    def revalidate_after_capture(
        self, stages: Sequence[Mapping[str, object]]
    ) -> dict[str, object]:
        if self._state != "capture-ready":
            raise IOSPacketLanPeerError(
                "ios_packet_lan_lease_state_invalid",
                f"after-capture validation cannot run from {self._state}",
            )
        self._sleeper(1.0)
        observed_at = self._time_source()
        try:
            result_data, result_copy = self._context.copy_receipt(
                ownership=self._ownership,
                name=RESULT_FILE_NAME,
                suffix="after-capture",
            )
            result = validate_result(
                result_data,
                session=self._session,
                ready=self._ready,
            )
            if result["status"] != "closed":
                raise IOSPacketLanPeerError(
                    "ios_packet_lan_server_result_failed",
                    "iPhone Packet server reported a failed session",
                )
            bindings = _reconcile_sender_and_server(
                stages=stages,
                result=result,
                peer_ipv4=self.peer_ipv4,
            )
            inventory, inventory_command = self._context.process_inventory(
                "packet-after-capture"
            )
            fresh_ready, ready_copy = self._context.copy_receipt(
                ownership=self._ownership,
                name=READY_FILE_NAME,
                suffix="after-capture",
            )
            authorize_packet_lan_process_cleanup(
                ownership=self._ownership,
                fresh_inventory=inventory,
                fresh_ready_receipt=fresh_ready,
                session_document=self._session_data,
                material=self._material,
                observed_at=observed_at,
            )
        except (IOSPeerLabError, IOSPeerContractError) as error:
            self._state = "poisoned"
            raise IOSPacketLanPeerError(
                "ios_packet_lan_after_capture_invalid",
                "iPhone Packet result or process revalidation is invalid",
            ) from error
        except IOSPacketLanPeerError:
            self._state = "poisoned"
            raise
        document = {
            "schema_version": SCHEMA_VERSION,
            "document": AFTER_CAPTURE_DOCUMENT,
            "claim_eligible": False,
            "session_id": self._material.session_id,
            "process_id": self._ownership.process_id,
            "peer_ipv4": self.peer_ipv4,
            "listener_port": LISTENER_PORT,
            "result_copy": result_copy,
            "result_sha256": hashlib.sha256(result_data).hexdigest(),
            "result_status": result["status"],
            "sender_server_bindings": bindings,
            "process_inventory": inventory_command,
            "process_inventory_sha256": inventory.receipt_sha256,
            "ready_copy": ready_copy,
            "observed_at": _timestamp(observed_at),
        }
        self._state = "capture-validated"
        return document

    def _release(self) -> None:
        if self._released:
            return
        workspace_error: BaseException | None = None
        try:
            _remove_workspace(self._context.workspace)
        except BaseException as error:
            workspace_error = error
        finally:
            _release_admission_lock(self._lock_descriptor)
            self._released = True
        if workspace_error is not None:
            raise workspace_error

    def _finish(self, *, outcome: str) -> dict[str, object]:
        if self._state == "closed":
            raise IOSPacketLanPeerError(
                "ios_packet_lan_lease_state_invalid", "lease is already closed"
            )
        if outcome == "capture-complete" and self._state != "capture-validated":
            raise IOSPacketLanPeerError(
                "ios_packet_lan_lease_state_invalid",
                f"successful close cannot run from {self._state}",
            )
        capture_state = self._state
        cleanup: dict[str, object] | None = None
        primary: BaseException | None = None
        try:
            cleanup = _cleanup_known_installation(
                self._context,
                installation=self._installation,
                packet_ownership=self._ownership,
                primer_ownership=None,
                session_data=self._session_data,
                material=self._material,
                suffix="packet-close",
                now=self._time_source(),
            )
        except BaseException as error:
            primary = error
        try:
            self._release()
        except BaseException as error:
            if primary is None:
                primary = error
            elif isinstance(primary, Exception):
                primary.add_note(
                    f"private workspace release also failed: {type(error).__name__}"
                )
        self._state = "closed"
        self._session_data = b""
        self._ready_data = b""
        if primary is not None:
            raise primary
        if cleanup is None:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_cleanup_unproven", "cleanup produced no receipt"
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "document": CLEANUP_DOCUMENT,
            "claim_eligible": False,
            "outcome": outcome,
            "capture_state": capture_state,
            "session_id": self._material.session_id,
            "process_id": self._ownership.process_id,
            **cleanup,
        }

    def close_with_receipt(self) -> dict[str, object]:
        return self._finish(outcome="capture-complete")

    def close(self) -> dict[str, object]:
        return self.close_with_receipt()

    def abort(self) -> dict[str, object]:
        return self._finish(outcome="aborted")


def _same_source_identity(
    left: IOSPacketLanPeerSourceIdentity,
    right: IOSPacketLanPeerSourceIdentity,
) -> bool:
    return (
        left.file_sha256 == right.file_sha256
        and left.identity_sha256 == right.identity_sha256
        and left.as_identity() == right.as_identity()
    )


def admit_ios_packet_lan_peer(
    *,
    runner: IOSPacketLanPeerRunner,
    tokens: Sequence[str],
    expected_source: IOSPacketLanPeerSourceIdentity,
    time_source: Callable[[], datetime] = _now,
    sleeper: Callable[[float], None] = time.sleep,
) -> IOSPacketLanPeerLease:
    """Admit the sole hash-pinned physical iPhone and start one Packet session."""

    if type(expected_source) is not IOSPacketLanPeerSourceIdentity:
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_invalid", "expected source identity is not typed"
        )
    current_source = load_source_identity()
    if not _same_source_identity(current_source, expected_source):
        raise IOSPacketLanPeerError(
            "ios_packet_lan_source_changed",
            "iOS Packet LAN source identity changed after import",
        )
    lock_descriptor = _acquire_admission_lock()
    workspace: Path | None = None
    context: _TransactionContext | None = None
    installation: IOSPeerInstallationOwnership | None = None
    cleanup_only: IOSPeerCleanupOnlyInstallationOwnership | None = None
    primer_ownership: IOSPeerPrimerProcessOwnership | None = None
    packet_ownership: IOSPeerProcessOwnership | None = None
    preflight: IOSPeerPreflight | None = None
    install_intent_sha256: str | None = None
    session_data: bytes | None = None
    material: IOSPeerPacketLanSessionMaterial | None = None
    try:
        workspace = _create_workspace()
        device_list_output = workspace / "device-json/device-list.json"
        device_list_spec = device_inventory_command(
            REPOSITORY_ROOT, device_list_output
        )
        device_list_result, device_list_command = _run(runner, device_list_spec)
        if device_list_result.stdout or device_list_result.stderr:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_device_inventory_invalid",
                "CoreDevice device list emitted an unreviewed stream",
            )
        device_list_data = _read_stable_file(
            device_list_output, maximum=MAX_PRIVATE_FILE_BYTES, private=True
        )
        selection = _parse_device_selection(
            device_list_data, spec=device_list_spec, source=current_source
        )
        observed_at = time_source()
        artifact_validation = _validate_artifact(
            runner=runner,
            source=current_source,
            device=selection.device,
            workspace=workspace,
            now=observed_at,
        )
        context = _TransactionContext(
            runner=runner,
            source=current_source,
            workspace=workspace,
            device=selection.device,
            artifact=artifact_validation.artifact,
        )

        details_output = context.json_path("device-details-admission.json")
        details_spec = context.plan.device_details(details_output)
        details_data, details_command = context.run_json(details_spec, details_output)
        try:
            admission = parse_device_admission(
                details_data,
                spec=details_spec,
                runtime=current_source.devicectl_runtime,
                device=selection.device,
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_device_admission_invalid",
                "selected iPhone device details differ",
            ) from error

        lock_receipt_sha256, lock_command = context.prove_unlocked("admission")

        apps_before, apps_before_command = context.app_inventory("before")
        processes_before, processes_before_command = context.process_inventory("before")
        try:
            preflight = build_preflight(
                app_inventory=apps_before,
                process_inventory=processes_before,
                device=selection.device,
                observed_at=observed_at,
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_preexisting_test_app",
                "iPhone test app or executable existed before admission",
            ) from error

        install_output = context.json_path("install-admission.json")
        install_spec = context.plan.install(preflight, install_output)
        install_intent_sha256 = _write_install_intent(
            context,
            preflight=preflight,
            spec=install_spec,
            recorded_at=time_source(),
        )
        install_data, install_command = context.run_json(install_spec, install_output)
        apps_installed, apps_installed_command = context.app_inventory("installed")
        try:
            installation = parse_install_receipt(
                install_data,
                spec=install_spec,
                runtime=current_source.devicectl_runtime,
                device=selection.device,
                artifact=artifact_validation.artifact,
                post_install_inventory=apps_installed,
                installed_at=time_source(),
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_install_invalid",
                "iPhone test-app install ownership cannot be proven",
            ) from error

        primer_lock_receipt_sha256, primer_lock_command = context.prove_unlocked(
            "primer-launch"
        )
        primer_launch_output = context.json_path("primer-launch-admission.json")
        primer_launch_spec = context.plan.launch_primer(
            installation, primer_launch_output
        )
        primer_launch_data, primer_launch_command = context.run_json(
            primer_launch_spec, primer_launch_output
        )
        try:
            primer_launch = parse_primer_launch_receipt(
                primer_launch_data,
                spec=primer_launch_spec,
                runtime=current_source.devicectl_runtime,
                device=selection.device,
                installation=installation,
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_primer_launch_invalid",
                "iPhone local-network primer launch receipt differs",
            ) from error
        sleeper(PRIMER_SETTLE_SECONDS)
        primer_processes, primer_processes_command = context.process_inventory(
            "primer-admission"
        )
        primer_data, primer_copy = context.copy_receipt(
            ownership=installation,
            name=PRIMER_RESULT_FILE_NAME,
            suffix="primer-admission",
            primer=True,
        )
        try:
            primer_ownership = bind_primer_process(
                launch=primer_launch,
                process_inventory=primer_processes,
                primer_receipt=primer_data,
                installation=installation,
                device=selection.device,
                artifact=artifact_validation.artifact,
                now=time_source(),
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_primer_invalid",
                "iPhone local-network primer lifecycle cannot be proven",
            ) from error
        stopped_primer, primer_cleanup = _terminate_primer_process(
            context,
            installation=installation,
            ownership=primer_ownership,
            suffix="primer-admission",
            now=time_source(),
        )
        primer_ownership = None

        session_data, session, material = _session_material(
            workspace,
            tokens=tokens,
            now=time_source(),
        )
        session_copy_output = context.json_path("packet-lan-session-copy.json")
        session_copy_spec = context.plan.copy_packet_lan_session_to_device(
            stopped_primer, material.directory, session_copy_output
        )
        session_copy_data, session_copy_command = context.run_json(
            session_copy_spec, session_copy_output
        )
        try:
            session_copy = parse_packet_lan_session_copy_receipt(
                session_copy_data,
                spec=session_copy_spec,
                runtime=current_source.devicectl_runtime,
                device=selection.device,
                stopped_primer=stopped_primer,
                material=material,
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_session_copy_invalid",
                "iPhone Packet session copy receipt differs",
            ) from error

        packet_lock_receipt_sha256, packet_lock_command = context.prove_unlocked(
            "packet-launch"
        )
        launch_output = context.json_path("packet-lan-launch-admission.json")
        launch_spec = context.plan.launch_packet_lan(installation, launch_output)
        launch_data, launch_command = context.run_json(launch_spec, launch_output)
        try:
            launch = parse_packet_lan_launch_receipt(
                launch_data,
                spec=launch_spec,
                runtime=current_source.devicectl_runtime,
                device=selection.device,
                installation=installation,
            )
        except IOSPeerLabError as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_launch_invalid", "iPhone Packet launch receipt differs"
            ) from error
        packet_processes, packet_processes_command = context.process_inventory(
            "packet-admission"
        )
        ready_data, ready_copy = context.copy_receipt(
            ownership=installation,
            name=READY_FILE_NAME,
            suffix="packet-admission",
        )
        try:
            packet_ownership = bind_packet_lan_process(
                launch=launch,
                process_inventory=packet_processes,
                session_document=session_data,
                ready_receipt=ready_data,
                material=material,
                installation=installation,
                device=selection.device,
                artifact=artifact_validation.artifact,
                now=time_source(),
            )
            ready = validate_ready(ready_data, session=session, now=time_source())
        except (IOSPeerLabError, IOSPeerContractError) as error:
            raise IOSPacketLanPeerError(
                "ios_packet_lan_ready_invalid",
                "iPhone Packet process or ready receipt cannot be bound",
            ) from error

        admission_document = {
            "schema_version": SCHEMA_VERSION,
            "document": ADMISSION_DOCUMENT,
            "evidence_role": EVIDENCE_ROLE,
            "claim_eligible": False,
            "source_identity_sha256": current_source.identity_sha256,
            "source_identity_file_sha256": current_source.file_sha256,
            "device": {
                "core_device_identifier_sha256": (
                    current_source.core_device_identifier_sha256
                ),
                "provisioning_udid_sha256": current_source.provisioning_udid_sha256,
                "product_type": selection.product_type,
                "os_version": selection.os_version,
                "os_build": selection.os_build,
                "inventory_connection_state": (
                    selection.inventory_connection_state
                ),
                "inventory_preparedness_state": (
                    selection.inventory_preparedness_state
                ),
                "device_list_receipt_sha256": selection.receipt_sha256,
                "device_list_command": device_list_command,
                "device_details_receipt_sha256": admission.receipt_sha256,
                "device_details_command": details_command,
                "lock_receipt_sha256": lock_receipt_sha256,
                "lock_command": lock_command,
            },
            "artifact": {
                "app_tree_sha256": current_source.app_tree_sha256,
                "executable_sha256": current_source.executable_sha256,
                "source_tree_sha256": current_source.source_tree_sha256,
                "profile_sha256": current_source.profile_sha256,
                "entitlements_sha256": current_source.entitlements_sha256,
                "signing_certificate_sha256": (
                    current_source.signing_certificate_sha256
                ),
                "validation": copy.deepcopy(dict(artifact_validation.receipts)),
            },
            "preflight": {
                "app_inventory_sha256": preflight.app_inventory_receipt_sha256,
                "process_inventory_sha256": (
                    preflight.process_inventory_receipt_sha256
                ),
                "app_inventory_command": apps_before_command,
                "process_inventory_command": processes_before_command,
                "app_absent": True,
                "process_absent": True,
            },
            "installation": {
                "install_intent_sha256": install_intent_sha256,
                "install_receipt_sha256": installation.install_receipt_sha256,
                "post_install_app_inventory_sha256": (
                    installation.app_inventory_receipt_sha256
                ),
                "install_command": install_command,
                "post_install_app_inventory_command": apps_installed_command,
            },
            "primer": {
                "pre_launch_lock_receipt_sha256": primer_lock_receipt_sha256,
                "pre_launch_lock_command": primer_lock_command,
                "launch_receipt_sha256": primer_launch.receipt_sha256,
                "launch_command": primer_launch_command,
                "process_inventory_sha256": primer_processes.receipt_sha256,
                "process_inventory_command": primer_processes_command,
                "receipt_copy": primer_copy,
                "cleanup": primer_cleanup,
            },
            "session": {
                "session_id": material.session_id,
                "session_sha256": material.session_sha256,
                "copy_receipt_sha256": session_copy.receipt_sha256,
                "copy_command": session_copy_command,
            },
            "process": {
                "pre_launch_lock_receipt_sha256": packet_lock_receipt_sha256,
                "pre_launch_lock_command": packet_lock_command,
                "process_id": packet_ownership.process_id,
                "launch_receipt_sha256": launch.receipt_sha256,
                "launch_command": launch_command,
                "process_inventory_sha256": packet_processes.receipt_sha256,
                "process_inventory_command": packet_processes_command,
                "ready_copy": ready_copy,
            },
            "network": copy.deepcopy(ready["network"]),
            "listener": copy.deepcopy(ready["listener"]),
            "admitted_at": _timestamp(time_source()),
        }
        lease = IOSPacketLanPeerLease(
            context=context,
            lock_descriptor=lock_descriptor,
            installation=installation,
            ownership=packet_ownership,
            session_data=session_data,
            session=session,
            material=material,
            ready_data=ready_data,
            ready=ready,
            admission=admission_document,
            time_source=time_source,
            sleeper=sleeper,
        )
        return lease
    except BaseException as primary:
        cleanup_error: BaseException | None = None
        if context is not None and preflight is not None:
            try:
                if installation is None and install_intent_sha256 is not None:
                    post_intent_apps, _post_apps_command = context.app_inventory(
                        "ambiguous-install"
                    )
                    matching_apps = [
                        item
                        for item in post_intent_apps.entries
                        if item.bundle_identifier == BUNDLE_IDENTIFIER
                    ]
                    if matching_apps:
                        cleanup_only = (
                            authorize_cleanup_only_installation_from_preflight(
                                preflight=preflight,
                                post_intent_inventory=post_intent_apps,
                                device=context.device,
                                artifact=context.artifact,
                                install_intent_sha256=install_intent_sha256,
                                observed_at=time_source(),
                            )
                        )
                    else:
                        post_intent_processes, _post_processes_command = (
                            context.process_inventory("ambiguous-install")
                        )
                        verify_post_uninstall_absence(
                            app_inventory=post_intent_apps,
                            process_inventory=post_intent_processes,
                            device=context.device,
                            ownership=None,
                        )
                cleanup_installation = (
                    installation if installation is not None else cleanup_only
                )
                if cleanup_installation is not None:
                    _cleanup_known_installation(
                        context,
                        installation=cleanup_installation,
                        packet_ownership=packet_ownership,
                        primer_ownership=primer_ownership,
                        session_data=session_data,
                        material=material,
                        suffix="admission-abort",
                        now=time_source(),
                    )
            except BaseException as error:
                cleanup_error = error
        if workspace is not None:
            try:
                _remove_workspace(workspace)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
                elif isinstance(cleanup_error, Exception):
                    cleanup_error.add_note(
                        f"workspace removal also failed: {type(error).__name__}"
                    )
        _release_admission_lock(lock_descriptor)
        if cleanup_error is not None and isinstance(primary, IOSPacketLanPeerError):
            primary.attach_cleanup_context(cleanup_error)
        elif cleanup_error is not None and isinstance(primary, Exception):
            primary.add_note(
                f"iPhone Packet LAN cleanup also failed: {type(cleanup_error).__name__}"
            )
        if isinstance(primary, IOSPacketLanPeerError) or not isinstance(
            primary, Exception
        ):
            raise
        raise IOSPacketLanPeerError(
            "ios_packet_lan_admission_failed",
            "iPhone Packet LAN admission failed at an unexpected boundary",
        ) from primary


__all__ = [
    "ADMISSION_DOCUMENT",
    "AFTER_CAPTURE_DOCUMENT",
    "BEFORE_CAPTURE_DOCUMENT",
    "CLEANUP_DOCUMENT",
    "IOSPacketLanPeerError",
    "IOSPacketLanPeerLease",
    "IOSPacketLanPeerRunner",
    "IOSPacketLanPeerSourceIdentity",
    "PROVENANCE_DOCUMENT",
    "SOURCE_IDENTITY_FILE_SHA256",
    "SOURCE_IDENTITY_PATH",
    "admit_ios_packet_lan_peer",
    "load_source_identity",
    "validate_static_source_identity",
]
