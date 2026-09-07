"""Strict host-side foundations for one controlled iPhone transport-peer smoke.

This module has no CLI and deliberately executes nothing.  It provides pure
command specifications, parsers, ownership bindings, and a local durable
transaction journal.  A later operator-owned runner must explicitly execute
each command and must keep the existing CFW installation and network settings
read-only.

The lab transaction is not physical release evidence by itself.  Its typed
Packet-LAN ownership primitives are consumed by the separate versioned adapter;
only that adapter's joint Packet-v4 provenance can participate in a claim.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import ipaddress
import json
import os
import plistlib
import re
import stat
import uuid
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Final, Self
from urllib.parse import quote, unquote, urlsplit

from scripts.harness.raw_artifacts import (
    RawArtifactError,
    canonical_json,
    load_json_bytes,
)

from .execution import CommandSpec
from .ios_transport_peer import (
    APP_EXECUTABLE,
    BUNDLE_IDENTIFIER,
    CERTIFICATE_FILE_NAME,
    MAX_JSON_BYTES,
    MAX_PID,
    PRIMER_LAUNCH_ARGUMENT,
    PRIMER_RESULT_FILE_NAME,
    PRIVATE_KEY_FILE_NAME,
    SESSION_DIRECTORY_NAME,
    SESSION_FILE_NAME,
    TRANSPORT_RUN_ARGUMENT,
    UNKNOWN_LAUNCH_SERVICES_IDENTIFIER,
    IOSPeerArtifact,
    IOSPeerCleanupOnlyInstallationOwnership,
    IOSPeerContractError,
    IOSPeerDevice,
    IOSPeerInstallationOwnership,
    IOSPeerPreflight,
    IOSPeerPrimerProcessCleanupAuthority,
    IOSPeerPrimerProcessOwnership,
    IOSPeerProcessCleanupAuthority,
    IOSPeerProcessOwnership,
    PrimerStoppedOwnership,
    device_identifier_sha256,
    transport_payload_receipt_sha256,
    validate_primer_receipt,
    validate_ready_receipt,
    validate_result_receipt,
    validate_session_document,
)
from .ios_packet_lan_peer import (
    DEVICE_DIRECTORY as PACKET_LAN_DEVICE_DIRECTORY,
    DIRECTORY_NAME as PACKET_LAN_DIRECTORY_NAME,
    LAUNCH_ARGUMENT as PACKET_LAN_LAUNCH_ARGUMENT,
    SESSION_FILE_NAME as PACKET_LAN_SESSION_FILE_NAME,
    validate_ready as validate_packet_lan_ready,
    validate_session as validate_packet_lan_session,
)

LAB_SCHEMA_VERSION: Final = 3
JOURNAL_DOCUMENT: Final = "cfm-ios-transport-peer-lab-journal-v3"
JOURNAL_DIRECTORY: Final = "journal"
LOCK_FILE: Final = "transaction.lock"
MAX_DEVICECTL_JSON_BYTES: Final = 2 * 1024 * 1024
MAX_PROFILE_BYTES: Final = 2 * 1024 * 1024
MAX_CODESIGN_OUTPUT_BYTES: Final = 256 * 1024
MAX_APP_TREE_FILES: Final = 4096
MAX_APP_TREE_BYTES: Final = 128 * 1024 * 1024
MAX_JOURNAL_EVENT_BYTES: Final = 32 * 1024
MAX_JOURNAL_EVENTS: Final = 32
SECURITY: Final = Path("/usr/bin/security")
CODESIGN: Final = Path("/usr/bin/codesign")
PS: Final = Path("/bin/ps")
NETSTAT: Final = Path("/usr/sbin/netstat")
NETWORKSETUP: Final = Path("/usr/sbin/networksetup")
ROUTE: Final = Path("/sbin/route")
LIPO: Final = Path("/usr/bin/lipo")
VTOOL: Final = Path("/usr/bin/vtool")
COREDEVICE_CONTROL_TRANSPORT: Final = "localNetwork"
COREDEVICE_AUTHENTICATION_TYPE: Final = "manualPairing"
COREDEVICE_TUNNEL_TRANSPORT_PROTOCOL: Final = "tcp"

_HEX_40_UPPER = re.compile(r"^[0-9A-F]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_TEAM_IDENTIFIER = re.compile(r"^[A-Z0-9]{10}$")
_VERSION = re.compile(r"^[1-9][0-9]*(?:\.[0-9]+){1,3}$")
_COMMAND_TYPE = re.compile(r"^devicectl(?:\.[A-Za-z][A-Za-z0-9-]*){2,8}$")
_REMOTE_PATH = re.compile(r"^/[\x21-\x7e]{1,4095}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_DEVICE_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)
_REMOTE_SESSION_PATH = re.compile(
    r"^/private/var/mobile/Containers/Data/Application/"
    r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/"
    rf"Documents/{SESSION_DIRECTORY_NAME}$"
)
_REMOTE_PACKET_LAN_SESSION_PATH = re.compile(
    r"^/private/var/mobile/Containers/Data/Application/"
    r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/"
    rf"{PACKET_LAN_DEVICE_DIRECTORY}$"
)
_APP_INFO_REQUIRED = {
    "appClip",
    "builtByDeveloper",
    "containerAccessible",
    "defaultApp",
    "hidden",
    "internalApp",
    "name",
    "removable",
}
_APP_INFO_OPTIONAL = {"bundleIdentifier", "bundleVersion", "url", "version"}
_PROCESS_INFO_REQUIRED = {"processIdentifier"}
_PROCESS_INFO_OPTIONAL = {"auditToken", "executable"}
_APP_INVENTORY_RESULT_FIELDS = {
    "apps",
    "defaultAppsIncluded",
    "deviceIdentifier",
    "hiddenAppsIncluded",
    "internalAppsIncluded",
    "matchingBundleIdentifier",
    "removableAppsIncluded",
}
_INSTALL_RESULT_FIELDS = {"deviceIdentifier", "installedApplications"}
_INSTALLED_APP_FIELDS = {
    "bundleID",
    "databaseSequenceNumber",
    "databaseUUID",
    "installationURL",
    "launchServicesIdentifier",
    "options",
}
_PROCESS_INVENTORY_RESULT_FIELDS = {"deviceIdentifier", "runningProcesses"}
_LAUNCH_RESULT_FIELDS = {
    "deviceIdentifier",
    "launchOptions",
    "process",
}
_TERMINATE_RESULT_FIELDS = {
    "deviceIdentifier",
    "deviceTimestamp",
    "process",
    "signal",
}
_SIGNAL_FIELDS = {"name", "value"}
_SESSION_COPY_RESULT_FIELDS = {
    "destination",
    "deviceIdentifier",
    "domain",
    "domainIdentifier",
    "file",
    "source",
    "sources",
}
_SESSION_COPY_FILE_FIELDS = {"metadata", "name", "relativePath", "resources"}
_SESSION_COPY_METADATA_FIELDS = {
    "extendedAttributes",
    "lastModDate",
    "ownerGid",
    "ownerUid",
    "permissions",
    "size",
}
_SESSION_COPY_RESOURCE_FIELDS = {
    "isDirectory",
    "isHidden",
    "isReadable",
    "isSymbolicLink",
    "isWritable",
}
_UNINSTALL_RESULT_FIELDS = {"deviceIdentifier", "uninstalledApplications"}
_LAUNCH_OPTION_FIELDS = {
    "activatedWhenStarted",
    "arguments",
    "environmentVariables",
    "platformSpecificOptions",
    "startStopped",
    "terminateExistingInstances",
    "user",
}
_INFO_REQUIRED_FIELDS = {
    "arguments",
    "commandType",
    "environment",
    "jsonVersion",
    "outcome",
    "version",
}
_INFO_OPTIONAL_FIELDS = {"details"}


class IOSPeerLabError(RuntimeError):
    """A lab input, parser result, or transaction transition is unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise IOSPeerLabError("ios_lab_digest_invalid", f"{label} is not one SHA-256")
    return value


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise IOSPeerLabError(
            "ios_lab_time_invalid", f"{label} is not one canonical UTC timestamp"
        )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise IOSPeerLabError("ios_lab_time_invalid", f"{label} is not real") from error


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise IOSPeerLabError(
            "ios_lab_time_invalid", "lab timestamp must be timezone-aware"
        )
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _exact_object(
    value: object,
    required: set[str],
    label: str,
    *,
    optional: set[str] = frozenset(),
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise IOSPeerLabError("ios_lab_json_invalid", f"{label} is not an object")
    keys = set(value)
    if not required <= keys or keys - required - optional:
        raise IOSPeerLabError(
            "ios_lab_json_invalid", f"{label} has unknown or missing fields"
        )
    if any(not isinstance(key, str) for key in value):
        raise IOSPeerLabError("ios_lab_json_invalid", f"{label} has a non-string key")
    return value


def _read_stable_file(path: Path, *, maximum: int, label: str) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise IOSPeerLabError("ios_lab_file_invalid", f"{label} path is not absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_file_invalid", f"{label} is unavailable"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or before.st_mode & 0o022
            or not 1 <= before.st_size <= maximum
        ):
            raise IOSPeerLabError("ios_lab_file_invalid", f"{label} metadata is unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 128 * 1024))
            if not chunk:
                raise IOSPeerLabError(
                    "ios_lab_file_invalid", f"{label} was truncated while read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise IOSPeerLabError(
                "ios_lab_file_invalid", f"{label} grew while it was read"
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise IOSPeerLabError("ios_lab_file_invalid", f"{label} changed while read")
    return b"".join(chunks)


def _require_private_directory(path: Path, *, label: str) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise IOSPeerLabError("ios_lab_directory_invalid", f"{label} is not absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_directory_invalid", f"{label} is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise IOSPeerLabError(
            "ios_lab_directory_invalid", f"{label} is not a private real directory"
        )


def _require_absent_private_output(path: Path, *, suffix: str, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.suffix != suffix:
        raise IOSPeerLabError("ios_lab_output_invalid", f"{label} path is not fixed")
    _require_private_directory(path.parent, label=f"{label} parent")
    try:
        path.lstat()
    except FileNotFoundError:
        return path
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_output_invalid", f"{label} is unavailable"
        ) from error
    raise IOSPeerLabError(
        "ios_lab_output_invalid", f"{label} must not exist before the command"
    )


def _fixed_command(
    role: str,
    executable: Path,
    *arguments: str,
    cwd: Path,
    timeout_seconds: float = 30.0,
    stdout_limit: int = MAX_CODESIGN_OUTPUT_BYTES,
) -> CommandSpec:
    return CommandSpec(
        role=role,
        argv=(str(executable), *arguments),
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        stdout_limit=stdout_limit,
        stderr_limit=MAX_CODESIGN_OUTPUT_BYTES,
    )


@dataclass(frozen=True, slots=True)
class IOSPeerSigningInputs:
    """All operator-selected signing authority; nothing is auto-discovered."""

    profile_path: Path
    profile_sha256: str
    keychain_path: Path
    signing_identity_sha1: str
    signing_identity_label: str
    signing_certificate_sha256: str
    team_identifier: str

    def __post_init__(self) -> None:
        profile = _read_stable_file(
            self.profile_path, maximum=MAX_PROFILE_BYTES, label="provisioning profile"
        )
        keychain = _read_stable_file(
            self.keychain_path, maximum=64 * 1024 * 1024, label="signing keychain"
        )
        if _sha256(profile) != _require_sha256(
            self.profile_sha256, "provisioning profile digest"
        ):
            raise IOSPeerLabError(
                "ios_lab_profile_invalid", "provisioning profile digest differs"
            )
        if not keychain:
            raise IOSPeerLabError(
                "ios_lab_keychain_invalid", "signing keychain is empty"
            )
        if (
            not isinstance(self.signing_identity_sha1, str)
            or _HEX_40_UPPER.fullmatch(self.signing_identity_sha1) is None
            or not isinstance(self.signing_identity_label, str)
            or not 1 <= len(self.signing_identity_label) <= 256
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in self.signing_identity_label
            )
            or _TEAM_IDENTIFIER.fullmatch(self.team_identifier) is None
        ):
            raise IOSPeerLabError(
                "ios_lab_signing_identity_invalid",
                "explicit signing identity is invalid",
            )
        _require_sha256(self.signing_certificate_sha256, "signing certificate digest")


@dataclass(frozen=True, slots=True)
class IOSPeerProvisioningProfile:
    uuid: str
    name: str
    team_identifier: str
    application_identifier: str
    provisioning_udids: tuple[str, ...]
    signing_certificate_sha256: str
    creation_at: str
    expires_at: str
    get_task_allow: bool


def parse_decoded_provisioning_profile(
    data: bytes,
    *,
    inputs: IOSPeerSigningInputs,
    device: IOSPeerDevice,
    now: datetime,
) -> IOSPeerProvisioningProfile:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_PROFILE_BYTES:
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "decoded provisioning profile size is invalid"
        )
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "decoded provisioning profile is not a plist"
        ) from error
    if not isinstance(value, dict):
        raise IOSPeerLabError(
            "ios_lab_profile_invalid",
            "decoded provisioning profile is not a dictionary",
        )
    required = {
        "CreationDate",
        "DeveloperCertificates",
        "Entitlements",
        "ExpirationDate",
        "Name",
        "Platform",
        "ProvisionedDevices",
        "TeamIdentifier",
        "UUID",
    }
    if not required <= set(value):
        raise IOSPeerLabError(
            "ios_lab_profile_invalid",
            "decoded provisioning profile lacks authority fields",
        )
    team_values = value["TeamIdentifier"]
    devices = value["ProvisionedDevices"]
    certificates = value["DeveloperCertificates"]
    entitlements = value["Entitlements"]
    platforms = value["Platform"]
    if (
        team_values != [inputs.team_identifier]
        or not isinstance(platforms, list)
        or not platforms
        or any(not isinstance(item, str) for item in platforms)
        or len(platforms) != len(set(platforms))
        or "iOS" not in platforms
        or not set(platforms) <= {"iOS", "xrOS", "visionOS"}
        or not isinstance(devices, list)
        or not devices
        or any(not isinstance(item, str) for item in devices)
        or len(set(devices)) != len(devices)
        or device.provisioning_udid not in devices
        or not isinstance(certificates, list)
        or not certificates
        or any(not isinstance(item, bytes) for item in certificates)
        or not isinstance(entitlements, dict)
    ):
        raise IOSPeerLabError(
            "ios_lab_profile_invalid",
            "provisioning profile does not bind the explicit iPhone, team, and platform",
        )
    certificate_digests = {_sha256(item) for item in certificates}
    if inputs.signing_certificate_sha256 not in certificate_digests:
        raise IOSPeerLabError(
            "ios_lab_profile_invalid",
            "signing certificate is not authorized by the profile",
        )
    app_identifier = f"{inputs.team_identifier}.{BUNDLE_IDENTIFIER}"
    profile_app_identifier = entitlements.get("application-identifier")
    if (
        profile_app_identifier not in {app_identifier, f"{inputs.team_identifier}.*"}
        or entitlements.get("com.apple.developer.team-identifier")
        != inputs.team_identifier
        or entitlements.get("get-task-allow") is not True
    ):
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "profile App ID or team entitlement differs"
        )
    creation = value["CreationDate"]
    expiry = value["ExpirationDate"]
    if (
        not isinstance(creation, datetime)
        or not isinstance(expiry, datetime)
        or creation.tzinfo is not None
        or expiry.tzinfo is not None
    ):
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "profile dates are not canonical plist UTC dates"
        )
    current = now.astimezone(timezone.utc).replace(tzinfo=None)
    if not creation <= current < expiry:
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "provisioning profile is not currently valid"
        )
    name = value["Name"]
    profile_uuid = value["UUID"]
    try:
        canonical_uuid_lower = str(uuid.UUID(profile_uuid))
    except (TypeError, ValueError, AttributeError) as error:
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "profile UUID is invalid"
        ) from error
    if (
        profile_uuid not in {canonical_uuid_lower, canonical_uuid_lower.upper()}
        or not isinstance(name, str)
        or not 1 <= len(name) <= 256
    ):
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "profile name or UUID is not canonical"
        )
    return IOSPeerProvisioningProfile(
        uuid=canonical_uuid_lower.upper(),
        name=name,
        team_identifier=inputs.team_identifier,
        application_identifier=app_identifier,
        provisioning_udids=tuple(devices),
        signing_certificate_sha256=inputs.signing_certificate_sha256,
        creation_at=_canonical_timestamp(creation.replace(tzinfo=timezone.utc)),
        expires_at=_canonical_timestamp(expiry.replace(tzinfo=timezone.utc)),
        get_task_allow=entitlements["get-task-allow"],
    )


def minimal_entitlements_plist(profile: IOSPeerProvisioningProfile) -> bytes:
    if type(profile) is not IOSPeerProvisioningProfile:
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "entitlements require a validated profile"
        )
    value = {
        "application-identifier": profile.application_identifier,
        "com.apple.developer.team-identifier": profile.team_identifier,
        "get-task-allow": profile.get_task_allow,
    }
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)


@dataclass(frozen=True, slots=True)
class ManualSigningAuthorization:
    """Explicit mutation intent required merely to construct a signing command."""

    profile_uuid: str
    app_tree_sha256: str
    entitlements_sha256: str
    explicitly_authorized: bool

    def __post_init__(self) -> None:
        try:
            canonical = str(uuid.UUID(self.profile_uuid)).upper()
        except (TypeError, ValueError, AttributeError) as error:
            raise IOSPeerLabError(
                "ios_lab_signing_authority_invalid", "signing profile UUID is invalid"
            ) from error
        if self.profile_uuid != canonical or self.explicitly_authorized is not True:
            raise IOSPeerLabError(
                "ios_lab_signing_authority_invalid", "manual signing was not explicit"
            )
        _require_sha256(self.app_tree_sha256, "pre-sign app-tree digest")
        _require_sha256(self.entitlements_sha256, "manual entitlements digest")


@dataclass(frozen=True, slots=True)
class IOSPeerSigningCommandPlan:
    repository: Path
    artifact: IOSPeerArtifact
    inputs: IOSPeerSigningInputs

    def __post_init__(self) -> None:
        _require_real_working_directory(
            self.repository, label="signing working directory"
        )

    def decode_profile(self, output: Path) -> CommandSpec:
        output = _require_absent_private_output(
            output, suffix=".plist", label="decoded profile"
        )
        return _fixed_command(
            "ios-peer-profile-decode",
            SECURITY,
            "cms",
            "-D",
            "-i",
            str(self.inputs.profile_path),
            "-o",
            str(output),
            cwd=self.repository,
        )

    def export_keychain_certificate(self) -> CommandSpec:
        return _fixed_command(
            "ios-peer-keychain-certificate",
            SECURITY,
            "find-certificate",
            "-c",
            self.inputs.signing_identity_label,
            "-p",
            str(self.inputs.keychain_path),
            cwd=self.repository,
        )

    def verify_signature(self) -> CommandSpec:
        return _fixed_command(
            "ios-peer-codesign-verify",
            CODESIGN,
            "--verify",
            "--strict",
            "--verbose=4",
            str(self.artifact.app_path),
            cwd=self.repository,
        )

    def signature_details(self) -> CommandSpec:
        return _fixed_command(
            "ios-peer-codesign-details",
            CODESIGN,
            "--display",
            "--verbose=4",
            str(self.artifact.app_path),
            cwd=self.repository,
        )

    def signature_entitlements(self) -> CommandSpec:
        return _fixed_command(
            "ios-peer-codesign-entitlements",
            CODESIGN,
            "--display",
            "--entitlements",
            "-",
            "--xml",
            str(self.artifact.app_path),
            cwd=self.repository,
        )

    def executable_architectures(self) -> CommandSpec:
        return _fixed_command(
            "ios-peer-executable-architectures",
            LIPO,
            "-archs",
            str(self.artifact.app_path / APP_EXECUTABLE),
            cwd=self.repository,
        )

    def executable_build_version(self) -> CommandSpec:
        return _fixed_command(
            "ios-peer-executable-build-version",
            VTOOL,
            "-show-build",
            str(self.artifact.app_path / APP_EXECUTABLE),
            cwd=self.repository,
        )

    def manual_sign(
        self,
        profile: IOSPeerProvisioningProfile,
        entitlements_path: Path,
        authorization: ManualSigningAuthorization,
    ) -> CommandSpec:
        entitlements = _read_stable_file(
            entitlements_path,
            maximum=64 * 1024,
            label="manual signing entitlements",
        )
        if (
            type(profile) is not IOSPeerProvisioningProfile
            or type(authorization) is not ManualSigningAuthorization
            or authorization.profile_uuid != profile.uuid
            or authorization.app_tree_sha256 != self.artifact.app_tree_sha256
            or authorization.entitlements_sha256 != _sha256(entitlements)
            or entitlements != minimal_entitlements_plist(profile)
        ):
            raise IOSPeerLabError(
                "ios_lab_signing_authority_invalid",
                "manual signing command is not bound to the reviewed inputs",
            )
        return _fixed_command(
            "ios-peer-manual-codesign",
            CODESIGN,
            "--force",
            "--sign",
            self.inputs.signing_identity_sha1,
            "--keychain",
            str(self.inputs.keychain_path),
            "--entitlements",
            str(entitlements_path),
            "--generate-entitlement-der",
            "--timestamp=none",
            str(self.artifact.app_path),
            cwd=self.repository,
            timeout_seconds=120.0,
        )


def validate_keychain_certificate_pem(
    data: bytes, *, inputs: IOSPeerSigningInputs
) -> None:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_CODESIGN_OUTPUT_BYTES:
        raise IOSPeerLabError(
            "ios_lab_keychain_invalid", "exported keychain certificate is invalid"
        )
    begin = b"-----BEGIN CERTIFICATE-----\n"
    end = b"-----END CERTIFICATE-----\n"
    if not data.startswith(begin) or not data.endswith(end) or data.count(begin) != 1:
        raise IOSPeerLabError(
            "ios_lab_keychain_invalid",
            "keychain output is not exactly one PEM certificate",
        )
    encoded = b"".join(data[len(begin) : -len(end)].splitlines())
    try:
        certificate = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IOSPeerLabError(
            "ios_lab_keychain_invalid", "keychain certificate PEM is malformed"
        ) from error
    if _sha256(certificate) != inputs.signing_certificate_sha256:
        raise IOSPeerLabError(
            "ios_lab_keychain_invalid", "keychain certificate is not profile-authorized"
        )


def validate_profile_source_unchanged(inputs: IOSPeerSigningInputs) -> str:
    data = _read_stable_file(
        inputs.profile_path,
        maximum=MAX_PROFILE_BYTES,
        label="embedded profile source",
    )
    digest = _sha256(data)
    if digest != inputs.profile_sha256:
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "provisioning profile source changed"
        )
    return digest


def validate_embedded_profile(
    artifact: IOSPeerArtifact, *, inputs: IOSPeerSigningInputs
) -> str:
    if type(artifact) is not IOSPeerArtifact:
        raise IOSPeerLabError(
            "ios_lab_profile_invalid", "embedded profile lacks typed app identity"
        )
    source = _read_stable_file(
        inputs.profile_path, maximum=MAX_PROFILE_BYTES, label="profile source"
    )
    embedded = _read_stable_file(
        artifact.app_path / "embedded.mobileprovision",
        maximum=MAX_PROFILE_BYTES,
        label="embedded provisioning profile",
    )
    digest = _sha256(source)
    if digest != inputs.profile_sha256 or embedded != source:
        raise IOSPeerLabError(
            "ios_lab_profile_invalid",
            "embedded provisioning profile differs from the explicit source bytes",
        )
    return digest


def validate_codesign_details(data: bytes, *, inputs: IOSPeerSigningInputs) -> str:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_CODESIGN_OUTPUT_BYTES:
        raise IOSPeerLabError(
            "ios_lab_signature_invalid", "codesign details size is invalid"
        )
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise IOSPeerLabError(
            "ios_lab_signature_invalid", "codesign details are not UTF-8"
        ) from error
    fields: dict[str, list[str]] = {}
    signature_lines: list[str] = []
    for line in lines:
        if not line or any(ord(character) < 0x20 for character in line):
            raise IOSPeerLabError(
                "ios_lab_signature_invalid", "codesign details contain invalid text"
            )
        if line.startswith(("Signature size=", "Signature=")):
            signature_lines.append(line)
        if "=" in line:
            key, value = line.split("=", 1)
            fields.setdefault(key, []).append(value)
    identifier = fields.get("Identifier", [])
    team = fields.get("TeamIdentifier", [])
    authorities = fields.get("Authority", [])
    cdhash = fields.get("CDHash", [])
    if (
        identifier != [BUNDLE_IDENTIFIER]
        or team != [inputs.team_identifier]
        or authorities.count(inputs.signing_identity_label) != 1
        or len(cdhash) != 1
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", cdhash[0]) is None
        or len(signature_lines) != 1
        or "adhoc" in signature_lines[0].lower()
    ):
        raise IOSPeerLabError(
            "ios_lab_signature_invalid",
            "codesign identity, authority, CDHash, or signature mode differs",
        )
    validate_profile_source_unchanged(inputs)
    return cdhash[0]


def validate_executable_architectures(data: bytes) -> None:
    if data != b"arm64\n":
        raise IOSPeerLabError(
            "ios_lab_artifact_invalid", "peer executable is not thin arm64"
        )


def validate_executable_build_version(data: bytes) -> None:
    if not isinstance(data, bytes) or not 1 <= len(data) <= 64 * 1024:
        raise IOSPeerLabError(
            "ios_lab_artifact_invalid", "vtool build output size is invalid"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IOSPeerLabError(
            "ios_lab_artifact_invalid", "vtool build output is not UTF-8"
        ) from error
    platforms = re.findall(r"^\s*platform\s+(\S+)\s*$", text, re.MULTILINE)
    minimum_versions = re.findall(r"^\s*minos\s+(\S+)\s*$", text, re.MULTILINE)
    commands = re.findall(r"^\s*cmd\s+LC_BUILD_VERSION\s*$", text, re.MULTILINE)
    if platforms != ["IOS"] or minimum_versions != ["17.0"] or len(commands) != 1:
        raise IOSPeerLabError(
            "ios_lab_artifact_invalid",
            "peer executable platform or minimum iOS version differs",
        )


def validate_signed_entitlements(
    data: bytes, *, profile: IOSPeerProvisioningProfile
) -> None:
    if not isinstance(data, bytes) or not 1 <= len(data) <= 64 * 1024:
        raise IOSPeerLabError(
            "ios_lab_signature_invalid", "signed entitlements size is invalid"
        )
    try:
        value = plistlib.loads(data)
        expected = plistlib.loads(minimal_entitlements_plist(profile))
    except (plistlib.InvalidFileException, ValueError) as error:
        raise IOSPeerLabError(
            "ios_lab_signature_invalid", "signed entitlements are not a plist"
        ) from error
    if value != expected:
        raise IOSPeerLabError(
            "ios_lab_signature_invalid",
            "signed entitlements differ from the reviewed subset",
        )


def inspect_ios_peer_artifact(app_path: Path) -> IOSPeerArtifact:
    """Re-open and hash the exact staged app tree without following symlinks."""

    if (
        not isinstance(app_path, Path)
        or not app_path.is_absolute()
        or app_path.name != f"{APP_EXECUTABLE}.app"
    ):
        raise IOSPeerLabError("ios_lab_artifact_invalid", "staged app path is invalid")
    try:
        root_metadata = app_path.lstat()
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_artifact_invalid", "staged app is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or app_path.is_symlink()
        or root_metadata.st_uid not in {0, os.geteuid()}
        or root_metadata.st_mode & 0o022
    ):
        raise IOSPeerLabError("ios_lab_artifact_invalid", "staged app root is unsafe")
    info_data = _read_stable_file(
        app_path / "Info.plist", maximum=256 * 1024, label="staged app Info.plist"
    )
    try:
        info = plistlib.loads(info_data)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise IOSPeerLabError(
            "ios_lab_artifact_invalid", "staged app Info.plist is invalid"
        ) from error
    if (
        not isinstance(info, dict)
        or info.get("CFBundleIdentifier") != BUNDLE_IDENTIFIER
        or info.get("CFBundleExecutable") != APP_EXECUTABLE
    ):
        raise IOSPeerLabError("ios_lab_artifact_invalid", "staged app identity differs")
    executable_path = app_path / APP_EXECUTABLE
    executable = _read_stable_file(
        executable_path, maximum=MAX_APP_TREE_BYTES, label="staged app executable"
    )
    records: list[bytes] = []
    total = 0
    count = 0
    forbidden_directories = {"Frameworks", "PlugIns", "Extensions", "XPCServices"}
    for current, directory_names, file_names in os.walk(app_path, followlinks=False):
        current_path = Path(current)
        for name in sorted(directory_names):
            directory = current_path / name
            metadata = directory.lstat()
            if (
                name in forbidden_directories
                or directory.suffix in {".framework", ".appex", ".xpc", ".app"}
                or directory.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
            ):
                raise IOSPeerLabError(
                    "ios_lab_artifact_invalid",
                    "staged app contains nested code or a non-real directory",
                )
        for name in sorted(file_names):
            path = current_path / name
            if path.suffix in {".dylib", ".so"}:
                raise IOSPeerLabError(
                    "ios_lab_artifact_invalid",
                    "staged app contains nested dynamic code",
                )
            data = _read_stable_file(
                path, maximum=MAX_APP_TREE_BYTES, label="staged app member"
            )
            metadata = path.lstat()
            count += 1
            total += len(data)
            if count > MAX_APP_TREE_FILES or total > MAX_APP_TREE_BYTES:
                raise IOSPeerLabError(
                    "ios_lab_artifact_invalid", "staged app tree exceeds its bound"
                )
            relative = path.relative_to(app_path).as_posix().encode("utf-8")
            records.append(
                len(relative).to_bytes(4, "big")
                + relative
                + stat.S_IMODE(metadata.st_mode).to_bytes(4, "big")
                + len(data).to_bytes(8, "big")
                + hashlib.sha256(data).digest()
            )
    if not records:
        raise IOSPeerLabError("ios_lab_artifact_invalid", "staged app tree is empty")
    return IOSPeerArtifact(
        app_path=app_path,
        executable_sha256=_sha256(executable),
        app_tree_sha256=_sha256(b"".join(records)),
    )


@dataclass(frozen=True, slots=True)
class DevicectlRuntime:
    """The separately observed CoreDevice JSON implementation for this run."""

    version: str
    json_version: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.version, str)
            or _VERSION.fullmatch(self.version) is None
            or type(self.json_version) is not int
            or not 1 <= self.json_version <= 32
        ):
            raise IOSPeerLabError(
                "ios_lab_devicectl_runtime_invalid",
                "devicectl runtime version contract is invalid",
            )


@dataclass(frozen=True, slots=True)
class DeviceAdmission:
    receipt_sha256: str
    core_device_identifier: str
    provisioning_udid: str
    platform: str
    reality: str
    cpu_name: str
    control_transport: str
    authentication_type: str
    tunnel_transport_protocol: str

    def __post_init__(self) -> None:
        _require_sha256(self.receipt_sha256, "device-admission receipt digest")
        if (
            self.control_transport != COREDEVICE_CONTROL_TRANSPORT
            or self.authentication_type != COREDEVICE_AUTHENTICATION_TYPE
            or self.tunnel_transport_protocol != COREDEVICE_TUNNEL_TRANSPORT_PROTOCOL
        ):
            raise IOSPeerLabError(
                "ios_lab_device_binding_invalid",
                "device-admission control channel differs from the fixed policy",
            )


@dataclass(frozen=True, slots=True)
class AppInventoryEntry:
    bundle_identifier: str | None
    name: str
    url: str | None
    built_by_developer: bool
    removable: bool


@dataclass(frozen=True, slots=True)
class AppInventory:
    receipt_sha256: str
    device_identifier: str
    entries: tuple[AppInventoryEntry, ...]


@dataclass(frozen=True, slots=True)
class DeviceProcess:
    process_id: int
    executable_path: str | None


@dataclass(frozen=True, slots=True)
class ProcessInventory:
    receipt_sha256: str
    device_identifier: str
    processes: tuple[DeviceProcess, ...]


@dataclass(frozen=True, slots=True)
class PrimerLaunchObservation:
    receipt_sha256: str
    device_identifier: str
    process_id: int
    executable_path: str


@dataclass(frozen=True, slots=True)
class TransportLaunchObservation:
    receipt_sha256: str
    device_identifier: str
    process_id: int
    executable_path: str


@dataclass(frozen=True, slots=True)
class PacketLanLaunchObservation:
    receipt_sha256: str
    device_identifier: str
    process_id: int
    executable_path: str


@dataclass(frozen=True, slots=True)
class ProcessTerminationObservation:
    receipt_sha256: str
    device_identifier: str
    process_id: int
    executable_path: str
    signal_name: str
    signal_value: int
    device_timestamp: str

    def __post_init__(self) -> None:
        _require_sha256(self.receipt_sha256, "process termination receipt digest")
        if (
            type(self.process_id) is not int
            or not 1 <= self.process_id <= MAX_PID
            or not self.executable_path.endswith(
                f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}"
            )
            or self.signal_name != "SIGTERM"
            or type(self.signal_value) is not int
            or self.signal_value != 15
            or not isinstance(self.device_timestamp, str)
            or _DEVICE_TIMESTAMP.fullmatch(self.device_timestamp) is None
        ):
            raise IOSPeerLabError(
                "ios_lab_terminate_receipt_invalid",
                "process termination observation differs from the fixed policy",
            )
        try:
            datetime.strptime(self.device_timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError as error:
            raise IOSPeerLabError(
                "ios_lab_terminate_receipt_invalid",
                "process termination device timestamp is not real",
            ) from error


@dataclass(frozen=True, slots=True)
class IOSPeerSessionMaterial:
    directory: Path
    session_id: str
    certificate_sha256: str
    private_key_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.directory, Path)
            or not self.directory.is_absolute()
            or self.directory.name != SESSION_DIRECTORY_NAME
        ):
            raise IOSPeerLabError(
                "ios_lab_session_material_invalid",
                "session material directory is not the fixed absolute path",
            )
        _require_sha256(self.session_id, "session material identifier")
        _require_sha256(self.certificate_sha256, "session certificate digest")
        _require_sha256(self.private_key_sha256, "session private-key digest")


@dataclass(frozen=True, slots=True)
class IOSPeerPacketLanSessionMaterial:
    directory: Path
    session_id: str
    session_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.directory, Path)
            or not self.directory.is_absolute()
            or self.directory.name != PACKET_LAN_DIRECTORY_NAME
        ):
            raise IOSPeerLabError(
                "ios_lab_packet_lan_material_invalid",
                "packet LAN material directory is not the fixed absolute path",
            )
        _require_sha256(self.session_id, "packet LAN session identifier")
        _require_sha256(self.session_sha256, "packet LAN session document digest")


@dataclass(frozen=True, slots=True)
class SessionCopyObservation:
    receipt_sha256: str
    device_identifier: str
    source_directory: Path
    destination_path: str
    session_id: str
    certificate_sha256: str
    last_modified_at: str

    def __post_init__(self) -> None:
        _require_sha256(self.receipt_sha256, "session-copy receipt digest")
        _require_sha256(self.session_id, "copied session identifier")
        _require_sha256(self.certificate_sha256, "copied session certificate digest")
        if (
            not isinstance(self.source_directory, Path)
            or not self.source_directory.is_absolute()
            or self.source_directory.name != SESSION_DIRECTORY_NAME
            or not isinstance(self.destination_path, str)
            or _REMOTE_SESSION_PATH.fullmatch(self.destination_path) is None
            or not isinstance(self.last_modified_at, str)
            or _DEVICE_TIMESTAMP.fullmatch(self.last_modified_at) is None
        ):
            raise IOSPeerLabError(
                "ios_lab_session_copy_invalid",
                "session-copy observation differs from the fixed policy",
            )
        try:
            datetime.strptime(self.last_modified_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError as error:
            raise IOSPeerLabError(
                "ios_lab_session_copy_invalid",
                "session-copy device timestamp is not real",
            ) from error


@dataclass(frozen=True, slots=True)
class PacketLanSessionCopyObservation:
    receipt_sha256: str
    device_identifier: str
    source_directory: Path
    destination_path: str
    session_id: str
    session_sha256: str
    last_modified_at: str

    def __post_init__(self) -> None:
        _require_sha256(self.receipt_sha256, "packet LAN copy receipt digest")
        _require_sha256(self.session_id, "copied packet LAN session identifier")
        _require_sha256(self.session_sha256, "copied packet LAN session digest")
        if (
            not isinstance(self.source_directory, Path)
            or not self.source_directory.is_absolute()
            or self.source_directory.name != PACKET_LAN_DIRECTORY_NAME
            or not isinstance(self.destination_path, str)
            or _REMOTE_PACKET_LAN_SESSION_PATH.fullmatch(self.destination_path) is None
            or not isinstance(self.last_modified_at, str)
            or _DEVICE_TIMESTAMP.fullmatch(self.last_modified_at) is None
        ):
            raise IOSPeerLabError(
                "ios_lab_packet_lan_copy_invalid",
                "packet LAN copy observation differs from the fixed policy",
            )
        try:
            datetime.strptime(self.last_modified_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError as error:
            raise IOSPeerLabError(
                "ios_lab_packet_lan_copy_invalid",
                "packet LAN copy device timestamp is not real",
            ) from error


@dataclass(frozen=True, slots=True)
class PrimerRetryAuthorization:
    """One-shot authority after the first primer generation is proven absent."""

    device_identifier_sha256: str
    app_tree_sha256: str
    launch_services_identifier: str
    first_launch_receipt_sha256: str
    first_process_inventory_receipt_sha256: str
    first_process_id: int
    executable_path: str
    observed_at: str
    retry_number: int = 1

    def __post_init__(self) -> None:
        _require_sha256(self.device_identifier_sha256, "primer retry device digest")
        _require_sha256(self.app_tree_sha256, "primer retry app-tree digest")
        _require_sha256(
            self.first_launch_receipt_sha256, "primer first-launch receipt digest"
        )
        _require_sha256(
            self.first_process_inventory_receipt_sha256,
            "primer retry process-inventory digest",
        )
        _canonical_launch_services_identifier(self.launch_services_identifier)
        _parse_timestamp(self.observed_at, "primer retry observation")
        if (
            type(self.first_process_id) is not int
            or not 1 <= self.first_process_id <= MAX_PID
            or type(self.retry_number) is not int
            or self.retry_number != 1
            or not self.executable_path.endswith(
                f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}"
            )
        ):
            raise IOSPeerLabError(
                "ios_lab_primer_retry_invalid",
                "primer retry authority does not identify one first generation",
            )


@dataclass(frozen=True, slots=True)
class UninstallObservation:
    receipt_sha256: str
    device_identifier: str
    bundle_identifier: str


@dataclass(frozen=True, slots=True)
class TransportPairVerification:
    mac_result_sha256: str
    peer_result_sha256: str
    session_id: str
    certificate_sha256: str
    process_id: int


def _parse_devicectl_envelope(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    command_type: str,
) -> tuple[dict[str, object], str]:
    if (
        not isinstance(data, bytes)
        or not 1 <= len(data) <= MAX_DEVICECTL_JSON_BYTES
        or type(spec) is not CommandSpec
        or type(runtime) is not DevicectlRuntime
        or _COMMAND_TYPE.fullmatch(command_type) is None
    ):
        raise IOSPeerLabError(
            "ios_lab_devicectl_json_invalid", "devicectl JSON parser inputs are invalid"
        )
    try:
        value = _load_devicectl_json(data)
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise IOSPeerLabError(
            "ios_lab_devicectl_json_invalid", "devicectl output is not strict JSON"
        ) from error
    envelope = _exact_object(value, {"info", "result"}, "devicectl envelope")
    info = _exact_object(
        envelope["info"],
        _INFO_REQUIRED_FIELDS,
        "devicectl info",
        optional=_INFO_OPTIONAL_FIELDS,
    )
    arguments = info["arguments"]
    environment = info["environment"]
    if (
        not isinstance(arguments, list)
        or arguments != list(spec.argv[1:])
        or not isinstance(environment, dict)
        or any(
            not isinstance(key, str)
            or not isinstance(item, str)
            or "\x00" in key
            or "\x00" in item
            for key, item in environment.items()
        )
        or len(environment) > 32
        or info["commandType"] != command_type
        or info["jsonVersion"] != runtime.json_version
        or info["outcome"] != "success"
        or info["version"] != runtime.version
        or ("details" in info and info["details"] is not None)
    ):
        raise IOSPeerLabError(
            "ios_lab_devicectl_json_invalid",
            "devicectl command identity, runtime, or outcome differs",
        )
    result = envelope["result"]
    if not isinstance(result, dict):
        raise IOSPeerLabError(
            "ios_lab_devicectl_json_invalid", "devicectl result is not an object"
        )
    return result, _sha256(data)


def parse_devicectl_envelope(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    command_type: str,
) -> tuple[dict[str, object], str]:
    """Validate one pinned CoreDevice envelope for a command-specific parser."""

    return _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type=command_type,
    )


def _load_devicectl_json(data: bytes) -> object:
    """Parse pinned CoreDevice JSON without truncating unsigned 64-bit fields."""

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate devicectl JSON field")
            result[key] = value
        return result

    def parse_integer(token: str) -> int:
        value = int(token)
        if not -(2**63) <= value <= 2**64 - 1:
            raise ValueError("devicectl JSON integer is outside 64-bit bounds")
        return value

    def reject_float(_token: str) -> float:
        raise ValueError("devicectl JSON floating-point value is unreviewed")

    def reject_constant(_token: str) -> None:
        raise ValueError("devicectl JSON non-finite value is invalid")

    def validate_tree(value: object, depth: int = 0) -> None:
        if depth > 32:
            raise ValueError("devicectl JSON nesting is excessive")
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 4096:
                    raise ValueError("devicectl JSON key is invalid")
                validate_tree(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                validate_tree(item, depth + 1)
        elif isinstance(value, str) and len(value.encode("utf-8")) > 64 * 1024:
            raise ValueError("devicectl JSON string exceeds its bound")

    text = data.decode("utf-8")
    value = json.loads(
        text,
        object_pairs_hook=reject_duplicates,
        parse_int=parse_integer,
        parse_float=reject_float,
        parse_constant=reject_constant,
    )
    validate_tree(value)
    return value


def _require_device_identifier(value: object, device: IOSPeerDevice) -> str:
    if value != device.core_device_identifier:
        raise IOSPeerLabError(
            "ios_lab_device_binding_invalid",
            "devicectl result does not bind the selected CoreDevice UUID",
        )
    return device.core_device_identifier


def _file_url_to_remote_path(value: object, *, executable: bool) -> str:
    if not isinstance(value, str) or not value.startswith("file:///"):
        raise IOSPeerLabError(
            "ios_lab_remote_path_invalid", "devicectl remote URL is not a file URL"
        )
    parsed = urlsplit(value)
    if parsed.scheme != "file" or parsed.netloc or parsed.query or parsed.fragment:
        raise IOSPeerLabError(
            "ios_lab_remote_path_invalid", "devicectl remote URL is ambiguous"
        )
    path = unquote(parsed.path)
    canonical_url = f"file://{quote(path, safe='/')}"
    if value != canonical_url:
        raise IOSPeerLabError(
            "ios_lab_remote_path_invalid", "devicectl remote URL is not canonical"
        )
    if executable:
        normalized_path = path
    else:
        if not path.endswith("/") or path.endswith("//"):
            raise IOSPeerLabError(
                "ios_lab_remote_path_invalid",
                "devicectl app URL must have one trailing slash",
            )
        normalized_path = path[:-1]
    suffix = (
        f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}"
        if executable
        else f"/{APP_EXECUTABLE}.app"
    )
    if (
        _REMOTE_PATH.fullmatch(normalized_path) is None
        or not normalized_path.endswith(suffix)
        or "//" in normalized_path
        or any(component in {".", ".."} for component in normalized_path.split("/"))
    ):
        raise IOSPeerLabError(
            "ios_lab_remote_path_invalid", "devicectl remote app path differs"
        )
    return normalized_path


def parse_device_admission(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
) -> DeviceAdmission:
    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.info.details",
    )
    result = _exact_object(
        result,
        {
            "capabilities",
            "identifier",
            "properties",
            "propertyDisplayNames",
            "visibilityClass",
        },
        "device details",
    )
    _require_device_identifier(result["identifier"], device)
    if (
        not isinstance(result["capabilities"], list)
        or result["propertyDisplayNames"] is not None
        or result["visibilityClass"] != "default"
    ):
        raise IOSPeerLabError(
            "ios_lab_device_binding_invalid",
            "CoreDevice details envelope differs from the pinned runtime",
        )
    properties = _exact_object(
        result["properties"],
        {"connection", "hardware", "software", "state"},
        "device properties",
    )
    hardware = _exact_object(
        properties["hardware"],
        {
            "cpuType",
            "deviceType",
            "platform",
            "reality",
            "supportedCPUTypes",
            "supportedDeviceFamilies",
            "udid",
        },
        "device hardware properties",
        optional={
            "cpuCount",
            "ecid",
            "hasActionButton",
            "internalStorageCapacity",
            "marketingName",
            "productType",
            "serialNumber",
            "supportedBiometrics",
            "supportsSiri",
            "thinningProductType",
        },
    )
    cpu = _exact_object(hardware["cpuType"], {"subtype", "type"}, "device CPU")
    supported_cpus = hardware["supportedCPUTypes"]
    connection = _exact_object(
        properties["connection"],
        {
            "authenticationType",
            "lastConnectionDate",
            "pairingState",
            "screenViewingURL",
            "state",
            "transportType",
            "tunnelIPAddressString",
            "tunnelTransportProtocol",
        },
        "device connection properties",
    )
    state = _exact_object(
        properties["state"],
        {"bootState", "developerModeStatus", "name", "preparednessState"},
        "device state properties",
    )
    developer_mode = _exact_object(
        state["developerModeStatus"], {"enabled"}, "device developer mode"
    )
    enabled_mode = _exact_object(
        developer_mode["enabled"], {"mode"}, "device developer-mode state"
    )
    software = _exact_object(
        properties["software"],
        {"osBuildVersions", "osVersionNumber", "supportsCheckedAllocations"},
        "device software properties",
    )
    os_version = _exact_object(
        software["osVersionNumber"],
        {"components", "originalComponentsCount", "stringValue"},
        "device OS version",
    )
    if (
        hardware.get("udid") != device.provisioning_udid
        or hardware.get("platform") != "iOS"
        or hardware.get("reality") != "physical"
        or hardware.get("deviceType") != "iPhone"
        or cpu["type"] != 16_777_228
        or type(cpu["subtype"]) is not int
        or not isinstance(supported_cpus, list)
        or not supported_cpus
        or any(
            _exact_object(item, {"subtype", "type"}, "supported device CPU")["type"]
            != 16_777_228
            for item in supported_cpus
        )
        or hardware["supportedDeviceFamilies"] != [1]
        or connection["pairingState"] != "paired"
        or connection["state"] != "connected"
        or connection["authenticationType"] != COREDEVICE_AUTHENTICATION_TYPE
        or connection["transportType"] != COREDEVICE_CONTROL_TRANSPORT
        or connection["tunnelTransportProtocol"] != COREDEVICE_TUNNEL_TRANSPORT_PROTOCOL
        or state["bootState"] != "booted"
        or enabled_mode["mode"] != 1
        or state["preparednessState"] != 7
        or not isinstance(state["name"], str)
        or not state["name"]
        or type(software["supportsCheckedAllocations"]) is not bool
        or not isinstance(os_version["components"], list)
        or not os_version["components"]
        or type(os_version["components"][0]) is not int
        or os_version["components"][0] < 17
        or not isinstance(os_version["stringValue"], str)
    ):
        raise IOSPeerLabError(
            "ios_lab_device_binding_invalid",
            "CoreDevice UUID does not resolve to the explicit physical arm64 iPhone UDID",
        )
    return DeviceAdmission(
        receipt_sha256=digest,
        core_device_identifier=device.core_device_identifier,
        provisioning_udid=device.provisioning_udid,
        platform="iOS",
        reality="physical",
        cpu_name="arm64",
        control_transport=connection["transportType"],
        authentication_type=connection["authenticationType"],
        tunnel_transport_protocol=connection["tunnelTransportProtocol"],
    )


def parse_lock_state(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
) -> str:
    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.info.lockState",
    )
    result = _exact_object(
        result,
        {"deviceIdentifier", "passcodeRequired", "unlockedSinceBoot"},
        "device lock state",
    )
    _require_device_identifier(result["deviceIdentifier"], device)
    if (
        type(result["passcodeRequired"]) is not bool
        or result["unlockedSinceBoot"] is not True
    ):
        raise IOSPeerLabError(
            "ios_lab_device_locked",
            "iPhone is not in the explicit unlocked-since-boot state",
        )
    return digest


def parse_app_inventory(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
) -> AppInventory:
    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.info.apps",
    )
    result = _exact_object(result, _APP_INVENTORY_RESULT_FIELDS, "app inventory")
    identifier = _require_device_identifier(result["deviceIdentifier"], device)
    if (
        not isinstance(result["apps"], list)
        or result["matchingBundleIdentifier"] != BUNDLE_IDENTIFIER
        or any(
            type(result[field]) is not bool
            for field in (
                "defaultAppsIncluded",
                "hiddenAppsIncluded",
                "internalAppsIncluded",
                "removableAppsIncluded",
            )
        )
    ):
        raise IOSPeerLabError(
            "ios_lab_app_inventory_invalid", "full app inventory metadata differs"
        )
    entries: list[AppInventoryEntry] = []
    seen: set[tuple[str | None, str | None]] = set()
    for index, item in enumerate(result["apps"]):
        app = _exact_object(
            item,
            _APP_INFO_REQUIRED,
            f"app inventory item {index}",
            optional=_APP_INFO_OPTIONAL,
        )
        if (
            any(type(app[field]) is not bool for field in _APP_INFO_REQUIRED - {"name"})
            or not isinstance(app["name"], str)
            or not 1 <= len(app["name"]) <= 512
            or (
                "bundleIdentifier" in app
                and app["bundleIdentifier"] is not None
                and not isinstance(app["bundleIdentifier"], str)
            )
            or (
                "url" in app
                and app["url"] is not None
                and not isinstance(app["url"], str)
            )
            or any(
                field in app
                and app[field] is not None
                and not isinstance(app[field], str)
                for field in ("bundleVersion", "version")
            )
        ):
            raise IOSPeerLabError(
                "ios_lab_app_inventory_invalid", "app inventory item types differ"
            )
        key = (app.get("bundleIdentifier"), app.get("url"))
        if key in seen:
            raise IOSPeerLabError(
                "ios_lab_app_inventory_invalid",
                "app inventory contains duplicate identity",
            )
        seen.add(key)
        entries.append(
            AppInventoryEntry(
                bundle_identifier=app.get("bundleIdentifier"),
                name=app["name"],
                url=app.get("url"),
                built_by_developer=app["builtByDeveloper"],
                removable=app["removable"],
            )
        )
    return AppInventory(digest, identifier, tuple(entries))


def _parse_process(value: object, *, label: str) -> DeviceProcess:
    process = _exact_object(
        value,
        _PROCESS_INFO_REQUIRED,
        label,
        optional=_PROCESS_INFO_OPTIONAL,
    )
    process_id = process["processIdentifier"]
    executable = process.get("executable")
    if (
        type(process_id) is not int
        or not 1 <= process_id <= MAX_PID
        or (executable is not None and not isinstance(executable, str))
    ):
        raise IOSPeerLabError(
            "ios_lab_process_inventory_invalid", f"{label} identity is invalid"
        )
    executable_path = (
        None if executable is None else _file_url_to_any_remote_path(executable)
    )
    audit_token = process.get("auditToken")
    if audit_token is not None and not (
        isinstance(audit_token, str)
        or (
            isinstance(audit_token, list)
            and len(audit_token) == 8
            and all(
                type(item) is int and 0 <= item <= 2**32 - 1 for item in audit_token
            )
        )
    ):
        raise IOSPeerLabError(
            "ios_lab_process_inventory_invalid", f"{label} audit token is invalid"
        )
    return DeviceProcess(process_id=process_id, executable_path=executable_path)


def _file_url_to_any_remote_path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("file:///"):
        raise IOSPeerLabError(
            "ios_lab_remote_path_invalid", "process executable is not a file URL"
        )
    parsed = urlsplit(value)
    path = unquote(parsed.path)
    canonical_url = f"file://{quote(path, safe='/')}"
    if (
        parsed.scheme != "file"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not path.startswith("/")
        or len(path.encode("utf-8")) > 4096
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
        or "//" in path
        or value != canonical_url
        or any(component in {".", ".."} for component in path.split("/"))
    ):
        raise IOSPeerLabError(
            "ios_lab_remote_path_invalid", "process executable URL is ambiguous"
        )
    return path


def _validate_local_directory_copy_source(
    source: object,
    sources: object,
    *,
    expected_directory: Path,
    label: str,
) -> None:
    """Bind a CoreDevice source URL to the exact private source directory.

    CoreDevice reports macOS's system ``/private/tmp`` directory through its
    public ``/tmp`` alias. Lexical URL equality therefore rejects a valid copy.
    Filesystem identity is the stronger boundary: the reported URL must resolve
    to the same live, private, non-symlink directory admitted by the command.
    """

    if (
        not isinstance(source, str)
        or not isinstance(sources, list)
        or sources != [source]
    ):
        raise IOSPeerLabError(
            "ios_lab_session_copy_invalid",
            f"{label} source list does not bind one URL",
        )
    source_path = _file_url_to_any_remote_path(source)
    if not source_path.endswith("/") or source_path.endswith("//"):
        raise IOSPeerLabError(
            "ios_lab_session_copy_invalid",
            f"{label} source URL is not one directory",
        )
    _require_private_directory(expected_directory, label=f"{label} source directory")
    observed_directory = Path(source_path[:-1])
    try:
        observed_metadata = observed_directory.lstat()
        expected_metadata = expected_directory.lstat()
        observed_resolved = observed_directory.resolve(strict=True)
        expected_resolved = expected_directory.resolve(strict=True)
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_session_copy_invalid",
            f"{label} source directory is unavailable",
        ) from error
    if (
        observed_directory.is_symlink()
        or not stat.S_ISDIR(observed_metadata.st_mode)
        or observed_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(observed_metadata.st_mode) != 0o700
        or observed_resolved != expected_resolved
        or (observed_metadata.st_dev, observed_metadata.st_ino)
        != (expected_metadata.st_dev, expected_metadata.st_ino)
    ):
        raise IOSPeerLabError(
            "ios_lab_session_copy_invalid",
            f"{label} source URL resolves to another directory",
        )


def parse_process_inventory(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
) -> ProcessInventory:
    if "--search" in spec.argv or "--filter" in spec.argv:
        raise IOSPeerLabError(
            "ios_lab_process_inventory_invalid",
            "filtered process output cannot authorize lifecycle operations",
        )
    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.info.processes",
    )
    result = _exact_object(
        result, _PROCESS_INVENTORY_RESULT_FIELDS, "process inventory"
    )
    identifier = _require_device_identifier(result["deviceIdentifier"], device)
    values = result["runningProcesses"]
    if not isinstance(values, list):
        raise IOSPeerLabError(
            "ios_lab_process_inventory_invalid", "runningProcesses is not a list"
        )
    processes = tuple(
        _parse_process(item, label=f"process inventory item {index}")
        for index, item in enumerate(values)
    )
    if len({item.process_id for item in processes}) != len(processes):
        raise IOSPeerLabError(
            "ios_lab_process_inventory_invalid", "process inventory repeats a PID"
        )
    return ProcessInventory(digest, identifier, processes)


def build_preflight(
    *,
    app_inventory: AppInventory,
    process_inventory: ProcessInventory,
    device: IOSPeerDevice,
    observed_at: datetime,
) -> IOSPeerPreflight:
    if (
        type(app_inventory) is not AppInventory
        or type(process_inventory) is not ProcessInventory
        or app_inventory.device_identifier != device.core_device_identifier
        or process_inventory.device_identifier != device.core_device_identifier
    ):
        raise IOSPeerLabError(
            "ios_lab_preflight_invalid", "preflight inventories bind another device"
        )
    app_absent = not any(
        entry.bundle_identifier == BUNDLE_IDENTIFIER for entry in app_inventory.entries
    )
    suffix = f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}"
    process_absent = not any(
        process.executable_path is not None and process.executable_path.endswith(suffix)
        for process in process_inventory.processes
    )
    return IOSPeerPreflight(
        device_identifier_sha256=device.core_device_identifier_sha256,
        app_inventory_receipt_sha256=app_inventory.receipt_sha256,
        process_inventory_receipt_sha256=process_inventory.receipt_sha256,
        observed_at=_canonical_timestamp(observed_at),
        app_absent=app_absent,
        process_absent=process_absent,
    )


def _canonical_launch_services_identifier(value: object) -> str:
    if value == UNKNOWN_LAUNCH_SERVICES_IDENTIFIER:
        return value
    if not isinstance(value, str) or not 4 <= len(value) <= 4096:
        raise IOSPeerLabError(
            "ios_lab_install_receipt_invalid",
            "launchServicesIdentifier is outside the fixed bound",
        )
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IOSPeerLabError(
            "ios_lab_install_receipt_invalid",
            "launchServicesIdentifier is not canonical base64",
        ) from error
    if not decoded or base64.b64encode(decoded).decode("ascii") != value:
        raise IOSPeerLabError(
            "ios_lab_install_receipt_invalid",
            "launchServicesIdentifier is not canonical base64",
        )
    return value


def parse_install_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    artifact: IOSPeerArtifact,
    post_install_inventory: AppInventory,
    installed_at: datetime,
) -> IOSPeerInstallationOwnership:
    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.install.app",
    )
    result = _exact_object(result, _INSTALL_RESULT_FIELDS, "install result")
    _require_device_identifier(result["deviceIdentifier"], device)
    applications = result["installedApplications"]
    if not isinstance(applications, list) or len(applications) != 1:
        raise IOSPeerLabError(
            "ios_lab_install_receipt_invalid",
            "install result does not contain exactly one application",
        )
    installed = _exact_object(
        applications[0], _INSTALLED_APP_FIELDS, "installed application"
    )
    database_sequence = installed["databaseSequenceNumber"]
    database_uuid = installed["databaseUUID"]
    options = installed["options"]
    try:
        canonical_database_uuid = str(uuid.UUID(database_uuid)).upper()
    except (TypeError, ValueError, AttributeError) as error:
        raise IOSPeerLabError(
            "ios_lab_install_receipt_invalid", "install database UUID is invalid"
        ) from error
    if (
        installed["bundleID"] != BUNDLE_IDENTIFIER
        or type(database_sequence) is not int
        or not 0 <= database_sequence <= 2**64 - 1
        or database_uuid != canonical_database_uuid
        or options != {}
    ):
        raise IOSPeerLabError(
            "ios_lab_install_receipt_invalid", "installed application metadata differs"
        )
    installation_path = _file_url_to_remote_path(
        installed["installationURL"], executable=False
    )
    launch_services_identifier = _canonical_launch_services_identifier(
        installed["launchServicesIdentifier"]
    )
    if (
        type(post_install_inventory) is not AppInventory
        or post_install_inventory.device_identifier != device.core_device_identifier
    ):
        raise IOSPeerLabError(
            "ios_lab_install_receipt_invalid",
            "post-install inventory binds another device",
        )
    matches = [
        entry
        for entry in post_install_inventory.entries
        if entry.bundle_identifier == BUNDLE_IDENTIFIER
    ]
    if (
        len(matches) != 1
        or matches[0].url != installed["installationURL"]
        or matches[0].built_by_developer is not True
        or matches[0].removable is not True
        or not installation_path.endswith(f"/{APP_EXECUTABLE}.app")
    ):
        raise IOSPeerLabError(
            "ios_lab_install_receipt_invalid",
            "post-install full inventory does not contain the owned removable app",
        )
    try:
        return IOSPeerInstallationOwnership(
            device_identifier_sha256=device.core_device_identifier_sha256,
            app_tree_sha256=artifact.app_tree_sha256,
            install_receipt_sha256=digest,
            app_inventory_receipt_sha256=post_install_inventory.receipt_sha256,
            launch_services_identifier=launch_services_identifier,
            installed_at=_canonical_timestamp(installed_at),
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_install_receipt_invalid", "install ownership binding is invalid"
        ) from error


def _parse_explicit_launch_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    installation: IOSPeerInstallationOwnership,
    expected_role: str,
    expected_argument: str,
) -> tuple[str, str, int, str]:
    launch_arguments = {
        PRIMER_LAUNCH_ARGUMENT,
        TRANSPORT_RUN_ARGUMENT,
        PACKET_LAN_LAUNCH_ARGUMENT,
    }
    if (
        type(installation) is not IOSPeerInstallationOwnership
        or installation.device_identifier_sha256 != device.core_device_identifier_sha256
        or spec.role != expected_role
        or spec.argv[-2:] != (BUNDLE_IDENTIFIER, expected_argument)
        or spec.argv.count(expected_argument) != 1
        or any(
            argument != expected_argument and argument in spec.argv
            for argument in launch_arguments
        )
    ):
        raise IOSPeerLabError(
            "ios_lab_launch_receipt_invalid",
            "launch lacks exact install ownership or explicit mode argument",
        )
    persistent_flag_count = spec.argv.count("--launch-persistent-identifier")
    if installation.launch_services_identifier == UNKNOWN_LAUNCH_SERVICES_IDENTIFIER:
        persistent_identifier_differs = persistent_flag_count != 0
    elif persistent_flag_count == 1:
        persistent_index = spec.argv.index("--launch-persistent-identifier")
        persistent_identifier_differs = (
            persistent_index + 1 >= len(spec.argv)
            or spec.argv[persistent_index + 1]
            != installation.launch_services_identifier
        )
    else:
        persistent_identifier_differs = True
    if persistent_identifier_differs or "--terminate-existing" in spec.argv:
        raise IOSPeerLabError(
            "ios_lab_launch_receipt_invalid",
            "launch command does not match the install synchronization token policy",
        )
    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.process.launch",
    )
    result = _exact_object(result, _LAUNCH_RESULT_FIELDS, "launch result")
    identifier = _require_device_identifier(result["deviceIdentifier"], device)
    options = _exact_object(
        result["launchOptions"], _LAUNCH_OPTION_FIELDS, "launch options"
    )
    if (
        options["activatedWhenStarted"] is not True
        or options["arguments"] != [expected_argument]
        or options["environmentVariables"] != {"TERM": "vt100"}
        or options["platformSpecificOptions"] != {}
        or options["startStopped"] is not False
        or options["terminateExistingInstances"] is not False
        or options["user"] != {"active": True}
    ):
        raise IOSPeerLabError(
            "ios_lab_launch_receipt_invalid", "launch result options differ"
        )
    process = _parse_process(result["process"], label="launched process")
    if process.executable_path is None:
        raise IOSPeerLabError(
            "ios_lab_launch_receipt_invalid", "launch result omits executable identity"
        )
    executable_path = _file_url_to_remote_path(
        f"file://{process.executable_path}", executable=True
    )
    return digest, identifier, process.process_id, executable_path


def parse_primer_launch_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    installation: IOSPeerInstallationOwnership,
) -> PrimerLaunchObservation:
    digest, identifier, process_id, executable_path = _parse_explicit_launch_receipt(
        data,
        spec=spec,
        runtime=runtime,
        device=device,
        installation=installation,
        expected_role="ios-peer-primer-launch",
        expected_argument=PRIMER_LAUNCH_ARGUMENT,
    )
    return PrimerLaunchObservation(
        receipt_sha256=digest,
        device_identifier=identifier,
        process_id=process_id,
        executable_path=executable_path,
    )


def parse_transport_launch_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    installation: IOSPeerInstallationOwnership,
) -> TransportLaunchObservation:
    digest, identifier, process_id, executable_path = _parse_explicit_launch_receipt(
        data,
        spec=spec,
        runtime=runtime,
        device=device,
        installation=installation,
        expected_role="ios-peer-transport-launch",
        expected_argument=TRANSPORT_RUN_ARGUMENT,
    )
    return TransportLaunchObservation(
        receipt_sha256=digest,
        device_identifier=identifier,
        process_id=process_id,
        executable_path=executable_path,
    )


def parse_packet_lan_launch_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    installation: IOSPeerInstallationOwnership,
) -> PacketLanLaunchObservation:
    digest, identifier, process_id, executable_path = _parse_explicit_launch_receipt(
        data,
        spec=spec,
        runtime=runtime,
        device=device,
        installation=installation,
        expected_role="ios-peer-packet-lan-launch",
        expected_argument=PACKET_LAN_LAUNCH_ARGUMENT,
    )
    return PacketLanLaunchObservation(
        receipt_sha256=digest,
        device_identifier=identifier,
        process_id=process_id,
        executable_path=executable_path,
    )


def validate_session_material(
    directory: Path,
    *,
    expected_session_id: str,
    now: datetime,
) -> IOSPeerSessionMaterial:
    _require_sha256(expected_session_id, "expected session identifier")
    if not isinstance(directory, Path) or directory.name != SESSION_DIRECTORY_NAME:
        raise IOSPeerLabError(
            "ios_lab_session_material_invalid",
            "session material directory name differs from the fixed contract",
        )
    _require_private_directory(directory, label="session material directory")
    expected_entries = {
        CERTIFICATE_FILE_NAME,
        PRIVATE_KEY_FILE_NAME,
        SESSION_FILE_NAME,
    }
    try:
        entries_before = {entry.name for entry in directory.iterdir()}
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_session_material_invalid",
            "session material directory cannot be enumerated",
        ) from error
    if entries_before != expected_entries:
        raise IOSPeerLabError(
            "ios_lab_session_material_invalid",
            "session material directory must contain exactly three fixed files",
        )

    paths = {
        name: directory / name
        for name in (
            CERTIFICATE_FILE_NAME,
            PRIVATE_KEY_FILE_NAME,
            SESSION_FILE_NAME,
        )
    }
    for name, path in paths.items():
        try:
            metadata = path.lstat()
        except OSError as error:
            raise IOSPeerLabError(
                "ios_lab_session_material_invalid",
                f"session material {name} is unavailable",
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise IOSPeerLabError(
                "ios_lab_session_material_invalid",
                f"session material {name} metadata is unsafe",
            )

    certificate = _read_stable_file(
        paths[CERTIFICATE_FILE_NAME],
        maximum=16 * 1024,
        label="session certificate",
    )
    private_key = _read_stable_file(
        paths[PRIVATE_KEY_FILE_NAME],
        maximum=1024,
        label="session private key",
    )
    session_data = _read_stable_file(
        paths[SESSION_FILE_NAME],
        maximum=MAX_JSON_BYTES,
        label="session document",
    )
    if len(private_key) != 97 or private_key[0] != 0x04:
        raise IOSPeerLabError(
            "ios_lab_session_material_invalid",
            "session private key is not one P-256 X9.63 identity",
        )
    try:
        session = validate_session_document(session_data, now=now)
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_session_material_invalid",
            "session document is invalid",
        ) from error
    certificate_sha256 = _sha256(certificate)
    private_key_sha256 = _sha256(private_key)
    if (
        session["session_id"] != expected_session_id
        or session["certificate_sha256"] != certificate_sha256
        or session["private_key_sha256"] != private_key_sha256
    ):
        raise IOSPeerLabError(
            "ios_lab_session_material_invalid",
            "session document does not bind the exact identity files",
        )
    try:
        entries_after = {entry.name for entry in directory.iterdir()}
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_session_material_invalid",
            "session material directory disappeared after validation",
        ) from error
    if entries_after != entries_before:
        raise IOSPeerLabError(
            "ios_lab_session_material_invalid",
            "session material directory changed while validated",
        )
    return IOSPeerSessionMaterial(
        directory=directory,
        session_id=expected_session_id,
        certificate_sha256=certificate_sha256,
        private_key_sha256=private_key_sha256,
    )


def validate_packet_lan_session_material(
    directory: Path,
    *,
    expected_session_id: str,
    now: datetime,
) -> IOSPeerPacketLanSessionMaterial:
    _require_sha256(expected_session_id, "expected packet LAN session identifier")
    if not isinstance(directory, Path) or directory.name != PACKET_LAN_DIRECTORY_NAME:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_material_invalid",
            "packet LAN material directory name differs from the fixed contract",
        )
    _require_private_directory(directory, label="packet LAN material directory")
    try:
        entries_before = {entry.name for entry in directory.iterdir()}
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_material_invalid",
            "packet LAN material directory cannot be enumerated",
        ) from error
    if entries_before != {PACKET_LAN_SESSION_FILE_NAME}:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_material_invalid",
            "packet LAN material directory must contain only session.json",
        )
    session_path = directory / PACKET_LAN_SESSION_FILE_NAME
    try:
        metadata = session_path.lstat()
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_material_invalid",
            "packet LAN session document is unavailable",
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or session_path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise IOSPeerLabError(
            "ios_lab_packet_lan_material_invalid",
            "packet LAN session document metadata is unsafe",
        )
    session_data = _read_stable_file(
        session_path,
        maximum=MAX_JSON_BYTES,
        label="packet LAN session document",
    )
    try:
        session = validate_packet_lan_session(session_data, now=now)
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_material_invalid",
            "packet LAN session document is invalid",
        ) from error
    if session["session_id"] != expected_session_id:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_material_invalid",
            "packet LAN material binds another session",
        )
    try:
        entries_after = {entry.name for entry in directory.iterdir()}
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_material_invalid",
            "packet LAN material disappeared after validation",
        ) from error
    if entries_after != entries_before:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_material_invalid",
            "packet LAN material changed while validated",
        )
    return IOSPeerPacketLanSessionMaterial(
        directory=directory,
        session_id=expected_session_id,
        session_sha256=_sha256(session_data),
    )


def parse_session_copy_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    stopped_primer: PrimerStoppedOwnership,
    material: IOSPeerSessionMaterial,
) -> SessionCopyObservation:
    if (
        type(stopped_primer) is not PrimerStoppedOwnership
        or type(material) is not IOSPeerSessionMaterial
        or stopped_primer.process.device_identifier_sha256
        != device.core_device_identifier_sha256
        or spec.role != "ios-peer-session-copy"
    ):
        raise IOSPeerLabError(
            "ios_lab_session_copy_invalid",
            "session copy lacks stopped-primer and material ownership",
        )

    expected_flags = {
        "--source": str(material.directory),
        "--destination": f"Documents/{SESSION_DIRECTORY_NAME}",
        "--domain-type": "appDataContainer",
        "--domain-identifier": BUNDLE_IDENTIFIER,
        "--remove-existing-content": "false",
    }
    for flag, expected in expected_flags.items():
        if spec.argv.count(flag) != 1:
            raise IOSPeerLabError(
                "ios_lab_session_copy_invalid",
                f"session-copy command omits exact {flag} binding",
            )
        index = spec.argv.index(flag)
        if index + 1 >= len(spec.argv) or spec.argv[index + 1] != expected:
            raise IOSPeerLabError(
                "ios_lab_session_copy_invalid",
                f"session-copy command changes {flag}",
            )

    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.copy.to",
    )
    result = _exact_object(result, _SESSION_COPY_RESULT_FIELDS, "session-copy result")
    identifier = _require_device_identifier(result["deviceIdentifier"], device)
    destination_path = _file_url_to_any_remote_path(result["destination"])
    _validate_local_directory_copy_source(
        result["source"],
        result["sources"],
        expected_directory=material.directory,
        label="session-copy",
    )
    file = _exact_object(result["file"], _SESSION_COPY_FILE_FIELDS, "copied file")
    metadata = _exact_object(
        file["metadata"], _SESSION_COPY_METADATA_FIELDS, "copied file metadata"
    )
    resources = _exact_object(
        file["resources"], _SESSION_COPY_RESOURCE_FIELDS, "copied file resources"
    )
    if (
        _REMOTE_SESSION_PATH.fullmatch(destination_path) is None
        or result["domain"] != "appDataContainer"
        or result["domainIdentifier"] != BUNDLE_IDENTIFIER
        or file["name"] != destination_path
        or file["relativePath"] != destination_path
        or resources
        != {
            "isDirectory": True,
            "isHidden": False,
            "isReadable": True,
            "isSymbolicLink": False,
            "isWritable": True,
        }
        or metadata["extendedAttributes"] != {}
        or metadata["ownerGid"] != 501
        or metadata["ownerUid"] != 501
        or metadata["permissions"] != 0o755
        or metadata["size"] != 160
        or not isinstance(metadata["lastModDate"], str)
        or _DEVICE_TIMESTAMP.fullmatch(metadata["lastModDate"]) is None
    ):
        raise IOSPeerLabError(
            "ios_lab_session_copy_invalid",
            "session-copy result differs from the pinned CoreDevice contract",
        )
    return SessionCopyObservation(
        receipt_sha256=digest,
        device_identifier=identifier,
        source_directory=material.directory,
        destination_path=destination_path,
        session_id=material.session_id,
        certificate_sha256=material.certificate_sha256,
        last_modified_at=metadata["lastModDate"],
    )


def parse_packet_lan_session_copy_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    stopped_primer: PrimerStoppedOwnership,
    material: IOSPeerPacketLanSessionMaterial,
) -> PacketLanSessionCopyObservation:
    if (
        type(stopped_primer) is not PrimerStoppedOwnership
        or type(material) is not IOSPeerPacketLanSessionMaterial
        or stopped_primer.process.device_identifier_sha256
        != device.core_device_identifier_sha256
        or spec.role != "ios-peer-packet-lan-session-copy"
    ):
        raise IOSPeerLabError(
            "ios_lab_packet_lan_copy_invalid",
            "packet LAN copy lacks stopped-primer and material ownership",
        )
    expected_flags = {
        "--source": str(material.directory),
        "--destination": PACKET_LAN_DEVICE_DIRECTORY,
        "--domain-type": "appDataContainer",
        "--domain-identifier": BUNDLE_IDENTIFIER,
        "--remove-existing-content": "false",
    }
    for flag, expected in expected_flags.items():
        if spec.argv.count(flag) != 1:
            raise IOSPeerLabError(
                "ios_lab_packet_lan_copy_invalid",
                f"packet LAN copy omits exact {flag} binding",
            )
        index = spec.argv.index(flag)
        if index + 1 >= len(spec.argv) or spec.argv[index + 1] != expected:
            raise IOSPeerLabError(
                "ios_lab_packet_lan_copy_invalid",
                f"packet LAN copy changes {flag}",
            )
    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.copy.to",
    )
    result = _exact_object(result, _SESSION_COPY_RESULT_FIELDS, "packet LAN copy result")
    identifier = _require_device_identifier(result["deviceIdentifier"], device)
    destination_path = _file_url_to_any_remote_path(result["destination"])
    _validate_local_directory_copy_source(
        result["source"],
        result["sources"],
        expected_directory=material.directory,
        label="packet LAN copy",
    )
    file = _exact_object(result["file"], _SESSION_COPY_FILE_FIELDS, "packet LAN copied file")
    metadata = _exact_object(
        file["metadata"], _SESSION_COPY_METADATA_FIELDS, "packet LAN copied metadata"
    )
    resources = _exact_object(
        file["resources"], _SESSION_COPY_RESOURCE_FIELDS, "packet LAN copied resources"
    )
    directory_size = metadata["size"]
    if (
        _REMOTE_PACKET_LAN_SESSION_PATH.fullmatch(destination_path) is None
        or result["domain"] != "appDataContainer"
        or result["domainIdentifier"] != BUNDLE_IDENTIFIER
        or file["name"] != destination_path
        or file["relativePath"] != destination_path
        or resources
        != {
            "isDirectory": True,
            "isHidden": False,
            "isReadable": True,
            "isSymbolicLink": False,
            "isWritable": True,
        }
        or metadata["extendedAttributes"] != {}
        or metadata["ownerGid"] != 501
        or metadata["ownerUid"] != 501
        or metadata["permissions"] != 0o755
        or type(directory_size) is not int
        or not 1 <= directory_size <= 4_096
        or not isinstance(metadata["lastModDate"], str)
        or _DEVICE_TIMESTAMP.fullmatch(metadata["lastModDate"]) is None
    ):
        raise IOSPeerLabError(
            "ios_lab_packet_lan_copy_invalid",
            "packet LAN copy result differs from the bounded CoreDevice contract",
        )
    return PacketLanSessionCopyObservation(
        receipt_sha256=digest,
        device_identifier=identifier,
        source_directory=material.directory,
        destination_path=destination_path,
        session_id=material.session_id,
        session_sha256=material.session_sha256,
        last_modified_at=metadata["lastModDate"],
    )


def _parse_process_termination_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    authority: IOSPeerPrimerProcessCleanupAuthority | IOSPeerProcessCleanupAuthority,
    expected_role: str,
) -> ProcessTerminationObservation:
    if type(authority) not in {
        IOSPeerPrimerProcessCleanupAuthority,
        IOSPeerProcessCleanupAuthority,
    }:
        raise IOSPeerLabError(
            "ios_lab_terminate_receipt_invalid",
            "process termination lacks typed cleanup authority",
        )
    process_ownership = authority.process
    if (
        process_ownership.device_identifier_sha256
        != device.core_device_identifier_sha256
        or spec.role != expected_role
        or spec.argv.count("--pid") != 1
        or "--kill" in spec.argv
    ):
        raise IOSPeerLabError(
            "ios_lab_terminate_receipt_invalid",
            "process termination command differs from the exact authority",
        )
    pid_index = spec.argv.index("--pid")
    if pid_index + 1 >= len(spec.argv) or spec.argv[pid_index + 1] != str(
        process_ownership.process_id
    ):
        raise IOSPeerLabError(
            "ios_lab_terminate_receipt_invalid",
            "process termination command targets another PID",
        )
    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.process.terminate",
    )
    result = _exact_object(result, _TERMINATE_RESULT_FIELDS, "terminate result")
    identifier = _require_device_identifier(result["deviceIdentifier"], device)
    process = _parse_process(result["process"], label="terminated process")
    signal = _exact_object(result["signal"], _SIGNAL_FIELDS, "termination signal")
    if (
        process.process_id != process_ownership.process_id
        or process.executable_path != process_ownership.executable_path
        or signal != {"name": "SIGTERM", "value": 15}
    ):
        raise IOSPeerLabError(
            "ios_lab_terminate_receipt_invalid",
            "terminated process or signal differs from the exact authority",
        )
    return ProcessTerminationObservation(
        receipt_sha256=digest,
        device_identifier=identifier,
        process_id=process.process_id,
        executable_path=process.executable_path,
        signal_name="SIGTERM",
        signal_value=15,
        device_timestamp=result["deviceTimestamp"],
    )


def parse_primer_terminate_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    authority: IOSPeerPrimerProcessCleanupAuthority,
) -> ProcessTerminationObservation:
    if type(authority) is not IOSPeerPrimerProcessCleanupAuthority:
        raise IOSPeerLabError(
            "ios_lab_terminate_receipt_invalid",
            "primer termination lacks primer cleanup authority",
        )
    return _parse_process_termination_receipt(
        data,
        spec=spec,
        runtime=runtime,
        device=device,
        authority=authority,
        expected_role="ios-peer-primer-terminate",
    )


def parse_transport_terminate_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    authority: IOSPeerProcessCleanupAuthority,
) -> ProcessTerminationObservation:
    if type(authority) is not IOSPeerProcessCleanupAuthority:
        raise IOSPeerLabError(
            "ios_lab_terminate_receipt_invalid",
            "transport termination lacks transport cleanup authority",
        )
    return _parse_process_termination_receipt(
        data,
        spec=spec,
        runtime=runtime,
        device=device,
        authority=authority,
        expected_role="ios-peer-terminate",
    )


def parse_packet_lan_terminate_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    authority: IOSPeerProcessCleanupAuthority,
) -> ProcessTerminationObservation:
    if type(authority) is not IOSPeerProcessCleanupAuthority:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_terminate_receipt_invalid",
            "packet LAN termination lacks exact process cleanup authority",
        )
    return _parse_process_termination_receipt(
        data,
        spec=spec,
        runtime=runtime,
        device=device,
        authority=authority,
        expected_role="ios-peer-terminate",
    )


def _require_unique_launched_process(
    *,
    launch: PrimerLaunchObservation
    | TransportLaunchObservation
    | PacketLanLaunchObservation,
    process_inventory: ProcessInventory,
    device: IOSPeerDevice,
    error_code: str,
) -> None:
    if (
        type(launch)
        not in {
            PrimerLaunchObservation,
            TransportLaunchObservation,
            PacketLanLaunchObservation,
        }
        or type(process_inventory) is not ProcessInventory
        or launch.device_identifier != device.core_device_identifier
        or process_inventory.device_identifier != device.core_device_identifier
    ):
        raise IOSPeerLabError(error_code, "launch and inventory bind different devices")
    matches = [
        process
        for process in process_inventory.processes
        if process.process_id == launch.process_id
        and process.executable_path == launch.executable_path
    ]
    peer_executables = [
        process
        for process in process_inventory.processes
        if process.executable_path is not None
        and process.executable_path.endswith(f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}")
    ]
    if len(matches) != 1 or len(peer_executables) != 1:
        raise IOSPeerLabError(
            error_code,
            "full process inventory does not uniquely bind launch PID and executable",
        )


def authorize_single_primer_retry(
    *,
    first_launch: PrimerLaunchObservation,
    fresh_inventory: ProcessInventory,
    installation: IOSPeerInstallationOwnership,
    device: IOSPeerDevice,
    artifact: IOSPeerArtifact,
    observed_at: datetime,
) -> PrimerRetryAuthorization:
    """Authorize the only retry after the first primer generation is absent."""

    if (
        type(first_launch) is not PrimerLaunchObservation
        or type(fresh_inventory) is not ProcessInventory
        or type(installation) is not IOSPeerInstallationOwnership
        or first_launch.device_identifier != device.core_device_identifier
        or fresh_inventory.device_identifier != device.core_device_identifier
        or installation.device_identifier_sha256 != device.core_device_identifier_sha256
        or installation.app_tree_sha256 != artifact.app_tree_sha256
        or any(
            process.process_id == first_launch.process_id
            or (
                process.executable_path is not None
                and process.executable_path.endswith(
                    f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}"
                )
            )
            for process in fresh_inventory.processes
        )
    ):
        raise IOSPeerLabError(
            "ios_lab_primer_retry_invalid",
            "first primer generation absence is not proven by a full inventory",
        )
    return PrimerRetryAuthorization(
        device_identifier_sha256=device.core_device_identifier_sha256,
        app_tree_sha256=artifact.app_tree_sha256,
        launch_services_identifier=installation.launch_services_identifier,
        first_launch_receipt_sha256=first_launch.receipt_sha256,
        first_process_inventory_receipt_sha256=fresh_inventory.receipt_sha256,
        first_process_id=first_launch.process_id,
        executable_path=first_launch.executable_path,
        observed_at=_canonical_timestamp(observed_at),
    )


def bind_primer_process(
    *,
    launch: PrimerLaunchObservation,
    process_inventory: ProcessInventory,
    primer_receipt: bytes,
    installation: IOSPeerInstallationOwnership,
    device: IOSPeerDevice,
    artifact: IOSPeerArtifact,
    now: datetime,
) -> IOSPeerPrimerProcessOwnership:
    if (
        type(launch) is not PrimerLaunchObservation
        or type(installation) is not IOSPeerInstallationOwnership
        or installation.device_identifier_sha256 != device.core_device_identifier_sha256
        or installation.app_tree_sha256 != artifact.app_tree_sha256
    ):
        raise IOSPeerLabError(
            "ios_lab_primer_ownership_invalid",
            "primer launch bindings refer to different inputs",
        )
    _require_unique_launched_process(
        launch=launch,
        process_inventory=process_inventory,
        device=device,
        error_code="ios_lab_primer_ownership_invalid",
    )
    try:
        validate_primer_receipt(
            primer_receipt, expected_process_id=launch.process_id, now=now
        )
        return IOSPeerPrimerProcessOwnership(
            device_identifier_sha256=device.core_device_identifier_sha256,
            app_tree_sha256=artifact.app_tree_sha256,
            process_id=launch.process_id,
            launch_services_identifier=installation.launch_services_identifier,
            executable_path=launch.executable_path,
            launch_receipt_sha256=launch.receipt_sha256,
            process_inventory_receipt_sha256=process_inventory.receipt_sha256,
            primer_receipt_sha256=_sha256(primer_receipt),
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_primer_ownership_invalid",
            "primer lifecycle receipt or ownership binding is invalid",
        ) from error


def authorize_primer_process_cleanup(
    *,
    ownership: IOSPeerPrimerProcessOwnership,
    fresh_inventory: ProcessInventory,
    fresh_primer_receipt: bytes,
    device: IOSPeerDevice,
    observed_at: datetime,
) -> IOSPeerPrimerProcessCleanupAuthority:
    if (
        type(ownership) is not IOSPeerPrimerProcessOwnership
        or type(fresh_inventory) is not ProcessInventory
        or type(device) is not IOSPeerDevice
        or fresh_inventory.device_identifier != device.core_device_identifier
        or ownership.device_identifier_sha256 != device.core_device_identifier_sha256
    ):
        raise IOSPeerLabError(
            "ios_lab_primer_cleanup_invalid",
            "primer cleanup inputs lack typed same-device ownership",
        )
    matches = [
        process
        for process in fresh_inventory.processes
        if process.process_id == ownership.process_id
        and process.executable_path == ownership.executable_path
    ]
    peer_executables = [
        process
        for process in fresh_inventory.processes
        if process.executable_path is not None
        and process.executable_path.endswith(f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}")
    ]
    if len(matches) != 1 or len(peer_executables) != 1:
        raise IOSPeerLabError(
            "ios_lab_primer_cleanup_invalid",
            "fresh full inventory cannot exclude primer PID reuse or drift",
        )
    try:
        validate_primer_receipt(
            fresh_primer_receipt,
            expected_process_id=ownership.process_id,
            now=observed_at,
        )
        if _sha256(fresh_primer_receipt) != ownership.primer_receipt_sha256:
            raise IOSPeerLabError(
                "ios_lab_primer_cleanup_invalid",
                "fresh primer receipt no longer binds the launch generation",
            )
        return IOSPeerPrimerProcessCleanupAuthority(
            process=ownership,
            revalidated_process_inventory_receipt_sha256=fresh_inventory.receipt_sha256,
            revalidated_primer_receipt_sha256=ownership.primer_receipt_sha256,
            observed_at=_canonical_timestamp(observed_at),
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_primer_cleanup_invalid", "primer cleanup authority is invalid"
        ) from error


def bind_stopped_primer(
    *,
    authority: IOSPeerPrimerProcessCleanupAuthority,
    termination: ProcessTerminationObservation,
    post_terminate_inventory: ProcessInventory,
    device: IOSPeerDevice,
    observed_at: datetime,
) -> PrimerStoppedOwnership:
    if (
        type(authority) is not IOSPeerPrimerProcessCleanupAuthority
        or type(termination) is not ProcessTerminationObservation
        or type(post_terminate_inventory) is not ProcessInventory
        or type(device) is not IOSPeerDevice
        or post_terminate_inventory.device_identifier != device.core_device_identifier
        or authority.process.device_identifier_sha256
        != device.core_device_identifier_sha256
        or termination.device_identifier != device.core_device_identifier
        or termination.process_id != authority.process.process_id
        or termination.executable_path != authority.process.executable_path
    ):
        raise IOSPeerLabError(
            "ios_lab_primer_stopped_invalid",
            "stopped-primer proof lacks exact typed ownership",
        )
    executable_suffix = f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}"
    if any(
        process.process_id == authority.process.process_id
        or (
            process.executable_path is not None
            and process.executable_path.endswith(executable_suffix)
        )
        for process in post_terminate_inventory.processes
    ):
        raise IOSPeerLabError(
            "ios_lab_primer_stopped_invalid",
            "post-terminate full inventory still contains the primer generation",
        )
    try:
        return PrimerStoppedOwnership(
            process=authority.process,
            terminate_receipt_sha256=termination.receipt_sha256,
            post_terminate_process_inventory_receipt_sha256=(
                post_terminate_inventory.receipt_sha256
            ),
            stopped_at=_canonical_timestamp(observed_at),
            process_absent=True,
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_primer_stopped_invalid", "stopped-primer binding is invalid"
        ) from error


def _bind_launched_process(
    *,
    launch: TransportLaunchObservation | PacketLanLaunchObservation,
    expected_launch_type: type[TransportLaunchObservation]
    | type[PacketLanLaunchObservation],
    process_inventory: ProcessInventory,
    ready_receipt: bytes,
    ready_process_id: object,
    installation: IOSPeerInstallationOwnership,
    device: IOSPeerDevice,
    artifact: IOSPeerArtifact,
    expected_session_id: str,
    error_code: str,
) -> IOSPeerProcessOwnership:
    if (
        type(launch) is not expected_launch_type
        or type(installation) is not IOSPeerInstallationOwnership
        or installation.device_identifier_sha256 != device.core_device_identifier_sha256
        or installation.app_tree_sha256 != artifact.app_tree_sha256
    ):
        raise IOSPeerLabError(
            error_code,
            "launch bindings refer to different inputs",
        )
    _require_unique_launched_process(
        launch=launch,
        process_inventory=process_inventory,
        device=device,
        error_code=error_code,
    )
    if ready_process_id != launch.process_id:
        raise IOSPeerLabError(
            error_code,
            "ready receipt does not bind the launched process generation",
        )
    try:
        return IOSPeerProcessOwnership(
            device_identifier_sha256=device.core_device_identifier_sha256,
            app_tree_sha256=artifact.app_tree_sha256,
            session_id=expected_session_id,
            process_id=launch.process_id,
            launch_services_identifier=installation.launch_services_identifier,
            executable_path=launch.executable_path,
            launch_receipt_sha256=launch.receipt_sha256,
            process_inventory_receipt_sha256=process_inventory.receipt_sha256,
            ready_receipt_sha256=_sha256(ready_receipt),
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            error_code, "process ownership binding is invalid"
        ) from error


def bind_transport_process(
    *,
    launch: TransportLaunchObservation,
    process_inventory: ProcessInventory,
    ready_receipt: bytes,
    installation: IOSPeerInstallationOwnership,
    device: IOSPeerDevice,
    artifact: IOSPeerArtifact,
    expected_session_id: str,
    expected_certificate_sha256: str,
    now: datetime,
) -> IOSPeerProcessOwnership:
    try:
        ready = validate_ready_receipt(
            ready_receipt,
            expected_session_id=expected_session_id,
            expected_certificate_sha256=expected_certificate_sha256,
            now=now,
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_process_ownership_invalid", "ready receipt is invalid"
        ) from error
    return _bind_launched_process(
        launch=launch,
        expected_launch_type=TransportLaunchObservation,
        process_inventory=process_inventory,
        ready_receipt=ready_receipt,
        ready_process_id=ready["process_id"],
        installation=installation,
        device=device,
        artifact=artifact,
        expected_session_id=expected_session_id,
        error_code="ios_lab_process_ownership_invalid",
    )


def _validate_packet_lan_session_binding(
    *,
    session_document: bytes,
    material: IOSPeerPacketLanSessionMaterial,
    now: datetime,
    error_code: str,
) -> dict[str, object]:
    if (
        type(session_document) is not bytes
        or type(material) is not IOSPeerPacketLanSessionMaterial
        or _sha256(session_document) != material.session_sha256
    ):
        raise IOSPeerLabError(
            error_code,
            "packet LAN session bytes do not match the validated local material",
        )
    try:
        session = validate_packet_lan_session(session_document, now=now)
    except IOSPeerContractError as error:
        raise IOSPeerLabError(error_code, "packet LAN session is invalid") from error
    if session["session_id"] != material.session_id:
        raise IOSPeerLabError(
            error_code,
            "packet LAN session identifier differs from the validated material",
        )
    return session


def bind_packet_lan_process(
    *,
    launch: PacketLanLaunchObservation,
    process_inventory: ProcessInventory,
    session_document: bytes,
    ready_receipt: bytes,
    material: IOSPeerPacketLanSessionMaterial,
    installation: IOSPeerInstallationOwnership,
    device: IOSPeerDevice,
    artifact: IOSPeerArtifact,
    now: datetime,
) -> IOSPeerProcessOwnership:
    session = _validate_packet_lan_session_binding(
        session_document=session_document,
        material=material,
        now=now,
        error_code="ios_lab_packet_lan_process_ownership_invalid",
    )
    try:
        ready = validate_packet_lan_ready(
            ready_receipt,
            session=session,
            now=now,
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_process_ownership_invalid",
            "packet LAN ready receipt is invalid",
        ) from error
    return _bind_launched_process(
        launch=launch,
        expected_launch_type=PacketLanLaunchObservation,
        process_inventory=process_inventory,
        ready_receipt=ready_receipt,
        ready_process_id=ready["process_id"],
        installation=installation,
        device=device,
        artifact=artifact,
        expected_session_id=material.session_id,
        error_code="ios_lab_packet_lan_process_ownership_invalid",
    )


def _authorize_process_cleanup(
    *,
    ownership: IOSPeerProcessOwnership,
    fresh_inventory: ProcessInventory,
    fresh_ready_receipt: bytes,
    ready_process_id: object,
    observed_at: datetime,
    error_code: str,
) -> IOSPeerProcessCleanupAuthority:
    if (
        type(ownership) is not IOSPeerProcessOwnership
        or type(fresh_inventory) is not ProcessInventory
        or device_identifier_sha256(fresh_inventory.device_identifier)
        != ownership.device_identifier_sha256
    ):
        raise IOSPeerLabError(
            error_code, "cleanup inputs lack typed ownership"
        )
    matches = [
        process
        for process in fresh_inventory.processes
        if process.process_id == ownership.process_id
        and process.executable_path == ownership.executable_path
    ]
    same_executable = [
        process
        for process in fresh_inventory.processes
        if process.executable_path == ownership.executable_path
    ]
    if len(matches) != 1 or len(same_executable) != 1:
        raise IOSPeerLabError(
            error_code,
            "fresh full inventory cannot exclude PID reuse or executable drift",
        )
    if (
        ready_process_id != ownership.process_id
        or _sha256(fresh_ready_receipt) != ownership.ready_receipt_sha256
    ):
        raise IOSPeerLabError(
            error_code,
            "fresh ready receipt no longer binds the launched generation",
        )
    try:
        return IOSPeerProcessCleanupAuthority(
            process=ownership,
            revalidated_process_inventory_receipt_sha256=fresh_inventory.receipt_sha256,
            revalidated_ready_receipt_sha256=ownership.ready_receipt_sha256,
            observed_at=_canonical_timestamp(observed_at),
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            error_code, "cleanup authority binding is invalid"
        ) from error


def authorize_exceptional_process_cleanup(
    *,
    ownership: IOSPeerProcessOwnership,
    fresh_inventory: ProcessInventory,
    fresh_ready_receipt: bytes,
    expected_certificate_sha256: str,
    observed_at: datetime,
) -> IOSPeerProcessCleanupAuthority:
    if type(ownership) is not IOSPeerProcessOwnership:
        raise IOSPeerLabError(
            "ios_lab_cleanup_authority_invalid",
            "cleanup inputs lack typed process ownership",
        )
    try:
        ready = validate_ready_receipt(
            fresh_ready_receipt,
            expected_session_id=ownership.session_id,
            expected_certificate_sha256=expected_certificate_sha256,
            now=observed_at,
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_cleanup_authority_invalid", "fresh ready receipt is invalid"
        ) from error
    return _authorize_process_cleanup(
        ownership=ownership,
        fresh_inventory=fresh_inventory,
        fresh_ready_receipt=fresh_ready_receipt,
        ready_process_id=ready["process_id"],
        observed_at=observed_at,
        error_code="ios_lab_cleanup_authority_invalid",
    )


def authorize_packet_lan_process_cleanup(
    *,
    ownership: IOSPeerProcessOwnership,
    fresh_inventory: ProcessInventory,
    fresh_ready_receipt: bytes,
    session_document: bytes,
    material: IOSPeerPacketLanSessionMaterial,
    observed_at: datetime,
) -> IOSPeerProcessCleanupAuthority:
    if type(ownership) is not IOSPeerProcessOwnership:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_cleanup_authority_invalid",
            "packet LAN cleanup lacks typed process ownership",
        )
    session = _validate_packet_lan_session_binding(
        session_document=session_document,
        material=material,
        now=observed_at,
        error_code="ios_lab_packet_lan_cleanup_authority_invalid",
    )
    if ownership.session_id != material.session_id:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_cleanup_authority_invalid",
            "packet LAN ownership refers to another session",
        )
    try:
        ready = validate_packet_lan_ready(
            fresh_ready_receipt,
            session=session,
            now=observed_at,
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_packet_lan_cleanup_authority_invalid",
            "fresh packet LAN ready receipt is invalid",
        ) from error
    return _authorize_process_cleanup(
        ownership=ownership,
        fresh_inventory=fresh_inventory,
        fresh_ready_receipt=fresh_ready_receipt,
        ready_process_id=ready["process_id"],
        observed_at=observed_at,
        error_code="ios_lab_packet_lan_cleanup_authority_invalid",
    )


def parse_uninstall_receipt(
    data: bytes,
    *,
    spec: CommandSpec,
    runtime: DevicectlRuntime,
    device: IOSPeerDevice,
    installation: IOSPeerInstallationOwnership
    | IOSPeerCleanupOnlyInstallationOwnership,
) -> UninstallObservation:
    if (
        type(installation)
        not in {
            IOSPeerInstallationOwnership,
            IOSPeerCleanupOnlyInstallationOwnership,
        }
        or installation.device_identifier_sha256 != device.core_device_identifier_sha256
    ):
        raise IOSPeerLabError(
            "ios_lab_uninstall_receipt_invalid", "uninstall lacks install ownership"
        )
    result, digest = _parse_devicectl_envelope(
        data,
        spec=spec,
        runtime=runtime,
        command_type="devicectl.device.uninstall.app",
    )
    result = _exact_object(result, _UNINSTALL_RESULT_FIELDS, "uninstall result")
    identifier = _require_device_identifier(result["deviceIdentifier"], device)
    applications = result["uninstalledApplications"]
    if (
        not isinstance(applications, list)
        or len(applications) != 1
        or _exact_object(applications[0], {"bundleID"}, "uninstalled application")[
            "bundleID"
        ]
        != BUNDLE_IDENTIFIER
    ):
        raise IOSPeerLabError(
            "ios_lab_uninstall_receipt_invalid",
            "uninstall result does not name exactly the owned bundle",
        )
    return UninstallObservation(digest, identifier, BUNDLE_IDENTIFIER)


def verify_post_uninstall_absence(
    *,
    app_inventory: AppInventory,
    process_inventory: ProcessInventory,
    device: IOSPeerDevice,
    ownership: IOSPeerProcessOwnership | IOSPeerPrimerProcessOwnership | None,
) -> tuple[str, str]:
    if (
        type(app_inventory) is not AppInventory
        or type(process_inventory) is not ProcessInventory
        or app_inventory.device_identifier != device.core_device_identifier
        or process_inventory.device_identifier != device.core_device_identifier
        or any(
            entry.bundle_identifier == BUNDLE_IDENTIFIER
            for entry in app_inventory.entries
        )
    ):
        raise IOSPeerLabError(
            "ios_lab_cleanup_unproven", "post-uninstall app absence is unproven"
        )
    suffix = f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}"
    if any(
        process.executable_path is not None and process.executable_path.endswith(suffix)
        for process in process_inventory.processes
    ):
        raise IOSPeerLabError(
            "ios_lab_cleanup_unproven", "post-uninstall peer process remains"
        )
    if ownership is not None and type(ownership) not in {
        IOSPeerProcessOwnership,
        IOSPeerPrimerProcessOwnership,
    }:
        raise IOSPeerLabError(
            "ios_lab_cleanup_unproven", "cleanup ownership type is invalid"
        )
    return app_inventory.receipt_sha256, process_inventory.receipt_sha256


@dataclass(frozen=True, slots=True)
class VerifiedCopiedReceipt:
    path: Path
    size: int
    sha256: str
    data: bytes


def validate_copied_receipt(
    path: Path, *, expected_name: str, maximum: int = MAX_JSON_BYTES
) -> VerifiedCopiedReceipt:
    if expected_name not in {PRIMER_RESULT_FILE_NAME, "ready.json", "result.json"}:
        raise IOSPeerLabError(
            "ios_lab_receipt_copy_invalid", "receipt copy name is not reviewed"
        )
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.name != expected_name
    ):
        raise IOSPeerLabError(
            "ios_lab_receipt_copy_invalid", "receipt copy path is not fixed"
        )
    _require_private_directory(path.parent, label="receipt copy parent")
    first = _read_stable_file(path, maximum=maximum, label="copied iOS receipt")
    try:
        first_metadata = path.lstat()
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_receipt_copy_invalid", "receipt copy disappeared"
        ) from error
    if stat.S_IMODE(first_metadata.st_mode) != 0o600:
        raise IOSPeerLabError(
            "ios_lab_receipt_copy_invalid", "receipt copy is not private mode 0600"
        )
    second = _read_stable_file(path, maximum=maximum, label="reopened iOS receipt")
    try:
        second_metadata = path.lstat()
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_receipt_copy_invalid", "reopened receipt disappeared"
        ) from error
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if first != second or identity(first_metadata) != identity(second_metadata):
        raise IOSPeerLabError(
            "ios_lab_receipt_copy_invalid", "receipt copy changed across reopen"
        )
    return VerifiedCopiedReceipt(path, len(first), _sha256(first), first)


def verify_transport_pair(
    *,
    mac_result: bytes,
    peer_result: bytes,
    expected_session_id: str,
    expected_certificate_sha256: str,
    expected_process_id: int,
    now: datetime,
) -> TransportPairVerification:
    """Require complementary canonical Mac and iPhone transport receipts."""

    def fields_have_exact_types(
        value: dict[str, object],
        *,
        booleans: tuple[str, ...] = (),
        integers: tuple[str, ...] = (),
        strings: tuple[str, ...] = (),
    ) -> bool:
        return (
            all(type(value[field]) is bool for field in booleans)
            and all(type(value[field]) is int for field in integers)
            and all(type(value[field]) is str for field in strings)
        )

    _require_sha256(expected_session_id, "transport-pair session identifier")
    _require_sha256(expected_certificate_sha256, "transport-pair certificate")
    if (
        type(expected_process_id) is not int
        or not 1 <= expected_process_id <= MAX_PID
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid",
            "transport-pair identity or validation time is invalid",
        )
    try:
        peer = validate_result_receipt(
            peer_result,
            expected_session_id=expected_session_id,
            expected_certificate_sha256=expected_certificate_sha256,
            expected_process_id=expected_process_id,
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid", "iPhone result receipt is invalid"
        ) from error
    if peer["status"] != "pair_required":
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid",
            "iPhone transport result is not the exact pair-resolvable outcome",
        )

    root_fields = {
        "schema_version",
        "document",
        "mode",
        "claim_eligible",
        "session_id",
        "certificate_sha256",
        "process_id",
        "peer_ipv4",
        "attempt_count",
        "started_at",
        "completed_at",
        "negative_checks",
        "positive_checks",
    }
    if (
        not isinstance(mac_result, bytes)
        or not 1 < len(mac_result) <= MAX_JSON_BYTES
        or not mac_result.endswith(b"\n")
        or mac_result.endswith(b"\n\n")
    ):
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid", "Mac result size or terminator differs"
        )
    try:
        mac = _exact_object(
            load_json_bytes(mac_result, "Mac transport result"),
            root_fields,
            "Mac transport result",
        )
    except (TypeError, ValueError, RawArtifactError, IOSPeerLabError) as error:
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid", "Mac result fields are invalid"
        ) from error
    if canonical_json(mac) + b"\n" != mac_result:
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid", "Mac result is not canonical JSON"
        )
    if not fields_have_exact_types(
        mac,
        booleans=("claim_eligible",),
        integers=("schema_version", "process_id", "attempt_count"),
        strings=(
            "document",
            "mode",
            "session_id",
            "certificate_sha256",
            "peer_ipv4",
            "started_at",
            "completed_at",
        ),
    ):
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid", "Mac result field types differ"
        )
    try:
        address = ipaddress.IPv4Address(mac["peer_ipv4"])
    except (TypeError, ipaddress.AddressValueError) as error:
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid", "Mac result peer address is invalid"
        ) from error
    controlled_networks = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    started = _parse_timestamp(mac["started_at"], "Mac probe start")
    completed = _parse_timestamp(mac["completed_at"], "Mac probe completion")
    peer_completed = _parse_timestamp(peer["completed_at"], "iPhone result completion")
    current = now.astimezone(timezone.utc)
    if (
        mac["schema_version"] != 3
        or mac["document"] != "cfm-ios-transport-peer-mac-probe-result-v3"
        or mac["mode"] != "lab_smoke_only"
        or mac["claim_eligible"] is not False
        or mac["session_id"] != expected_session_id
        or mac["certificate_sha256"] != expected_certificate_sha256
        or mac["process_id"] != expected_process_id
        or type(mac["process_id"]) is not int
        or mac["peer_ipv4"] != str(address)
        or not any(address in network for network in controlled_networks)
        or mac["attempt_count"] != 7
        or type(mac["attempt_count"]) is not int
        or not started <= completed <= current
        or (completed - started).total_seconds() > 15 * 60
        or not peer_completed <= current
        or (current - peer_completed).total_seconds() > 15 * 60
    ):
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid",
            "transport-pair top-level identity differs",
        )

    negative = _exact_object(
        mac["negative_checks"],
        {
            "tls12_did_not_reach_ready",
            "wrong_leaf_pin_rejected",
            "alpn_mismatch_did_not_reach_ready",
            "zero_length_frame_connection_ended",
        },
        "Mac negative checks",
    )
    for name in ("tls12_did_not_reach_ready", "alpn_mismatch_did_not_reach_ready"):
        check = _exact_object(
            negative[name],
            {"did_not_reach_ready", "client_bytes_sent"},
            f"Mac {name}",
        )
        if not fields_have_exact_types(
            check,
            booleans=("did_not_reach_ready",),
            integers=("client_bytes_sent",),
        ) or check != {"did_not_reach_ready": True, "client_bytes_sent": 0}:
            raise IOSPeerLabError(
                "ios_lab_transport_pair_invalid", f"Mac {name} did not fail closed"
            )
    wrong_leaf = _exact_object(
        negative["wrong_leaf_pin_rejected"],
        {
            "did_not_reach_ready",
            "client_bytes_sent",
            "verify_callback_invoked",
            "leaf_matched_session_certificate",
            "verify_returned_false",
        },
        "Mac wrong-leaf check",
    )
    if not fields_have_exact_types(
        wrong_leaf,
        booleans=(
            "did_not_reach_ready",
            "verify_callback_invoked",
            "leaf_matched_session_certificate",
            "verify_returned_false",
        ),
        integers=("client_bytes_sent",),
    ) or wrong_leaf != {
        "did_not_reach_ready": True,
        "client_bytes_sent": 0,
        "verify_callback_invoked": True,
        "leaf_matched_session_certificate": True,
        "verify_returned_false": True,
    }:
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid", "Mac wrong-leaf check differs"
        )
    zero_frame = _exact_object(
        negative["zero_length_frame_connection_ended"],
        {
            "client_completed",
            "connection_ended",
            "tls_version",
            "cipher_suite",
            "alpn",
            "early_data_accepted",
            "client_bytes_sent",
            "invalid_zero_length_frame_sent",
        },
        "Mac zero-frame check",
    )
    if (
        not fields_have_exact_types(
            zero_frame,
            booleans=(
                "client_completed",
                "connection_ended",
                "early_data_accepted",
                "invalid_zero_length_frame_sent",
            ),
            integers=("tls_version", "cipher_suite", "client_bytes_sent"),
            strings=("alpn",),
        )
        or zero_frame["client_completed"] is not True
        or zero_frame["connection_ended"] is not True
        or zero_frame["tls_version"] != 0x0304
        or type(zero_frame["cipher_suite"]) is not int
        or not 0x1301 <= zero_frame["cipher_suite"] <= 0x1305
        or zero_frame["alpn"] != "cfm-transport-peer-tls/1"
        or zero_frame["early_data_accepted"] is not False
        or zero_frame["client_bytes_sent"] != 2
        or zero_frame["invalid_zero_length_frame_sent"] is not True
    ):
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid", "Mac zero-frame check differs"
        )

    positive = _exact_object(
        mac["positive_checks"],
        {"tcp_sink", "tls13_echo", "quic_echo"},
        "Mac positive checks",
    )
    peer_connections = peer["connections"]
    payload_digests = {
        service: transport_payload_receipt_sha256(service, expected_session_id)
        for service in ("tcp_sink", "tls13_echo", "quic_echo")
    }
    tcp = _exact_object(
        positive["tcp_sink"],
        {
            "client_completed",
            "transport",
            "payload_sha256",
            "payload_bytes",
            "client_bytes_sent",
            "client_bytes_received",
        },
        "Mac TCP result",
    )
    peer_tcp = peer_connections["tcp_sink"]
    if (
        not fields_have_exact_types(
            tcp,
            booleans=("client_completed",),
            integers=(
                "payload_bytes",
                "client_bytes_sent",
                "client_bytes_received",
            ),
            strings=("transport", "payload_sha256"),
        )
        or tcp["client_completed"] is not True
        or tcp["transport"] != "tcp4"
        or tcp["payload_sha256"] != payload_digests["tcp_sink"]
        or tcp["payload_bytes"] != 32
        or tcp["client_bytes_sent"] != peer_tcp["bytes_received"]
        or tcp["client_bytes_received"] != peer_tcp["bytes_sent"]
        or peer_tcp["accepted"] != 1
        or peer_tcp["evidence_disposition"] != "accepted"
        or peer_tcp["peer_terminal_observed"] is not True
        or peer_tcp["delivery_acknowledgement_final_context_observed"] is not False
    ):
        raise IOSPeerLabError(
            "ios_lab_transport_pair_invalid", "Mac and iPhone TCP results differ"
        )

    secure_fields = {
        "client_completed",
        "transport",
        "payload_sha256",
        "payload_bytes",
        "client_bytes_sent",
        "client_bytes_received",
        "client_control_bytes_sent",
        "client_control_bytes_received",
        "delivery_acknowledgement_hex",
        "delivery_confirmation_hex",
        "delivery_confirmation_stream_complete",
        "tls_version",
        "cipher_suite",
        "alpn",
        "early_data_accepted",
        "certificate_sha256",
    }
    for service, transport, expected_alpn in (
        ("tls13_echo", "tls13-tcp4", "cfm-transport-peer-tls/1"),
        ("quic_echo", "quic-tls13", "cfm-transport-peer-quic/1"),
    ):
        client = _exact_object(
            positive[service], secure_fields, f"Mac {service} result"
        )
        server = peer_connections[service]
        if (
            not fields_have_exact_types(
                client,
                booleans=(
                    "client_completed",
                    "delivery_confirmation_stream_complete",
                    "early_data_accepted",
                ),
                integers=(
                    "payload_bytes",
                    "client_bytes_sent",
                    "client_bytes_received",
                    "client_control_bytes_sent",
                    "client_control_bytes_received",
                    "tls_version",
                    "cipher_suite",
                ),
                strings=(
                    "transport",
                    "payload_sha256",
                    "delivery_acknowledgement_hex",
                    "delivery_confirmation_hex",
                    "alpn",
                    "certificate_sha256",
                ),
            )
            or client["client_completed"] is not True
            or client["delivery_acknowledgement_hex"] != "a5"
            or client["delivery_confirmation_hex"] != "5a"
            or client["delivery_confirmation_stream_complete"] is not True
            or client["transport"] != transport
            or client["payload_sha256"] != payload_digests[service]
            or client["payload_sha256"] != server["payload_sha256"]
            or client["payload_bytes"] != server["bytes_received"]
            or client["client_bytes_sent"] != server["bytes_received"] + 2
            or client["client_bytes_received"] != server["bytes_sent"]
            or client["client_control_bytes_sent"] != server["control_bytes_received"]
            or client["client_control_bytes_received"]
            != server["control_bytes_submitted"]
            or client["tls_version"] != server["tls_version"]
            or client["cipher_suite"] != server["cipher_suite"]
            or client["alpn"] != expected_alpn
            or client["alpn"] != server["alpn"]
            or client["early_data_accepted"] is not False
            or client["early_data_accepted"] != server["early_data_accepted"]
            or client["certificate_sha256"] != expected_certificate_sha256
            or server["accepted"] != 0
            or server["evidence_disposition"] != "pair_required"
            or server["delivery_confirmation_completion"] != "processed"
            or server["peer_terminal_observed"] is not False
            or server["delivery_acknowledgement_final_context_observed"] is not True
        ):
            raise IOSPeerLabError(
                "ios_lab_transport_pair_invalid",
                f"Mac and iPhone {service} results differ",
            )
    return TransportPairVerification(
        mac_result_sha256=_sha256(mac_result),
        peer_result_sha256=_sha256(peer_result),
        session_id=expected_session_id,
        certificate_sha256=expected_certificate_sha256,
        process_id=expected_process_id,
    )


def _require_real_working_directory(path: Path, *, label: str) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise IOSPeerLabError("ios_lab_directory_invalid", f"{label} is not absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise IOSPeerLabError(
            "ios_lab_directory_invalid", f"{label} is unavailable"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise IOSPeerLabError("ios_lab_directory_invalid", f"{label} is not real")


@dataclass(frozen=True, slots=True)
class LegacyProxyConfiguration:
    enabled: bool
    server: str
    port: int
    authenticated: bool

    def __post_init__(self) -> None:
        if (
            type(self.enabled) is not bool
            or not isinstance(self.server, str)
            or not 1 <= len(self.server) <= 255
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or type(self.authenticated) is not bool
        ):
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_invalid", "legacy CFW proxy expectation is invalid"
            )


@dataclass(frozen=True, slots=True)
class LegacyCFWExpectedState:
    gui_executable_path: Path
    gui_executable_sha256: str
    core_executable_path: Path
    core_executable_sha256: str
    gui_uid: int
    core_uid: int
    network_service: str
    http_proxy: LegacyProxyConfiguration
    https_proxy: LegacyProxyConfiguration
    socks_proxy: LegacyProxyConfiguration

    def __post_init__(self) -> None:
        for path, digest, label in (
            (
                self.gui_executable_path,
                self.gui_executable_sha256,
                "legacy CFW GUI executable",
            ),
            (
                self.core_executable_path,
                self.core_executable_sha256,
                "legacy CFW core executable",
            ),
        ):
            data = _read_stable_file(path, maximum=512 * 1024 * 1024, label=label)
            if _sha256(data) != _require_sha256(digest, f"{label} digest"):
                raise IOSPeerLabError(
                    "ios_lab_cfw_guard_invalid", f"{label} digest differs"
                )
        if (
            type(self.gui_uid) is not int
            or not 0 <= self.gui_uid <= 2**31 - 1
            or type(self.core_uid) is not int
            or not 0 <= self.core_uid <= 2**31 - 1
            or not isinstance(self.network_service, str)
            or not 1 <= len(self.network_service) <= 128
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in self.network_service
            )
            or type(self.http_proxy) is not LegacyProxyConfiguration
            or type(self.https_proxy) is not LegacyProxyConfiguration
            or type(self.socks_proxy) is not LegacyProxyConfiguration
        ):
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_invalid", "legacy CFW guard inputs are invalid"
            )


@dataclass(frozen=True, slots=True)
class LegacyProcessIdentity:
    process_id: int
    uid: int
    started_at: str
    executable_path: str
    executable_sha256: str


@dataclass(frozen=True, slots=True)
class LegacyPortOwner:
    protocol: str
    port: int
    process_id: int
    uid: int
    command: str


@dataclass(frozen=True, slots=True)
class LegacyRoute:
    destination: str
    interface: str


@dataclass(frozen=True, slots=True)
class LegacyCFWGuardSnapshot:
    gui: LegacyProcessIdentity
    core: LegacyProcessIdentity
    tcp_owner: LegacyPortOwner
    udp_owner: LegacyPortOwner
    http_proxy: LegacyProxyConfiguration
    https_proxy: LegacyProxyConfiguration
    socks_proxy: LegacyProxyConfiguration

    @property
    def binding_sha256(self) -> str:
        value = {
            "core": asdict(self.core),
            "gui": asdict(self.gui),
            "http_proxy": asdict(self.http_proxy),
            "https_proxy": asdict(self.https_proxy),
            "socks_proxy": asdict(self.socks_proxy),
            "tcp_owner": asdict(self.tcp_owner),
            "udp_owner": asdict(self.udp_owner),
        }
        return _sha256(canonical_json(value))


@dataclass(frozen=True, slots=True)
class LegacyCFWGuardPlan:
    """Only read-only observations; this type cannot build kill or set commands."""

    repository: Path
    expected: LegacyCFWExpectedState

    def __post_init__(self) -> None:
        _require_real_working_directory(
            self.repository, label="CFW guard working directory"
        )
        if type(self.expected) is not LegacyCFWExpectedState:
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_invalid", "CFW guard lacks typed expectations"
            )

    def process_inventory(self) -> CommandSpec:
        return _fixed_command(
            "ios-peer-cfw-process-inventory",
            PS,
            "-ww",
            "-axo",
            "pid=,uid=,lstart=,comm=",
            cwd=self.repository,
        )

    def tcp_7890_owner(self) -> CommandSpec:
        return _fixed_command(
            "ios-peer-cfw-tcp-owner",
            NETSTAT,
            "-anv",
            "-p",
            "tcp",
            cwd=self.repository,
        )

    def udp_7890_owner(self) -> CommandSpec:
        return _fixed_command(
            "ios-peer-cfw-udp-owner",
            NETSTAT,
            "-anv",
            "-p",
            "udp",
            cwd=self.repository,
        )

    def http_proxy(self) -> CommandSpec:
        return self._proxy("ios-peer-cfw-http-proxy", "-getwebproxy")

    def https_proxy(self) -> CommandSpec:
        return self._proxy("ios-peer-cfw-https-proxy", "-getsecurewebproxy")

    def socks_proxy(self) -> CommandSpec:
        return self._proxy("ios-peer-cfw-socks-proxy", "-getsocksfirewallproxy")

    def _proxy(self, role: str, operation: str) -> CommandSpec:
        if not operation.startswith("-get"):
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_invalid", "CFW guard proxy command is not read-only"
            )
        return _fixed_command(
            role,
            NETWORKSETUP,
            operation,
            self.expected.network_service,
            cwd=self.repository,
        )

    def route_to_peer(self, ipv4: str) -> CommandSpec:
        import ipaddress

        try:
            address = ipaddress.IPv4Address(ipv4)
        except (ipaddress.AddressValueError, TypeError) as error:
            raise IOSPeerLabError(
                "ios_lab_route_invalid", "peer route target is not IPv4"
            ) from error
        if str(address) != ipv4:
            raise IOSPeerLabError(
                "ios_lab_route_invalid", "peer route target is not canonical IPv4"
            )
        return _fixed_command(
            "ios-peer-cfw-peer-route",
            ROUTE,
            "-n",
            "get",
            ipv4,
            cwd=self.repository,
        )


_PS_LINE = re.compile(
    r"^\s*([1-9][0-9]*)\s+([0-9]+)\s+"
    r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"([ 0-9][0-9])\s+([0-9]{2}:[0-9]{2}:[0-9]{2})\s+"
    r"([0-9]{4})\s+(/[^\x00\r\n]+)$"
)


def parse_legacy_process_inventory(
    data: bytes, *, expected: LegacyCFWExpectedState
) -> tuple[LegacyProcessIdentity, LegacyProcessIdentity]:
    if not isinstance(data, bytes) or not 1 <= len(data) <= 4 * 1024 * 1024:
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "legacy process inventory size is invalid"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "legacy process inventory is not UTF-8"
        ) from error
    targets = {
        str(expected.gui_executable_path): (
            expected.gui_executable_sha256,
            expected.gui_uid,
        ),
        str(expected.core_executable_path): (
            expected.core_executable_sha256,
            expected.core_uid,
        ),
    }
    found: dict[str, LegacyProcessIdentity] = {}
    for line in text.splitlines():
        match = _PS_LINE.fullmatch(line)
        if match is None:
            continue
        path = match.group(8)
        if path not in targets:
            continue
        if path in found:
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_invalid", "legacy CFW process identity is ambiguous"
            )
        process_id = int(match.group(1))
        uid = int(match.group(2))
        expected_digest, expected_uid = targets[path]
        if uid != expected_uid or process_id > MAX_PID:
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_invalid", "legacy CFW PID or UID differs"
            )
        executable_data = _read_stable_file(
            Path(path), maximum=512 * 1024 * 1024, label="running legacy CFW executable"
        )
        digest = _sha256(executable_data)
        if digest != expected_digest:
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_invalid", "running legacy CFW executable changed"
            )
        started_at = (
            f"{match.group(3)} {match.group(4)} {match.group(5)} "
            f"{match.group(6)} {match.group(7)}"
        )
        found[path] = LegacyProcessIdentity(process_id, uid, started_at, path, digest)
    if set(found) != set(targets):
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "legacy CFW GUI or core process is absent"
        )
    return found[str(expected.gui_executable_path)], found[
        str(expected.core_executable_path)
    ]


def parse_legacy_port_owner(
    data: bytes,
    *,
    protocol: str,
    expected_process: LegacyProcessIdentity,
) -> LegacyPortOwner:
    if (
        protocol not in {"tcp", "udp"}
        or not isinstance(data, bytes)
        or not 1 <= len(data) <= MAX_CODESIGN_OUTPUT_BYTES
    ):
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "legacy port observation inputs are invalid"
        )
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "netstat output is not UTF-8"
        ) from error
    command = Path(expected_process.executable_path).name
    owner_token = f"{command}:{expected_process.process_id}"
    candidates: list[list[str]] = []
    for line in lines:
        fields = line.split()
        if not fields or fields[0] != f"{protocol}4":
            continue
        if protocol == "tcp":
            if (
                len(fields) >= 11
                and fields[3] == "127.0.0.1.7890"
                and fields[4] == "*.*"
                and fields[5] == "LISTEN"
            ):
                candidates.append(fields)
        elif len(fields) >= 10 and fields[3] == "127.0.0.1.7890" and fields[4] == "*.*":
            candidates.append(fields)
    if len(candidates) != 1 or candidates[0].count(owner_token) != 1:
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "legacy CFW port ownership differs"
        )
    return LegacyPortOwner(
        protocol=protocol,
        port=7890,
        process_id=expected_process.process_id,
        uid=expected_process.uid,
        command=command,
    )


def parse_legacy_proxy_configuration(data: bytes) -> LegacyProxyConfiguration:
    if not isinstance(data, bytes) or not 1 <= len(data) <= 4096:
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "networksetup output size is invalid"
        )
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "networksetup output is not UTF-8"
        ) from error
    fields: dict[str, str] = {}
    for line in lines:
        if ": " not in line:
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_invalid", "networksetup output is malformed"
            )
        key, value = line.split(": ", 1)
        if key in fields or key not in {
            "Enabled",
            "Server",
            "Port",
            "Authenticated Proxy Enabled",
        }:
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_invalid", "networksetup output fields differ"
            )
        fields[key] = value
    if set(fields) != {
        "Enabled",
        "Server",
        "Port",
        "Authenticated Proxy Enabled",
    }:
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "networksetup output lacks proxy fields"
        )
    if fields["Enabled"] not in {"Yes", "No"} or fields[
        "Authenticated Proxy Enabled"
    ] not in {"0", "1"}:
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "networksetup booleans are invalid"
        )
    try:
        port = int(fields["Port"])
    except ValueError as error:
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "networksetup proxy port is invalid"
        ) from error
    return LegacyProxyConfiguration(
        enabled=fields["Enabled"] == "Yes",
        server=fields["Server"],
        port=port,
        authenticated=fields["Authenticated Proxy Enabled"] == "1",
    )


def parse_route_to_peer(data: bytes, *, expected_ipv4: str) -> LegacyRoute:
    if not isinstance(data, bytes) or not 1 <= len(data) <= 64 * 1024:
        raise IOSPeerLabError("ios_lab_route_invalid", "route output size is invalid")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise IOSPeerLabError(
            "ios_lab_route_invalid", "route output is not UTF-8"
        ) from error
    fields: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if ": " not in stripped:
            continue
        key, value = stripped.split(": ", 1)
        if key in {"route to", "destination", "interface"}:
            if key in fields:
                raise IOSPeerLabError(
                    "ios_lab_route_invalid", "route output repeats an authority field"
                )
            fields[key] = value
    if (
        fields.get("route to") != expected_ipv4
        or "destination" not in fields
        or fields.get("interface") != "en0"
        or fields.get("interface", "").startswith("utun")
    ):
        raise IOSPeerLabError(
            "ios_lab_route_invalid", "peer route is missing or traverses a tunnel"
        )
    return LegacyRoute(destination=fields["destination"], interface="en0")


def build_legacy_cfw_guard_snapshot(
    *,
    process_output: bytes,
    tcp_owner_output: bytes,
    udp_owner_output: bytes,
    http_proxy_output: bytes,
    https_proxy_output: bytes,
    socks_proxy_output: bytes,
    expected: LegacyCFWExpectedState,
) -> LegacyCFWGuardSnapshot:
    gui, core = parse_legacy_process_inventory(process_output, expected=expected)
    snapshot = LegacyCFWGuardSnapshot(
        gui=gui,
        core=core,
        tcp_owner=parse_legacy_port_owner(
            tcp_owner_output, protocol="tcp", expected_process=core
        ),
        udp_owner=parse_legacy_port_owner(
            udp_owner_output, protocol="udp", expected_process=core
        ),
        http_proxy=parse_legacy_proxy_configuration(http_proxy_output),
        https_proxy=parse_legacy_proxy_configuration(https_proxy_output),
        socks_proxy=parse_legacy_proxy_configuration(socks_proxy_output),
    )
    if (
        snapshot.http_proxy != expected.http_proxy
        or snapshot.https_proxy != expected.https_proxy
        or snapshot.socks_proxy != expected.socks_proxy
    ):
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_invalid", "legacy CFW proxy configuration differs"
        )
    return snapshot


def verify_legacy_cfw_unchanged(
    before: LegacyCFWGuardSnapshot, after: LegacyCFWGuardSnapshot
) -> str:
    if (
        type(before) is not LegacyCFWGuardSnapshot
        or type(after) is not LegacyCFWGuardSnapshot
        or before != after
    ):
        raise IOSPeerLabError(
            "ios_lab_cfw_guard_drift", "legacy CFW changed during the iPhone smoke"
        )
    return before.binding_sha256


class IOSPeerTransactionState(str, Enum):
    PREPARED = "prepared"
    INSTALL_INTENT = "install_intent"
    INSTALLED = "installed"
    PRIMER_LAUNCH_INTENT = "primer_launch_intent"
    PRIMER_RETRY_AUTHORIZED = "primer_retry_authorized"
    PRIMER_RETRY_LAUNCH_INTENT = "primer_retry_launch_intent"
    PRIMER_LAUNCHED = "primer_launched"
    PRIMER_TERMINATE_INTENT = "primer_terminate_intent"
    PRIMER_TERMINATED = "primer_terminated"
    PRIMER_STOPPED = "primer_stopped"
    SESSION_COPY_INTENT = "session_copy_intent"
    SESSION_COPIED = "session_copied"
    TRANSPORT_LAUNCH_INTENT = "transport_launch_intent"
    TRANSPORT_LAUNCHED = "transport_launched"
    RESULT_RECEIVED = "result_received"
    TERMINATE_INTENT = "terminate_intent"
    TERMINATED = "terminated"
    UNINSTALL_INTENT = "uninstall_intent"
    UNINSTALLED = "uninstalled"
    ABSENCE_VERIFIED = "absence_verified"
    # This means owned resources and CFW preservation are proven, never that
    # transport acceptance or release evidence succeeded.
    COMPLETE = "cleanup_complete"


_TRANSITIONS: Final[
    dict[IOSPeerTransactionState | None, set[IOSPeerTransactionState]]
] = {
    None: {IOSPeerTransactionState.PREPARED},
    IOSPeerTransactionState.PREPARED: {IOSPeerTransactionState.INSTALL_INTENT},
    IOSPeerTransactionState.INSTALL_INTENT: {
        IOSPeerTransactionState.INSTALLED,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.INSTALLED: {
        IOSPeerTransactionState.PRIMER_LAUNCH_INTENT,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.PRIMER_LAUNCH_INTENT: {
        IOSPeerTransactionState.PRIMER_RETRY_AUTHORIZED,
        IOSPeerTransactionState.PRIMER_LAUNCHED,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.PRIMER_RETRY_AUTHORIZED: {
        IOSPeerTransactionState.PRIMER_RETRY_LAUNCH_INTENT,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.PRIMER_RETRY_LAUNCH_INTENT: {
        IOSPeerTransactionState.PRIMER_LAUNCHED,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.PRIMER_LAUNCHED: {
        IOSPeerTransactionState.PRIMER_TERMINATE_INTENT,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.PRIMER_TERMINATE_INTENT: {
        IOSPeerTransactionState.PRIMER_TERMINATED,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.PRIMER_TERMINATED: {
        IOSPeerTransactionState.PRIMER_STOPPED,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.PRIMER_STOPPED: {
        IOSPeerTransactionState.SESSION_COPY_INTENT,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.SESSION_COPY_INTENT: {
        IOSPeerTransactionState.SESSION_COPIED,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.SESSION_COPIED: {
        IOSPeerTransactionState.TRANSPORT_LAUNCH_INTENT,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.TRANSPORT_LAUNCH_INTENT: {
        IOSPeerTransactionState.TRANSPORT_LAUNCHED,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.TRANSPORT_LAUNCHED: {
        IOSPeerTransactionState.RESULT_RECEIVED,
        IOSPeerTransactionState.TERMINATE_INTENT,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.RESULT_RECEIVED: {
        IOSPeerTransactionState.TERMINATE_INTENT,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.TERMINATE_INTENT: {
        IOSPeerTransactionState.TERMINATED,
        IOSPeerTransactionState.UNINSTALL_INTENT,
    },
    IOSPeerTransactionState.TERMINATED: {IOSPeerTransactionState.UNINSTALL_INTENT},
    IOSPeerTransactionState.UNINSTALL_INTENT: {IOSPeerTransactionState.UNINSTALLED},
    IOSPeerTransactionState.UNINSTALLED: {IOSPeerTransactionState.ABSENCE_VERIFIED},
    IOSPeerTransactionState.ABSENCE_VERIFIED: {IOSPeerTransactionState.COMPLETE},
    IOSPeerTransactionState.COMPLETE: set(),
}


@dataclass(frozen=True, slots=True)
class IOSPeerTransactionInputs:
    transaction_id: str
    device: IOSPeerDevice
    device_admission: DeviceAdmission
    artifact: IOSPeerArtifact
    session_id: str
    preflight: IOSPeerPreflight
    legacy_cfw_before_sha256: str

    def __post_init__(self) -> None:
        try:
            canonical = str(uuid.UUID(self.transaction_id)).lower()
        except (TypeError, ValueError, AttributeError) as error:
            raise IOSPeerLabError(
                "ios_lab_transaction_invalid", "transaction ID is invalid"
            ) from error
        if (
            self.transaction_id != canonical
            or type(self.device) is not IOSPeerDevice
            or type(self.device_admission) is not DeviceAdmission
            or self.device_admission.core_device_identifier
            != self.device.core_device_identifier
            or self.device_admission.provisioning_udid != self.device.provisioning_udid
            or type(self.artifact) is not IOSPeerArtifact
            or type(self.preflight) is not IOSPeerPreflight
            or self.preflight.device_identifier_sha256
            != self.device.core_device_identifier_sha256
        ):
            raise IOSPeerLabError(
                "ios_lab_transaction_invalid", "transaction inputs do not bind one run"
            )
        _require_sha256(self.session_id, "transaction session ID")
        _require_sha256(
            self.legacy_cfw_before_sha256, "legacy CFW before-snapshot digest"
        )


@dataclass(frozen=True, slots=True)
class IOSPeerTransactionEvidence:
    transaction_id: str
    core_device_identifier_sha256: str
    provisioning_udid_sha256: str
    device_admission_sha256: str
    control_transport: str
    authentication_type: str
    tunnel_transport_protocol: str
    app_tree_sha256: str
    session_id: str
    preflight_app_inventory_sha256: str
    preflight_process_inventory_sha256: str
    legacy_cfw_before_sha256: str
    cleanup_only_install_intent_sha256: str | None = None
    cleanup_only_app_inventory_sha256: str | None = None
    cleanup_only_installation_path: str | None = None
    install_receipt_sha256: str | None = None
    post_install_app_inventory_sha256: str | None = None
    launch_services_identifier: str | None = None
    primer_first_launch_receipt_sha256: str | None = None
    primer_first_process_inventory_sha256: str | None = None
    primer_first_process_id: int | None = None
    primer_first_executable_path: str | None = None
    primer_launch_receipt_sha256: str | None = None
    primer_process_inventory_sha256: str | None = None
    primer_receipt_sha256: str | None = None
    primer_process_id: int | None = None
    primer_executable_path: str | None = None
    primer_cleanup_process_inventory_sha256: str | None = None
    primer_terminate_receipt_sha256: str | None = None
    primer_post_terminate_process_inventory_sha256: str | None = None
    session_copy_receipt_sha256: str | None = None
    transport_launch_receipt_sha256: str | None = None
    transport_process_inventory_sha256: str | None = None
    ready_receipt_sha256: str | None = None
    transport_process_id: int | None = None
    transport_executable_path: str | None = None
    result_receipt_sha256: str | None = None
    cleanup_process_inventory_sha256: str | None = None
    terminate_receipt_sha256: str | None = None
    uninstall_receipt_sha256: str | None = None
    final_app_inventory_sha256: str | None = None
    final_process_inventory_sha256: str | None = None
    legacy_cfw_after_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class IOSPeerTransactionSnapshot:
    state: IOSPeerTransactionState
    sequence: int
    last_event_sha256: str
    recorded_at: str
    evidence: IOSPeerTransactionEvidence


def authorize_cleanup_only_installation(
    *,
    snapshot: IOSPeerTransactionSnapshot,
    post_intent_inventory: AppInventory,
    device: IOSPeerDevice,
    artifact: IOSPeerArtifact,
    observed_at: datetime,
) -> IOSPeerCleanupOnlyInstallationOwnership:
    """Bind an ambiguous install to uninstall-only authority, never launch."""

    if (
        type(snapshot) is not IOSPeerTransactionSnapshot
        or snapshot.state is not IOSPeerTransactionState.INSTALL_INTENT
        or type(post_intent_inventory) is not AppInventory
        or post_intent_inventory.device_identifier != device.core_device_identifier
        or snapshot.evidence.core_device_identifier_sha256
        != device.core_device_identifier_sha256
        or snapshot.evidence.app_tree_sha256 != artifact.app_tree_sha256
    ):
        raise IOSPeerLabError(
            "ios_lab_cleanup_install_invalid",
            "cleanup-only ownership lacks the durable install intent binding",
        )
    matches = [
        entry
        for entry in post_intent_inventory.entries
        if entry.bundle_identifier == BUNDLE_IDENTIFIER
    ]
    if (
        len(matches) != 1
        or matches[0].url is None
        or matches[0].built_by_developer is not True
        or matches[0].removable is not True
    ):
        raise IOSPeerLabError(
            "ios_lab_cleanup_install_invalid",
            "post-intent full inventory does not uniquely identify the removable app",
        )
    installation_path = _file_url_to_remote_path(matches[0].url, executable=False)
    try:
        return IOSPeerCleanupOnlyInstallationOwnership(
            device_identifier_sha256=device.core_device_identifier_sha256,
            app_tree_sha256=artifact.app_tree_sha256,
            preflight_app_inventory_receipt_sha256=snapshot.evidence.preflight_app_inventory_sha256,
            install_intent_event_sha256=snapshot.last_event_sha256,
            post_intent_app_inventory_receipt_sha256=post_intent_inventory.receipt_sha256,
            installation_path=installation_path,
            observed_at=_canonical_timestamp(observed_at),
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_cleanup_install_invalid", "cleanup-only ownership is invalid"
        ) from error


def authorize_cleanup_only_installation_from_preflight(
    *,
    preflight: IOSPeerPreflight,
    post_intent_inventory: AppInventory,
    device: IOSPeerDevice,
    artifact: IOSPeerArtifact,
    install_intent_sha256: str,
    observed_at: datetime,
) -> IOSPeerCleanupOnlyInstallationOwnership:
    """Authorize uninstall only after an exact install attempt became ambiguous.

    This is the non-journal adapter boundary.  The caller must durably write the
    canonical install-intent event before executing ``devicectl install`` and
    supplies its digest here.  The authority can only uninstall the one bundle
    that was proven absent by the typed preflight and then appeared as one
    removable developer-built app; it cannot launch or terminate a PID.
    """

    intent_sha256 = _require_sha256(
        install_intent_sha256, "cleanup-only install-intent digest"
    )
    if (
        type(preflight) is not IOSPeerPreflight
        or type(post_intent_inventory) is not AppInventory
        or type(device) is not IOSPeerDevice
        or type(artifact) is not IOSPeerArtifact
        or preflight.device_identifier_sha256
        != device.core_device_identifier_sha256
        or preflight.app_absent is not True
        or preflight.process_absent is not True
        or post_intent_inventory.device_identifier
        != device.core_device_identifier
    ):
        raise IOSPeerLabError(
            "ios_lab_cleanup_install_invalid",
            "cleanup-only ownership lacks exact preflight and device binding",
        )
    matches = [
        entry
        for entry in post_intent_inventory.entries
        if entry.bundle_identifier == BUNDLE_IDENTIFIER
    ]
    if (
        len(matches) != 1
        or matches[0].url is None
        or matches[0].built_by_developer is not True
        or matches[0].removable is not True
    ):
        raise IOSPeerLabError(
            "ios_lab_cleanup_install_invalid",
            "post-intent inventory does not identify one removable owned app",
        )
    installation_path = _file_url_to_remote_path(matches[0].url, executable=False)
    try:
        return IOSPeerCleanupOnlyInstallationOwnership(
            device_identifier_sha256=device.core_device_identifier_sha256,
            app_tree_sha256=artifact.app_tree_sha256,
            preflight_app_inventory_receipt_sha256=(
                preflight.app_inventory_receipt_sha256
            ),
            install_intent_event_sha256=intent_sha256,
            post_intent_app_inventory_receipt_sha256=(
                post_intent_inventory.receipt_sha256
            ),
            installation_path=installation_path,
            observed_at=_canonical_timestamp(observed_at),
        )
    except IOSPeerContractError as error:
        raise IOSPeerLabError(
            "ios_lab_cleanup_install_invalid", "cleanup-only ownership is invalid"
        ) from error


_EVIDENCE_FIELDS = set(IOSPeerTransactionEvidence.__dataclass_fields__)
_EVENT_FIELDS = {
    "document",
    "event",
    "evidence",
    "from_state",
    "previous_event_sha256",
    "recorded_at",
    "schema_version",
    "sequence",
    "to_state",
}


def _validate_evidence(value: object) -> IOSPeerTransactionEvidence:
    value = _exact_object(value, _EVIDENCE_FIELDS, "transaction evidence")
    try:
        evidence = IOSPeerTransactionEvidence(**value)
    except TypeError as error:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "transaction evidence types differ"
        ) from error
    for field in (
        "core_device_identifier_sha256",
        "provisioning_udid_sha256",
        "device_admission_sha256",
        "app_tree_sha256",
        "session_id",
        "preflight_app_inventory_sha256",
        "preflight_process_inventory_sha256",
        "legacy_cfw_before_sha256",
    ):
        _require_sha256(getattr(evidence, field), f"transaction {field}")
    if (
        evidence.control_transport != COREDEVICE_CONTROL_TRANSPORT
        or evidence.authentication_type != COREDEVICE_AUTHENTICATION_TYPE
        or evidence.tunnel_transport_protocol != COREDEVICE_TUNNEL_TRANSPORT_PROTOCOL
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid",
            "transaction control-channel admission differs from the fixed policy",
        )
    for field in (
        "install_receipt_sha256",
        "post_install_app_inventory_sha256",
        "primer_first_launch_receipt_sha256",
        "primer_first_process_inventory_sha256",
        "primer_launch_receipt_sha256",
        "primer_process_inventory_sha256",
        "primer_receipt_sha256",
        "primer_cleanup_process_inventory_sha256",
        "primer_terminate_receipt_sha256",
        "primer_post_terminate_process_inventory_sha256",
        "session_copy_receipt_sha256",
        "transport_launch_receipt_sha256",
        "transport_process_inventory_sha256",
        "ready_receipt_sha256",
        "result_receipt_sha256",
        "cleanup_process_inventory_sha256",
        "terminate_receipt_sha256",
        "uninstall_receipt_sha256",
        "final_app_inventory_sha256",
        "final_process_inventory_sha256",
        "legacy_cfw_after_sha256",
        "cleanup_only_install_intent_sha256",
        "cleanup_only_app_inventory_sha256",
    ):
        item = getattr(evidence, field)
        if item is not None:
            _require_sha256(item, f"transaction {field}")
    if evidence.launch_services_identifier is not None:
        _canonical_launch_services_identifier(evidence.launch_services_identifier)
    for field in (
        "primer_first_process_id",
        "primer_process_id",
        "transport_process_id",
    ):
        process_id = getattr(evidence, field)
        if process_id is not None and (
            type(process_id) is not int or not 1 <= process_id <= MAX_PID
        ):
            raise IOSPeerLabError(
                "ios_lab_journal_invalid", f"transaction {field} is invalid"
            )
    for field in (
        "primer_first_executable_path",
        "primer_executable_path",
        "transport_executable_path",
    ):
        executable_path = getattr(evidence, field)
        if executable_path is not None and not executable_path.endswith(
            f"/{APP_EXECUTABLE}.app/{APP_EXECUTABLE}"
        ):
            raise IOSPeerLabError(
                "ios_lab_journal_invalid", f"transaction {field} differs"
            )
    if evidence.cleanup_only_installation_path is not None and (
        not evidence.cleanup_only_installation_path.endswith(f"/{APP_EXECUTABLE}.app")
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "cleanup-only installation path differs"
        )
    return evidence


def _validate_state_evidence(
    state: IOSPeerTransactionState, evidence: IOSPeerTransactionEvidence
) -> None:
    cleanup_states = {
        IOSPeerTransactionState.UNINSTALL_INTENT,
        IOSPeerTransactionState.UNINSTALLED,
        IOSPeerTransactionState.ABSENCE_VERIFIED,
        IOSPeerTransactionState.COMPLETE,
    }
    install_fields = (
        evidence.install_receipt_sha256,
        evidence.post_install_app_inventory_sha256,
        evidence.launch_services_identifier,
    )
    install_complete = all(item is not None for item in install_fields)
    if any(item is not None for item in install_fields) and not install_complete:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal install ownership is partial"
        )
    cleanup_install_fields = (
        evidence.cleanup_only_install_intent_sha256,
        evidence.cleanup_only_app_inventory_sha256,
        evidence.cleanup_only_installation_path,
    )
    cleanup_only = all(item is not None for item in cleanup_install_fields)
    if any(item is not None for item in cleanup_install_fields) and not cleanup_only:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "cleanup-only installation binding is partial"
        )
    retry_fields = (
        evidence.primer_first_launch_receipt_sha256,
        evidence.primer_first_process_inventory_sha256,
        evidence.primer_first_process_id,
        evidence.primer_first_executable_path,
    )
    retry_complete = all(item is not None for item in retry_fields)
    if any(item is not None for item in retry_fields) and not retry_complete:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "primer retry binding is partial"
        )
    primer_fields = (
        evidence.primer_launch_receipt_sha256,
        evidence.primer_process_inventory_sha256,
        evidence.primer_receipt_sha256,
        evidence.primer_process_id,
        evidence.primer_executable_path,
    )
    primer_complete = all(item is not None for item in primer_fields)
    if any(item is not None for item in primer_fields) and not primer_complete:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "primer process ownership is partial"
        )
    transport_fields = (
        evidence.transport_launch_receipt_sha256,
        evidence.transport_process_inventory_sha256,
        evidence.ready_receipt_sha256,
        evidence.transport_process_id,
        evidence.transport_executable_path,
    )
    transport_complete = all(item is not None for item in transport_fields)
    if any(item is not None for item in transport_fields) and not transport_complete:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "transport process ownership is partial"
        )
    normal_flow_fields = (
        *retry_fields,
        *primer_fields,
        evidence.primer_cleanup_process_inventory_sha256,
        evidence.primer_terminate_receipt_sha256,
        evidence.primer_post_terminate_process_inventory_sha256,
        evidence.session_copy_receipt_sha256,
        *transport_fields,
        evidence.result_receipt_sha256,
        evidence.cleanup_process_inventory_sha256,
        evidence.terminate_receipt_sha256,
    )
    if cleanup_only:
        if (
            state not in cleanup_states
            or install_complete
            or any(item is not None for item in normal_flow_fields)
        ):
            raise IOSPeerLabError(
                "ios_lab_journal_invalid",
                "cleanup-only install cannot contain normal lifecycle evidence",
            )
    else:
        install_required = state not in {
            IOSPeerTransactionState.PREPARED,
            IOSPeerTransactionState.INSTALL_INTENT,
        }
        if install_required != install_complete:
            raise IOSPeerLabError(
                "ios_lab_journal_invalid",
                "journal install ownership does not match state",
            )

    retry_states = {
        IOSPeerTransactionState.PRIMER_RETRY_AUTHORIZED,
        IOSPeerTransactionState.PRIMER_RETRY_LAUNCH_INTENT,
    }
    retry_downstream_states = {
        IOSPeerTransactionState.PRIMER_LAUNCHED,
        IOSPeerTransactionState.PRIMER_TERMINATE_INTENT,
        IOSPeerTransactionState.PRIMER_TERMINATED,
        IOSPeerTransactionState.PRIMER_STOPPED,
        IOSPeerTransactionState.SESSION_COPY_INTENT,
        IOSPeerTransactionState.SESSION_COPIED,
        IOSPeerTransactionState.TRANSPORT_LAUNCH_INTENT,
        IOSPeerTransactionState.TRANSPORT_LAUNCHED,
        IOSPeerTransactionState.RESULT_RECEIVED,
        IOSPeerTransactionState.TERMINATE_INTENT,
        IOSPeerTransactionState.TERMINATED,
    }
    if state in retry_states and not retry_complete:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "primer retry state lacks one-shot authority"
        )
    if (
        retry_complete
        and state not in retry_states | retry_downstream_states | cleanup_states
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal records primer retry prematurely"
        )

    primer_required_states = retry_downstream_states
    if state in primer_required_states and not primer_complete:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal lacks primer process ownership"
        )
    if primer_complete and state not in primer_required_states | cleanup_states:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal records primer ownership prematurely"
        )

    primer_cleanup = evidence.primer_cleanup_process_inventory_sha256 is not None
    primer_terminated = evidence.primer_terminate_receipt_sha256 is not None
    primer_stopped = evidence.primer_post_terminate_process_inventory_sha256 is not None
    if (
        (primer_cleanup and not primer_complete)
        or (primer_terminated and not primer_cleanup)
        or (primer_stopped and not primer_terminated)
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "primer cleanup evidence is out of order"
        )
    primer_cleanup_expectations = {
        IOSPeerTransactionState.PRIMER_LAUNCHED: (False, False, False),
        IOSPeerTransactionState.PRIMER_TERMINATE_INTENT: (True, False, False),
        IOSPeerTransactionState.PRIMER_TERMINATED: (True, True, False),
        IOSPeerTransactionState.PRIMER_STOPPED: (True, True, True),
        IOSPeerTransactionState.SESSION_COPY_INTENT: (True, True, True),
        IOSPeerTransactionState.SESSION_COPIED: (True, True, True),
        IOSPeerTransactionState.TRANSPORT_LAUNCH_INTENT: (True, True, True),
        IOSPeerTransactionState.TRANSPORT_LAUNCHED: (True, True, True),
        IOSPeerTransactionState.RESULT_RECEIVED: (True, True, True),
        IOSPeerTransactionState.TERMINATE_INTENT: (True, True, True),
        IOSPeerTransactionState.TERMINATED: (True, True, True),
    }
    expected_primer_cleanup = primer_cleanup_expectations.get(state)
    if expected_primer_cleanup is not None and expected_primer_cleanup != (
        primer_cleanup,
        primer_terminated,
        primer_stopped,
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid",
            "primer cleanup evidence does not match the journal state",
        )

    session_copied = evidence.session_copy_receipt_sha256 is not None
    session_required_states = {
        IOSPeerTransactionState.SESSION_COPIED,
        IOSPeerTransactionState.TRANSPORT_LAUNCH_INTENT,
        IOSPeerTransactionState.TRANSPORT_LAUNCHED,
        IOSPeerTransactionState.RESULT_RECEIVED,
        IOSPeerTransactionState.TERMINATE_INTENT,
        IOSPeerTransactionState.TERMINATED,
    }
    if session_copied and not primer_stopped:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid",
            "session copy precedes stopped-primer proof",
        )
    if state in session_required_states and not session_copied:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal state lacks session-copy receipt"
        )
    if session_copied and state not in session_required_states | cleanup_states:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal records session copy prematurely"
        )

    transport_required_states = {
        IOSPeerTransactionState.TRANSPORT_LAUNCHED,
        IOSPeerTransactionState.RESULT_RECEIVED,
        IOSPeerTransactionState.TERMINATE_INTENT,
        IOSPeerTransactionState.TERMINATED,
    }
    if transport_complete and not session_copied:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "transport launch precedes session copy"
        )
    if state in transport_required_states and not transport_complete:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal lacks transport process ownership"
        )
    if transport_complete and state not in transport_required_states | cleanup_states:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal records transport launch prematurely"
        )

    result_present = evidence.result_receipt_sha256 is not None
    result_allowed_states = {
        IOSPeerTransactionState.RESULT_RECEIVED,
        IOSPeerTransactionState.TERMINATE_INTENT,
        IOSPeerTransactionState.TERMINATED,
    }
    if result_present and not transport_complete:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "result receipt lacks transport ownership"
        )
    if state is IOSPeerTransactionState.RESULT_RECEIVED and not result_present:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "result-received state lacks its receipt"
        )
    if result_present and state not in result_allowed_states | cleanup_states:
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal records result receipt prematurely"
        )

    cleanup_inventory = evidence.cleanup_process_inventory_sha256 is not None
    transport_terminated = evidence.terminate_receipt_sha256 is not None
    if (cleanup_inventory and not transport_complete) or (
        transport_terminated and not cleanup_inventory
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "transport cleanup evidence is out of order"
        )
    if state is IOSPeerTransactionState.TERMINATE_INTENT and (
        not cleanup_inventory or transport_terminated
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "terminate intent lacks fresh inventory"
        )
    if state is IOSPeerTransactionState.TERMINATED and (
        not cleanup_inventory or not transport_terminated
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "terminated state lacks strict receipts"
        )
    if state not in {
        IOSPeerTransactionState.TERMINATE_INTENT,
        IOSPeerTransactionState.TERMINATED,
    } | cleanup_states and (cleanup_inventory or transport_terminated):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal records transport cleanup prematurely"
        )

    if (
        state
        in {
            IOSPeerTransactionState.UNINSTALLED,
            IOSPeerTransactionState.ABSENCE_VERIFIED,
            IOSPeerTransactionState.COMPLETE,
        }
        and evidence.uninstall_receipt_sha256 is None
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "uninstalled state lacks its receipt"
        )
    if (
        state
        not in {
            IOSPeerTransactionState.UNINSTALLED,
            IOSPeerTransactionState.ABSENCE_VERIFIED,
            IOSPeerTransactionState.COMPLETE,
        }
        and evidence.uninstall_receipt_sha256 is not None
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal records uninstall prematurely"
        )
    final_fields = (
        evidence.final_app_inventory_sha256,
        evidence.final_process_inventory_sha256,
        evidence.legacy_cfw_after_sha256,
    )
    final_required = state in {
        IOSPeerTransactionState.ABSENCE_VERIFIED,
        IOSPeerTransactionState.COMPLETE,
    }
    if final_required != all(item is not None for item in final_fields):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "final absence proof does not match state"
        )
    if not final_required and any(item is not None for item in final_fields):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "journal records final proof prematurely"
        )
    if final_required and (
        evidence.legacy_cfw_after_sha256 != evidence.legacy_cfw_before_sha256
    ):
        raise IOSPeerLabError(
            "ios_lab_journal_invalid", "legacy CFW before/after binding differs"
        )


def _immutable_evidence_fields(
    evidence: IOSPeerTransactionEvidence,
) -> tuple[object, ...]:
    return (
        evidence.transaction_id,
        evidence.core_device_identifier_sha256,
        evidence.provisioning_udid_sha256,
        evidence.device_admission_sha256,
        evidence.control_transport,
        evidence.authentication_type,
        evidence.tunnel_transport_protocol,
        evidence.app_tree_sha256,
        evidence.session_id,
        evidence.preflight_app_inventory_sha256,
        evidence.preflight_process_inventory_sha256,
        evidence.legacy_cfw_before_sha256,
    )


def _require_evidence_monotonic(
    previous: IOSPeerTransactionEvidence, current: IOSPeerTransactionEvidence
) -> None:
    for field in _EVIDENCE_FIELDS:
        old = getattr(previous, field)
        if old is not None and getattr(current, field) != old:
            raise IOSPeerLabError(
                "ios_lab_journal_invalid",
                f"journal evidence field {field} was removed or changed",
            )


class IOSPeerTransactionJournal:
    """Append-only, fsync-durable ownership journal guarded by nonblocking flock."""

    def __init__(
        self,
        root: Path,
        root_fd: int,
        lock_fd: int,
        journal_fd: int,
        snapshot: IOSPeerTransactionSnapshot,
    ) -> None:
        self.root = root
        self._root_fd: int | None = root_fd
        self._lock_fd: int | None = lock_fd
        self._journal_fd: int | None = journal_fd
        self._snapshot = snapshot

    @classmethod
    def create(
        cls,
        root: Path,
        inputs: IOSPeerTransactionInputs,
        *,
        recorded_at: datetime,
    ) -> IOSPeerTransactionJournal:
        _require_private_directory(root, label="iOS lab transaction root")
        if type(inputs) is not IOSPeerTransactionInputs:
            raise IOSPeerLabError(
                "ios_lab_transaction_invalid", "journal creation inputs are invalid"
            )
        root_fd = -1
        lock_fd = -1
        journal_fd = -1
        try:
            if tuple(root.iterdir()):
                raise IOSPeerLabError(
                    "ios_lab_transaction_invalid",
                    "transaction root is not initially empty",
                )
            root_fd = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            lock_fd = os.open(
                LOCK_FILE,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_fd,
            )
            os.fsync(lock_fd)
            os.mkdir(JOURNAL_DIRECTORY, 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
            cls._acquire_lock(lock_fd)
            journal_fd = os.open(
                JOURNAL_DIRECTORY,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
        except (IOSPeerLabError, OSError) as error:
            for descriptor in (journal_fd, lock_fd, root_fd):
                if descriptor >= 0:
                    os.close(descriptor)
            if isinstance(error, IOSPeerLabError):
                raise
            raise IOSPeerLabError(
                "ios_lab_journal_io", "cannot initialize the lab journal"
            ) from error
        evidence = IOSPeerTransactionEvidence(
            transaction_id=inputs.transaction_id,
            core_device_identifier_sha256=inputs.device.core_device_identifier_sha256,
            provisioning_udid_sha256=inputs.device.provisioning_udid_sha256,
            device_admission_sha256=inputs.device_admission.receipt_sha256,
            control_transport=inputs.device_admission.control_transport,
            authentication_type=inputs.device_admission.authentication_type,
            tunnel_transport_protocol=(
                inputs.device_admission.tunnel_transport_protocol
            ),
            app_tree_sha256=inputs.artifact.app_tree_sha256,
            session_id=inputs.session_id,
            preflight_app_inventory_sha256=inputs.preflight.app_inventory_receipt_sha256,
            preflight_process_inventory_sha256=inputs.preflight.process_inventory_receipt_sha256,
            legacy_cfw_before_sha256=inputs.legacy_cfw_before_sha256,
        )
        empty = IOSPeerTransactionSnapshot(
            state=IOSPeerTransactionState.PREPARED,
            sequence=0,
            last_event_sha256="0" * 64,
            recorded_at="1970-01-01T00:00:00.000000Z",
            evidence=evidence,
        )
        journal = cls(root, root_fd, lock_fd, journal_fd, empty)
        try:
            journal._append(IOSPeerTransactionState.PREPARED, evidence, recorded_at)
        except BaseException:
            journal.close()
            raise
        return journal

    @classmethod
    def open(cls, root: Path) -> IOSPeerTransactionJournal:
        _require_private_directory(root, label="iOS lab transaction root")
        root_fd = -1
        lock_fd = -1
        journal_fd = -1
        try:
            if {path.name for path in root.iterdir()} != {LOCK_FILE, JOURNAL_DIRECTORY}:
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "transaction root entries differ"
                )
            root_fd = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            lock_fd = os.open(
                LOCK_FILE,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            lock_metadata = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_nlink != 1
                or lock_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(lock_metadata.st_mode) != 0o600
            ):
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "transaction lock metadata differs"
                )
            cls._acquire_lock(lock_fd)
            journal_fd = os.open(
                JOURNAL_DIRECTORY,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            journal_metadata = os.fstat(journal_fd)
            if (
                not stat.S_ISDIR(journal_metadata.st_mode)
                or journal_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(journal_metadata.st_mode) != 0o700
            ):
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal directory metadata differs"
                )
        except (IOSPeerLabError, OSError) as error:
            for descriptor in (journal_fd, lock_fd, root_fd):
                if descriptor >= 0:
                    os.close(descriptor)
            if isinstance(error, IOSPeerLabError):
                raise
            raise IOSPeerLabError(
                "ios_lab_journal_io", "cannot open the lab journal"
            ) from error
        journal = cls.__new__(cls)
        journal.root = root
        journal._root_fd = root_fd
        journal._lock_fd = lock_fd
        journal._journal_fd = journal_fd
        try:
            journal._snapshot = journal._replay()
        except BaseException:
            journal.close()
            raise
        return journal

    @staticmethod
    def _acquire_lock(descriptor: int) -> None:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise IOSPeerLabError(
                "ios_lab_transaction_locked", "iOS lab transaction is already locked"
            ) from error
        except OSError as error:
            raise IOSPeerLabError(
                "ios_lab_journal_io", "cannot acquire the iOS lab transaction lock"
            ) from error

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._journal_fd is not None:
            os.close(self._journal_fd)
            self._journal_fd = None
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def _require_open(self) -> int:
        if self._journal_fd is None:
            raise IOSPeerLabError("ios_lab_transaction_closed", "journal is closed")
        return self._journal_fd

    @property
    def snapshot(self) -> IOSPeerTransactionSnapshot:
        self._require_open()
        return self._snapshot

    def _event_bytes(
        self,
        next_state: IOSPeerTransactionState,
        evidence: IOSPeerTransactionEvidence,
        recorded_at: datetime,
    ) -> bytes:
        previous = self._snapshot
        from_state = None if previous.sequence == 0 else previous.state.value
        value = {
            "document": JOURNAL_DOCUMENT,
            "event": next_state.value,
            "evidence": asdict(evidence),
            "from_state": from_state,
            "previous_event_sha256": previous.last_event_sha256,
            "recorded_at": _canonical_timestamp(recorded_at),
            "schema_version": LAB_SCHEMA_VERSION,
            "sequence": previous.sequence + 1,
            "to_state": next_state.value,
        }
        return canonical_json(value) + b"\n"

    def _append(
        self,
        next_state: IOSPeerTransactionState,
        evidence: IOSPeerTransactionEvidence,
        recorded_at: datetime,
    ) -> None:
        journal_fd = self._require_open()
        current_state = None if self._snapshot.sequence == 0 else self._snapshot.state
        if next_state not in _TRANSITIONS[current_state]:
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                f"cannot transition from {current_state} to {next_state.value}",
            )
        if self._snapshot.sequence and (
            _immutable_evidence_fields(evidence)
            != _immutable_evidence_fields(self._snapshot.evidence)
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid", "immutable transaction bindings changed"
            )
        if self._snapshot.sequence:
            _require_evidence_monotonic(self._snapshot.evidence, evidence)
        _validate_state_evidence(next_state, evidence)
        data = self._event_bytes(next_state, evidence, recorded_at)
        if len(data) > MAX_JOURNAL_EVENT_BYTES:
            raise IOSPeerLabError(
                "ios_lab_journal_invalid", "journal event exceeds its bound"
            )
        sequence = self._snapshot.sequence + 1
        final_name = f"{sequence:08d}.json"
        pending_name = f".{sequence:08d}.json.pending"
        descriptor = -1
        try:
            descriptor = os.open(
                pending_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=journal_fd,
            )
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise OSError("short journal write")
                offset += written
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != len(data)
            ):
                raise OSError("journal pending metadata differs")
            os.close(descriptor)
            descriptor = -1
            try:
                os.stat(final_name, dir_fd=journal_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal final event already exists"
                )
            os.rename(
                pending_name,
                final_name,
                src_dir_fd=journal_fd,
                dst_dir_fd=journal_fd,
            )
            os.fsync(journal_fd)
        except IOSPeerLabError:
            raise
        except OSError as error:
            raise IOSPeerLabError(
                "ios_lab_journal_io", "cannot durably append the journal event"
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        timestamp = _canonical_timestamp(recorded_at)
        self._snapshot = IOSPeerTransactionSnapshot(
            state=next_state,
            sequence=sequence,
            last_event_sha256=_sha256(data),
            recorded_at=timestamp,
            evidence=evidence,
        )

    def _read_event(self, name: str) -> bytes:
        journal_fd = self._require_open()
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=journal_fd,
            )
        except OSError as error:
            raise IOSPeerLabError(
                "ios_lab_journal_invalid", "journal event is unavailable"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or not 1 <= metadata.st_size <= MAX_JOURNAL_EVENT_BYTES
            ):
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal event metadata differs"
                )
            data = os.read(descriptor, metadata.st_size + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if len(data) != metadata.st_size or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise IOSPeerLabError(
                "ios_lab_journal_invalid", "journal event changed while read"
            )
        return data

    def _replay(self) -> IOSPeerTransactionSnapshot:
        journal_fd = self._require_open()
        try:
            names = os.listdir(journal_fd)
        except OSError as error:
            raise IOSPeerLabError(
                "ios_lab_journal_io", "cannot list the journal directory"
            ) from error
        if not names or len(names) > MAX_JOURNAL_EVENTS:
            raise IOSPeerLabError(
                "ios_lab_journal_invalid", "journal event count is invalid"
            )
        if any(not re.fullmatch(r"[0-9]{8}\.json", name) for name in names):
            raise IOSPeerLabError(
                "ios_lab_journal_invalid",
                "journal contains a pending or unreviewed entry",
            )
        snapshot: IOSPeerTransactionSnapshot | None = None
        for expected_sequence, name in enumerate(sorted(names), start=1):
            if name != f"{expected_sequence:08d}.json":
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal sequence is not contiguous"
                )
            data = self._read_event(name)
            try:
                value = load_json_bytes(data, "iOS lab journal event")
            except (TypeError, ValueError) as error:
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal event is not strict JSON"
                ) from error
            event = _exact_object(value, _EVENT_FIELDS, "journal event")
            if canonical_json(event) + b"\n" != data:
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal event is not canonical JSON"
                )
            try:
                state = IOSPeerTransactionState(event["to_state"])
            except (TypeError, ValueError) as error:
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal state is unknown"
                ) from error
            previous_state = None if snapshot is None else snapshot.state
            previous_digest = (
                "0" * 64 if snapshot is None else snapshot.last_event_sha256
            )
            previous_timestamp = None if snapshot is None else snapshot.recorded_at
            if (
                type(event["schema_version"]) is not int
                or event["schema_version"] != LAB_SCHEMA_VERSION
                or event["document"] != JOURNAL_DOCUMENT
                or type(event["sequence"]) is not int
                or event["sequence"] != expected_sequence
                or event["event"] != state.value
                or event["from_state"]
                != (None if previous_state is None else previous_state.value)
                or state not in _TRANSITIONS[previous_state]
                or event["previous_event_sha256"] != previous_digest
            ):
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal header or transition differs"
                )
            recorded_at = _parse_timestamp(event["recorded_at"], "journal event time")
            if previous_timestamp is not None and recorded_at < _parse_timestamp(
                previous_timestamp, "previous journal event time"
            ):
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal time moves backwards"
                )
            evidence = _validate_evidence(event["evidence"])
            _validate_state_evidence(state, evidence)
            if snapshot is not None and (
                _immutable_evidence_fields(evidence)
                != _immutable_evidence_fields(snapshot.evidence)
            ):
                raise IOSPeerLabError(
                    "ios_lab_journal_invalid", "journal immutable bindings changed"
                )
            if snapshot is not None:
                _require_evidence_monotonic(snapshot.evidence, evidence)
            snapshot = IOSPeerTransactionSnapshot(
                state=state,
                sequence=expected_sequence,
                last_event_sha256=_sha256(data),
                recorded_at=event["recorded_at"],
                evidence=evidence,
            )
        if snapshot is None:
            raise IOSPeerLabError("ios_lab_journal_invalid", "journal is empty")
        return snapshot

    def record_install_intent(self, *, recorded_at: datetime) -> None:
        self._append(
            IOSPeerTransactionState.INSTALL_INTENT,
            self.snapshot.evidence,
            recorded_at,
        )

    def record_installed(
        self,
        ownership: IOSPeerInstallationOwnership,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(ownership) is not IOSPeerInstallationOwnership
            or ownership.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or ownership.app_tree_sha256 != evidence.app_tree_sha256
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "install ownership does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.INSTALLED,
            replace(
                evidence,
                install_receipt_sha256=ownership.install_receipt_sha256,
                post_install_app_inventory_sha256=ownership.app_inventory_receipt_sha256,
                launch_services_identifier=ownership.launch_services_identifier,
            ),
            recorded_at,
        )

    def record_cleanup_only_uninstall_intent(
        self,
        ownership: IOSPeerCleanupOnlyInstallationOwnership,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(ownership) is not IOSPeerCleanupOnlyInstallationOwnership
            or self.snapshot.state is not IOSPeerTransactionState.INSTALL_INTENT
            or ownership.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or ownership.app_tree_sha256 != evidence.app_tree_sha256
            or ownership.preflight_app_inventory_receipt_sha256
            != evidence.preflight_app_inventory_sha256
            or ownership.install_intent_event_sha256 != self.snapshot.last_event_sha256
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "cleanup-only uninstall authority does not bind this install intent",
            )
        self._append(
            IOSPeerTransactionState.UNINSTALL_INTENT,
            replace(
                evidence,
                cleanup_only_install_intent_sha256=ownership.install_intent_event_sha256,
                cleanup_only_app_inventory_sha256=ownership.post_intent_app_inventory_receipt_sha256,
                cleanup_only_installation_path=ownership.installation_path,
            ),
            recorded_at,
        )

    def record_primer_launch_intent(self, *, recorded_at: datetime) -> None:
        self._append(
            IOSPeerTransactionState.PRIMER_LAUNCH_INTENT,
            self.snapshot.evidence,
            recorded_at,
        )

    def record_primer_retry_authorized(
        self,
        authority: PrimerRetryAuthorization,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(authority) is not PrimerRetryAuthorization
            or authority.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or authority.app_tree_sha256 != evidence.app_tree_sha256
            or authority.launch_services_identifier
            != evidence.launch_services_identifier
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "primer retry authority does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.PRIMER_RETRY_AUTHORIZED,
            replace(
                evidence,
                primer_first_launch_receipt_sha256=(
                    authority.first_launch_receipt_sha256
                ),
                primer_first_process_inventory_sha256=(
                    authority.first_process_inventory_receipt_sha256
                ),
                primer_first_process_id=authority.first_process_id,
                primer_first_executable_path=authority.executable_path,
            ),
            recorded_at,
        )

    def record_primer_retry_launch_intent(
        self,
        authority: PrimerRetryAuthorization,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(authority) is not PrimerRetryAuthorization
            or authority.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or authority.app_tree_sha256 != evidence.app_tree_sha256
            or authority.launch_services_identifier
            != evidence.launch_services_identifier
            or authority.first_launch_receipt_sha256
            != evidence.primer_first_launch_receipt_sha256
            or authority.first_process_inventory_receipt_sha256
            != evidence.primer_first_process_inventory_sha256
            or authority.first_process_id != evidence.primer_first_process_id
            or authority.executable_path != evidence.primer_first_executable_path
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "primer retry launch lacks the durable one-shot authority",
            )
        self._append(
            IOSPeerTransactionState.PRIMER_RETRY_LAUNCH_INTENT,
            evidence,
            recorded_at,
        )

    def record_primer_launched(
        self,
        ownership: IOSPeerPrimerProcessOwnership,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(ownership) is not IOSPeerPrimerProcessOwnership
            or ownership.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or ownership.app_tree_sha256 != evidence.app_tree_sha256
            or ownership.launch_services_identifier
            != evidence.launch_services_identifier
            or (
                evidence.primer_first_launch_receipt_sha256 is not None
                and ownership.launch_receipt_sha256
                == evidence.primer_first_launch_receipt_sha256
            )
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "primer process ownership does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.PRIMER_LAUNCHED,
            replace(
                evidence,
                primer_launch_receipt_sha256=ownership.launch_receipt_sha256,
                primer_process_inventory_sha256=(
                    ownership.process_inventory_receipt_sha256
                ),
                primer_receipt_sha256=ownership.primer_receipt_sha256,
                primer_process_id=ownership.process_id,
                primer_executable_path=ownership.executable_path,
            ),
            recorded_at,
        )

    def record_primer_terminate_intent(
        self,
        authority: IOSPeerPrimerProcessCleanupAuthority,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(authority) is not IOSPeerPrimerProcessCleanupAuthority
            or authority.process.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or authority.process.app_tree_sha256 != evidence.app_tree_sha256
            or authority.process.launch_services_identifier
            != evidence.launch_services_identifier
            or authority.process.process_id != evidence.primer_process_id
            or authority.process.executable_path != evidence.primer_executable_path
            or authority.process.primer_receipt_sha256 != evidence.primer_receipt_sha256
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "primer terminate authority does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.PRIMER_TERMINATE_INTENT,
            replace(
                evidence,
                primer_cleanup_process_inventory_sha256=(
                    authority.revalidated_process_inventory_receipt_sha256
                ),
            ),
            recorded_at,
        )

    def record_primer_terminated(
        self,
        observation: ProcessTerminationObservation,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(observation) is not ProcessTerminationObservation
            or device_identifier_sha256(observation.device_identifier)
            != evidence.core_device_identifier_sha256
            or observation.process_id != evidence.primer_process_id
            or observation.executable_path != evidence.primer_executable_path
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "primer termination observation does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.PRIMER_TERMINATED,
            replace(
                evidence,
                primer_terminate_receipt_sha256=observation.receipt_sha256,
            ),
            recorded_at,
        )

    def record_primer_stopped(
        self, ownership: PrimerStoppedOwnership, *, recorded_at: datetime
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(ownership) is not PrimerStoppedOwnership
            or ownership.process.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or ownership.process.app_tree_sha256 != evidence.app_tree_sha256
            or ownership.process.launch_services_identifier
            != evidence.launch_services_identifier
            or ownership.process.process_id != evidence.primer_process_id
            or ownership.process.executable_path != evidence.primer_executable_path
            or ownership.process.primer_receipt_sha256 != evidence.primer_receipt_sha256
            or ownership.terminate_receipt_sha256
            != evidence.primer_terminate_receipt_sha256
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "stopped-primer ownership does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.PRIMER_STOPPED,
            replace(
                evidence,
                primer_post_terminate_process_inventory_sha256=(
                    ownership.post_terminate_process_inventory_receipt_sha256
                ),
            ),
            recorded_at,
        )

    def record_session_copy_intent(
        self, ownership: PrimerStoppedOwnership, *, recorded_at: datetime
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(ownership) is not PrimerStoppedOwnership
            or ownership.process.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or ownership.process.app_tree_sha256 != evidence.app_tree_sha256
            or ownership.process.launch_services_identifier
            != evidence.launch_services_identifier
            or ownership.process.process_id != evidence.primer_process_id
            or ownership.terminate_receipt_sha256
            != evidence.primer_terminate_receipt_sha256
            or ownership.post_terminate_process_inventory_receipt_sha256
            != evidence.primer_post_terminate_process_inventory_sha256
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "session copy lacks stopped-primer ownership",
            )
        self._append(IOSPeerTransactionState.SESSION_COPY_INTENT, evidence, recorded_at)

    def record_session_copied(
        self, observation: SessionCopyObservation, *, recorded_at: datetime
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(observation) is not SessionCopyObservation
            or device_identifier_sha256(observation.device_identifier)
            != evidence.core_device_identifier_sha256
            or observation.session_id != evidence.session_id
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "session-copy observation does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.SESSION_COPIED,
            replace(
                evidence,
                session_copy_receipt_sha256=observation.receipt_sha256,
            ),
            recorded_at,
        )

    def record_transport_launch_intent(self, *, recorded_at: datetime) -> None:
        self._append(
            IOSPeerTransactionState.TRANSPORT_LAUNCH_INTENT,
            self.snapshot.evidence,
            recorded_at,
        )

    def record_transport_launched(
        self, ownership: IOSPeerProcessOwnership, *, recorded_at: datetime
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(ownership) is not IOSPeerProcessOwnership
            or ownership.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or ownership.app_tree_sha256 != evidence.app_tree_sha256
            or ownership.session_id != evidence.session_id
            or ownership.launch_services_identifier
            != evidence.launch_services_identifier
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "transport process ownership does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.TRANSPORT_LAUNCHED,
            replace(
                evidence,
                transport_launch_receipt_sha256=ownership.launch_receipt_sha256,
                transport_process_inventory_sha256=(
                    ownership.process_inventory_receipt_sha256
                ),
                ready_receipt_sha256=ownership.ready_receipt_sha256,
                transport_process_id=ownership.process_id,
                transport_executable_path=ownership.executable_path,
            ),
            recorded_at,
        )

    def record_result_received(
        self, receipt_sha256: str, *, recorded_at: datetime
    ) -> None:
        self._append(
            IOSPeerTransactionState.RESULT_RECEIVED,
            replace(
                self.snapshot.evidence,
                result_receipt_sha256=_require_sha256(
                    receipt_sha256, "peer result receipt digest"
                ),
            ),
            recorded_at,
        )

    def record_terminate_intent(
        self,
        authority: IOSPeerProcessCleanupAuthority,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(authority) is not IOSPeerProcessCleanupAuthority
            or authority.process.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or authority.process.app_tree_sha256 != evidence.app_tree_sha256
            or authority.process.session_id != evidence.session_id
            or authority.process.launch_services_identifier
            != evidence.launch_services_identifier
            or authority.process.process_id != evidence.transport_process_id
            or authority.process.executable_path != evidence.transport_executable_path
            or authority.process.ready_receipt_sha256 != evidence.ready_receipt_sha256
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "terminate authority does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.TERMINATE_INTENT,
            replace(
                evidence,
                cleanup_process_inventory_sha256=authority.revalidated_process_inventory_receipt_sha256,
            ),
            recorded_at,
        )

    def record_terminated(
        self,
        observation: ProcessTerminationObservation,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(observation) is not ProcessTerminationObservation
            or device_identifier_sha256(observation.device_identifier)
            != evidence.core_device_identifier_sha256
            or observation.process_id != evidence.transport_process_id
            or observation.executable_path != evidence.transport_executable_path
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "transport termination observation does not bind this journal",
            )
        self._append(
            IOSPeerTransactionState.TERMINATED,
            replace(
                evidence,
                terminate_receipt_sha256=observation.receipt_sha256,
            ),
            recorded_at,
        )

    def record_uninstall_intent(
        self,
        ownership: IOSPeerInstallationOwnership,
        *,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if (
            type(ownership) is not IOSPeerInstallationOwnership
            or ownership.device_identifier_sha256
            != evidence.core_device_identifier_sha256
            or ownership.app_tree_sha256 != evidence.app_tree_sha256
            or ownership.install_receipt_sha256 != evidence.install_receipt_sha256
            or ownership.app_inventory_receipt_sha256
            != evidence.post_install_app_inventory_sha256
            or ownership.launch_services_identifier
            != evidence.launch_services_identifier
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid",
                "uninstall ownership does not bind this journal",
            )
        self._append(IOSPeerTransactionState.UNINSTALL_INTENT, evidence, recorded_at)

    def record_uninstalled(
        self, observation: UninstallObservation, *, recorded_at: datetime
    ) -> None:
        if (
            type(observation) is not UninstallObservation
            or observation.bundle_identifier != BUNDLE_IDENTIFIER
            or device_identifier_sha256(observation.device_identifier)
            != self.snapshot.evidence.core_device_identifier_sha256
        ):
            raise IOSPeerLabError(
                "ios_lab_transition_invalid", "uninstall observation type is invalid"
            )
        self._append(
            IOSPeerTransactionState.UNINSTALLED,
            replace(
                self.snapshot.evidence,
                uninstall_receipt_sha256=observation.receipt_sha256,
            ),
            recorded_at,
        )

    def record_absence_verified(
        self,
        *,
        app_inventory_sha256: str,
        process_inventory_sha256: str,
        legacy_cfw_after_sha256: str,
        recorded_at: datetime,
    ) -> None:
        evidence = self.snapshot.evidence
        if legacy_cfw_after_sha256 != evidence.legacy_cfw_before_sha256:
            raise IOSPeerLabError(
                "ios_lab_cfw_guard_drift", "legacy CFW before/after binding differs"
            )
        self._append(
            IOSPeerTransactionState.ABSENCE_VERIFIED,
            replace(
                evidence,
                final_app_inventory_sha256=_require_sha256(
                    app_inventory_sha256, "final app inventory digest"
                ),
                final_process_inventory_sha256=_require_sha256(
                    process_inventory_sha256, "final process inventory digest"
                ),
                legacy_cfw_after_sha256=_require_sha256(
                    legacy_cfw_after_sha256, "legacy CFW after-snapshot digest"
                ),
            ),
            recorded_at,
        )

    def complete(self, *, recorded_at: datetime) -> None:
        self._append(
            IOSPeerTransactionState.COMPLETE, self.snapshot.evidence, recorded_at
        )


__all__ = [
    "AppInventory",
    "AppInventoryEntry",
    "DeviceAdmission",
    "DeviceProcess",
    "DevicectlRuntime",
    "IOSPeerLabError",
    "IOSPeerProvisioningProfile",
    "IOSPeerPacketLanSessionMaterial",
    "IOSPeerSessionMaterial",
    "IOSPeerSigningCommandPlan",
    "IOSPeerSigningInputs",
    "IOSPeerTransactionInputs",
    "IOSPeerTransactionJournal",
    "IOSPeerTransactionSnapshot",
    "IOSPeerTransactionState",
    "LegacyCFWExpectedState",
    "LegacyCFWGuardPlan",
    "LegacyCFWGuardSnapshot",
    "LegacyPortOwner",
    "LegacyProcessIdentity",
    "LegacyProxyConfiguration",
    "LegacyRoute",
    "ManualSigningAuthorization",
    "PacketLanLaunchObservation",
    "PacketLanSessionCopyObservation",
    "PrimerLaunchObservation",
    "PrimerRetryAuthorization",
    "ProcessInventory",
    "ProcessTerminationObservation",
    "SessionCopyObservation",
    "TransportLaunchObservation",
    "TransportPairVerification",
    "UninstallObservation",
    "VerifiedCopiedReceipt",
    "authorize_cleanup_only_installation",
    "authorize_cleanup_only_installation_from_preflight",
    "authorize_exceptional_process_cleanup",
    "authorize_packet_lan_process_cleanup",
    "authorize_primer_process_cleanup",
    "authorize_single_primer_retry",
    "bind_primer_process",
    "bind_packet_lan_process",
    "bind_stopped_primer",
    "bind_transport_process",
    "build_legacy_cfw_guard_snapshot",
    "build_preflight",
    "inspect_ios_peer_artifact",
    "minimal_entitlements_plist",
    "parse_app_inventory",
    "parse_decoded_provisioning_profile",
    "parse_device_admission",
    "parse_devicectl_envelope",
    "parse_install_receipt",
    "parse_legacy_port_owner",
    "parse_legacy_process_inventory",
    "parse_legacy_proxy_configuration",
    "parse_lock_state",
    "parse_packet_lan_launch_receipt",
    "parse_packet_lan_session_copy_receipt",
    "parse_packet_lan_terminate_receipt",
    "parse_primer_launch_receipt",
    "parse_primer_terminate_receipt",
    "parse_process_inventory",
    "parse_route_to_peer",
    "parse_session_copy_receipt",
    "parse_transport_launch_receipt",
    "parse_transport_terminate_receipt",
    "parse_uninstall_receipt",
    "validate_codesign_details",
    "validate_copied_receipt",
    "validate_embedded_profile",
    "validate_executable_architectures",
    "validate_executable_build_version",
    "validate_keychain_certificate_pem",
    "validate_profile_source_unchanged",
    "validate_packet_lan_session_material",
    "validate_session_material",
    "validate_signed_entitlements",
    "verify_legacy_cfw_unchanged",
    "verify_post_uninstall_absence",
    "verify_transport_pair",
]
