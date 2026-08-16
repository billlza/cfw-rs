"""Fail-closed admission for the controlled Android LAN packet peer.

The adapter owns every ADB argv vector.  Runtime callers supply only the
source-typed network identity that the independent Mac route projection has
already selected; no caller value is ever interpreted as a command or shell
fragment.  Sensitive device identifiers are reduced to domain-separated
SHA-256 leaves before a document can leave this module.

The peer artifact is verified twice from host bytes: once before ``adb push``
and once after a quiet, uncompressed ``adb pull`` into an exclusive private
directory.  Device-side digest tools are deliberately outside the trust
boundary.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
import threading
import time
from typing import Callable, Final, Protocol, Sequence

from .execution import (
    CommandResult,
    CommandSpec,
    command_sha256,
)


REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[2]
ADB: Final = Path("/Users/bill/Library/Android/sdk/platform-tools/adb")
ADB_VERSION: Final = "37.0.0-14910828"
ADB_SHA256: Final = "5759ea07285e5a5b66d84f489c118a3fa3998e69cd37725e5a3dc7cbe0597278"

LOCAL_ARTIFACT: Final = REPOSITORY_ROOT / "target/packet-lan-peer-linux-arm64"
REMOTE_DIRECTORY: Final = "/data/local/tmp/cfw-release-evidence-v040"
REMOTE_ARTIFACT: Final = f"{REMOTE_DIRECTORY}/packet-lan-peer-linux-arm64"
ARTIFACT_SHA256: Final = "873df1f69324c1310af9c6115802e46426da70f38fe893ebf3054632764e8b17"
ARTIFACT_SIZE: Final = 2_359_422
SHELL_UID: Final = 2000
SHELL_GID: Final = 2000
DIRECTORY_MODE: Final = 0o700
BINARY_MODE: Final = 0o500

LISTENER_ADDRESS: Final = "0.0.0.0"
LISTENER_PORT: Final = 44_333
LISTENER_PORT_HEX: Final = f"{LISTENER_PORT:04X}"
PROCESS_NAME: Final = "packet-lan-peer"
PROCESS_LOOKUP_NAME: Final = "packet-lan-peer-linux-arm64"

IDENTITY_DOCUMENT: Final = "cfw-android-lan-peer-identity-v1"
ADMISSION_DOCUMENT: Final = "cfw-android-lan-peer-admission-v1"
DISCOVERY_DOCUMENT: Final = "cfw-android-lan-peer-discovery-v1"
PROCESS_DOCUMENT: Final = "cfw-android-lan-peer-process-v1"
DEPLOYMENT_DOCUMENT: Final = "cfw-android-lan-peer-deployment-v1"
SCHEMA_VERSION: Final = 1

SERIAL_DOMAIN: Final = b"cfw-android-adb-serial-v1\0"
FINGERPRINT_DOMAIN: Final = b"cfw-android-build-fingerprint-v1\0"
BOOT_ID_DOMAIN: Final = b"cfw-android-boot-id-v1\0"

COMMAND_TIMEOUT_SECONDS: Final = 15.0
TRANSFER_TIMEOUT_SECONDS: Final = 120.0
PROCESS_TIMEOUT_SECONDS: Final = 600.0
PROCESS_READY_SECONDS: Final = 5.0
PROCESS_STOP_SECONDS: Final = 5.0
POLL_INTERVAL_SECONDS: Final = 0.05
SMALL_OUTPUT_LIMIT: Final = 64 * 1024
TRANSFER_OUTPUT_LIMIT: Final = 16 * 1024
MAX_LOCAL_FILE_BYTES: Final = 32 * 1024 * 1024
ADB_SERVER_STATUS_OUTPUT_LIMIT: Final = 16 * 1024
ADB_SERVER_START_TIMEOUT_SECONDS: Final = 15.0
ADB_SERVER_STOP_TIMEOUT_SECONDS: Final = 15.0

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SERIAL_RE = re.compile(rb"^[A-Za-z0-9._:-]{1,128}$")
_FINGERPRINT_RE = re.compile(rb"^[!-~]{1,512}$")
_BOOT_ID_RE = re.compile(
    rb"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
_INVENTORY_TOKEN_RE = re.compile(r"^([A-Za-z0-9_]+):([^\s:]+)$")
_PID_RE = re.compile(rb"^[1-9][0-9]{0,9}$")
_FD_SOCKET_RE = re.compile(r"(?:^|\s)([0-9]+) -> socket:\[([1-9][0-9]*)\]$")
_ROLE_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_REMOTE_EXECUTABLES: Final = frozenset(
    {
        "/system/bin/cat",
        "/system/bin/chmod",
        "/system/bin/getprop",
        "/system/bin/ip",
        "/system/bin/ls",
        "/system/bin/mkdir",
        "/system/bin/pidof",
        "/system/bin/readlink",
        "/system/bin/rm",
        "/system/bin/rmdir",
        "/system/bin/stat",
        "/system/bin/test",
    }
)
_REMOTE_ROLE_STAGE_SUFFIXES: Final = (
    "-post-deploy",
    "-post-start",
    "-before-capture",
    "-after-capture",
    "-cleanup-before-delete",
    "-cleanup-after-delete",
    "-before",
    "-after",
    "-before-deploy",
)
_REMOTE_ROLE_EXECUTABLES: Final = {
    "android-build-fingerprint": "/system/bin/getprop",
    "android-boot-id": "/system/bin/cat",
    "android-verified-boot": "/system/bin/getprop",
    "android-vbmeta-state": "/system/bin/getprop",
    "android-flash-lock": "/system/bin/getprop",
    "android-primary-abi": "/system/bin/getprop",
    "android-network-addresses": "/system/bin/ip",
    "android-peer-pid": "/system/bin/pidof",
    "android-peer-directory-create": "/system/bin/mkdir",
    "android-peer-directory-mode": "/system/bin/chmod",
    "android-peer-directory-stat": "/system/bin/stat",
    "android-peer-binary-mode": "/system/bin/chmod",
    "android-peer-binary-stat": "/system/bin/stat",
    "android-peer-process": REMOTE_ARTIFACT,
    "android-peer-process-stat": "/system/bin/cat",
    "android-peer-process-exe": "/system/bin/readlink",
    "android-peer-process-status": "/system/bin/cat",
    "android-peer-process-cmdline": "/system/bin/cat",
    "android-peer-process-descriptors": "/system/bin/ls",
    "android-peer-process-tcp": "/system/bin/cat",
    "android-peer-binary-stat-cleanup": "/system/bin/stat",
    "android-peer-binary-cleanup": "/system/bin/rm",
    "android-peer-directory-stat-cleanup": "/system/bin/stat",
    "android-peer-directory-cleanup": "/system/bin/rmdir",
    "android-peer-original-pid-absence": "/system/bin/test",
}

_ADMISSION_LOCK: Final = threading.Lock()

_IDENTITY_FIELDS: Final = {
    "schema_version",
    "document",
    "role",
    "platform",
    "transport",
    "listener_address",
    "listener_port",
    "serial_sha256",
    "build_fingerprint_sha256",
    "boot_id_sha256",
    "verified_boot_state",
    "vbmeta_device_state",
    "flash_locked",
    "abi",
    "network_interface_name",
    "ipv4",
    "deployment",
    "process_uid",
    "process_gid",
}
_DEPLOYMENT_IDENTITY_FIELDS: Final = {
    "directory_path",
    "directory_uid",
    "directory_gid",
    "directory_mode",
    "binary_path",
    "binary_sha256",
    "binary_size",
    "binary_uid",
    "binary_gid",
    "binary_mode",
}


class AndroidLanPeerAdmissionError(RuntimeError):
    """The Android peer could not be admitted without ambiguity."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.cleanup_code: str | None = None

    def attach_cleanup_context(self, error: BaseException) -> None:
        self.cleanup_code = (
            error.code
            if isinstance(error, AndroidLanPeerAdmissionError)
            else "android_peer_cleanup_unexpected"
        )
        self.add_note(
            "Android LAN peer cleanup also failed "
            f"[{self.cleanup_code}]: {type(error).__name__}"
        )


class StartedPeerCommand(Protocol):
    def cancel(self) -> None: ...


class AndroidLanPeerRunner(Protocol):
    """The existing collection command boundary required by this adapter."""

    def run_command(self, spec: CommandSpec) -> CommandResult: ...

    def start_command(self, spec: CommandSpec) -> StartedPeerCommand: ...


@dataclass(frozen=True, slots=True)
class AndroidLanNetworkExpectation:
    """Network identity selected by the independently verified Mac projection."""

    interface_name: str
    ipv4: str

    def __post_init__(self) -> None:
        _validate_network_identity(self.interface_name, self.ipv4)


@dataclass(frozen=True, slots=True)
class _FileMetadata:
    device_id: int
    inode: int
    link_count: int
    mode: int
    uid: int
    gid: int
    size: int


@dataclass(frozen=True, slots=True)
class _ProcessStat:
    pid: int
    name: str
    state: str
    parent_pid: int
    start_time_ticks: int


@dataclass(frozen=True, slots=True)
class _ProcessStatus:
    name: str
    state: str
    uid: int
    gid: int
    thread_count: int


@dataclass(slots=True)
class _AdbServerLease:
    """Private ADB server endpoint owned by one admission transaction."""

    root: Path
    socket: Path
    adb_path: Path
    environment: tuple[tuple[str, str], ...] = ()
    status: dict[str, object] | None = None

    def __post_init__(self) -> None:
        if (
            self.root.is_symlink()
            or not self.root.is_dir()
            or self.socket.parent != self.root
            or self.adb_path.parent != self.root
            or not self.root.is_absolute()
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_workspace_invalid",
                "ADB server workspace is not a private absolute directory",
            )
        if not self.environment:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_workspace_invalid",
                "ADB server environment is not privately bound",
            )

    @property
    def socket_argument(self) -> str:
        return f"localfilesystem:{self.socket}"


@dataclass(frozen=True, slots=True)
class _SocketObservation:
    descriptor: int
    inode: int


@dataclass(frozen=True, slots=True)
class _DeviceSelector:
    serial: bytes
    transport_id: int
    server_socket: str = ""
    adb_path: str = ""
    environment: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.serial) is not bytes
            or _SERIAL_RE.fullmatch(self.serial) is None
            or type(self.transport_id) is not int
            or not 1 <= self.transport_id <= 2_147_483_647
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_device_inventory_invalid",
                "Android device selector is not a canonical positive transport identity",
            )
        if self.server_socket:
            socket = Path(self.server_socket)
            if (
                not socket.is_absolute()
                or socket.is_symlink()
                or "\x00" in self.server_socket
                or any(ord(character) < 0x20 for character in self.server_socket)
            ):
                raise AndroidLanPeerAdmissionError(
                    "android_peer_server_workspace_invalid",
                    "ADB server socket path is not canonical",
                )
        if self.adb_path:
            adb_path = Path(self.adb_path)
            if (
                not adb_path.is_absolute()
                or adb_path.is_symlink()
                or "\x00" in self.adb_path
                or any(ord(character) < 0x20 for character in self.adb_path)
            ):
                raise AndroidLanPeerAdmissionError(
                    "android_peer_server_workspace_invalid",
                    "ADB client path is not canonical",
                )
        if not isinstance(self.environment, tuple) or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
            for item in self.environment
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_workspace_invalid",
                "ADB command environment is not canonical",
            )


@dataclass(frozen=True, slots=True)
class _IdentitySnapshot:
    serial: bytes
    fingerprint: bytes
    boot_id: bytes
    verified_boot_state: bytes
    vbmeta_device_state: bytes
    flash_locked: bytes
    abi: bytes
    network_prefix_length: int


@dataclass(slots=True)
class _DeploymentOwnership:
    directory_create_attempted: bool = False
    directory_created: bool = False
    directory_metadata: _FileMetadata | None = None
    binary_push_attempted: bool = False
    binary_created: bool = False
    binary_metadata: _FileMetadata | None = None


@dataclass(frozen=True, slots=True)
class _RemotePathState:
    exists: bool
    symlink: bool

    @property
    def present(self) -> bool:
        return self.exists or self.symlink


def _fixed_spec(
    role: str,
    *arguments: str,
    timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
    accepted_exit_codes: frozenset[int] = frozenset({0}),
    stdout_limit: int = SMALL_OUTPUT_LIMIT,
    stderr_limit: int = SMALL_OUTPUT_LIMIT,
    selector: _DeviceSelector | None = None,
    inventory: bool = False,
    server_socket: str | None = None,
    adb_path: str | None = None,
    environment: tuple[tuple[str, str], ...] | None = None,
) -> CommandSpec:
    if inventory and selector is not None:
        raise AndroidLanPeerAdmissionError(
            "android_peer_source_contract_drift",
            "inventory and transport selectors cannot be combined",
        )
    if selector is not None:
        if server_socket is not None:
            raise AndroidLanPeerAdmissionError(
                "android_peer_source_contract_drift",
                "ADB selector command cannot override its private server socket",
            )
        server_socket = selector.server_socket
        adb_path = selector.adb_path or str(ADB)
        if environment is not None:
            raise AndroidLanPeerAdmissionError(
                "android_peer_source_contract_drift",
                "ADB selector command cannot override its private environment",
            )
        environment = selector.environment
    if adb_path is None:
        adb_path = str(ADB)
    if (
        not isinstance(adb_path, str)
        or not adb_path
        or not Path(adb_path).is_absolute()
        or Path(adb_path).is_symlink()
        or "\x00" in adb_path
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_workspace_invalid",
            "ADB client path is not canonical",
        )
    if not isinstance(server_socket, str) or not server_socket:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_unavailable",
            "ADB command is missing its private server socket",
        )
    socket_path = Path(server_socket)
    if (
        not socket_path.is_absolute()
        or socket_path.is_symlink()
        or "\x00" in server_socket
        or any(ord(character) < 0x20 for character in server_socket)
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_workspace_invalid",
            "ADB server socket path is not canonical",
        )
    if inventory:
        prefix = (adb_path, "-L", f"localfilesystem:{socket_path}", "-d")
    elif selector is not None:
        prefix = (
            adb_path,
            "-L",
            f"localfilesystem:{socket_path}",
            "-t",
            str(selector.transport_id),
        )
    else:
        prefix = (adb_path, "-L", f"localfilesystem:{socket_path}")
    return CommandSpec(
        role=role,
        argv=(*prefix, *arguments),
        cwd=REPOSITORY_ROOT,
        timeout_seconds=timeout_seconds,
        accepted_exit_codes=accepted_exit_codes,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
        environment=environment or (),
    )


def _remote_spec(
    role: str,
    selector: _DeviceSelector,
    executable: str,
    *arguments: str,
    timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
    accepted_exit_codes: frozenset[int] = frozenset({0}),
    stdout_limit: int = SMALL_OUTPUT_LIMIT,
) -> CommandSpec:
    if executable not in _REMOTE_EXECUTABLES and executable != REMOTE_ARTIFACT:
        raise AndroidLanPeerAdmissionError(
            "android_peer_source_contract_drift",
            "remote executable is outside the source-reviewed allowlist",
        )
    base_role = role
    stripped = True
    while stripped:
        stripped = False
        for suffix in _REMOTE_ROLE_STAGE_SUFFIXES:
            if base_role.endswith(suffix):
                base_role = base_role[: -len(suffix)]
                stripped = True
                break
    expected_executable = _REMOTE_ROLE_EXECUTABLES.get(base_role)
    if expected_executable is None and (
        base_role.startswith("android-peer-directory-")
        or base_role.startswith("android-peer-binary-")
    ):
        expected_executable = {
            "exists": "/system/bin/test",
            "symlink": "/system/bin/test",
        }.get(base_role.rsplit("-", 1)[-1])
    if expected_executable is None:
        raise AndroidLanPeerAdmissionError(
            "android_peer_source_contract_drift",
            f"remote role {role} has no fixed executable contract",
        )
    if executable != expected_executable:
        raise AndroidLanPeerAdmissionError(
            "android_peer_source_contract_drift",
            f"remote role {role} executable differs from its fixed contract",
        )
    return _fixed_spec(
        role,
        "exec-out",
        executable,
        *arguments,
        selector=selector,
        timeout_seconds=timeout_seconds,
        accepted_exit_codes=accepted_exit_codes,
        stdout_limit=stdout_limit,
    )


def _run(runner: AndroidLanPeerRunner, spec: CommandSpec) -> CommandResult:
    try:
        result = runner.run_command(spec)
    except Exception as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_command_failed",
            f"fixed Android peer command failed for role {spec.role}",
        ) from error
    if (
        type(result) is not CommandResult
        or result.role != spec.role
        or result.argv_sha256 != command_sha256(spec.argv)
        or type(result.exit_code) is not int
        or result.exit_code not in spec.accepted_exit_codes
        or type(result.duration_ms) is not int
        or result.duration_ms < 1
        or result.duration_ms > int(spec.timeout_seconds * 1000)
        or type(result.started_at) is not str
        or type(result.completed_at) is not str
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > spec.stdout_limit
        or len(result.stderr) > spec.stderr_limit
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_command_result_drift",
            f"fixed Android peer command result drifted for role {spec.role}",
        )
    started_at = _parse_command_timestamp(result.started_at, spec.role)
    completed_at = _parse_command_timestamp(result.completed_at, spec.role)
    if completed_at < started_at or (
        completed_at - started_at
    ).total_seconds() > spec.timeout_seconds:
        raise AndroidLanPeerAdmissionError(
            "android_peer_command_result_drift",
            f"fixed Android peer command time boundary drifted for role {spec.role}",
        )
    return result


def _parse_command_timestamp(value: str, role: str) -> datetime:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        raise AndroidLanPeerAdmissionError(
            "android_peer_command_result_drift",
            f"fixed Android peer command timestamp is not canonical for role {role}",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_command_result_drift",
            f"fixed Android peer command timestamp is invalid for role {role}",
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise AndroidLanPeerAdmissionError(
            "android_peer_command_result_drift",
            f"fixed Android peer command timestamp is not UTC for role {role}",
        )
    return parsed


def _command_receipt(result: CommandResult) -> dict[str, object]:
    return {
        "role": result.role,
        "argv_sha256": result.argv_sha256,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "duration_ms": result.duration_ms,
        "exit_code": result.exit_code,
    }


def _command_window(results: Sequence[CommandResult]) -> dict[str, object]:
    return _receipt_window([_command_receipt(result) for result in results])


def _receipt_window(receipts: Sequence[dict[str, object]]) -> dict[str, object]:
    if not receipts:
        raise AndroidLanPeerAdmissionError(
            "android_peer_command_result_drift", "Android command window is empty"
        )
    previous_completed: datetime | None = None
    expected_fields = {
        "role",
        "argv_sha256",
        "started_at",
        "completed_at",
        "duration_ms",
        "exit_code",
    }
    for receipt in receipts:
        if type(receipt) is not dict or set(receipt) != expected_fields:
            raise AndroidLanPeerAdmissionError(
                "android_peer_command_result_drift",
                "Android command receipt fields differ",
            )
        role = receipt["role"]
        if (
            type(role) is not str
            or _ROLE_RE.fullmatch(role) is None
            or type(receipt["argv_sha256"]) is not str
            or _SHA256_RE.fullmatch(receipt["argv_sha256"]) is None
            or type(receipt["duration_ms"]) is not int
            or receipt["duration_ms"] < 1
            or type(receipt["exit_code"]) is not int
            or not 0 <= receipt["exit_code"] <= 255
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_command_result_drift",
                "Android command receipt value types differ",
            )
        started = _parse_command_timestamp(receipt["started_at"], role)
        completed = _parse_command_timestamp(receipt["completed_at"], role)
        if completed < started or (
            previous_completed is not None and started < previous_completed
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_command_result_drift",
                "Android command receipt window overlaps or is not in call order",
            )
        previous_completed = completed
    return {
        "started_at": receipts[0]["started_at"],
        "completed_at": receipts[-1]["completed_at"],
        "commands": copy.deepcopy(list(receipts)),
    }


def _require_silent(result: CommandResult) -> None:
    if result.stdout != b"" or result.stderr != b"":
        raise AndroidLanPeerAdmissionError(
            "android_peer_command_output_unexpected",
            f"fixed Android peer command emitted unexpected output for role {result.role}",
        )


def _single_lf(value: bytes, label: str, *, maximum: int) -> bytes:
    if (
        type(value) is not bytes
        or not 2 <= len(value) <= maximum
        or value.count(b"\n") != 1
        or not value.endswith(b"\n")
        or b"\r" in value
        or b"\0" in value
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_output_invalid",
            f"{label} is not one bounded canonical LF-terminated line",
        )
    line = value[:-1]
    try:
        line.decode("ascii")
    except UnicodeDecodeError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_output_invalid", f"{label} is not canonical ASCII"
        ) from error
    return line


def _leaf_hash(domain: bytes, value: bytes) -> str:
    return hashlib.sha256(domain + value).hexdigest()


def _read_pinned_file(
    path: Path,
    *,
    expected_sha256: str,
    expected_size: int | None,
    expected_mode: int | None,
    executable: bool,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_host_file_unavailable",
            "a pinned Android peer host file is unavailable",
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or before.st_mode & 0o022
            or (expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode)
            or (executable and not before.st_mode & stat.S_IXUSR)
            or before.st_size < 1
            or before.st_size > MAX_LOCAL_FILE_BYTES
            or (expected_size is not None and before.st_size != expected_size)
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_host_file_unsafe",
                "a pinned Android peer host file has unsafe identity or metadata",
            )
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 128 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_LOCAL_FILE_BYTES:
                raise AndroidLanPeerAdmissionError(
                    "android_peer_host_file_unsafe",
                    "a pinned Android peer host file exceeds its byte bound",
                )
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_host_file_unavailable",
            "a pinned Android peer host file could not be read safely",
        ) from error
    finally:
        os.close(descriptor)
    if (
        total != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or not hmac.compare_digest(digest.hexdigest(), expected_sha256)
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_host_file_drift",
            "a pinned Android peer host file changed or differs from its digest",
        )
    return b"".join(chunks)


def _validate_host_inputs() -> bytes:
    _read_pinned_file(
        ADB,
        expected_sha256=ADB_SHA256,
        expected_size=None,
        expected_mode=None,
        executable=True,
    )
    return _read_pinned_file(
        LOCAL_ARTIFACT,
        expected_sha256=ARTIFACT_SHA256,
        expected_size=ARTIFACT_SIZE,
        expected_mode=0o555,
        executable=True,
    )


def _parse_adb_version(value: bytes, *, expected_path: str | None = None) -> None:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_adb_version_invalid", "ADB version output is not ASCII"
        ) from error
    if "\r" in text or "\0" in text or not text.endswith("\n"):
        raise AndroidLanPeerAdmissionError(
            "android_peer_adb_version_invalid", "ADB version output is not canonical"
        )
    lines = text[:-1].split("\n")
    expected = (
        "Android Debug Bridge version 1.0.41",
        f"Version {ADB_VERSION}",
        f"Installed as {expected_path or ADB}",
    )
    if (
        len(lines) != 4
        or tuple(lines[:3]) != expected
        or re.fullmatch(r"Running on Darwin [0-9]+(?:\.[0-9]+)* \(arm64\)", lines[3])
        is None
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_adb_version_invalid",
            "ADB runtime identity differs from the pinned binary contract",
        )


def _parse_device_inventory(value: bytes) -> _DeviceSelector:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid", "ADB device inventory is not ASCII"
        ) from error
    if "\r" in text or "\0" in text or not text.endswith("\n"):
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid",
            "ADB device inventory is not canonical LF text",
        )
    lines = text[:-1].split("\n")
    if not lines or lines[0] != "List of devices attached":
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid",
            "ADB device inventory header differs",
        )
    rows = lines[1:]
    if len(rows) == 2 and rows[1] == "":
        rows = rows[:1]
    if len(rows) != 1 or not rows[0]:
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid",
            "exactly one USB Android device must be present",
        )
    pieces = rows[0].split()
    if len(pieces) < 6:
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid",
            "the sole Android device inventory row is incomplete",
        )
    serial_text, state = pieces[0], pieces[1]
    try:
        serial = serial_text.encode("ascii")
    except UnicodeEncodeError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid", "device serial is not ASCII"
        ) from error
    if _SERIAL_RE.fullmatch(serial) is None or state != "device":
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid",
            "the sole USB Android device is not authorized",
        )
    metadata: dict[str, str] = {}
    for token in pieces[2:]:
        match = _INVENTORY_TOKEN_RE.fullmatch(token)
        if match is None or match.group(1) in metadata:
            raise AndroidLanPeerAdmissionError(
                "android_peer_device_inventory_invalid",
                "the sole Android device metadata is malformed or duplicated",
            )
        metadata[match.group(1)] = match.group(2)
    required = {"usb", "product", "model", "device", "transport_id"}
    if set(metadata) != required:
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid",
            "the sole Android device metadata differs from the fixed inventory schema",
        )
    transport_text = metadata["transport_id"]
    if (
        not transport_text.isascii()
        or not transport_text.isdecimal()
        or transport_text.startswith("0")
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid",
            "the sole Android transport identifier is not canonical",
        )
    transport_id = int(transport_text)
    return _DeviceSelector(serial=serial, transport_id=transport_id)


def _validate_network_identity(interface_name: str, ipv4: str) -> None:
    if type(interface_name) is not str or _INTERFACE_RE.fullmatch(interface_name) is None:
        raise AndroidLanPeerAdmissionError(
            "android_peer_network_identity_invalid",
            "Android LAN interface name is not canonical",
        )
    if type(ipv4) is not str:
        raise AndroidLanPeerAdmissionError(
            "android_peer_network_identity_invalid", "Android LAN address is not IPv4"
        )
    try:
        address = ipaddress.IPv4Address(ipv4)
    except ipaddress.AddressValueError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_network_identity_invalid", "Android LAN address is not IPv4"
        ) from error
    private_networks = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if str(address) != ipv4 or not any(address in network for network in private_networks):
        raise AndroidLanPeerAdmissionError(
            "android_peer_network_identity_invalid",
            "Android LAN address is not canonical RFC1918 IPv4",
        )


def _parse_network_addresses(
    value: bytes, expectation: AndroidLanNetworkExpectation
) -> int:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_network_observation_invalid",
            "Android address inventory is not ASCII",
        ) from error
    if (
        not text
        or not text.endswith("\n")
        or "\r" in text
        or "\0" in text
        or len(text) > SMALL_OUTPUT_LIMIT
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_network_observation_invalid",
            "Android address inventory is not bounded canonical LF text",
        )
    matches = 0
    prefix_length = 0
    for line in text[:-1].split("\n"):
        match = re.fullmatch(
            r"[0-9]+: ([A-Za-z0-9][A-Za-z0-9_.-]{0,14})(?:@[A-Za-z0-9_.-]+)?"
            r"\s+inet ([0-9.]+)/([0-9]{1,2})(?:\s+.*)?",
            line,
        )
        if match is None:
            raise AndroidLanPeerAdmissionError(
                "android_peer_network_observation_invalid",
                "Android address inventory contains a malformed row",
            )
        try:
            address = ipaddress.IPv4Address(match.group(2))
            prefix = int(match.group(3))
        except (ipaddress.AddressValueError, ValueError) as error:
            raise AndroidLanPeerAdmissionError(
                "android_peer_network_observation_invalid",
                "Android address inventory contains an invalid IPv4 prefix",
            ) from error
        if str(address) != match.group(2) or not 1 <= prefix <= 32:
            raise AndroidLanPeerAdmissionError(
                "android_peer_network_observation_invalid",
                "Android address inventory contains a non-canonical IPv4 prefix",
            )
        if (
            match.group(1) == expectation.interface_name
            and match.group(2) == expectation.ipv4
        ):
            matches += 1
            prefix_length = prefix
    if matches != 1:
        raise AndroidLanPeerAdmissionError(
            "android_peer_network_observation_invalid",
            "the selected Android LAN interface/address pair was not observed exactly once",
        )
    return prefix_length


def _parse_file_metadata(
    value: bytes,
    *,
    expected_type: int,
    expected_mode: int | None,
    expected_size: int | None,
    require_single_link: bool,
    label: str,
) -> _FileMetadata:
    line = _single_lf(value, label, maximum=128)
    pieces = line.split(b":")
    if len(pieces) != 7:
        raise AndroidLanPeerAdmissionError(
            "android_peer_remote_metadata_invalid", f"{label} metadata is malformed"
        )
    try:
        device_id, inode, link_count = (int(piece, 10) for piece in pieces[:3])
        mode = int(pieces[3], 16)
        uid, gid, size = (int(piece, 10) for piece in pieces[4:])
    except ValueError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_remote_metadata_invalid", f"{label} metadata is not numeric"
        ) from error
    if (
        stat.S_IFMT(mode) != expected_type
        or (expected_mode is not None and stat.S_IMODE(mode) != expected_mode)
        or device_id < 0
        or inode < 1
        or link_count < 1
        or (require_single_link and link_count != 1)
        or uid != SHELL_UID
        or gid != SHELL_GID
        or size < 0
        or (expected_size is not None and size != expected_size)
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_remote_metadata_invalid",
            f"{label} owner, mode, type, or size differs",
        )
    return _FileMetadata(
        device_id=device_id,
        inode=inode,
        link_count=link_count,
        mode=mode,
        uid=uid,
        gid=gid,
        size=size,
    )


def _parse_pid(value: bytes) -> int:
    line = _single_lf(value, "Android peer PID", maximum=16)
    if _PID_RE.fullmatch(line) is None:
        raise AndroidLanPeerAdmissionError(
            "android_peer_pid_invalid", "Android peer PID is not one canonical decimal"
        )
    pid = int(line)
    if pid <= 1:
        raise AndroidLanPeerAdmissionError(
            "android_peer_pid_invalid", "Android peer PID is outside the admitted range"
        )
    return pid


def _parse_process_stat(value: bytes, expected_pid: int) -> _ProcessStat:
    line = _single_lf(value, "Android peer /proc stat", maximum=4096).decode("ascii")
    prefix = f"{expected_pid} ("
    close = line.rfind(") ")
    if not line.startswith(prefix) or close <= len(prefix):
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_stat_invalid", "Android peer /proc stat is malformed"
        )
    name = line[len(prefix) : close]
    fields = line[close + 2 :].split(" ")
    if len(fields) < 20 or any(not field for field in fields):
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_stat_invalid", "Android peer /proc stat is incomplete"
        )
    state = fields[0]
    try:
        parent_pid = int(fields[1])
        start_time_ticks = int(fields[19])
    except ValueError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_stat_invalid",
            "Android peer /proc stat has non-numeric identity fields",
        ) from error
    if (
        name != PROCESS_NAME
        or state not in {"R", "S", "D"}
        or parent_pid < 1
        or start_time_ticks < 1
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_stat_invalid",
            "Android peer /proc stat identity differs",
        )
    return _ProcessStat(
        pid=expected_pid,
        name=name,
        state=state,
        parent_pid=parent_pid,
        start_time_ticks=start_time_ticks,
    )


def _parse_process_status(value: bytes) -> _ProcessStatus:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_status_invalid", "Android peer status is not ASCII"
        ) from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_status_invalid",
            "Android peer status is not canonical LF text",
        )
    fields: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        if ":" not in line:
            raise AndroidLanPeerAdmissionError(
                "android_peer_process_status_invalid",
                "Android peer status contains a malformed row",
            )
        key, raw = line.split(":", 1)
        if not key or key in fields:
            raise AndroidLanPeerAdmissionError(
                "android_peer_process_status_invalid",
                "Android peer status contains a duplicate field",
            )
        fields[key] = raw.strip()
    required = {"Name", "State", "Uid", "Gid", "Threads"}
    if not required.issubset(fields):
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_status_invalid",
            "Android peer status is missing identity fields",
        )
    uid_values = fields["Uid"].split()
    gid_values = fields["Gid"].split()
    if len(uid_values) != 4 or len(gid_values) != 4:
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_status_invalid",
            "Android peer status credential vectors are malformed",
        )
    try:
        uids = tuple(int(item) for item in uid_values)
        gids = tuple(int(item) for item in gid_values)
        thread_count = int(fields["Threads"])
    except ValueError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_status_invalid",
            "Android peer status identity values are not numeric",
        ) from error
    state_match = re.fullmatch(r"([RSD]) \([a-z ]+\)", fields["State"])
    if (
        fields["Name"] != PROCESS_NAME
        or state_match is None
        or uids != (SHELL_UID,) * 4
        or gids != (SHELL_GID,) * 4
        or not 1 <= thread_count <= 64
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_status_invalid",
            "Android peer status identity or credentials differ",
        )
    return _ProcessStatus(
        name=PROCESS_NAME,
        state=state_match.group(1),
        uid=SHELL_UID,
        gid=SHELL_GID,
        thread_count=thread_count,
    )


def _parse_socket_descriptors(value: bytes) -> tuple[_SocketObservation, ...]:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_socket_invalid", "Android peer descriptor inventory is not ASCII"
        ) from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        raise AndroidLanPeerAdmissionError(
            "android_peer_socket_invalid",
            "Android peer descriptor inventory is not canonical LF text",
        )
    sockets: list[_SocketObservation] = []
    for line in text[:-1].split("\n"):
        if line == "total 0":
            continue
        match = _FD_SOCKET_RE.search(line)
        if match is None:
            continue
        sockets.append(_SocketObservation(int(match.group(1)), int(match.group(2))))
    if len(sockets) != 1:
        raise AndroidLanPeerAdmissionError(
            "android_peer_socket_invalid",
            "Android peer must own exactly one socket before packet capture",
        )
    return tuple(sockets)


def _parse_tcp_listener(value: bytes, socket: _SocketObservation) -> None:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_socket_invalid", "Android peer TCP table is not ASCII"
        ) from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        raise AndroidLanPeerAdmissionError(
            "android_peer_socket_invalid", "Android peer TCP table is not canonical LF text"
        )
    lines = text[:-1].split("\n")
    if not lines or "local_address" not in lines[0] or "rem_address" not in lines[0]:
        raise AndroidLanPeerAdmissionError(
            "android_peer_socket_invalid", "Android peer TCP table header differs"
        )
    matching = 0
    for line in lines[1:]:
        pieces = line.split()
        if len(pieces) < 10:
            raise AndroidLanPeerAdmissionError(
                "android_peer_socket_invalid", "Android peer TCP table row is incomplete"
            )
        try:
            uid = int(pieces[7])
            inode = int(pieces[9])
        except ValueError as error:
            raise AndroidLanPeerAdmissionError(
                "android_peer_socket_invalid",
                "Android peer TCP table identity is not numeric",
            ) from error
        if inode != socket.inode:
            continue
        matching += 1
        if (
            pieces[1] != f"00000000:{LISTENER_PORT_HEX}"
            or pieces[2] != "00000000:0000"
            or pieces[3] != "0A"
            or uid != SHELL_UID
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_socket_invalid",
                "Android peer socket is not the fixed IPv4 TCP listener",
            )
    if matching != 1:
        raise AndroidLanPeerAdmissionError(
            "android_peer_socket_invalid",
            "Android peer socket inode was not observed exactly once in TCP LISTEN",
        )


def _pid_spec(
    selector: _DeviceSelector, role: str = "android-peer-pid"
) -> CommandSpec:
    return _remote_spec(
        role,
        selector,
        "/system/bin/pidof",
        PROCESS_LOOKUP_NAME,
        accepted_exit_codes=frozenset({0, 1}),
        stdout_limit=64,
    )


def _wait_for_pid(
    runner: AndroidLanPeerRunner,
    selector: _DeviceSelector,
    *,
    present: bool,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    observations: list[CommandResult] | None = None,
) -> int | None:
    deadline = monotonic() + (PROCESS_READY_SECONDS if present else PROCESS_STOP_SECONDS)
    while True:
        result = _run(runner, _pid_spec(selector))
        if observations is not None:
            observations.append(result)
        if result.stderr != b"":
            raise AndroidLanPeerAdmissionError(
                "android_peer_pid_invalid", "Android peer PID query emitted stderr"
            )
        if result.exit_code == 0:
            pid = _parse_pid(result.stdout)
            if present:
                return pid
        elif result.stdout != b"":
            raise AndroidLanPeerAdmissionError(
                "android_peer_pid_invalid", "absent Android peer PID query emitted stdout"
            )
        elif not present:
            return None
        if monotonic() >= deadline:
            break
        sleep(POLL_INTERVAL_SECONDS)
    raise AndroidLanPeerAdmissionError(
        "android_peer_process_timeout",
        "Android peer did not reach the required process state within the bound",
    )


def _verify_pulled_artifact(
    runner: AndroidLanPeerRunner,
    selector: _DeviceSelector,
    expected_bytes: bytes,
    *,
    remote_path: str = REMOTE_ARTIFACT,
    role: str = "android-peer-pull-verify",
) -> dict[str, object]:
    target = REPOSITORY_ROOT / "target"
    try:
        target_metadata = target.lstat()
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_pull_workspace_invalid", "repository target directory is unavailable"
        ) from error
    if target.is_symlink() or not stat.S_ISDIR(target_metadata.st_mode):
        raise AndroidLanPeerAdmissionError(
            "android_peer_pull_workspace_invalid", "repository target path is not a real directory"
        )
    private_parent = target / "physical-capture-private"
    parent_created = False
    try:
        try:
            os.mkdir(private_parent, 0o700)
            parent_created = True
        except FileExistsError:
            parent_created = False
        parent_metadata = private_parent.lstat()
        if (
            private_parent.is_symlink()
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_pull_workspace_invalid",
                "Android peer pull parent is not private and owner-bound",
            )
        workspace = Path(tempfile.mkdtemp(prefix="peer-verify.", dir=private_parent))
    except OSError as error:
        wrapped = AndroidLanPeerAdmissionError(
            "android_peer_pull_workspace_invalid",
            "Android peer pull workspace could not be created safely",
        )
        if parent_created:
            try:
                private_parent.rmdir()
            except OSError as cleanup_error:
                wrapped.attach_cleanup_context(
                    AndroidLanPeerAdmissionError(
                        "android_peer_pull_cleanup_unproven",
                        "failed pull workspace parent was not proven removed",
                    )
                )
                wrapped.add_note(
                    "private pull parent rmdir failed with "
                    f"errno={cleanup_error.errno}"
                )
        raise wrapped from error
    except AndroidLanPeerAdmissionError as primary:
        if parent_created:
            try:
                private_parent.rmdir()
            except OSError as cleanup_error:
                primary.attach_cleanup_context(
                    AndroidLanPeerAdmissionError(
                        "android_peer_pull_cleanup_unproven",
                        "failed pull workspace parent was not proven removed",
                    )
                )
                primary.add_note(
                    "private pull parent rmdir failed with "
                    f"errno={cleanup_error.errno}"
                )
        raise
    destination = workspace / f"{role}.pulled"
    pull_result: CommandResult | None = None
    primary_error: BaseException | None = None
    try:
        workspace_metadata = workspace.lstat()
        if (
            workspace.is_symlink()
            or not stat.S_ISDIR(workspace_metadata.st_mode)
            or workspace_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(workspace_metadata.st_mode) != 0o700
            or destination.exists()
            or destination.is_symlink()
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_pull_workspace_invalid",
                "Android peer pull workspace is not exclusive and private",
            )
        pull_spec = _fixed_spec(
            role,
            "pull",
            "-q",
            "-Z",
            remote_path,
            str(destination),
            selector=selector,
            timeout_seconds=TRANSFER_TIMEOUT_SECONDS,
            stdout_limit=TRANSFER_OUTPUT_LIMIT,
            stderr_limit=TRANSFER_OUTPUT_LIMIT,
        )
        pull_result = _run(runner, pull_spec)
        _require_silent(pull_result)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination, flags)
        try:
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != ARTIFACT_SIZE
            ):
                raise AndroidLanPeerAdmissionError(
                    "android_peer_pulled_artifact_invalid",
                    "pulled Android peer artifact metadata differs",
                )
            pulled = bytearray()
            while True:
                chunk = os.read(descriptor, 128 * 1024)
                if not chunk:
                    break
                if len(pulled) + len(chunk) > ARTIFACT_SIZE:
                    raise AndroidLanPeerAdmissionError(
                        "android_peer_pulled_artifact_invalid",
                        "pulled Android peer artifact exceeds the fixed byte count",
                    )
                pulled.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            len(pulled) != ARTIFACT_SIZE
            or (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or not hmac.compare_digest(bytes(pulled), expected_bytes)
            or not hmac.compare_digest(hashlib.sha256(pulled).hexdigest(), ARTIFACT_SHA256)
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_pulled_artifact_invalid",
                "pulled Android peer bytes differ from the reviewed local artifact",
            )
        return {
            "command": _command_receipt(pull_result),
            "sha256": ARTIFACT_SHA256,
            "size": ARTIFACT_SIZE,
            "verification": "adb-pull-host-bytes-v1",
        }
    except OSError as error:
        wrapped = AndroidLanPeerAdmissionError(
            "android_peer_pulled_artifact_invalid",
            "pulled Android peer bytes could not be reopened safely",
        )
        primary_error = wrapped
        raise wrapped from error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_error: OSError | None = None
        try:
            destination.unlink(missing_ok=True)
            if destination.exists() or destination.is_symlink():
                raise OSError(errno.EBUSY, "pulled artifact remained after unlink")
            workspace.rmdir()
            if workspace.exists():
                raise OSError(errno.EBUSY, "pull workspace remained after rmdir")
            try:
                private_parent.rmdir()
            except OSError as error:
                if error.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
                    raise
        except OSError as error:
            cleanup_error = error
        if cleanup_error is not None:
            wrapped = AndroidLanPeerAdmissionError(
                "android_peer_pull_cleanup_unproven",
                "pulled Android peer verification bytes were not proven removed",
            )
            if primary_error is not None:
                if isinstance(primary_error, AndroidLanPeerAdmissionError):
                    primary_error.attach_cleanup_context(wrapped)
                else:
                    _attach_cleanup_failure(
                        primary_error, wrapped, phase="host-pull-cleanup"
                    )
            else:
                raise wrapped from cleanup_error


def _identity_document(
    *,
    serial: bytes,
    fingerprint: bytes,
    boot_id: bytes,
    expectation: AndroidLanNetworkExpectation,
) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "document": IDENTITY_DOCUMENT,
        "role": "packet-lan-peer",
        "platform": "android",
        "transport": "adb-usb",
        "listener_address": LISTENER_ADDRESS,
        "listener_port": LISTENER_PORT,
        "serial_sha256": _leaf_hash(SERIAL_DOMAIN, serial),
        "build_fingerprint_sha256": _leaf_hash(FINGERPRINT_DOMAIN, fingerprint),
        "boot_id_sha256": _leaf_hash(BOOT_ID_DOMAIN, boot_id),
        "verified_boot_state": "green",
        "vbmeta_device_state": "locked",
        "flash_locked": True,
        "abi": "arm64-v8a",
        "network_interface_name": expectation.interface_name,
        "ipv4": expectation.ipv4,
        "deployment": {
            "directory_path": REMOTE_DIRECTORY,
            "directory_uid": SHELL_UID,
            "directory_gid": SHELL_GID,
            "directory_mode": "0700",
            "binary_path": REMOTE_ARTIFACT,
            "binary_sha256": ARTIFACT_SHA256,
            "binary_size": ARTIFACT_SIZE,
            "binary_uid": SHELL_UID,
            "binary_gid": SHELL_GID,
            "binary_mode": "0500",
        },
        "process_uid": SHELL_UID,
        "process_gid": SHELL_GID,
    }
    validate_android_lan_peer_identity(document)
    return document


def validate_android_lan_peer_identity(value: object) -> dict[str, object]:
    """Validate and copy the stable, non-sensitive Android identity schema."""

    if type(value) is not dict or set(value) != _IDENTITY_FIELDS:
        raise AndroidLanPeerAdmissionError(
            "android_peer_identity_invalid", "Android peer identity fields differ"
        )
    document = value
    exact_values: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "document": IDENTITY_DOCUMENT,
        "role": "packet-lan-peer",
        "platform": "android",
        "transport": "adb-usb",
        "listener_address": LISTENER_ADDRESS,
        "listener_port": LISTENER_PORT,
        "verified_boot_state": "green",
        "vbmeta_device_state": "locked",
        "flash_locked": True,
        "abi": "arm64-v8a",
        "process_uid": SHELL_UID,
        "process_gid": SHELL_GID,
    }
    for field, expected in exact_values.items():
        if type(document[field]) is not type(expected) or document[field] != expected:
            raise AndroidLanPeerAdmissionError(
                "android_peer_identity_invalid",
                f"Android peer identity {field} differs",
            )
    for field in ("serial_sha256", "build_fingerprint_sha256", "boot_id_sha256"):
        if type(document[field]) is not str or _SHA256_RE.fullmatch(document[field]) is None:
            raise AndroidLanPeerAdmissionError(
                "android_peer_identity_invalid",
                f"Android peer identity {field} is not canonical SHA-256",
            )
    _validate_network_identity(document["network_interface_name"], document["ipv4"])
    deployment = document["deployment"]
    if type(deployment) is not dict or set(deployment) != _DEPLOYMENT_IDENTITY_FIELDS:
        raise AndroidLanPeerAdmissionError(
            "android_peer_identity_invalid", "Android peer deployment identity fields differ"
        )
    expected_deployment: dict[str, object] = {
        "directory_path": REMOTE_DIRECTORY,
        "directory_uid": SHELL_UID,
        "directory_gid": SHELL_GID,
        "directory_mode": "0700",
        "binary_path": REMOTE_ARTIFACT,
        "binary_sha256": ARTIFACT_SHA256,
        "binary_size": ARTIFACT_SIZE,
        "binary_uid": SHELL_UID,
        "binary_gid": SHELL_GID,
        "binary_mode": "0500",
    }
    for field, expected in expected_deployment.items():
        if type(deployment[field]) is not type(expected) or deployment[field] != expected:
            raise AndroidLanPeerAdmissionError(
                "android_peer_identity_invalid",
                f"Android peer deployment identity {field} differs",
            )
    return copy.deepcopy(document)


def _staged_role(base: str, stage: str) -> str:
    if stage not in {
        "initial",
        "post-deploy",
        "post-start",
        "before-capture",
        "after-capture",
        "cleanup-before-delete",
        "cleanup-after-delete",
    }:
        raise AndroidLanPeerAdmissionError(
            "android_peer_source_contract_drift", "Android identity stage is not reviewed"
        )
    return base if stage == "initial" else f"{base}-{stage}"


def _observe_device_identity(
    runner: AndroidLanPeerRunner,
    selector: _DeviceSelector,
    expectation: AndroidLanNetworkExpectation,
    *,
    stage: str,
    observations: list[CommandResult] | None = None,
) -> tuple[_IdentitySnapshot, tuple[CommandResult, ...]]:
    serial_spec = _fixed_spec(
        _staged_role("android-device-serial", stage),
        "get-serialno",
        selector=selector,
        stdout_limit=256,
    )
    fingerprint_spec = _remote_spec(
        _staged_role("android-build-fingerprint", stage),
        selector,
        "/system/bin/getprop",
        "ro.build.fingerprint",
        stdout_limit=1024,
    )
    boot_spec = _remote_spec(
        _staged_role("android-boot-id", stage),
        selector,
        "/system/bin/cat",
        "/proc/sys/kernel/random/boot_id",
        stdout_limit=128,
    )
    verified_spec = _remote_spec(
        _staged_role("android-verified-boot", stage),
        selector,
        "/system/bin/getprop",
        "ro.boot.verifiedbootstate",
        stdout_limit=64,
    )
    vbmeta_spec = _remote_spec(
        _staged_role("android-vbmeta-state", stage),
        selector,
        "/system/bin/getprop",
        "ro.boot.vbmeta.device_state",
        stdout_limit=64,
    )
    flash_spec = _remote_spec(
        _staged_role("android-flash-lock", stage),
        selector,
        "/system/bin/getprop",
        "ro.boot.flash.locked",
        stdout_limit=64,
    )
    abi_spec = _remote_spec(
        _staged_role("android-primary-abi", stage),
        selector,
        "/system/bin/getprop",
        "ro.product.cpu.abi",
        stdout_limit=64,
    )
    network_spec = _remote_spec(
        _staged_role("android-network-addresses", stage),
        selector,
        "/system/bin/ip",
        "-o",
        "-4",
        "addr",
        "show",
        "up",
        "scope",
        "global",
    )
    specs = (
        serial_spec,
        fingerprint_spec,
        boot_spec,
        verified_spec,
        vbmeta_spec,
        flash_spec,
        abi_spec,
        network_spec,
    )
    result_list: list[CommandResult] = []
    for spec in specs:
        result = _run(runner, spec)
        result_list.append(result)
        if observations is not None:
            observations.append(result)
    results = tuple(result_list)
    if any(result.stderr != b"" for result in results):
        raise AndroidLanPeerAdmissionError(
            "android_peer_identity_output_invalid",
            "an Android identity command emitted stderr",
        )
    serial = _single_lf(results[0].stdout, "Android serial", maximum=256)
    fingerprint = _single_lf(
        results[1].stdout, "Android build fingerprint", maximum=1024
    )
    boot_id = _single_lf(results[2].stdout, "Android boot ID", maximum=128)
    if (
        _SERIAL_RE.fullmatch(serial) is None
        or not hmac.compare_digest(serial, selector.serial)
        or _FINGERPRINT_RE.fullmatch(fingerprint) is None
        or _BOOT_ID_RE.fullmatch(boot_id) is None
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_identity_output_invalid",
            "Android sensitive identity is malformed or differs from inventory",
        )
    exact_lines = (b"green", b"locked", b"1", b"arm64-v8a")
    observed_exact: list[bytes] = []
    for result, expected, label in zip(
        results[3:7],
        exact_lines,
        ("verified", "vbmeta", "flash", "abi"),
    ):
        observed = _single_lf(
            result.stdout, f"Android identity {label}", maximum=64
        )
        if not hmac.compare_digest(observed, expected):
            raise AndroidLanPeerAdmissionError(
                "android_peer_identity_output_invalid",
                f"Android identity {label} differs from the admitted value",
            )
        observed_exact.append(observed)
    prefix_length = _parse_network_addresses(results[7].stdout, expectation)
    return (
        _IdentitySnapshot(
            serial=serial,
            fingerprint=fingerprint,
            boot_id=boot_id,
            verified_boot_state=observed_exact[0],
            vbmeta_device_state=observed_exact[1],
            flash_locked=observed_exact[2],
            abi=observed_exact[3],
            network_prefix_length=prefix_length,
        ),
        results,
    )


def _revalidate_identity(
    runner: AndroidLanPeerRunner,
    selector: _DeviceSelector,
    expectation: AndroidLanNetworkExpectation,
    baseline: _IdentitySnapshot,
    *,
    stage: str,
    observations: list[CommandResult] | None = None,
) -> dict[str, object]:
    observed, results = _observe_device_identity(
        runner,
        selector,
        expectation,
        stage=stage,
        observations=observations,
    )
    if observed != baseline:
        raise AndroidLanPeerAdmissionError(
            "android_peer_identity_drift",
            f"Android device identity or LAN network changed during {stage}",
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "document": "cfw-android-lan-peer-identity-revalidation-v1",
        "stage": stage,
        "window": _command_window(results),
    }


def _server_status_fields(value: bytes) -> dict[str, str]:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_status_invalid",
            "ADB server status is not canonical ASCII",
        ) from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_status_invalid",
            "ADB server status is not canonical LF text",
        )
    fields: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        match = re.fullmatch(r"([a-z_]+): (?:\"([^\"]*)\"|([^\"]+))", line)
        if match is None or match.group(1) in fields:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_status_invalid",
                "ADB server status contains an unknown or duplicate field",
            )
        fields[match.group(1)] = (
            match.group(2) if match.group(2) is not None else match.group(3)
        )
    expected = {
        "usb_backend",
        "mdns_backend",
        "version",
        "build",
        "executable_absolute_path",
        "log_absolute_path",
        "os",
        "trace_level",
        "burst_mode",
        "mdns_enabled",
        "keystore_path",
        "known_hosts_path",
    }
    if set(fields) != expected:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_status_invalid",
            "ADB server status field set differs from the pinned contract",
        )
    return fields


def _validate_server_status(value: bytes, server: _AdbServerLease) -> dict[str, object]:
    fields = _server_status_fields(value)
    version, separator, build = ADB_VERSION.partition("-")
    if (
        separator != "-"
        or fields["version"] != version
        or fields["build"] != build
        or fields["executable_absolute_path"] != str(server.adb_path)
        or fields["usb_backend"] != "LIBUSB"
        or fields["mdns_backend"] != "MDNS_DISABLED"
        or fields["mdns_enabled"] != "false"
        or fields["burst_mode"] != "false"
        or fields["trace_level"] != ""
        or fields["log_absolute_path"] != str(server.root / "adb.log")
        or fields["keystore_path"]
        != str(server.root / "home" / ".android" / "adbkey")
        or fields["known_hosts_path"]
        != str(server.root / "home" / ".android" / "adb_known_hosts.pb")
        or re.fullmatch(r"Darwin [0-9]+(?:\.[0-9]+)* \(arm64\)", fields["os"])
        is None
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_status_invalid",
            "ADB server executable, version, architecture, or configuration differs",
        )
    try:
        metadata = server.socket.lstat()
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_socket_invalid",
            "private ADB server socket is unavailable",
        ) from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_socket_invalid",
            "private ADB server socket is not owned by the collector",
        )
    return {
        "fields": fields,
        "socket": str(server.socket),
        "adb_path": str(server.adb_path),
        "adb_sha256": ADB_SHA256,
    }


def _write_private_adb_copy(root: Path, data: bytes) -> Path:
    path = root / "adb"
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o700,
        )
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short private ADB client write")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_size != len(data)
            or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), ADB_SHA256)
        ):
            raise OSError("private ADB client identity differs")
        return path
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_client_copy_failed",
            "pinned ADB client could not be copied into the private server workspace",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_private_host_file(path: Path, *, expected_mode: int, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_credentials_unavailable",
            "the authorized ADB host key is unavailable",
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_size < 1
            or before.st_size > maximum
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_credentials_unsafe",
                "the authorized ADB host key has unsafe identity or metadata",
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 128 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise AndroidLanPeerAdmissionError(
                    "android_peer_credentials_unsafe",
                    "the authorized ADB host key exceeds its byte bound",
                )
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except AndroidLanPeerAdmissionError:
        raise
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_credentials_unavailable",
            "the authorized ADB host key could not be read safely",
        ) from error
    finally:
        os.close(descriptor)
    if (
        total != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_credentials_drift",
            "the authorized ADB host key changed while it was read",
        )
    return b"".join(chunks)


def _write_private_file(root: Path, name: str, data: bytes, *, mode: int) -> Path:
    path = root / name
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short private file write")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_size != len(data)
        ):
            raise OSError("private file identity differs")
        return path
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_workspace_invalid",
            "private ADB server file could not be created safely",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _private_adb_environment(root: Path) -> tuple[tuple[str, str], ...]:
    home = root / "home"
    user_home = home / ".android"
    try:
        home.mkdir(mode=0o700)
        home_metadata = home.lstat()
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_workspace_invalid",
            "private ADB server home directory could not be created",
        ) from error
    if (
        home.is_symlink()
        or not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(home_metadata.st_mode) != 0o700
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_workspace_invalid",
            "private ADB server home directory is not owner-bound",
        )
    for directory in (user_home,):
        try:
            directory.mkdir(mode=0o700)
            metadata = directory.lstat()
        except OSError as error:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_workspace_invalid",
                "private ADB server home directory could not be created",
            ) from error
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_nlink != 2
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_workspace_invalid",
                "private ADB server home directory is not owner-bound",
            )

    source_key = Path.home() / ".android" / "adbkey"
    key = _read_private_host_file(source_key, expected_mode=0o600, maximum=16 * 1024)
    _write_private_file(user_home, "adbkey", key, mode=0o600)
    source_public = source_key.with_suffix(".pub")
    if source_public.exists():
        public = _read_private_host_file(source_public, expected_mode=0o644, maximum=16 * 1024)
        _write_private_file(user_home, "adbkey.pub", public, mode=0o644)
    return (
        ("HOME", str(home)),
        ("ANDROID_USER_HOME", str(user_home)),
        ("ANDROID_ADB_LOG_PATH", str(root / "adb.log")),
    )


def _remove_private_file(path: Path, *, expected_mode: int | None = None) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_cleanup_failed",
            "private ADB server cleanup target could not be inspected",
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
        or (expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode)
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_cleanup_failed",
            "private ADB server cleanup target has unsafe identity",
        )
    try:
        path.unlink()
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_cleanup_failed",
            "private ADB server cleanup target could not be removed",
        ) from error


def _cleanup_adb_server_workspace(server: _AdbServerLease) -> None:
    for path, mode in (
        (server.adb_path, 0o700),
        (server.root / "adb.log", None),
        (server.root / "home" / ".android" / "adbkey", 0o600),
        (server.root / "home" / ".android" / "adbkey.pub", 0o644),
        (server.root / "home" / ".android" / "adb_known_hosts.pb", None),
    ):
        _remove_private_file(path, expected_mode=mode)
    for directory in (
        server.root / "home" / ".android",
        server.root / "home",
    ):
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_cleanup_failed",
                "private ADB server directory could not be inspected",
            ) from error
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_cleanup_failed",
                "private ADB server directory has unsafe identity",
            )
        try:
            directory.rmdir()
        except OSError as error:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_cleanup_failed",
                "private ADB server directory was not empty after shutdown",
            ) from error
    try:
        server.root.rmdir()
    except FileNotFoundError:
        return
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_cleanup_failed",
            "private ADB server workspace could not be removed",
        ) from error


def _start_adb_server(runner: AndroidLanPeerRunner) -> _AdbServerLease:
    target = REPOSITORY_ROOT / "target"
    try:
        metadata = target.lstat()
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_workspace_invalid",
            "ADB server target directory is unavailable",
        ) from error
    if (
        target.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_workspace_invalid",
            "ADB server target directory is not private and owner-bound",
        )
    server: _AdbServerLease | None = None
    server_started = False
    try:
        root = Path(tempfile.mkdtemp(prefix="adb-server.", dir=target))
        os.chmod(root, 0o700)
        server = _AdbServerLease(
            root=root,
            socket=root / "adb.sock",
            adb_path=root / "adb",
            environment=_private_adb_environment(root),
        )
        adb_bytes = _read_pinned_file(
            ADB,
            expected_sha256=ADB_SHA256,
            expected_size=None,
            expected_mode=None,
            executable=True,
        )
        server.adb_path = _write_private_adb_copy(root, adb_bytes)
        start = _run(
            runner,
            _fixed_spec(
                "android-adb-server-start",
                "start-server",
                server_socket=str(server.socket),
                timeout_seconds=ADB_SERVER_START_TIMEOUT_SECONDS,
                stdout_limit=SMALL_OUTPUT_LIMIT,
                stderr_limit=SMALL_OUTPUT_LIMIT,
                adb_path=str(server.adb_path),
                environment=server.environment,
            ),
        )
        server_started = True
        expected_stderr = (
            f"* daemon not running; starting now at {server.socket_argument}\n"
            "* daemon started successfully\n"
        ).encode("ascii")
        if start.stdout != b"" or start.stderr != expected_stderr:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_start_invalid",
                "private ADB server start diagnostics differ from the fixed contract",
            )
        status = _run(
            runner,
            _fixed_spec(
                "android-adb-server-status",
                "server-status",
                server_socket=str(server.socket),
                stdout_limit=ADB_SERVER_STATUS_OUTPUT_LIMIT,
                stderr_limit=SMALL_OUTPUT_LIMIT,
                adb_path=str(server.adb_path),
                environment=server.environment,
            ),
        )
        if status.stderr != b"":
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_status_invalid",
                "ADB server status emitted stderr",
            )
        server.status = _validate_server_status(status.stdout, server)
        return server
    except BaseException as primary:
        cleanup_error: BaseException | None = None
        if server is not None:
            kill_succeeded = False
            if server_started or server.socket.exists():
                try:
                    _run(
                        runner,
                        _fixed_spec(
                            "android-adb-server-kill",
                            "kill-server",
                            server_socket=str(server.socket),
                            timeout_seconds=ADB_SERVER_STOP_TIMEOUT_SECONDS,
                            stdout_limit=SMALL_OUTPUT_LIMIT,
                            stderr_limit=SMALL_OUTPUT_LIMIT,
                            adb_path=str(server.adb_path),
                            environment=server.environment,
                        ),
                    )
                    kill_succeeded = True
                except BaseException as error:
                    cleanup_error = error
            if (not server_started or kill_succeeded) and not server.socket.exists():
                try:
                    _cleanup_adb_server_workspace(server)
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
        if cleanup_error is not None:
            _attach_cleanup_failure(primary, cleanup_error, phase="adb-server-start-cleanup")
        raise


def _stop_adb_server(runner: AndroidLanPeerRunner, server: _AdbServerLease) -> None:
    result = _run(
        runner,
        _fixed_spec(
            "android-adb-server-kill",
            "kill-server",
            server_socket=str(server.socket),
            timeout_seconds=ADB_SERVER_STOP_TIMEOUT_SECONDS,
            stdout_limit=SMALL_OUTPUT_LIMIT,
            stderr_limit=SMALL_OUTPUT_LIMIT,
            adb_path=str(server.adb_path),
            environment=server.environment,
        ),
    )
    if result.stdout != b"" or result.stderr != b"":
        raise AndroidLanPeerAdmissionError(
            "android_peer_server_stop_invalid",
            "private ADB server shutdown emitted unexpected diagnostics",
        )
    deadline = time.monotonic() + ADB_SERVER_STOP_TIMEOUT_SECONDS
    while server.socket.exists() and time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL_SECONDS)
    if server.socket.exists():
        try:
            metadata = server.socket.lstat()
        except OSError as error:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_stop_unproven",
                "private ADB server socket could not be inspected after shutdown",
            ) from error
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_stop_unproven",
                "private ADB server socket has unsafe identity after shutdown",
            )
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            result = probe.connect_ex(str(server.socket))
        finally:
            probe.close()
        if result == 0:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_stop_unproven",
                "private ADB server socket remained accepting after shutdown",
            )
        if result not in {errno.ECONNREFUSED, errno.ENOENT}:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_stop_unproven",
                "private ADB server socket did not reach a closed state",
            )
        try:
            after_metadata = server.socket.lstat()
        except OSError as error:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_stop_unproven",
                "private ADB server socket changed during shutdown verification",
            ) from error
        if (
            after_metadata.st_dev != metadata.st_dev
            or after_metadata.st_ino != metadata.st_ino
            or after_metadata.st_mode != metadata.st_mode
            or after_metadata.st_uid != metadata.st_uid
            or after_metadata.st_nlink != metadata.st_nlink
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_stop_unproven",
                "private ADB server socket identity changed during cleanup",
            )
        try:
            server.socket.unlink()
        except OSError as error:
            raise AndroidLanPeerAdmissionError(
                "android_peer_server_cleanup_failed",
                "stale private ADB server socket could not be removed",
            ) from error
    _cleanup_adb_server_workspace(server)


def _collect_identity(
    runner: AndroidLanPeerRunner,
    expectation: AndroidLanNetworkExpectation,
    server: _AdbServerLease,
) -> tuple[
    _DeviceSelector,
    _IdentitySnapshot,
    dict[str, object],
    dict[str, object],
]:
    version_spec = _fixed_spec(
        "android-adb-version",
        "version",
        stdout_limit=4096,
        server_socket=str(server.socket),
        adb_path=str(server.adb_path),
        environment=server.environment,
    )
    version = _run(runner, version_spec)
    if version.stderr != b"":
        raise AndroidLanPeerAdmissionError(
            "android_peer_adb_version_invalid", "ADB version command emitted stderr"
        )
    _parse_adb_version(version.stdout, expected_path=str(server.adb_path))

    inventory_spec = _fixed_spec(
        "android-device-inventory",
        "devices",
        "-l",
        inventory=True,
        server_socket=str(server.socket),
        adb_path=str(server.adb_path),
        environment=server.environment,
        stdout_limit=16 * 1024,
    )
    inventory = _run(runner, inventory_spec)
    if inventory.stderr != b"":
        raise AndroidLanPeerAdmissionError(
            "android_peer_device_inventory_invalid", "ADB device inventory emitted stderr"
        )
    parsed_selector = _parse_device_inventory(inventory.stdout)
    selector = _DeviceSelector(
        serial=parsed_selector.serial,
        transport_id=parsed_selector.transport_id,
        server_socket=str(server.socket),
        adb_path=str(server.adb_path),
        environment=server.environment,
    )
    snapshot, results = _observe_device_identity(
        runner, selector, expectation, stage="initial"
    )
    identity = _identity_document(
        serial=snapshot.serial,
        fingerprint=snapshot.fingerprint,
        boot_id=snapshot.boot_id,
        expectation=expectation,
    )
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "document": "cfw-android-lan-peer-identity-observation-v1",
        "window": _command_window((version, inventory, *results)),
        "network_prefix_length": snapshot.network_prefix_length,
        "adb_server": {
            "socket": str(server.socket),
            "status": copy.deepcopy(server.status),
        },
    }
    return selector, snapshot, identity, provenance


def _remote_path_present(
    runner: AndroidLanPeerRunner,
    selector: _DeviceSelector,
    path: str,
    *,
    label: str,
    stage: str,
    observations: list[CommandResult] | None = None,
) -> _RemotePathState:
    if label not in {"directory", "binary"} or stage not in {"before", "after"}:
        raise AndroidLanPeerAdmissionError(
            "android_peer_source_contract_drift", "remote path probe is not reviewed"
        )
    results: list[CommandResult] = []
    for predicate, role_part in (("-e", "exists"), ("-L", "symlink")):
        result = _run(
            runner,
            _remote_spec(
                f"android-peer-{label}-{role_part}-{stage}",
                selector,
                "/system/bin/test",
                predicate,
                path,
                accepted_exit_codes=frozenset({0, 1}),
                stdout_limit=0,
            ),
        )
        _require_silent(result)
        results.append(result)
        if observations is not None:
            observations.append(result)
    return _RemotePathState(
        exists=results[0].exit_code == 0,
        symlink=results[1].exit_code == 0,
    )


def _write_private_push_artifact(data: bytes) -> tuple[Path, Path]:
    target = REPOSITORY_ROOT / "target"
    try:
        metadata = target.lstat()
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_push_workspace_invalid",
            "Android peer push target directory is unavailable",
        ) from error
    if (
        target.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_push_workspace_invalid",
            "Android peer push target directory is not private and owner-bound",
        )
    try:
        root = Path(tempfile.mkdtemp(prefix="peer-push.", dir=target))
        os.chmod(root, 0o700)
        path = root / "artifact"
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o500,
        )
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise OSError("short private Android peer artifact write")
                offset += written
            os.fsync(descriptor)
            file_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_metadata.st_mode)
                or file_metadata.st_nlink != 1
                or file_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(file_metadata.st_mode) != 0o500
                or file_metadata.st_size != ARTIFACT_SIZE
                or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), ARTIFACT_SHA256)
            ):
                raise OSError("private Android peer artifact identity differs")
        finally:
            os.close(descriptor)
        return root, path
    except OSError as error:
        try:
            if 'path' in locals():
                path.unlink(missing_ok=True)
            root.rmdir()
        except OSError as cleanup_error:
            error.add_note(
                "private Android peer push workspace cleanup failed: "
                f"{type(cleanup_error).__name__}"
            )
        raise AndroidLanPeerAdmissionError(
            "android_peer_push_workspace_invalid",
            "Android peer artifact could not be staged in a private workspace",
        ) from error


def _remove_private_push_artifact(root: Path, path: Path) -> None:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o500
        ):
            raise OSError("private Android peer artifact cleanup identity drifted")
        path.unlink()
        root.rmdir()
    except FileNotFoundError:
        if root.exists():
            raise AndroidLanPeerAdmissionError(
                "android_peer_push_cleanup_unproven",
                "private Android peer push workspace disappeared ambiguously",
            )
    except OSError as error:
        raise AndroidLanPeerAdmissionError(
            "android_peer_push_cleanup_unproven",
            "private Android peer push workspace could not be removed",
        ) from error


def _deploy(
    runner: AndroidLanPeerRunner,
    selector: _DeviceSelector,
    artifact_bytes: bytes,
    ownership: _DeploymentOwnership,
) -> dict[str, object]:
    existing = _run(
        runner, _pid_spec(selector, "android-peer-pid-before-deploy")
    )
    if existing.stderr != b"" or existing.exit_code == 0 or existing.stdout != b"":
        raise AndroidLanPeerAdmissionError(
            "android_peer_preexisting_process",
            "an Android LAN peer process already exists before deployment",
        )
    if _remote_path_present(
        runner,
        selector,
        REMOTE_DIRECTORY,
        label="directory",
        stage="before",
    ).present or _remote_path_present(
        runner,
        selector,
        REMOTE_ARTIFACT,
        label="binary",
        stage="before",
    ).present:
        raise AndroidLanPeerAdmissionError(
            "android_peer_preexisting_deployment",
            "Android LAN peer deployment paths must be absent before admission",
        )

    mkdir = _remote_spec(
        "android-peer-directory-create",
        selector,
        "/system/bin/mkdir",
        REMOTE_DIRECTORY,
        stdout_limit=64,
    )
    chmod_directory = _remote_spec(
        "android-peer-directory-mode",
        selector,
        "/system/bin/chmod",
        "0700",
        REMOTE_DIRECTORY,
        stdout_limit=64,
    )
    stat_directory = _remote_spec(
        "android-peer-directory-stat",
        selector,
        "/system/bin/stat",
        "-c",
        "%d:%i:%h:%f:%u:%g:%s",
        REMOTE_DIRECTORY,
        stdout_limit=256,
    )
    chmod_binary = _remote_spec(
        "android-peer-binary-mode",
        selector,
        "/system/bin/chmod",
        "0500",
        REMOTE_ARTIFACT,
        stdout_limit=64,
    )
    stat_binary = _remote_spec(
        "android-peer-binary-stat",
        selector,
        "/system/bin/stat",
        "-c",
        "%d:%i:%h:%f:%u:%g:%s",
        REMOTE_ARTIFACT,
        stdout_limit=256,
    )

    ownership.directory_create_attempted = True
    mkdir_result = _run(runner, mkdir)
    ownership.directory_created = True
    chmod_directory_result = _run(runner, chmod_directory)
    for result in (mkdir_result, chmod_directory_result):
        _require_silent(result)
    directory_result = _run(runner, stat_directory)
    if directory_result.stderr != b"":
        raise AndroidLanPeerAdmissionError(
            "android_peer_remote_metadata_invalid", "remote directory stat emitted stderr"
        )
    directory = _parse_file_metadata(
        directory_result.stdout,
        expected_type=stat.S_IFDIR,
        expected_mode=DIRECTORY_MODE,
        expected_size=None,
        require_single_link=False,
        label="Android peer directory",
    )
    ownership.directory_metadata = directory
    if _remote_path_present(
        runner,
        selector,
        REMOTE_ARTIFACT,
        label="binary",
        stage="after",
    ).present:
        raise AndroidLanPeerAdmissionError(
            "android_peer_deployment_race",
            "Android LAN peer binary appeared before the owned push",
        )
    ownership.binary_push_attempted = True
    push_root, push_path = _write_private_push_artifact(artifact_bytes)
    push = _fixed_spec(
        "android-peer-push",
        "push",
        "-q",
        "-Z",
        str(push_path),
        REMOTE_ARTIFACT,
        selector=selector,
        timeout_seconds=TRANSFER_TIMEOUT_SECONDS,
        stdout_limit=TRANSFER_OUTPUT_LIMIT,
        stderr_limit=TRANSFER_OUTPUT_LIMIT,
    )
    primary_error: BaseException | None = None
    push_result: CommandResult | None = None
    try:
        push_result = _run(runner, push)
    except BaseException as error:
        primary_error = error
    try:
        _remove_private_push_artifact(push_root, push_path)
    except BaseException as cleanup_error:
        if primary_error is None:
            primary_error = cleanup_error
        else:
            _attach_cleanup_failure(primary_error, cleanup_error, phase="host-push-cleanup")
    if primary_error is not None:
        raise primary_error
    if push_result is None:
        raise AndroidLanPeerAdmissionError(
            "android_peer_push_failed", "Android peer push did not produce a result"
        )
    ownership.binary_created = True
    _require_silent(push_result)
    chmod_binary_result = _run(runner, chmod_binary)
    _require_silent(chmod_binary_result)
    binary_result = _run(runner, stat_binary)
    if binary_result.stderr != b"":
        raise AndroidLanPeerAdmissionError(
            "android_peer_remote_metadata_invalid", "remote binary stat emitted stderr"
        )
    binary = _parse_file_metadata(
        binary_result.stdout,
        expected_type=stat.S_IFREG,
        expected_mode=BINARY_MODE,
        expected_size=ARTIFACT_SIZE,
        require_single_link=True,
        label="Android peer binary",
    )
    ownership.binary_metadata = binary
    pull = _verify_pulled_artifact(runner, selector, artifact_bytes)
    return {
        "schema_version": SCHEMA_VERSION,
        "document": DEPLOYMENT_DOCUMENT,
        "window": _command_window(
            (
                existing,
                mkdir_result,
                chmod_directory_result,
                directory_result,
                push_result,
                chmod_binary_result,
                binary_result,
            )
        ),
        "directory": {
            "path": REMOTE_DIRECTORY,
            "device_id": directory.device_id,
            "inode": directory.inode,
            "link_count": directory.link_count,
            "uid": directory.uid,
            "gid": directory.gid,
            "mode": "0700",
            "stat_command_sha256": directory_result.argv_sha256,
        },
        "binary": {
            "path": REMOTE_ARTIFACT,
            "device_id": binary.device_id,
            "inode": binary.inode,
            "link_count": binary.link_count,
            "sha256": ARTIFACT_SHA256,
            "size": binary.size,
            "uid": binary.uid,
            "gid": binary.gid,
            "mode": "0500",
            "push_command_sha256": push_result.argv_sha256,
            "stat_command_sha256": binary_result.argv_sha256,
            "host_byte_verification": pull,
        },
    }


def _process_role(base: str, stage: str) -> str:
    if stage not in {"admission", "before-capture", "after-capture"}:
        raise AndroidLanPeerAdmissionError(
            "android_peer_source_contract_drift", "Android process stage is not reviewed"
        )
    return base if stage == "admission" else f"{base}-{stage}"


def _observe_process(
    runner: AndroidLanPeerRunner,
    selector: _DeviceSelector,
    artifact_bytes: bytes,
    pid: int,
    *,
    stage: str,
) -> tuple[dict[str, object], _ProcessStat]:
    proc = f"/proc/{pid}"
    stat_before_spec = _remote_spec(
        _process_role("android-peer-process-stat-before", stage),
        selector,
        "/system/bin/cat",
        f"{proc}/stat",
        stdout_limit=4096,
    )
    exe_spec = _remote_spec(
        _process_role("android-peer-process-exe", stage),
        selector,
        "/system/bin/readlink",
        f"{proc}/exe",
        stdout_limit=512,
    )
    status_spec = _remote_spec(
        _process_role("android-peer-process-status", stage),
        selector,
        "/system/bin/cat",
        f"{proc}/status",
        stdout_limit=32 * 1024,
    )
    cmdline_spec = _remote_spec(
        _process_role("android-peer-process-cmdline", stage),
        selector,
        "/system/bin/cat",
        f"{proc}/cmdline",
        stdout_limit=1024,
    )
    descriptors_spec = _remote_spec(
        _process_role("android-peer-process-descriptors", stage),
        selector,
        "/system/bin/ls",
        "-l",
        f"{proc}/fd",
        stdout_limit=16 * 1024,
    )
    tcp_spec = _remote_spec(
        _process_role("android-peer-process-tcp", stage),
        selector,
        "/system/bin/cat",
        f"{proc}/net/tcp",
        stdout_limit=64 * 1024,
    )
    stat_after_spec = _remote_spec(
        _process_role("android-peer-process-stat-after", stage),
        selector,
        "/system/bin/cat",
        f"{proc}/stat",
        stdout_limit=4096,
    )

    stat_before_result = _run(runner, stat_before_spec)
    exe_result = _run(runner, exe_spec)
    executable_bytes_receipt = _verify_pulled_artifact(
        runner,
        selector,
        artifact_bytes,
        remote_path=f"{proc}/exe",
        role=_process_role("android-peer-process-exe-pull", stage),
    )
    status_result = _run(runner, status_spec)
    cmdline_result = _run(runner, cmdline_spec)
    descriptors_result = _run(runner, descriptors_spec)
    tcp_result = _run(runner, tcp_spec)
    stat_after_result = _run(runner, stat_after_spec)
    results = (
        stat_before_result,
        exe_result,
        status_result,
        cmdline_result,
        descriptors_result,
        tcp_result,
        stat_after_result,
    )
    if any(result.stderr != b"" for result in results):
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_observation_invalid",
            "an Android peer process observation emitted stderr",
        )
    before = _parse_process_stat(stat_before_result.stdout, pid)
    after = _parse_process_stat(stat_after_result.stdout, pid)
    if (
        before.pid,
        before.name,
        before.parent_pid,
        before.start_time_ticks,
    ) != (
        after.pid,
        after.name,
        after.parent_pid,
        after.start_time_ticks,
    ):
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_drift",
            "Android peer process identity changed during observation",
        )
    executable = _single_lf(
        exe_result.stdout, "Android peer executable path", maximum=512
    )
    if not hmac.compare_digest(executable, REMOTE_ARTIFACT.encode("ascii")):
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_executable_invalid",
            "Android peer executable path differs from the deployed binary",
        )
    status = _parse_process_status(status_result.stdout)
    expected_cmdline = REMOTE_ARTIFACT.encode("ascii") + b"\0"
    if not hmac.compare_digest(cmdline_result.stdout, expected_cmdline):
        raise AndroidLanPeerAdmissionError(
            "android_peer_process_cmdline_invalid",
            "Android peer command line differs from the no-argument contract",
        )
    sockets = _parse_socket_descriptors(descriptors_result.stdout)
    socket = sockets[0]
    _parse_tcp_listener(tcp_result.stdout, socket)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "document": PROCESS_DOCUMENT,
        "pid": pid,
        "name": before.name,
        "parent_pid": before.parent_pid,
        "start_time_ticks": before.start_time_ticks,
        "executable_path": REMOTE_ARTIFACT,
        "uid": status.uid,
        "gid": status.gid,
        "thread_count": status.thread_count,
        "socket_descriptor": socket.descriptor,
        "socket_inode": socket.inode,
        "listener_address": LISTENER_ADDRESS,
        "listener_port": LISTENER_PORT,
        "tcp_state": "LISTEN",
        "observations": {
            "window": _command_window(results),
            "executable_host_byte_verification": executable_bytes_receipt,
            "process_argv_sha256": command_sha256((REMOTE_ARTIFACT,)),
        },
    }
    return receipt, before


def _cleanup_deployment(
    runner: AndroidLanPeerRunner,
    selector: _DeviceSelector,
    ownership: _DeploymentOwnership,
    observations: list[CommandResult] | None = None,
) -> list[CommandResult]:
    receipts = observations if observations is not None else []
    if not ownership.directory_create_attempted and not ownership.binary_push_attempted:
        return receipts
    failures: list[BaseException] = []
    try:
        binary_state = _remote_path_present(
            runner,
            selector,
            REMOTE_ARTIFACT,
            label="binary",
            stage="after",
            observations=receipts,
        )
        if binary_state.present:
            if (
                binary_state.symlink
                or not ownership.binary_created
            ):
                raise AndroidLanPeerAdmissionError(
                    "android_peer_cleanup_identity_drift",
                    "Android peer binary is present without confirmed owned metadata",
                )
            binary_stat_result = _run(
                runner,
                _remote_spec(
                    "android-peer-binary-stat-cleanup",
                    selector,
                    "/system/bin/stat",
                    "-c",
                    "%d:%i:%h:%f:%u:%g:%s",
                    REMOTE_ARTIFACT,
                    stdout_limit=256,
                ),
            )
            receipts.append(binary_stat_result)
            if binary_stat_result.stderr != b"":
                raise AndroidLanPeerAdmissionError(
                    "android_peer_cleanup_identity_drift",
                    "Android peer binary cleanup stat emitted stderr",
                )
            current_binary = _parse_file_metadata(
                binary_stat_result.stdout,
                expected_type=stat.S_IFREG,
                expected_mode=(
                    BINARY_MODE if ownership.binary_metadata is not None else None
                ),
                expected_size=ARTIFACT_SIZE,
                require_single_link=True,
                label="Android peer cleanup binary",
            )
            if ownership.binary_metadata is None:
                ownership.binary_metadata = current_binary
            elif not _same_file_identity(
                current_binary, ownership.binary_metadata, bind_size=True
            ):
                raise AndroidLanPeerAdmissionError(
                    "android_peer_cleanup_identity_drift",
                    "Android peer binary inode, device, links, or metadata changed",
                )
            removed = _run(
                runner,
                _remote_spec(
                    "android-peer-binary-cleanup",
                    selector,
                    "/system/bin/rm",
                    "-f",
                    REMOTE_ARTIFACT,
                    stdout_limit=0,
                ),
            )
            receipts.append(removed)
            _require_silent(removed)
        if _remote_path_present(
            runner,
            selector,
            REMOTE_ARTIFACT,
            label="binary",
            stage="after",
            observations=receipts,
        ).present:
            raise AndroidLanPeerAdmissionError(
                "android_peer_cleanup_unproven",
                "Android peer binary absence was not proven after cleanup",
            )
        ownership.binary_push_attempted = False
        ownership.binary_created = False
    except BaseException as error:
        failures.append(error)

    try:
        directory_state = _remote_path_present(
            runner,
            selector,
            REMOTE_DIRECTORY,
            label="directory",
            stage="after",
            observations=receipts,
        )
        if directory_state.present:
            if (
                directory_state.symlink
                or not ownership.directory_created
            ):
                raise AndroidLanPeerAdmissionError(
                    "android_peer_cleanup_identity_drift",
                    "Android peer directory is present without confirmed owned metadata",
                )
            directory_stat_result = _run(
                runner,
                _remote_spec(
                    "android-peer-directory-stat-cleanup",
                    selector,
                    "/system/bin/stat",
                    "-c",
                    "%d:%i:%h:%f:%u:%g:%s",
                    REMOTE_DIRECTORY,
                    stdout_limit=256,
                ),
            )
            receipts.append(directory_stat_result)
            if directory_stat_result.stderr != b"":
                raise AndroidLanPeerAdmissionError(
                    "android_peer_cleanup_identity_drift",
                    "Android peer directory cleanup stat emitted stderr",
                )
            current_directory = _parse_file_metadata(
                directory_stat_result.stdout,
                expected_type=stat.S_IFDIR,
                expected_mode=(
                    DIRECTORY_MODE
                    if ownership.directory_metadata is not None
                    else None
                ),
                expected_size=None,
                require_single_link=False,
                label="Android peer cleanup directory",
            )
            if ownership.directory_metadata is None:
                ownership.directory_metadata = current_directory
            elif not _same_file_identity(
                current_directory, ownership.directory_metadata, bind_size=False
            ):
                raise AndroidLanPeerAdmissionError(
                    "android_peer_cleanup_identity_drift",
                    "Android peer directory inode, device, links, or metadata changed",
                )
            remove_directory = _remote_spec(
                "android-peer-directory-cleanup",
                selector,
                "/system/bin/rmdir",
                REMOTE_DIRECTORY,
                stdout_limit=0,
            )
            remove_directory_result = _run(runner, remove_directory)
            receipts.append(remove_directory_result)
            _require_silent(remove_directory_result)
        if _remote_path_present(
            runner,
            selector,
            REMOTE_DIRECTORY,
            label="directory",
            stage="after",
            observations=receipts,
        ).present:
            raise AndroidLanPeerAdmissionError(
                "android_peer_cleanup_unproven",
                "Android peer directory absence was not proven after cleanup",
            )
        ownership.directory_created = False
        ownership.directory_create_attempted = False
    except BaseException as error:
        failures.append(error)

    if failures:
        control_failure = next(
            (failure for failure in failures if not isinstance(failure, Exception)),
            None,
        )
        if control_failure is not None:
            for failure in failures:
                if failure is not control_failure:
                    _attach_cleanup_failure(
                        control_failure,
                        failure,
                        phase="deployment-cleanup",
                    )
            raise control_failure
        primary = AndroidLanPeerAdmissionError(
            "android_peer_cleanup_unproven",
            "Android LAN peer deployment cleanup was not completely proven",
        )
        for failure in failures:
            primary.add_note(
                "cleanup step failed with "
                f"[{getattr(failure, 'code', 'android_peer_cleanup_unexpected')}]: "
                f"{type(failure).__name__}"
            )
        raise primary from failures[0]
    return receipts


def _same_file_identity(
    observed: _FileMetadata,
    owned: _FileMetadata,
    *,
    bind_size: bool,
) -> bool:
    return (
        observed.device_id,
        observed.inode,
        observed.link_count,
        observed.mode,
        observed.uid,
        observed.gid,
    ) == (
        owned.device_id,
        owned.inode,
        owned.link_count,
        owned.mode,
        owned.uid,
        owned.gid,
    ) and (not bind_size or observed.size == owned.size)


def _binding_receipt(metadata: _FileMetadata | None) -> dict[str, object]:
    if metadata is None:
        return {"created": False}
    return {
        "created": True,
        "device_id": metadata.device_id,
        "inode": metadata.inode,
        "link_count": metadata.link_count,
        "mode": f"{stat.S_IMODE(metadata.mode):04o}",
        "uid": metadata.uid,
        "gid": metadata.gid,
        "size": metadata.size,
    }


def _cleanup_transaction(
    runner: AndroidLanPeerRunner,
    selector: _DeviceSelector,
    ownership: _DeploymentOwnership,
    started: StartedPeerCommand | None,
    process_pid: int | None,
    network: AndroidLanNetworkExpectation,
    baseline: _IdentitySnapshot,
    history: list[dict[str, object]],
) -> dict[str, object]:
    cancel_error: BaseException | None = None
    if started is not None:
        try:
            started.cancel()
        except BaseException as error:
            cancel_error = error

    pre_delete_identity_error: BaseException | None = None
    pre_delete_identity_receipt: dict[str, object] | None = None
    pre_delete_results: list[CommandResult] = []
    try:
        pre_delete_identity_receipt = _revalidate_identity(
            runner,
            selector,
            network,
            baseline,
            stage="cleanup-before-delete",
            observations=pre_delete_results,
        )
    except BaseException as error:
        pre_delete_identity_error = error

    absence_error: BaseException | None = None
    process_results: list[CommandResult] = []
    try:
        _wait_for_pid(
            runner,
            selector,
            present=False,
            observations=process_results,
        )
        if process_pid is not None:
            process_path_result = _run(
                runner,
                _remote_spec(
                    "android-peer-original-pid-absence",
                    selector,
                    "/system/bin/test",
                    "-e",
                    f"/proc/{process_pid}",
                    accepted_exit_codes=frozenset({0, 1}),
                    stdout_limit=0,
                ),
            )
            process_results.append(process_path_result)
            _require_silent(process_path_result)
            if process_path_result.exit_code != 1:
                raise AndroidLanPeerAdmissionError(
                    "android_peer_cleanup_unproven",
                    "the admitted Android peer PID still exists after cancellation",
                )
    except BaseException as error:
        absence_error = error

    deployment_error: BaseException | None = None
    deployment_results: list[CommandResult] = []
    if absence_error is None and pre_delete_identity_error is None:
        try:
            _cleanup_deployment(
                runner,
                selector,
                ownership,
                observations=deployment_results,
            )
        except BaseException as error:
            deployment_error = error

    post_delete_identity_error: BaseException | None = None
    post_delete_identity_receipt: dict[str, object] | None = None
    post_delete_results: list[CommandResult] = []
    try:
        post_delete_identity_receipt = _revalidate_identity(
            runner,
            selector,
            network,
            baseline,
            stage="cleanup-after-delete",
            observations=post_delete_results,
        )
    except BaseException as error:
        post_delete_identity_error = error

    failures = (
        ("cancel", cancel_error),
        ("cleanup-before-delete", pre_delete_identity_error),
        ("process-absence", absence_error),
        ("deployment-delete", deployment_error),
        ("cleanup-after-delete", post_delete_identity_error),
    )
    command_results = (
        *pre_delete_results,
        *process_results,
        *deployment_results,
        *post_delete_results,
    )
    attempt = {
        "schema_version": SCHEMA_VERSION,
        "document": "cfw-android-lan-peer-cleanup-attempt-v1",
        "attempt": len(history) + 1,
        "status": (
            "failed" if any(error is not None for _phase, error in failures) else "complete"
        ),
        "errors": [
            _typed_failure_context(error, phase=phase)
            for phase, error in failures
            if error is not None
        ],
        "pre_delete_identity_revalidation": pre_delete_identity_receipt,
        "process_absence_proven": absence_error is None,
        "deployment_absence_proven": deployment_error is None
        and absence_error is None
        and pre_delete_identity_error is None,
        "post_delete_identity_revalidation": post_delete_identity_receipt,
        "commands": [_command_receipt(result) for result in command_results],
        "window": _command_window(command_results) if command_results else None,
    }
    history.append(copy.deepcopy(attempt))

    if any(error is not None for _phase, error in failures):
        control_failure = next(
            (
                error
                for _phase, error in failures
                if error is not None and not isinstance(error, Exception)
            ),
            None,
        )
        if control_failure is not None:
            for phase, failure in failures:
                if failure is not None and failure is not control_failure:
                    _attach_cleanup_failure(
                        control_failure,
                        failure,
                        phase=phase,
                    )
            raise control_failure
        primary = AndroidLanPeerAdmissionError(
            "android_peer_cleanup_unproven",
            "Android LAN peer process or deployment absence was not proven",
        )
        for phase, failure in failures:
            if failure is not None:
                context = _typed_failure_context(failure, phase=phase)
                primary.add_note(
                    "cleanup action failed with "
                    f"[{context['code']}]: {context['error_type']}"
                )
        cause = next(
            failure
            for _phase, failure in failures
            if failure is not None
        )
        raise primary from cause

    aggregate_commands = [
        command
        for recorded_attempt in history
        for command in recorded_attempt["commands"]
    ]
    process_commands = [
        command
        for command in aggregate_commands
        if command["role"]
        in {"android-peer-pid", "android-peer-original-pid-absence"}
    ]
    deployment_commands = [
        command
        for command in aggregate_commands
        if command["role"].startswith("android-peer-binary-")
        or command["role"].startswith("android-peer-directory-")
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "document": "cfw-android-lan-peer-cleanup-v1",
        "process_pid": process_pid,
        "process_absent": True,
        "deployment_absent": True,
        "pre_delete_identity_revalidation": pre_delete_identity_receipt,
        "post_delete_identity_revalidation": post_delete_identity_receipt,
        "removed_directory_binding": _binding_receipt(ownership.directory_metadata),
        "removed_binary_binding": _binding_receipt(ownership.binary_metadata),
        "process_absence_window": _receipt_window(process_commands),
        "deployment_absence_window": (
            _receipt_window(deployment_commands)
            if deployment_commands
            else {"created": False, "commands": []}
        ),
        "attempts": copy.deepcopy(history),
        "window": _receipt_window(aggregate_commands),
    }


def _same_process_identity(left: _ProcessStat, right: _ProcessStat) -> bool:
    return (
        left.pid,
        left.name,
        left.parent_pid,
        left.start_time_ticks,
    ) == (
        right.pid,
        right.name,
        right.parent_pid,
        right.start_time_ticks,
    )


def _typed_failure_context(error: BaseException, *, phase: str) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "document": "cfw-android-lan-peer-failure-context-v1",
        "phase": phase,
        "code": (
            error.code
            if isinstance(error, AndroidLanPeerAdmissionError)
            else "android_peer_unexpected_failure"
        ),
        "error_type": type(error).__name__,
    }


def _attach_cleanup_failure(
    primary: BaseException, cleanup: BaseException, *, phase: str
) -> None:
    if isinstance(primary, AndroidLanPeerAdmissionError):
        primary.attach_cleanup_context(cleanup)
        return
    context = _typed_failure_context(cleanup, phase=phase)
    primary.add_note(
        "Android LAN peer cleanup also failed "
        f"[{context['code']}]: {context['error_type']}"
    )


class AndroidLanPeerLease:
    """An admitted running peer whose shutdown remains fail-closed."""

    def __init__(
        self,
        *,
        runner: AndroidLanPeerRunner,
        server: _AdbServerLease,
        selector: _DeviceSelector,
        started: StartedPeerCommand,
        ownership: _DeploymentOwnership,
        network: AndroidLanNetworkExpectation,
        baseline: _IdentitySnapshot,
        artifact_bytes: bytes,
        process: _ProcessStat,
        document: dict[str, object],
    ) -> None:
        self._runner = runner
        self._server = server
        self._selector = selector
        self._started = started
        self._ownership = ownership
        self._network = network
        self._baseline = baseline
        self._artifact_bytes = artifact_bytes
        self._process = process
        self._document = copy.deepcopy(document)
        self._state = "admitted"
        self._cleanup_history: list[dict[str, object]] = []

    def __enter__(self) -> AndroidLanPeerLease:
        if self._state not in {
            "admitted",
            "capture-ready",
            "capture-validated",
        }:
            raise AndroidLanPeerAdmissionError(
                "android_peer_lease_state_invalid",
                f"Android peer lease cannot enter from {self._state}",
            )
        return self

    def __exit__(
        self, _type: object, value: object, _traceback: object
    ) -> bool | None:
        primary = value if isinstance(value, BaseException) else None
        if primary is not None:
            if self._state != "closed":
                try:
                    self.abort()
                except BaseException as cleanup:
                    _attach_cleanup_failure(
                        primary, cleanup, phase="context-exit-abort"
                    )
            return False
        if self._state == "capture-validated":
            self.close()
        elif self._state != "closed":
            self.abort()
        return None

    def as_document(self) -> dict[str, object]:
        if self._state not in {
            "admitted",
            "capture-ready",
            "capture-validated",
        }:
            raise AndroidLanPeerAdmissionError(
                "android_peer_lease_state_invalid",
                f"Android peer lease document is unavailable from {self._state}",
            )
        return copy.deepcopy(self._document)

    def _capture_revalidation_receipt(self, *, stage: str) -> dict[str, object]:
        identity_receipt = _revalidate_identity(
            self._runner,
            self._selector,
            self._network,
            self._baseline,
            stage=stage,
        )
        pid = _wait_for_pid(self._runner, self._selector, present=True)
        if pid != self._process.pid:
            raise AndroidLanPeerAdmissionError(
                "android_peer_process_drift",
                "Android peer PID changed before packet capture",
            )
        process_receipt, process = _observe_process(
            self._runner,
            self._selector,
            self._artifact_bytes,
            self._process.pid,
            stage=stage,
        )
        original_receipt = self._document["process_receipt"]
        if (
            not _same_process_identity(self._process, process)
            or type(original_receipt) is not dict
            or process_receipt["socket_descriptor"]
            != original_receipt.get("socket_descriptor")
            or process_receipt["socket_inode"] != original_receipt.get("socket_inode")
        ):
            raise AndroidLanPeerAdmissionError(
                "android_peer_process_drift",
                "Android peer process or listener identity changed before packet capture",
            )
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "document": f"cfw-android-lan-peer-{stage}-revalidation-v1",
            "stage": stage,
            "identity_revalidation": identity_receipt,
            "process_revalidation": process_receipt,
        }
        return copy.deepcopy(receipt)

    def _revalidate_capture_stage(
        self, *, stage: str, expected_state: str, next_state: str
    ) -> dict[str, object]:
        if self._state != expected_state:
            raise AndroidLanPeerAdmissionError(
                "android_peer_lease_state_invalid",
                f"Android peer lease cannot run {stage} from {self._state}",
            )
        self._state = f"validating-{stage}"
        try:
            receipt = self._capture_revalidation_receipt(stage=stage)
        except BaseException as error:
            failure = _typed_failure_context(error, phase=stage)
            self._document["capture_revalidation_failure"] = failure
            self._state = "poisoned"
            if isinstance(error, AndroidLanPeerAdmissionError):
                raise
            if not isinstance(error, Exception):
                raise
            raise AndroidLanPeerAdmissionError(
                "android_peer_capture_revalidation_failed",
                f"Android peer {stage} revalidation failed",
            ) from error
        self._document[f"{stage.replace('-', '_')}_receipt"] = copy.deepcopy(receipt)
        self._state = next_state
        return receipt

    def revalidate_before_capture(self) -> dict[str, object]:
        """Move the one-shot lease from admitted to capture-ready."""

        return self._revalidate_capture_stage(
            stage="before-capture",
            expected_state="admitted",
            next_state="capture-ready",
        )

    def revalidate_after_capture(self) -> dict[str, object]:
        """Move the one-shot lease from capture-ready to capture-validated."""

        return self._revalidate_capture_stage(
            stage="after-capture",
            expected_state="capture-ready",
            next_state="capture-validated",
        )

    def _finish(self, *, outcome: str) -> dict[str, object]:
        receipt: dict[str, object] | None = None
        primary_error: BaseException | None = None
        try:
            receipt = _cleanup_transaction(
                self._runner,
                self._selector,
                self._ownership,
                self._started,
                self._process.pid,
                self._network,
                self._baseline,
                self._cleanup_history,
            )
        except BaseException as error:
            primary_error = error
        try:
            _stop_adb_server(self._runner, self._server)
        except BaseException as error:
            if primary_error is None:
                primary_error = error
            else:
                _attach_cleanup_failure(primary_error, error, phase="adb-server-stop")
        if primary_error is not None:
            raise primary_error
        if receipt is None:
            raise AndroidLanPeerAdmissionError(
                "android_peer_cleanup_unproven",
                "Android LAN peer cleanup did not produce a receipt",
            )
        receipt["outcome"] = outcome
        receipt["capture_state"] = self._state
        if "capture_revalidation_failure" in self._document:
            receipt["lease_failure"] = copy.deepcopy(
                self._document["capture_revalidation_failure"]
            )
        self._state = "closed"
        self._artifact_bytes = b""
        _ADMISSION_LOCK.release()
        return receipt

    def close_with_receipt(self) -> dict[str, object]:
        if self._state != "capture-validated":
            raise AndroidLanPeerAdmissionError(
                "android_peer_lease_state_invalid",
                f"Android peer lease cannot close from {self._state}",
            )
        return self._finish(outcome="capture-complete")

    def close(self) -> dict[str, object]:
        return self.close_with_receipt()

    def abort(self) -> dict[str, object]:
        if self._state == "closed":
            raise AndroidLanPeerAdmissionError(
                "android_peer_lease_state_invalid",
                "Android peer lease cannot abort after close",
            )
        return self._finish(outcome="aborted")


def admit_android_lan_peer(
    *,
    runner: AndroidLanPeerRunner,
    network: AndroidLanNetworkExpectation,
    expected_identity: object,
) -> AndroidLanPeerLease:
    """Verify, deploy, start, and type-observe the sole USB Android peer.

    The current machine has no authorized device, so a production call stops at
    the inventory gate without mutating the device.  Once exactly one device is
    present, all later commands remain source-built and bounded.
    """

    if type(network) is not AndroidLanNetworkExpectation:
        raise AndroidLanPeerAdmissionError(
            "android_peer_network_identity_invalid",
            "Android LAN network expectation must use the source-defined type",
        )
    expected = validate_android_lan_peer_identity(expected_identity)
    if not _ADMISSION_LOCK.acquire(blocking=False):
        raise AndroidLanPeerAdmissionError(
            "android_peer_admission_busy",
            "another Android LAN peer admission is active in this process",
        )
    selector: _DeviceSelector | None = None
    server: _AdbServerLease | None = None
    started: StartedPeerCommand | None = None
    process_pid: int | None = None
    baseline: _IdentitySnapshot | None = None
    ownership = _DeploymentOwnership()
    cleanup_proven = False
    server_stop_proven = False
    cleanup_history: list[dict[str, object]] = []
    try:
        artifact_bytes = _validate_host_inputs()
        server = _start_adb_server(runner)
        selector, baseline, identity, identity_provenance = _collect_identity(
            runner, network, server
        )
        if identity != expected:
            raise AndroidLanPeerAdmissionError(
                "android_peer_expected_identity_mismatch",
                "live Android peer identity differs from the source-pinned expectation",
            )
        deployment = _deploy(runner, selector, artifact_bytes, ownership)
        post_deploy = _revalidate_identity(
            runner,
            selector,
            network,
            baseline,
            stage="post-deploy",
        )
        start_spec = _remote_spec(
            "android-peer-process",
            selector,
            REMOTE_ARTIFACT,
            timeout_seconds=PROCESS_TIMEOUT_SECONDS,
            stdout_limit=0,
        )
        try:
            started = runner.start_command(start_spec)
        except Exception as error:
            raise AndroidLanPeerAdmissionError(
                "android_peer_process_start_failed",
                "Android peer process could not be started",
            ) from error
        pid = _wait_for_pid(runner, selector, present=True)
        if pid is None:
            raise AndroidLanPeerAdmissionError(
                "android_peer_pid_invalid", "Android peer PID was not returned"
            )
        process_pid = pid
        process_receipt, process = _observe_process(
            runner, selector, artifact_bytes, pid, stage="admission"
        )
        post_start = _revalidate_identity(
            runner,
            selector,
            network,
            baseline,
            stage="post-start",
        )
        document = {
            "schema_version": SCHEMA_VERSION,
            "document": ADMISSION_DOCUMENT,
            "identity": identity,
            "identity_provenance": identity_provenance,
            "deployment_receipt": deployment,
            "post_deploy_identity_receipt": post_deploy,
            "process_receipt": process_receipt,
            "post_start_identity_receipt": post_start,
        }
        return AndroidLanPeerLease(
            runner=runner,
            server=server,
            selector=selector,
            started=started,
            ownership=ownership,
            network=network,
            baseline=baseline,
            artifact_bytes=artifact_bytes,
            process=process,
            document=document,
        )
    except BaseException as primary:
        if selector is not None:
            try:
                if baseline is None:
                    raise AndroidLanPeerAdmissionError(
                        "android_peer_cleanup_unproven",
                        "Android cleanup identity baseline is unavailable",
                    )
                _cleanup_transaction(
                    runner,
                    selector,
                    ownership,
                    started,
                    process_pid,
                    network,
                    baseline,
                    cleanup_history,
                )
                cleanup_proven = True
            except BaseException as cleanup_error:
                if isinstance(primary, AndroidLanPeerAdmissionError):
                    primary.attach_cleanup_context(cleanup_error)
                else:
                    _attach_cleanup_failure(
                        primary, cleanup_error, phase="admission-abort"
                    )
        else:
            cleanup_proven = True
        if server is not None:
            try:
                _stop_adb_server(runner, server)
                server_stop_proven = True
            except BaseException as server_error:
                if isinstance(primary, AndroidLanPeerAdmissionError):
                    primary.attach_cleanup_context(server_error)
                else:
                    _attach_cleanup_failure(primary, server_error, phase="adb-server-stop")
        else:
            server_stop_proven = True
        if cleanup_proven and server_stop_proven:
            _ADMISSION_LOCK.release()
        raise


def discover_android_lan_peer_identity(
    *,
    runner: AndroidLanPeerRunner,
    network: AndroidLanNetworkExpectation,
) -> dict[str, object]:
    """Observe a strict redacted identity without mutating the Android device."""

    if type(network) is not AndroidLanNetworkExpectation:
        raise AndroidLanPeerAdmissionError(
            "android_peer_network_identity_invalid",
            "Android LAN network expectation must use the source-defined type",
        )
    if not _ADMISSION_LOCK.acquire(blocking=False):
        raise AndroidLanPeerAdmissionError(
            "android_peer_admission_busy",
            "another Android LAN peer admission is active in this process",
        )
    server: _AdbServerLease | None = None
    try:
        _validate_host_inputs()
        server = _start_adb_server(runner)
        _selector, _baseline, identity, provenance = _collect_identity(
            runner, network, server
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "document": DISCOVERY_DOCUMENT,
            "identity": validate_android_lan_peer_identity(identity),
            "identity_provenance": copy.deepcopy(provenance),
        }
    finally:
        try:
            if server is not None:
                _stop_adb_server(runner, server)
        finally:
            _ADMISSION_LOCK.release()


__all__ = [
    "ADB",
    "ADB_SHA256",
    "ADB_VERSION",
    "ADMISSION_DOCUMENT",
    "DISCOVERY_DOCUMENT",
    "ARTIFACT_SHA256",
    "ARTIFACT_SIZE",
    "AndroidLanNetworkExpectation",
    "AndroidLanPeerAdmissionError",
    "AndroidLanPeerLease",
    "IDENTITY_DOCUMENT",
    "LISTENER_PORT",
    "LOCAL_ARTIFACT",
    "REMOTE_ARTIFACT",
    "REMOTE_DIRECTORY",
    "admit_android_lan_peer",
    "discover_android_lan_peer_identity",
    "validate_android_lan_peer_identity",
]
