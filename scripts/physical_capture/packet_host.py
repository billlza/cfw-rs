"""Fixed inherited-FD launcher for the signed Packet evidence Host.

The production entry point accepts no executable, argv, environment, profile,
network configuration, or socket path. It accepts only one of thirteen
source-owned Packet case identifiers, launches the installed final Host with one exact flag,
passes one unnamed Unix stream as descriptor 3, and validates the Host's
OS-bound PID before any network transaction can be admitted.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import array
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import struct
import threading
import time
from typing import Any, Callable, Final, Iterator

from scripts.harness.raw_artifacts import canonical_json, exact_object, load_json_bytes


HOST_EXECUTABLE: Final = Path(
    "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"
)
HOST_ARGV: Final = (str(HOST_EXECUTABLE), "--physical-packet-evidence-v5")
CONTROL_FD: Final = 3
PROTOCOL_VERSION: Final = 5
MAX_FRAME_BYTES: Final = 16 * 1024
IO_TIMEOUT_SECONDS: Final = 10.0
TRANSACTION_IO_TIMEOUT_SECONDS: Final = 180.0
TERMINATION_GRACE_SECONDS: Final = 2.0
# Longer than the complete 180-second staged I/O budget. The credential is
# checked once by the actor-owning Host and is never refreshed mid-transaction.
SESSION_LIFETIME_MS: Final = 300_000
FIXED_ENVIRONMENT: Final = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
}
_SESSION_ID_RE = re.compile(r"^[0-9a-f]{64}$")
PACKET_CASE_IDS: Final = frozenset(
    {
        "tcp-ipv4",
        "tcp-ipv6",
        "udp",
        "quic",
        "dns-a-primary",
        "dns-a-secondary",
        "dns-aaaa-primary",
        "dns-aaaa-secondary",
        "lan-bypass",
        "included-routes",
        "excluded-routes",
        "stop-cleanup",
        "ipv6-disabled-absence",
    }
)


class PacketCaptureDisposition(Enum):
    """Closed collector result accepted by the Host transaction."""

    COMPLETE = "complete"
    COMMAND_FAILED = "command_failed"
    EVIDENCE_REJECTED = "evidence_rejected"
    ARCHIVE_FAILED = "archive_failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class PacketHostSnapshot:
    config_digest: str | None
    desired_mode: str
    generation: int
    ipv6_enabled: bool
    owner: str | None
    phase: str
    ready: bool


@dataclass(frozen=True, slots=True)
class PacketHostBaseline:
    baseline: PacketHostSnapshot
    baseline_observation_sequence: int
    case_id: str
    session_id: str


@dataclass(frozen=True, slots=True)
class PacketHostTestReady:
    case_id: str
    session_id: str
    test: PacketHostSnapshot
    test_observation_sequence: int


@dataclass(frozen=True, slots=True)
class PacketHostRestored:
    baseline: PacketHostSnapshot
    baseline_observation_sequence: int
    case_id: str
    restore: PacketHostSnapshot
    restore_observation_sequence: int
    session_id: str
    test: PacketHostSnapshot | None
    test_observation_sequence: int | None


@dataclass(frozen=True, slots=True)
class PacketHostAborted:
    baseline: PacketHostSnapshot
    baseline_observation_sequence: int
    case_id: str
    code: str
    session_id: str


@dataclass(frozen=True, slots=True)
class PacketHostReceipt:
    baseline: PacketHostSnapshot
    baseline_observation_sequence: int
    candidate_observation_sequence: int
    case_id: str
    restore: PacketHostSnapshot
    restore_observation_sequence: int
    session_id: str
    test: PacketHostSnapshot
    test_observation_sequence: int


class PacketHostError(RuntimeError):
    """The fixed Host transport is unavailable, ambiguous, or unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.cleanup_code: str | None = None
        self.cleanup_context: str | None = None

    def attach_cleanup_context(self, cleanup_error: BaseException) -> None:
        """Retain this primary failure while exposing a secondary cleanup failure."""

        cleanup_code, cleanup_context = _cleanup_error_details(cleanup_error)
        self.cleanup_code = cleanup_code
        self.cleanup_context = cleanup_context
        self.add_note(
            "Packet Host process-group cleanup also failed "
            f"[{cleanup_code}]: {cleanup_context}"
        )


def _cleanup_error_details(cleanup_error: BaseException) -> tuple[str, str]:
    if isinstance(cleanup_error, PacketHostError):
        return cleanup_error.code, str(cleanup_error)
    if isinstance(cleanup_error, OSError):
        return (
            "host_cleanup_unexpected",
            f"{type(cleanup_error).__name__}(errno={cleanup_error.errno})",
        )
    return "host_cleanup_unexpected", type(cleanup_error).__name__


def _attach_process_group_cleanup_context(
    primary_error: BaseException, cleanup_error: BaseException
) -> None:
    if isinstance(primary_error, PacketHostError):
        primary_error.attach_cleanup_context(cleanup_error)
        return
    cleanup_code, cleanup_context = _cleanup_error_details(cleanup_error)
    primary_error.add_note(
        "Packet Host process-group cleanup also failed "
        f"[{cleanup_code}]: {cleanup_context}"
    )


def _validate_host_executable() -> None:
    try:
        metadata = HOST_EXECUTABLE.lstat()
    except OSError as error:
        raise PacketHostError(
            "host_executable_unavailable",
            "the installed Packet evidence Host executable is unavailable",
        ) from error
    if (
        HOST_EXECUTABLE.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
        or not os.access(HOST_EXECUTABLE, os.X_OK)
    ):
        raise PacketHostError(
            "host_executable_unsafe",
            "the installed Packet evidence Host executable has unsafe identity or mode",
        )


def _open_fds() -> tuple[int, ...]:
    try:
        names = os.listdir("/dev/fd")
    except OSError as error:
        raise PacketHostError(
            "descriptor_inventory_unavailable",
            "open descriptor inventory is unavailable before Host launch",
        ) from error
    descriptors: list[int] = []
    for name in names:
        if not name.isascii() or not name.isdecimal():
            continue
        descriptor = int(name)
        if descriptor < 3:
            continue
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError:
            continue
        descriptors.append(descriptor)
    return tuple(sorted(set(descriptors)))


@contextmanager
def _child_cloexec_boundary() -> Iterator[None]:
    """Temporarily mark every unrelated open descriptor close-on-exec."""

    if threading.active_count() != 1:
        raise PacketHostError(
            "multithreaded_spawn_refused",
            "Packet evidence Host launch requires the single-threaded collector boundary",
        )
    changed: list[int] = []
    try:
        for descriptor in _open_fds():
            try:
                if os.get_inheritable(descriptor):
                    os.set_inheritable(descriptor, False)
                    changed.append(descriptor)
            except OSError as error:
                raise PacketHostError(
                    "descriptor_sealing_failed",
                    "an open descriptor could not be sealed before Host launch",
                ) from error
        yield
    finally:
        restoration_error: OSError | None = None
        for descriptor in changed:
            try:
                os.set_inheritable(descriptor, True)
            except OSError as error:
                restoration_error = restoration_error or error
        if restoration_error is not None:
            raise PacketHostError(
                "descriptor_restoration_failed",
                "collector descriptor inheritance could not be restored",
            ) from restoration_error


def _send_frame(channel: socket.socket, value: object) -> None:
    try:
        body = canonical_json(value)
    except Exception as error:
        raise PacketHostError(
            "frame_encoding_failed", "Packet Host frame could not be encoded"
        ) from error
    if not 1 <= len(body) <= MAX_FRAME_BYTES:
        raise PacketHostError(
            "frame_bound_exceeded", "Packet Host frame is outside its byte bound"
        )
    try:
        channel.sendall(struct.pack("!I", len(body)) + body)
    except OSError as error:
        raise PacketHostError(
            "frame_write_failed", "Packet Host frame could not be written"
        ) from error


def _recv_exact_no_ancillary(channel: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        buffer = bytearray(length - len(output))
        try:
            count, ancillary, flags, _address = channel.recvmsg_into(
                [buffer], socket.CMSG_SPACE(4 * 8)
            )
        except OSError as error:
            raise PacketHostError(
                "frame_read_failed", "Packet Host frame could not be read"
            ) from error
        ancillary_cleanup_failed = False
        if ancillary:
            for level, kind, payload in ancillary:
                if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                    continue
                descriptors = array.array("i")
                descriptors.frombytes(
                    payload[: len(payload) - (len(payload) % descriptors.itemsize)]
                )
                for descriptor in descriptors:
                    try:
                        os.close(descriptor)
                    except OSError:
                        ancillary_cleanup_failed = True
        if ancillary_cleanup_failed:
            raise PacketHostError(
                "ancillary_descriptor_cleanup_failed",
                "received ancillary descriptors could not be closed",
            )
        if ancillary or flags & socket.MSG_CTRUNC:
            raise PacketHostError(
                "ancillary_descriptor_rejected",
                "Packet Host frame carried ancillary descriptors",
            )
        if count == 0:
            raise PacketHostError(
                "frame_truncated", "Packet Host frame ended before its declared length"
            )
        output.extend(buffer[:count])
    return bytes(output)


def _receive_frame(channel: socket.socket) -> dict[str, Any]:
    length = struct.unpack("!I", _recv_exact_no_ancillary(channel, 4))[0]
    if not 1 <= length <= MAX_FRAME_BYTES:
        raise PacketHostError(
            "frame_bound_exceeded", "Packet Host frame is outside its byte bound"
        )
    body = _recv_exact_no_ancillary(channel, length)
    try:
        value = load_json_bytes(body, "Packet Host frame")
        if canonical_json(value) != body or not isinstance(value, dict):
            raise ValueError("frame is not an exact canonical object")
        return value
    except Exception as error:
        raise PacketHostError(
            "frame_invalid", "Packet Host frame is not exact canonical JSON"
        ) from error


def _reap_child_nonblocking(pid: int) -> bool:
    try:
        waited, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError as error:
        raise PacketHostError(
            "host_cleanup_unproven", "Packet Host child ownership was lost"
        ) from error
    if waited == 0:
        return False
    if waited != pid:
        raise PacketHostError(
            "host_cleanup_unproven", "Packet Host child could not be reaped"
        )
    return True


def _signal_process_group(
    pid: int, selected_signal: signal.Signals, *, child_reaped: bool
) -> tuple[bool, bool]:
    """Signal the owned group, resolving macOS's zombie-leader EPERM race."""

    for _attempt in range(2):
        try:
            os.killpg(pid, selected_signal)
            return True, child_reaped
        except ProcessLookupError:
            return False, child_reaped
        except PermissionError as error:
            if child_reaped:
                # Darwin can retain an already-signalled descendant as a
                # transient zombie and report EPERM for the whole group. This
                # proves only that the group still exists; disappearance is
                # still required by the bounded TERM/KILL cleanup below.
                return True, True
            if not child_reaped and _reap_child_nonblocking(pid):
                child_reaped = True
                continue
            raise PacketHostError(
                "host_cleanup_unproven",
                "Packet Host process-group cleanup is unproven",
            ) from error
    raise PacketHostError(
        "host_cleanup_unproven", "Packet Host process-group cleanup is unproven"
    )


def _process_group_exists_after_reap(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Darwin reports EPERM while an already-signalled descendant is a
        # transient zombie. Signal zero still proves that the group exists;
        # the bounded disappearance deadline below remains fail closed.
        return True
    return True


def _terminate_process_group(pid: int) -> None:
    child_reaped = _reap_child_nonblocking(pid)
    group_exists, child_reaped = _signal_process_group(
        pid, signal.SIGTERM, child_reaped=child_reaped
    )
    if child_reaped and not group_exists:
        return
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    while time.monotonic() < deadline:
        if not child_reaped:
            child_reaped = _reap_child_nonblocking(pid)
        if child_reaped:
            group_exists = _process_group_exists_after_reap(pid)
            if not group_exists:
                return
        time.sleep(0.01)

    group_exists, child_reaped = _signal_process_group(
        pid, signal.SIGKILL, child_reaped=child_reaped
    )
    if not child_reaped:
        if not group_exists:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError as error:
                raise PacketHostError(
                    "host_cleanup_unproven",
                    "Packet Host direct-child cleanup is unproven",
                ) from error

    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    while time.monotonic() < deadline:
        if not child_reaped:
            child_reaped = _reap_child_nonblocking(pid)
        if child_reaped and not _process_group_exists_after_reap(pid):
            return
        time.sleep(0.01)
    raise PacketHostError(
        "host_cleanup_unproven",
        "Packet Host process group remained after forced cleanup",
    )


def _spawn_fixed_host(child_fd: int, parent_fd: int) -> int:
    actions = [
        (os.POSIX_SPAWN_CLOSE, parent_fd),
        (os.POSIX_SPAWN_DUP2, child_fd, CONTROL_FD),
    ]
    if child_fd != CONTROL_FD:
        actions.append((os.POSIX_SPAWN_CLOSE, child_fd))
    try:
        return os.posix_spawn(
            str(HOST_EXECUTABLE),
            HOST_ARGV,
            dict(FIXED_ENVIRONMENT),
            file_actions=actions,
            setsid=True,
            setsigmask=(),
            setsigdef=(signal.SIGPIPE,),
        )
    except OSError as error:
        raise PacketHostError(
            "host_spawn_failed", "the fixed Packet evidence Host could not be launched"
        ) from error


def _exact_host_failure(
    raw: object, *, session_id: str, case_id: str
) -> dict[str, Any]:
    try:
        failure = exact_object(
            raw,
            {"case_id", "code", "document", "schema_version", "sequence", "session_id"},
            "Packet Host failure",
        )
    except Exception as error:
        raise PacketHostError(
            "host_failure_invalid", "Packet Host failure has an invalid field set"
        ) from error
    allowed_codes = {
        "maintenance_busy",
        "legacy_retirement_blocked",
        "tunnel_unavailable",
        "baseline_unavailable",
        "baseline_mismatch",
        "projection_failed",
        "test_apply_failed",
        "test_snapshot_invalid",
        "capture_command_failed",
        "capture_evidence_rejected",
        "capture_archive_failed",
        "capture_cancelled",
        "capture_control_failed",
        "capture_timeout",
        "capture_panicked",
        "restore_unproven_quarantined",
        "restore_mismatch_quarantined",
        "restore_quarantine_failed",
        "observation_failed",
        "completion_closed",
        "session_replayed",
        "session_capacity_exhausted",
        "session_invalid",
        "launcher_ticket_replayed",
        "launcher_ticket_capacity_exhausted",
        "launcher_ticket_invalid",
        "launcher_ticket_store_unavailable",
        "app_control_unavailable",
        "app_identity_invalid",
        "app_control_invalid",
        "app_control_failed",
    }
    if (
        type(failure["schema_version"]) is not int
        or failure["schema_version"] != PROTOCOL_VERSION
        or failure["document"] != "cfw-packet-host-failed-v5"
        or type(failure["sequence"]) is not int
        or failure["sequence"] != 8
        or failure["session_id"] != session_id
        or failure["case_id"] != case_id
        or not isinstance(failure["code"], str)
        or failure["code"] not in allowed_codes
    ):
        raise PacketHostError(
            "host_failure_invalid", "Packet Host failure response is not exact"
        )
    return failure


def _exact_host_snapshot(raw: object, *, context: str) -> PacketHostSnapshot:
    try:
        value = exact_object(
            raw,
            {
                "config_digest",
                "desired_mode",
                "generation",
                "ipv6_enabled",
                "owner",
                "phase",
                "ready",
            },
            context,
        )
    except Exception as error:
        raise PacketHostError(
            "host_snapshot_invalid", "Packet Host state receipt has an invalid field set"
        ) from error
    if (
        type(value["generation"]) is not int
        or value["generation"] <= 0
        or type(value["ipv6_enabled"]) is not bool
        or type(value["ready"]) is not bool
    ):
        raise PacketHostError(
            "host_snapshot_invalid", "Packet Host state receipt is not exact"
        )
    if value["phase"] == "off":
        exact_state = (
            value["desired_mode"] == "off"
            and value["config_digest"] is None
            and value["owner"] is None
            and value["ready"] is False
            and value["ipv6_enabled"] is False
        )
    elif value["phase"] == "tunnel_active":
        exact_state = (
            value["desired_mode"] == "tunnel"
            and isinstance(value["config_digest"], str)
            and _SESSION_ID_RE.fullmatch(value["config_digest"]) is not None
            and value["owner"] == "packet_tunnel_system_extension"
            and value["ready"] is True
        )
    else:
        exact_state = False
    if not exact_state:
        raise PacketHostError(
            "host_snapshot_invalid", "Packet Host state receipt is not exact"
        )
    return PacketHostSnapshot(
        config_digest=value["config_digest"],
        desired_mode=value["desired_mode"],
        generation=value["generation"],
        ipv6_enabled=value["ipv6_enabled"],
        owner=value["owner"],
        phase=value["phase"],
        ready=value["ready"],
    )


def _exact_host_baseline(
    raw: object, *, session_id: str, case_id: str
) -> PacketHostBaseline:
    try:
        value = exact_object(
            raw,
            {
                "baseline",
                "baseline_observation_sequence",
                "case_id",
                "document",
                "schema_version",
                "sequence",
                "session_id",
            },
            "Packet Host baseline",
        )
    except Exception as error:
        raise PacketHostError(
            "host_baseline_invalid", "Packet Host baseline has an invalid field set"
        ) from error
    baseline = _exact_host_snapshot(value["baseline"], context="Packet Host baseline state")
    if (
        value["schema_version"] != PROTOCOL_VERSION
        or type(value["schema_version"]) is not int
        or value["document"] != "cfw-packet-host-baseline-observed-v5"
        or value["sequence"] != 2
        or type(value["sequence"]) is not int
        or value["session_id"] != session_id
        or value["case_id"] != case_id
        or type(value["baseline_observation_sequence"]) is not int
        or value["baseline_observation_sequence"] <= 0
        or baseline.phase != "tunnel_active"
        or baseline.ipv6_enabled is not True
    ):
        raise PacketHostError(
            "host_baseline_invalid", "Packet Host baseline is not exact"
        )
    return PacketHostBaseline(
        baseline=baseline,
        baseline_observation_sequence=value["baseline_observation_sequence"],
        case_id=case_id,
        session_id=session_id,
    )


def _exact_host_test(
    raw: object,
    *,
    baseline: PacketHostBaseline,
    session_id: str,
    case_id: str,
) -> PacketHostTestReady:
    try:
        value = exact_object(
            raw,
            {
                "case_id",
                "document",
                "schema_version",
                "sequence",
                "session_id",
                "test",
                "test_observation_sequence",
            },
            "Packet Host test",
        )
    except Exception as error:
        raise PacketHostError(
            "host_test_invalid", "Packet Host test has an invalid field set"
        ) from error
    test = _exact_host_snapshot(value["test"], context="Packet Host test state")
    expected_phase = "off" if case_id == "stop-cleanup" else "tunnel_active"
    expected_ipv6 = case_id not in {"stop-cleanup", "ipv6-disabled-absence"}
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != PROTOCOL_VERSION
        or value["document"] != "cfw-packet-host-test-observed-v5"
        or type(value["sequence"]) is not int
        or value["sequence"] != 4
        or value["session_id"] != session_id
        or value["case_id"] != case_id
        or type(value["test_observation_sequence"]) is not int
        or value["test_observation_sequence"] <= 0
        or test.generation <= baseline.baseline.generation
        or test.config_digest == baseline.baseline.config_digest
        or test.phase != expected_phase
        or test.ipv6_enabled is not expected_ipv6
    ):
        raise PacketHostError("host_test_invalid", "Packet Host test is not exact")
    return PacketHostTestReady(
        case_id=case_id,
        session_id=session_id,
        test=test,
        test_observation_sequence=value["test_observation_sequence"],
    )


def _exact_host_restored(
    raw: object,
    *,
    baseline: PacketHostBaseline,
    test: PacketHostTestReady | None,
    session_id: str,
    case_id: str,
) -> PacketHostRestored:
    try:
        value = exact_object(
            raw,
            {
                "baseline",
                "baseline_observation_sequence",
                "case_id",
                "document",
                "restore",
                "restore_observation_sequence",
                "schema_version",
                "sequence",
                "session_id",
                "test",
                "test_observation_sequence",
            },
            "Packet Host restore",
        )
    except Exception as error:
        raise PacketHostError(
            "host_restore_invalid", "Packet Host restore has an invalid field set"
        ) from error
    baseline_state = _exact_host_snapshot(
        value["baseline"], context="Packet Host retained baseline state"
    )
    restore = _exact_host_snapshot(value["restore"], context="Packet Host restore state")
    test_state = (
        None
        if value["test"] is None
        else _exact_host_snapshot(value["test"], context="Packet Host retained test state")
    )
    test_matches = (
        test is None
        and test_state is None
        and value["test_observation_sequence"] is None
        and restore.generation >= baseline.baseline.generation
    ) or (
        test is not None
        and test_state == test.test
        and value["test_observation_sequence"] == test.test_observation_sequence
        and restore.generation > test.test.generation
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != PROTOCOL_VERSION
        or value["document"] != "cfw-packet-host-baseline-restored-v5"
        or type(value["sequence"]) is not int
        or value["sequence"] != 6
        or value["session_id"] != session_id
        or value["case_id"] != case_id
        or baseline_state != baseline.baseline
        or value["baseline_observation_sequence"]
        != baseline.baseline_observation_sequence
        or type(value["restore_observation_sequence"]) is not int
        or value["restore_observation_sequence"] <= 0
        or restore.phase != "tunnel_active"
        or restore.ipv6_enabled is not True
        or restore.config_digest != baseline.baseline.config_digest
        or not test_matches
    ):
        raise PacketHostError("host_restore_invalid", "Packet Host restore is not exact")
    return PacketHostRestored(
        baseline=baseline_state,
        baseline_observation_sequence=value["baseline_observation_sequence"],
        case_id=case_id,
        restore=restore,
        restore_observation_sequence=value["restore_observation_sequence"],
        session_id=session_id,
        test=test_state,
        test_observation_sequence=value["test_observation_sequence"],
    )


def _exact_host_aborted(
    raw: object,
    *,
    baseline: PacketHostBaseline,
    session_id: str,
    case_id: str,
) -> PacketHostAborted:
    try:
        value = exact_object(
            raw,
            {
                "baseline",
                "baseline_observation_sequence",
                "case_id",
                "code",
                "document",
                "schema_version",
                "sequence",
                "session_id",
            },
            "Packet Host capture abort",
        )
    except Exception as error:
        raise PacketHostError(
            "host_abort_invalid", "Packet Host capture abort has an invalid field set"
        ) from error
    baseline_state = _exact_host_snapshot(
        value["baseline"], context="Packet Host aborted baseline"
    )
    allowed_codes = {
        "test_apply_failed",
        "test_snapshot_invalid",
        "restore_unproven_quarantined",
        "restore_mismatch_quarantined",
        "restore_quarantine_failed",
        "observation_failed",
    }
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != PROTOCOL_VERSION
        or value["document"] != "cfw-packet-host-capture-aborted-v5"
        or type(value["sequence"]) is not int
        or value["sequence"] != 6
        or value["session_id"] != session_id
        or value["case_id"] != case_id
        or baseline_state != baseline.baseline
        or value["baseline_observation_sequence"]
        != baseline.baseline_observation_sequence
        or value["code"] not in allowed_codes
    ):
        raise PacketHostError(
            "host_abort_invalid", "Packet Host capture abort is not exact"
        )
    return PacketHostAborted(
        baseline=baseline_state,
        baseline_observation_sequence=value["baseline_observation_sequence"],
        case_id=case_id,
        code=value["code"],
        session_id=session_id,
    )


def _exact_host_receipt(
    raw: object,
    *,
    baseline: PacketHostBaseline,
    test: PacketHostTestReady,
    restored: PacketHostRestored,
    session_id: str,
    case_id: str,
) -> PacketHostReceipt:
    try:
        receipt = exact_object(
            raw,
            {
                "baseline",
                "baseline_observation_sequence",
                "candidate_observation_sequence",
                "case_id",
                "document",
                "restore",
                "restore_observation_sequence",
                "schema_version",
                "sequence",
                "session_id",
                "test",
                "test_observation_sequence",
            },
            "Packet Host receipt",
        )
    except Exception as error:
        raise PacketHostError(
            "host_receipt_invalid", "Packet Host receipt has an invalid field set"
        ) from error
    baseline_state = _exact_host_snapshot(
        receipt["baseline"], context="Packet Host completed baseline"
    )
    test_state = _exact_host_snapshot(receipt["test"], context="Packet Host completed test")
    restore_state = _exact_host_snapshot(
        receipt["restore"], context="Packet Host completed restore"
    )
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != PROTOCOL_VERSION
        or receipt["document"] != "cfw-packet-host-completed-v5"
        or type(receipt["sequence"]) is not int
        or receipt["sequence"] != 8
        or receipt["session_id"] != session_id
        or receipt["case_id"] != case_id
        or type(receipt["candidate_observation_sequence"]) is not int
        or receipt["candidate_observation_sequence"] <= 0
        or receipt["candidate_observation_sequence"]
        != receipt["test_observation_sequence"]
        or baseline_state != baseline.baseline
        or receipt["baseline_observation_sequence"]
        != baseline.baseline_observation_sequence
        or test_state != test.test
        or receipt["test_observation_sequence"] != test.test_observation_sequence
        or restore_state != restored.restore
        or receipt["restore_observation_sequence"]
        != restored.restore_observation_sequence
    ):
        raise PacketHostError(
            "host_receipt_invalid", "Packet Host receipt is not exact"
        )
    return PacketHostReceipt(
        baseline=baseline_state,
        baseline_observation_sequence=receipt["baseline_observation_sequence"],
        candidate_observation_sequence=receipt["candidate_observation_sequence"],
        case_id=case_id,
        restore=restore_state,
        restore_observation_sequence=receipt["restore_observation_sequence"],
        session_id=session_id,
        test=test_state,
        test_observation_sequence=receipt["test_observation_sequence"],
    )


def _send_stage_disposition(
    channel: socket.socket,
    *,
    disposition: PacketCaptureDisposition,
    session_id: str,
    case_id: str,
    sequence: int,
    complete_document: str,
    failed_document: str,
) -> None:
    if disposition is PacketCaptureDisposition.COMPLETE:
        value = {
            "case_id": case_id,
            "document": complete_document,
            "schema_version": PROTOCOL_VERSION,
            "sequence": sequence,
            "session_id": session_id,
        }
    else:
        value = {
            "case_id": case_id,
            "code": disposition.value,
            "document": failed_document,
            "schema_version": PROTOCOL_VERSION,
            "sequence": sequence,
            "session_id": session_id,
        }
    _send_frame(channel, value)


def _expected_final_failure_code(
    *,
    terminal: PacketHostRestored | PacketHostAborted,
    prior_disposition: PacketCaptureDisposition | None,
    finish_disposition: PacketCaptureDisposition,
) -> str | None:
    if finish_disposition is not PacketCaptureDisposition.COMPLETE:
        return f"capture_{finish_disposition.value}"
    if isinstance(terminal, PacketHostAborted):
        return terminal.code
    if (
        prior_disposition is not None
        and prior_disposition is not PacketCaptureDisposition.COMPLETE
    ):
        return f"capture_{prior_disposition.value}"
    return None


def run_fixed_host_transaction(
    *,
    case_id: str,
    begin_capture: Callable[[PacketHostBaseline], PacketCaptureDisposition],
    exercise_test: Callable[[PacketHostTestReady], PacketCaptureDisposition],
    finish_capture: Callable[
        [PacketHostRestored | PacketHostAborted], PacketCaptureDisposition
    ],
) -> PacketHostReceipt:
    """Run one source-owned staged Packet case through the actor-owning Host."""

    if type(case_id) is not str or case_id not in PACKET_CASE_IDS:
        raise PacketHostError(
            "case_invalid", "Packet Host case is not one of the source-owned Packet cases"
        )
    if not all(callable(stage) for stage in (begin_capture, exercise_test, finish_capture)):
        raise PacketHostError(
            "capture_invalid", "Packet Host staged capture coordinator is unavailable"
        )

    _validate_host_executable()
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    parent.settimeout(IO_TIMEOUT_SECONDS)
    pid: int | None = None
    primary_error: BaseException | None = None
    try:
        with _child_cloexec_boundary():
            pid = _spawn_fixed_host(child.fileno(), parent.fileno())
        child.close()
        try:
            hello = exact_object(
                _receive_frame(parent),
                {
                    "collector_pid",
                    "collector_uid",
                    "document",
                    "host_pid",
                    "host_uid",
                    "schema_version",
                },
                "Packet Host hello",
            )
        except Exception as error:
            raise PacketHostError(
                "host_hello_invalid", "Packet Host hello has an invalid field set"
            ) from error
        if (
            type(hello["schema_version"]) is not int
            or hello["schema_version"] != PROTOCOL_VERSION
            or hello["document"] != "cfw-packet-host-hello-v5"
            or type(hello["host_pid"]) is not int
            or hello["host_pid"] != pid
            or type(hello["host_uid"]) is not int
            or hello["host_uid"] != os.geteuid()
            or type(hello["collector_pid"]) is not int
            or hello["collector_pid"] != os.getpid()
            or type(hello["collector_uid"]) is not int
            or hello["collector_uid"] != os.geteuid()
        ):
            raise PacketHostError(
                "host_hello_identity_mismatch",
                "Packet Host hello differs from the spawned process identity",
            )

        session_id = secrets.token_hex(32)
        issued_at_unix_ms = time.time_ns() // 1_000_000
        expires_at_unix_ms = issued_at_unix_ms + SESSION_LIFETIME_MS
        _send_frame(
            parent,
            {
                "collector_pid": os.getpid(),
                "collector_uid": os.geteuid(),
                "document": "cfw-packet-collector-hello-v5",
                "expires_at_unix_ms": expires_at_unix_ms,
                "issued_at_unix_ms": issued_at_unix_ms,
                "schema_version": PROTOCOL_VERSION,
                "session_id": session_id,
            },
        )
        _send_frame(
            parent,
            {
                "case_id": case_id,
                "document": "cfw-packet-collector-request-v5",
                "schema_version": PROTOCOL_VERSION,
                "sequence": 1,
                "session_id": session_id,
            },
        )
        parent.settimeout(TRANSACTION_IO_TIMEOUT_SECONDS)
        first = _receive_frame(parent)
        if first.get("document") == "cfw-packet-host-failed-v5":
            failure = _exact_host_failure(
                first, session_id=session_id, case_id=case_id
            )
            raise PacketHostError(
                failure["code"], "Packet Host rejected the evidence transaction"
            )
        baseline = _exact_host_baseline(first, session_id=session_id, case_id=case_id)

        callback_errors: list[Exception] = []

        def invoke_stage(
            callback: Callable[[Any], PacketCaptureDisposition], value: object
        ) -> PacketCaptureDisposition:
            try:
                disposition = callback(value)
                if not isinstance(disposition, PacketCaptureDisposition):
                    raise TypeError(
                        "capture coordinator returned a non-closed disposition"
                    )
                return disposition
            except Exception as error:
                callback_errors.append(error)
                return PacketCaptureDisposition.CANCELLED

        begin_disposition = invoke_stage(begin_capture, baseline)
        _send_stage_disposition(
            parent,
            disposition=begin_disposition,
            session_id=session_id,
            case_id=case_id,
            sequence=3,
            complete_document="cfw-packet-collector-capture-started-v5",
            failed_document="cfw-packet-collector-capture-start-failed-v5",
        )
        progress = _receive_frame(parent)
        if begin_disposition is not PacketCaptureDisposition.COMPLETE:
            if progress.get("document") == "cfw-packet-host-baseline-restored-v5":
                begin_terminal: PacketHostRestored | PacketHostAborted = (
                    _exact_host_restored(
                        progress,
                        baseline=baseline,
                        test=None,
                        session_id=session_id,
                        case_id=case_id,
                    )
                )
            elif progress.get("document") == "cfw-packet-host-capture-aborted-v5":
                begin_terminal = _exact_host_aborted(
                    progress,
                    baseline=baseline,
                    session_id=session_id,
                    case_id=case_id,
                )
            else:
                raise PacketHostError(
                    "host_result_inconsistent",
                    "Packet Host omitted terminal cleanup after capture start failed",
                )
            finish_disposition = invoke_stage(finish_capture, begin_terminal)
            _send_stage_disposition(
                parent,
                disposition=finish_disposition,
                session_id=session_id,
                case_id=case_id,
                sequence=7,
                complete_document="cfw-packet-collector-capture-completed-v5",
                failed_document="cfw-packet-collector-capture-complete-failed-v5",
            )
            final = _receive_frame(parent)
            if final.get("document") != "cfw-packet-host-failed-v5":
                raise PacketHostError(
                    "host_result_inconsistent",
                    "Packet Host reported success after capture start failed",
                )
            failure = _exact_host_failure(final, session_id=session_id, case_id=case_id)
            expected_failure = _expected_final_failure_code(
                terminal=begin_terminal,
                prior_disposition=begin_disposition,
                finish_disposition=finish_disposition,
            )
            if failure["code"] != expected_failure:
                raise PacketHostError(
                    "host_result_inconsistent",
                    "Packet Host failure differs from begin or terminal cleanup",
                )
            if callback_errors and failure["code"] == "capture_cancelled":
                raise PacketHostError(
                    "capture_callback_failed",
                    "Packet capture start callback failed after terminal cleanup",
                ) from callback_errors[0]
            raise PacketHostError(
                failure["code"], "Packet Host rejected capture start after cleanup"
            )
        if progress.get("document") == "cfw-packet-host-failed-v5":
            failure = _exact_host_failure(
                progress, session_id=session_id, case_id=case_id
            )
            raise PacketHostError(
                failure["code"], "Packet Host failed before the test state was observed"
            )

        test: PacketHostTestReady | None
        test_disposition: PacketCaptureDisposition | None = None
        if progress.get("document") == "cfw-packet-host-capture-aborted-v5":
            test = None
            terminal: PacketHostRestored | PacketHostAborted = _exact_host_aborted(
                progress,
                baseline=baseline,
                session_id=session_id,
                case_id=case_id,
            )
        elif progress.get("document") == "cfw-packet-host-baseline-restored-v5":
            test = None
            terminal = _exact_host_restored(
                progress,
                baseline=baseline,
                test=None,
                session_id=session_id,
                case_id=case_id,
            )
        else:
            test = _exact_host_test(
                progress,
                baseline=baseline,
                session_id=session_id,
                case_id=case_id,
            )
            test_disposition = invoke_stage(exercise_test, test)
            _send_stage_disposition(
                parent,
                disposition=test_disposition,
                session_id=session_id,
                case_id=case_id,
                sequence=5,
                complete_document="cfw-packet-collector-test-submitted-v5",
                failed_document="cfw-packet-collector-test-submit-failed-v5",
            )
            restore_frame = _receive_frame(parent)
            if restore_frame.get("document") == "cfw-packet-host-failed-v5":
                failure = _exact_host_failure(
                    restore_frame, session_id=session_id, case_id=case_id
                )
                raise PacketHostError(
                    failure["code"], "Packet Host could not prove baseline restoration"
                )
            if restore_frame.get("document") == "cfw-packet-host-capture-aborted-v5":
                terminal = _exact_host_aborted(
                    restore_frame,
                    baseline=baseline,
                    session_id=session_id,
                    case_id=case_id,
                )
            else:
                terminal = _exact_host_restored(
                    restore_frame,
                    baseline=baseline,
                    test=test,
                    session_id=session_id,
                    case_id=case_id,
                )

        finish_disposition = invoke_stage(finish_capture, terminal)
        _send_stage_disposition(
            parent,
            disposition=finish_disposition,
            session_id=session_id,
            case_id=case_id,
            sequence=7,
            complete_document="cfw-packet-collector-capture-completed-v5",
            failed_document="cfw-packet-collector-capture-complete-failed-v5",
        )
        final = _receive_frame(parent)
        if final.get("document") == "cfw-packet-host-failed-v5":
            failure = _exact_host_failure(
                final, session_id=session_id, case_id=case_id
            )
            expected_failure = _expected_final_failure_code(
                terminal=terminal,
                prior_disposition=test_disposition,
                finish_disposition=finish_disposition,
            )
            if expected_failure is not None and failure["code"] != expected_failure:
                raise PacketHostError(
                    "host_result_inconsistent",
                    "Packet Host terminal failure differs from its cleanup disposition",
                )
            if callback_errors and failure["code"] == "capture_cancelled":
                raise PacketHostError(
                    "capture_callback_failed",
                    "Packet capture callback failed; Host restore completed with a typed result",
                ) from callback_errors[0]
            raise PacketHostError(
                failure["code"], "Packet Host transaction ended after capture cleanup"
            )
        if (
            callback_errors
            or begin_disposition is not PacketCaptureDisposition.COMPLETE
            or test is None
            or not isinstance(terminal, PacketHostRestored)
            or test_disposition is not PacketCaptureDisposition.COMPLETE
            or finish_disposition is not PacketCaptureDisposition.COMPLETE
        ):
            raise PacketHostError(
                "host_result_inconsistent",
                "Packet Host reported success for an incomplete staged capture",
            )
        return _exact_host_receipt(
            final,
            baseline=baseline,
            test=test,
            restored=terminal,
            session_id=session_id,
            case_id=case_id,
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        child.close()
        parent.close()
        if pid is not None:
            try:
                _terminate_process_group(pid)
            except BaseException as cleanup_error:
                if primary_error is None:
                    raise
                _attach_process_group_cleanup_context(primary_error, cleanup_error)


__all__ = [
    "PacketCaptureDisposition",
    "PacketHostAborted",
    "PacketHostBaseline",
    "PacketHostError",
    "PacketHostReceipt",
    "PacketHostRestored",
    "PacketHostSnapshot",
    "PacketHostTestReady",
    "run_fixed_host_transaction",
]
