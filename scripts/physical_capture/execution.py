"""Bounded execution for source-reviewed physical-evidence probes.

This module deliberately does not expose a command-line interface.  Probe
adapters construct :class:`CommandSpec` values in source; callers cannot pass an
arbitrary command through the production collector.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from typing import Callable, Mapping, Sequence


MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 4096
MAX_STREAM_BYTES = 1024 * 1024
MAX_TIMEOUT_SECONDS = 600.0
TERMINATION_GRACE_SECONDS = 1.0
MAX_READINESS_LINE_BYTES = 4096
ROLE_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
FIXED_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
    "ADB_MDNS": "0",
}
_FIXED_ENVIRONMENT_KEYS = frozenset(FIXED_ENVIRONMENT)
_CONTROLLED_EXTRA_ENVIRONMENT_KEYS = frozenset(
    {
        "HOME",
        "ANDROID_USER_HOME",
        "ANDROID_ADB_LOG_PATH",
        "ADB_VENDOR_KEYS",
    }
)


class ProbeExecutionError(RuntimeError):
    """A fixed physical probe could not produce a bounded trusted result."""

    def __init__(
        self, message: str, *, result: CommandResult | None = None
    ) -> None:
        super().__init__(message)
        self.result = result


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """One source-reviewed command contract.

    ``argv[0]`` must be an absolute executable path.  ``accepted_exit_codes``
    is intentionally explicit because denial probes use a fixed non-zero exit
    status while normal probes require zero.
    """

    role: str
    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: float
    accepted_exit_codes: frozenset[int] = frozenset({0})
    stdout_limit: int = MAX_STREAM_BYTES
    stderr_limit: int = 0
    # Empty means the normal fixed environment.  Non-empty values are only
    # accepted for source-owned, private-directory bindings such as the
    # Android LAN peer's isolated ADB server workspace.
    environment: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class CommandResult:
    role: str
    argv_sha256: str
    started_at: str
    completed_at: str
    duration_ms: int
    exit_code: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class ReadinessSpec:
    """One exact, bounded line that proves a fixed command became ready.

    Probe adapters construct this value beside their :class:`CommandSpec`.
    It deliberately supports neither regular expressions nor callbacks, so a
    runtime caller cannot turn readiness into a general output predicate.
    """

    stream: str
    line: bytes
    timeout_seconds: float


PopenFactory = Callable[..., subprocess.Popen[bytes]]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_spec(spec: CommandSpec) -> tuple[str, ...]:
    if not isinstance(spec, CommandSpec):
        raise ProbeExecutionError("probe command must use the source-built CommandSpec type")
    if not ROLE_RE.fullmatch(spec.role):
        raise ProbeExecutionError("probe command role is not canonical")
    if not 1 <= len(spec.argv) <= MAX_ARGUMENTS:
        raise ProbeExecutionError("probe command argument count is outside the bound")
    argv: list[str] = []
    total = 0
    for value in spec.argv:
        if (
            not isinstance(value, str)
            or not value
            or "\x00" in value
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise ProbeExecutionError("probe command contains a non-canonical argument")
        try:
            total += len(value.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise ProbeExecutionError("probe command contains invalid Unicode") from error
        argv.append(value)
    if total > MAX_ARGUMENT_BYTES:
        raise ProbeExecutionError("probe command arguments exceed the byte bound")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise ProbeExecutionError("probe executable path must be absolute")
    try:
        metadata = executable.lstat()
    except OSError as error:
        raise ProbeExecutionError("fixed probe executable is unavailable") from error
    if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise ProbeExecutionError("fixed probe executable is not a real executable file")
    if metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022:
        raise ProbeExecutionError("fixed probe executable has an unsafe owner or mode")
    try:
        cwd = spec.cwd.resolve(strict=True)
    except OSError as error:
        raise ProbeExecutionError("probe working directory is unavailable") from error
    if spec.cwd.is_symlink() or not cwd.is_dir():
        raise ProbeExecutionError("probe working directory must be a real directory")
    if (
        not isinstance(spec.timeout_seconds, (int, float))
        or isinstance(spec.timeout_seconds, bool)
        or not 0 < float(spec.timeout_seconds) <= MAX_TIMEOUT_SECONDS
    ):
        raise ProbeExecutionError("probe timeout is outside the fixed bound")
    if (
        not spec.accepted_exit_codes
        or any(
            not isinstance(code, int)
            or isinstance(code, bool)
            or not 0 <= code <= 255
            for code in spec.accepted_exit_codes
        )
    ):
        raise ProbeExecutionError("probe accepted exit-code set is invalid")
    for limit, label in (
        (spec.stdout_limit, "stdout"),
        (spec.stderr_limit, "stderr"),
    ):
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 0 <= limit <= MAX_STREAM_BYTES
        ):
            raise ProbeExecutionError(f"probe {label} limit is outside the bound")
    if not isinstance(spec.environment, tuple):
        raise ProbeExecutionError("probe environment contract is not a tuple")
    if len(spec.environment) > 8:
        raise ProbeExecutionError("probe environment contract exceeds its bound")
    environment: dict[str, str] = {}
    environment_bytes = 0
    for item in spec.environment:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
            or not item[0]
            or "\x00" in item[0]
            or "\x00" in item[1]
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item[0])
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item[1])
            or item[0] in environment
        ):
            raise ProbeExecutionError("probe environment contract is not canonical")
        environment_bytes += len(item[0].encode("utf-8")) + len(item[1].encode("utf-8"))
        if environment_bytes > MAX_ARGUMENT_BYTES:
            raise ProbeExecutionError("probe environment contract exceeds its byte bound")
        environment[item[0]] = item[1]
    unknown = set(environment) - (
        _FIXED_ENVIRONMENT_KEYS | _CONTROLLED_EXTRA_ENVIRONMENT_KEYS
    )
    if unknown:
        raise ProbeExecutionError("probe environment contains an unreviewed variable")
    for key, value in FIXED_ENVIRONMENT.items():
        if key in environment and environment[key] != value:
            raise ProbeExecutionError("probe environment differs from the fixed contract")
    for key in _CONTROLLED_EXTRA_ENVIRONMENT_KEYS & set(environment):
        value = environment[key]
        if not Path(value).is_absolute() or Path(value).is_symlink():
            raise ProbeExecutionError(
                "probe private environment paths must be absolute non-symlinks"
            )
    return tuple(argv)


def _command_environment(spec: CommandSpec) -> dict[str, str]:
    environment = dict(FIXED_ENVIRONMENT)
    environment.update(dict(spec.environment))
    return environment


def _validate_readiness(spec: CommandSpec, readiness: ReadinessSpec) -> None:
    if not isinstance(readiness, ReadinessSpec):
        raise ProbeExecutionError(
            "probe readiness must use the source-built ReadinessSpec type"
        )
    if readiness.stream not in {"stdout", "stderr"}:
        raise ProbeExecutionError("probe readiness stream is not stdout or stderr")
    if (
        not isinstance(readiness.line, bytes)
        or not 1 <= len(readiness.line) <= MAX_READINESS_LINE_BYTES
        or not readiness.line.endswith(b"\n")
        or b"\x00" in readiness.line
        or b"\r" in readiness.line
        or any(
            value != 0x09 and value != 0x0A and not 0x20 <= value <= 0x7E
            for value in readiness.line
        )
    ):
        raise ProbeExecutionError(
            "probe readiness line must be bounded canonical ASCII ending in LF"
        )
    if (
        not isinstance(readiness.timeout_seconds, (int, float))
        or isinstance(readiness.timeout_seconds, bool)
        or not 0 < float(readiness.timeout_seconds) <= float(spec.timeout_seconds)
    ):
        raise ProbeExecutionError(
            "probe readiness timeout is outside the command timeout"
        )
    stream_limit = (
        spec.stdout_limit if readiness.stream == "stdout" else spec.stderr_limit
    )
    if len(readiness.line) > stream_limit:
        raise ProbeExecutionError(
            "probe readiness line exceeds its fixed stream byte bound"
        )


def command_sha256(argv: Sequence[str]) -> str:
    """Bind an argv vector without shell rendering ambiguity."""

    import json

    encoded = json.dumps(
        list(argv), ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait_for_process_group_exit(process_group: int, deadline: float) -> bool:
    while _process_group_exists(process_group):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the complete group even if its original leader already exited."""

    process_group = process.pid
    leader_running = process.poll() is None
    if _process_group_exists(process_group):
        try:
            os.killpg(process_group, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            # Once the leader has been reaped, its numeric process-group ID can
            # be recycled. Never signal an unrelated group. A still-live direct
            # child remains safe to terminate through its Popen handle.
            if leader_running:
                process.terminate()
            else:
                raise ProbeExecutionError(
                    "probe process-group cleanup could not be proven"
                )
    if process.poll() is None:
        try:
            process.wait(timeout=TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
    term_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    if _wait_for_process_group_exit(process_group, term_deadline):
        if process.poll() is None:
            process.wait(timeout=TERMINATION_GRACE_SECONDS)
        return
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError as error:
        raise ProbeExecutionError(
            "probe process-group cleanup could not be proven"
        ) from error
    if process.poll() is None:
        try:
            process.wait(timeout=TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise ProbeExecutionError("probe process group could not be terminated") from error
    kill_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    if not _wait_for_process_group_exit(process_group, kill_deadline):
        raise ProbeExecutionError("probe process group could not be terminated")


class StartedCommand:
    """The sole bounded lifecycle for one already-started fixed command."""

    def __init__(
        self,
        *,
        spec: CommandSpec,
        argv: tuple[str, ...],
        process: subprocess.Popen[bytes],
        monotonic: Callable[[], float],
        wall_clock: Callable[[], datetime],
        started_monotonic: float,
        started_wall: datetime,
    ) -> None:
        if process.stdout is None or process.stderr is None:
            _terminate_process_group(process)
            raise ProbeExecutionError("fixed probe streams are unavailable")
        self._spec = spec
        self._argv = argv
        self._process = process
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._started_monotonic = started_monotonic
        self._started_wall = started_wall
        self._deadline = started_monotonic + float(spec.timeout_seconds)
        # Match subprocess' pipe coordination on Darwin. Kqueue can leave a
        # freshly exec'd child blocked in dyld's synchronous image notification
        # while the parent waits only for pipe readability; poll wakes the pipe
        # lifecycle without weakening any output or time bound.
        self._selector = selectors.PollSelector()
        self._streams: dict[int, tuple[str, int, bytearray]] = {
            process.stdout.fileno(): ("stdout", spec.stdout_limit, bytearray()),
            process.stderr.fileno(): ("stderr", spec.stderr_limit, bytearray()),
        }
        self._result: CommandResult | None = None
        self._cancelled = False
        self._closed = False
        self._readiness_waited = False
        self._readiness: ReadinessSpec | None = None
        try:
            for descriptor in self._streams:
                os.set_blocking(descriptor, False)
                self._selector.register(descriptor, selectors.EVENT_READ)
        except BaseException:
            self._cleanup(terminate=True)
            raise

    def __enter__(self) -> StartedCommand:
        self._require_active()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._result is None:
            self.cancel()

    def _require_active(self) -> None:
        if self._cancelled:
            raise ProbeExecutionError("fixed probe was cancelled")
        if self._closed and self._result is None:
            raise ProbeExecutionError("fixed probe lifecycle is closed")

    def _remaining(self, deadline: float | None = None) -> float:
        selected = self._deadline if deadline is None else min(self._deadline, deadline)
        return selected - self._monotonic()

    def _read_events(self, timeout: float) -> bool:
        read_any = False
        for key, _mask in self._selector.select(max(0.0, timeout)):
            descriptor = key.fd
            try:
                chunk = os.read(descriptor, 64 * 1024)
            except BlockingIOError:
                continue
            if not chunk:
                self._selector.unregister(descriptor)
                continue
            read_any = True
            label, limit, collected = self._streams[descriptor]
            if len(collected) + len(chunk) > limit:
                raise ProbeExecutionError(
                    f"fixed probe {label} exceeded its byte bound"
                )
            collected.extend(chunk)
        return read_any

    def _exact_line_count(self, readiness: ReadinessSpec) -> int:
        collected = next(
            value[2] for value in self._streams.values() if value[0] == readiness.stream
        )
        return bytes(collected).splitlines(keepends=True).count(readiness.line)

    def _drain_after_process_exit(self) -> bool:
        while self._read_events(0.0):
            pass
        return not self._selector.get_map()

    def _cleanup(self, *, terminate: bool) -> None:
        cleanup_error: BaseException | None = None
        if terminate:
            try:
                _terminate_process_group(self._process)
            except BaseException as error:
                cleanup_error = error
        if not self._closed:
            try:
                self._selector.close()
            except BaseException as error:
                cleanup_error = cleanup_error or error
            finally:
                for stream in (self._process.stdout, self._process.stderr):
                    if stream is None:
                        continue
                    try:
                        stream.close()
                    except BaseException as error:
                        cleanup_error = cleanup_error or error
                self._closed = True
        if cleanup_error is not None:
            raise cleanup_error

    def wait_for_readiness(self, readiness: ReadinessSpec) -> None:
        """Wait once for one source-declared exact output line."""

        self._require_active()
        if self._result is not None:
            raise ProbeExecutionError("fixed probe already completed")
        if self._readiness_waited:
            raise ProbeExecutionError("fixed probe readiness was already consumed")
        try:
            _validate_readiness(self._spec, readiness)
            self._readiness_waited = True
            self._readiness = readiness
            readiness_deadline = self._monotonic() + float(
                readiness.timeout_seconds
            )
            while True:
                ready_count = self._exact_line_count(readiness)
                if ready_count == 1:
                    return
                if ready_count > 1:
                    raise ProbeExecutionError(
                        "fixed probe emitted its exact readiness line more than once"
                    )
                return_code = self._process.poll()
                if return_code is not None:
                    self._drain_after_process_exit()
                    ready_count = self._exact_line_count(readiness)
                    if ready_count == 1:
                        return
                    if ready_count > 1:
                        raise ProbeExecutionError(
                            "fixed probe emitted its exact readiness line more than once"
                        )
                    raise ProbeExecutionError(
                        "fixed probe exited before its exact readiness line"
                    )
                remaining = self._remaining(readiness_deadline)
                if remaining <= 0:
                    raise ProbeExecutionError(
                        "fixed probe exact readiness wait exceeded its timeout"
                    )
                if not self._selector.get_map():
                    raise ProbeExecutionError(
                        "fixed probe streams closed before its exact readiness line"
                    )
                self._read_events(min(remaining, 0.25))
        except BaseException:
            self._cleanup(terminate=True)
            self._cancelled = True
            raise

    def finish(self) -> CommandResult:
        """Drain bounded streams and return the existing CommandResult shape."""

        if self._result is not None:
            return self._result
        self._require_active()
        try:
            while self._selector.get_map():
                return_code = self._process.poll()
                if return_code is not None:
                    if not self._drain_after_process_exit():
                        raise ProbeExecutionError(
                            "fixed probe exited while descendants retained its streams"
                        )
                    break
                remaining = self._remaining()
                if remaining <= 0:
                    raise ProbeExecutionError("fixed probe exceeded its timeout")
                self._read_events(min(remaining, 0.25))
            remaining = self._remaining()
            if remaining <= 0:
                raise ProbeExecutionError("fixed probe exceeded its timeout")
            try:
                return_code = self._process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                raise ProbeExecutionError("fixed probe exceeded its timeout") from error
            if _process_group_exists(self._process.pid):
                raise ProbeExecutionError(
                    "fixed probe exited while descendants remained in its process group"
                )
            completed_wall = self._wall_clock()
            duration_seconds = self._monotonic() - self._started_monotonic
            duration_ms = max(1, int(round(duration_seconds * 1000.0)))
            stdout = bytes(
                next(value[2] for value in self._streams.values() if value[0] == "stdout")
            )
            stderr = bytes(
                next(value[2] for value in self._streams.values() if value[0] == "stderr")
            )
            result = CommandResult(
                role=self._spec.role,
                argv_sha256=command_sha256(self._argv),
                started_at=_timestamp(self._started_wall),
                completed_at=_timestamp(completed_wall),
                duration_ms=duration_ms,
                exit_code=return_code,
                stdout=stdout,
                stderr=stderr,
            )
            if return_code < 0:
                raise ProbeExecutionError("fixed probe terminated by signal")
            if return_code not in self._spec.accepted_exit_codes:
                raise ProbeExecutionError(
                    "fixed probe returned an unexpected exit code",
                    result=result,
                )
            if (
                self._readiness is not None
                and self._exact_line_count(self._readiness) != 1
            ):
                raise ProbeExecutionError(
                    "fixed probe exact readiness line was absent or duplicated at completion",
                    result=result,
                )
            self._result = result
            self._cleanup(terminate=False)
            return self._result
        except BaseException:
            self._cleanup(terminate=True)
            self._cancelled = True
            raise

    def cancel(self) -> None:
        """Idempotently terminate the complete fixed-command process group."""

        if self._result is not None or self._cancelled:
            return
        self._cleanup(terminate=True)
        # A failed cleanup is deliberately retryable.  Marking the lifecycle
        # cancelled before the process-group absence proof succeeds would turn
        # every later cancel into a silent no-op and could strand descendants.
        self._cancelled = True


def start_fixed_command(
    spec: CommandSpec,
    *,
    popen_factory: PopenFactory = subprocess.Popen,
    environment: Mapping[str, str] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    wall_clock: Callable[[], datetime] = _utc_now,
) -> StartedCommand:
    """Start one fixed command without exposing shell, stdin, or caller argv."""

    argv = _validate_spec(spec)
    command_environment = (
        _command_environment(spec) if environment is None else dict(environment)
    )
    if environment is not None and command_environment != FIXED_ENVIRONMENT:
        raise ProbeExecutionError("probe environment differs from the fixed contract")
    started_wall = wall_clock()
    started_monotonic = monotonic()
    try:
        process = popen_factory(
            argv,
            cwd=str(spec.cwd.resolve(strict=True)),
            env=command_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
            text=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ProbeExecutionError("fixed probe could not be started") from error
    try:
        return StartedCommand(
            spec=spec,
            argv=argv,
            process=process,
            monotonic=monotonic,
            wall_clock=wall_clock,
            started_monotonic=started_monotonic,
            started_wall=started_wall,
        )
    except BaseException:
        _terminate_process_group(process)
        raise


def run_fixed_command(
    spec: CommandSpec,
    *,
    popen_factory: PopenFactory = subprocess.Popen,
    environment: Mapping[str, str] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    wall_clock: Callable[[], datetime] = _utc_now,
) -> CommandResult:
    """Execute one fixed command with bounded streams and descendant cleanup."""

    with start_fixed_command(
        spec,
        popen_factory=popen_factory,
        environment=environment,
        monotonic=monotonic,
        wall_clock=wall_clock,
    ) as command:
        return command.finish()


__all__ = [
    "CommandResult",
    "CommandSpec",
    "ProbeExecutionError",
    "ReadinessSpec",
    "StartedCommand",
    "command_sha256",
    "run_fixed_command",
    "start_fixed_command",
]
