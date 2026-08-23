"""Bounded subprocess execution with complete process-group cleanup."""

from __future__ import annotations

import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
from typing import Mapping, Sequence


class BoundedProcessError(RuntimeError):
    """A command exceeded a hard boundary or could not be cleaned up."""

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.stdout = stdout
        self.stderr = stderr


def _group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # macOS can transiently report EPERM for an orphaned group while a
        # killed descendant is being reparented and reaped. Treat that as
        # "possibly still present" and keep the bounded cleanup wait armed.
        return True
    return True


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError as error:
        raise BoundedProcessError(
            "cleanup",
            "bounded command process group cannot be terminated",
        ) from error
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        raise BoundedProcessError(
            "cleanup",
            "bounded command leader did not terminate after SIGKILL",
        ) from error
    deadline = time.monotonic() + 5
    while _group_exists(process.pid):
        if time.monotonic() >= deadline:
            raise BoundedProcessError(
                "cleanup",
                "bounded command descendants did not terminate after SIGKILL",
            )
        time.sleep(0.01)


def run_bounded_process(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    output_limit: int,
) -> subprocess.CompletedProcess[bytes]:
    if (
        not command
        or any(not isinstance(value, str) or not value for value in command)
        or not cwd.is_absolute()
        or not environment
        or timeout <= 0
        or output_limit <= 0
    ):
        raise BoundedProcessError("invalid", "bounded command contract is invalid")
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise BoundedProcessError("start", "bounded command could not start") from error
    if process.stdout is None or process.stderr is None:
        _terminate_group(process)
        raise BoundedProcessError("start", "bounded command output pipes are unavailable")

    streams = (process.stdout, process.stderr)
    buffers: dict[int, bytearray] = {}
    selector: selectors.BaseSelector | None = None
    try:
        buffers = {
            process.stdout.fileno(): bytearray(),
            process.stderr.fileno(): bytearray(),
        }
        selector = selectors.DefaultSelector()
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        failure: BoundedProcessError | None = None
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = BoundedProcessError("timeout", "bounded command timed out")
                break
            try:
                events = selector.select(min(remaining, 0.25))
            except InterruptedError:
                continue
            for key, _events in events:
                while True:
                    try:
                        chunk = os.read(key.fd, 64 * 1024)
                    except BlockingIOError:
                        break
                    if not chunk:
                        selector.unregister(key.fileobj)
                        break
                    current_size = sum(len(value) for value in buffers.values())
                    if len(chunk) > output_limit - current_size:
                        failure = BoundedProcessError(
                            "output-limit",
                            "bounded command output exceeded its fixed limit",
                        )
                        break
                    buffers[key.fd].extend(chunk)
                if failure is not None:
                    break
            if failure is not None:
                break
        if failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = BoundedProcessError("timeout", "bounded command timed out")
            else:
                try:
                    returncode = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    failure = BoundedProcessError(
                        "timeout", "bounded command timed out"
                    )
        if failure is not None:
            _terminate_group(process)
            raise BoundedProcessError(
                failure.reason,
                str(failure),
                stdout=bytes(buffers[process.stdout.fileno()]),
                stderr=bytes(buffers[process.stderr.fileno()]),
            )
        if _group_exists(process.pid):
            _terminate_group(process)
            raise BoundedProcessError(
                "descendant",
                "bounded command left a descendant process running",
                stdout=bytes(buffers[process.stdout.fileno()]),
                stderr=bytes(buffers[process.stderr.fileno()]),
            )
        return subprocess.CompletedProcess(
            list(command),
            returncode,
            bytes(buffers[process.stdout.fileno()]),
            bytes(buffers[process.stderr.fileno()]),
        )
    except BoundedProcessError:
        if process.poll() is None or _group_exists(process.pid):
            _terminate_group(process)
        raise
    except BaseException:
        _terminate_group(process)
        raise
    finally:
        try:
            if selector is not None:
                selector.close()
        finally:
            for stream in streams:
                stream.close()


__all__ = ["BoundedProcessError", "run_bounded_process"]
