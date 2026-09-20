"""Fixed terminal checkpoints and signal cancellation for performance capture."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import select
import signal
import stat
from types import FrameType
from typing import Any, Callable, Final, Protocol

from .performance import (
    MODE_CHANGE_TIMEOUT_SECONDS,
    PRIVILEGE_PREFLIGHT_INSTRUCTION,
    RECOVERY_PREFLIGHT_INSTRUCTION,
    PerformanceOperator,
)


MAX_CONFIRMATION_BYTES: Final = 256
PREFLIGHT_CONFIRMATION_TIMEOUT_SECONDS: Final = 10 * 60

_MODE_RULES: Final = {
    "transition-series-precondition": ("system_proxy", 0, 0),
    "transition-series-start": ("off", 0, 0),
    "connect-latency": ("tunnel", 0, 19),
    "disconnect-latency": ("off", 0, 19),
    "throughput-libbox-baseline": ("system_proxy", 0, 19),
    "throughput-tunnel": ("tunnel", 0, 19),
    "mode-switch-cycle": ("alternating", 0, 100),
    "three-hour-soak": ("tunnel", 0, 0),
}


class PerformanceOperatorAdapterError(RuntimeError):
    """A fixed operator checkpoint or cancellation boundary failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CheckpointPrompt(Protocol):
    def request(self, message: str, *, deadline: datetime) -> str: ...


class TerminalCheckpointPrompt:
    """Bounded confirmation input from the fixed controlling terminal."""

    def __init__(self, cancelled: Callable[[], bool]) -> None:
        if not callable(cancelled):
            raise PerformanceOperatorAdapterError(
                "invalid_cancellation", "terminal cancellation source is not callable"
            )
        self._cancelled = cancelled

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise PerformanceOperatorAdapterError(
                    "operator_terminal_unavailable",
                    "operator terminal could not display its fixed checkpoint",
                )
            offset += written

    def request(self, message: str, *, deadline: datetime) -> str:
        if (
            not isinstance(message, str)
            or not message
            or "\x00" in message
            or not isinstance(deadline, datetime)
            or deadline.utcoffset() is None
        ):
            raise PerformanceOperatorAdapterError(
                "operator_checkpoint_invalid", "operator checkpoint is not canonical"
            )
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOCTTY | os.O_NOFOLLOW
        try:
            descriptor = os.open("/dev/tty", flags)
        except OSError as error:
            raise PerformanceOperatorAdapterError(
                "operator_terminal_unavailable",
                "fixed controlling terminal /dev/tty is unavailable",
            ) from error
        try:
            if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
                raise PerformanceOperatorAdapterError(
                    "operator_terminal_unsafe", "/dev/tty is not a character device"
                )
            self._write_all(descriptor, message.encode("utf-8"))
            collected = bytearray()
            while True:
                if self._cancelled():
                    raise PerformanceOperatorAdapterError(
                        "performance_capture_cancelled",
                        "operator checkpoint was cancelled",
                    )
                remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
                if remaining <= 0:
                    raise PerformanceOperatorAdapterError(
                        "operator_checkpoint_timeout",
                        "operator checkpoint exceeded its fixed deadline",
                    )
                ready, _, _ = select.select(
                    [descriptor], [], [], min(remaining, 0.25)
                )
                if not ready:
                    continue
                chunk = os.read(descriptor, 64)
                if not chunk:
                    raise PerformanceOperatorAdapterError(
                        "operator_terminal_unavailable",
                        "operator terminal closed before confirmation",
                    )
                newline = chunk.find(b"\n")
                if newline >= 0:
                    collected.extend(chunk[:newline])
                    break
                collected.extend(chunk)
                if len(collected) > MAX_CONFIRMATION_BYTES:
                    raise PerformanceOperatorAdapterError(
                        "operator_confirmation_too_large",
                        "operator confirmation exceeded its fixed byte bound",
                    )
            if len(collected) > MAX_CONFIRMATION_BYTES or b"\r" in collected:
                raise PerformanceOperatorAdapterError(
                    "operator_confirmation_invalid",
                    "operator confirmation is not one canonical line",
                )
            try:
                return collected.decode("ascii", errors="strict")
            except UnicodeDecodeError as error:
                raise PerformanceOperatorAdapterError(
                    "operator_confirmation_invalid",
                    "operator confirmation is not canonical ASCII",
                ) from error
        finally:
            os.close(descriptor)


class TerminalPerformanceOperator(PerformanceOperator):
    """Interactive adapter whose confirmations are never treated as evidence."""

    def __init__(
        self,
        prompt: CheckpointPrompt,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._prompt = prompt
        self._now = now

    def request_terminal_mode(
        self,
        mode: str,
        *,
        reason: str,
        iteration: int,
        deadline: datetime,
    ) -> None:
        rule = _MODE_RULES.get(reason)
        if rule is None or type(iteration) is not int:
            raise PerformanceOperatorAdapterError(
                "operator_checkpoint_invalid",
                "performance requested an unknown terminal-mode checkpoint",
            )
        expected_mode, minimum, maximum = rule
        if expected_mode == "alternating":
            expected_mode = "system_proxy" if iteration % 2 == 0 else "tunnel"
        current = self._now()
        if (
            not isinstance(current, datetime)
            or current.utcoffset() is None
            or not isinstance(deadline, datetime)
            or deadline.utcoffset() is None
        ):
            raise PerformanceOperatorAdapterError(
                "operator_checkpoint_invalid",
                "terminal-mode checkpoint requires timezone-aware clocks",
            )
        now = current.astimezone(timezone.utc)
        normalized_deadline = deadline.astimezone(timezone.utc)
        if (
            mode != expected_mode
            or not minimum <= iteration <= maximum
            or normalized_deadline <= now
            or normalized_deadline
            > now + timedelta(seconds=MODE_CHANGE_TIMEOUT_SECONDS + 1)
        ):
            raise PerformanceOperatorAdapterError(
                "operator_checkpoint_invalid",
                "terminal-mode checkpoint differs from the source-owned schedule",
            )
        token = f"confirm mode {mode} {reason} {iteration}"
        answer = self._prompt.request(
            "\nSet the signed app to terminal mode "
            f"{mode!r} for {reason} iteration {iteration}.\n"
            f"Type exactly: {token}\n> ",
            deadline=normalized_deadline,
        )
        if answer != token:
            raise PerformanceOperatorAdapterError(
                "operator_confirmation_mismatch",
                "operator did not enter the exact mode checkpoint token",
            )

    def confirm_privileged_preflight(self, instruction: str) -> None:
        if instruction not in {
            PRIVILEGE_PREFLIGHT_INSTRUCTION,
            RECOVERY_PREFLIGHT_INSTRUCTION,
        }:
            raise PerformanceOperatorAdapterError(
                "operator_checkpoint_invalid",
                "privileged checkpoint differs from the fixed producer contract",
            )
        token = "confirm sudo-ready"
        current = self._now()
        if not isinstance(current, datetime) or current.utcoffset() is None:
            raise PerformanceOperatorAdapterError(
                "operator_checkpoint_invalid",
                "privileged checkpoint requires a timezone-aware clock",
            )
        deadline = current.astimezone(timezone.utc) + timedelta(
            seconds=PREFLIGHT_CONFIRMATION_TIMEOUT_SECONDS
        )
        answer = self._prompt.request(
            f"\n{instruction}\nType exactly: {token}\n> ", deadline=deadline
        )
        if answer != token:
            raise PerformanceOperatorAdapterError(
                "operator_confirmation_mismatch",
                "operator did not enter the exact sudo checkpoint token",
            )


class SignalCancellation:
    """Convert SIGINT/SIGTERM into cooperative producer cancellation."""

    def __init__(self) -> None:
        self._cancelled = False
        self._previous: dict[int, Any] = {}

    def cancelled(self) -> bool:
        return self._cancelled

    def _handle(self, _number: int, _frame: FrameType | None) -> None:
        self._cancelled = True

    def __enter__(self) -> SignalCancellation:
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                self._previous[number] = signal.getsignal(number)
                signal.signal(number, self._handle)
        except (ValueError, OSError) as error:
            for number, handler in self._previous.items():
                signal.signal(number, handler)
            raise PerformanceOperatorAdapterError(
                "signal_boundary_unavailable",
                "collector signal cancellation must be installed on the main thread",
            ) from error
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        for number, handler in self._previous.items():
            signal.signal(number, handler)
        self._previous.clear()


__all__ = [
    "CheckpointPrompt",
    "PerformanceOperatorAdapterError",
    "SignalCancellation",
    "TerminalCheckpointPrompt",
    "TerminalPerformanceOperator",
]
