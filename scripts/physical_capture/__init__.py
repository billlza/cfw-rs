"""Fail-closed private archive and session primitives for physical collection."""

from .archive import (
    ArchivedFile,
    PendingFile,
    PhysicalCaptureArchiveError,
    SecureArchive,
)
from .session import (
    CaptureEvent,
    CaptureState,
    PhysicalCaptureSession,
    PhysicalCaptureSessionError,
    SessionEventView,
    SessionSnapshot,
    TERMINAL_STATES,
)

__all__ = [
    "ArchivedFile",
    "CaptureEvent",
    "CaptureState",
    "PendingFile",
    "PhysicalCaptureArchiveError",
    "PhysicalCaptureSession",
    "PhysicalCaptureSessionError",
    "SecureArchive",
    "SessionEventView",
    "SessionSnapshot",
    "TERMINAL_STATES",
]
