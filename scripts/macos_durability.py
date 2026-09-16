"""macOS stable-storage barrier shared by release state transitions.

``fsync(2)`` alone does not require macOS storage to flush volatile caches.
Release journals and atomic publication boundaries use ``F_FULLFSYNC`` so a
successful ordering barrier means the preceding writes reached stable storage.
"""

from __future__ import annotations

import errno
import fcntl


def full_fsync(descriptor: int) -> None:
    """Flush one open file or directory descriptor to stable storage."""

    if type(descriptor) is not int or descriptor < 0:
        raise OSError(errno.EINVAL, "full-fsync descriptor must be a non-negative integer")
    operation = getattr(fcntl, "F_FULLFSYNC", None)
    if type(operation) is not int:
        raise OSError(errno.ENOTSUP, "macOS F_FULLFSYNC is unavailable")
    result = fcntl.fcntl(descriptor, operation)
    if result != 0:
        raise OSError(errno.EIO, "macOS F_FULLFSYNC returned a nonzero result")
