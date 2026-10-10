#!/usr/bin/env python3
"""Read one release-owned regular file without path or descriptor races."""

from __future__ import annotations

from collections.abc import Set
import os
from pathlib import Path
import stat


class ReleaseRegularFileError(ValueError):
    """A release input is not one stable bounded regular file."""


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_flags(label: str) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    close_on_exec = getattr(os, "O_CLOEXEC", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if (
        type(no_follow) is not int
        or type(close_on_exec) is not int
        or type(nonblocking) is not int
    ):
        raise ReleaseRegularFileError(
            f"{label} requires O_NOFOLLOW, O_CLOEXEC, and O_NONBLOCK"
        )
    return os.O_RDONLY | no_follow | close_on_exec | nonblocking


def read_bounded_regular_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    allowed_owner_uids: Set[int],
    exact_mode: int | None = None,
) -> bytes:
    """Return stable bytes from one explicitly owned, single-link file."""

    if (
        not isinstance(path, Path)
        or not isinstance(label, str)
        or not label
        or len(label) > 128
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in label)
    ):
        raise ValueError("release regular-file arguments are invalid")
    if type(maximum_bytes) is not int or maximum_bytes < 1:
        raise ValueError("release regular-file maximum must be positive")
    if (
        not isinstance(allowed_owner_uids, Set)
        or not allowed_owner_uids
        or any(type(uid) is not int or uid < 0 for uid in allowed_owner_uids)
    ):
        raise ValueError("release regular-file owner allowlist is invalid")
    if exact_mode is not None and (
        type(exact_mode) is not int or exact_mode < 0 or exact_mode > 0o777
    ):
        raise ValueError("release regular-file exact mode is invalid")

    try:
        before = path.lstat()
    except OSError as error:
        raise ReleaseRegularFileError(f"{label} is unavailable") from error
    observed_mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid not in allowed_owner_uids
        or before.st_size < 1
        or before.st_size > maximum_bytes
        or (exact_mode is None and observed_mode & 0o022)
    ):
        raise ReleaseRegularFileError(
            f"{label} is not one bounded owned single-link regular file"
        )
    if exact_mode is not None and observed_mode != exact_mode:
        raise ReleaseRegularFileError(
            f"{label} mode is {observed_mode:04o}, expected {exact_mode:04o}"
        )

    descriptor = -1
    try:
        descriptor = os.open(path, _open_flags(label))
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise ReleaseRegularFileError(f"{label} changed while opening")
        remaining = before.st_size + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        rebound = path.stat(follow_symlinks=False)
    except ReleaseRegularFileError:
        raise
    except OSError as error:
        raise ReleaseRegularFileError(f"cannot read {label}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(data) != before.st_size
        or _file_identity(after) != _file_identity(before)
        or _file_identity(rebound) != _file_identity(before)
    ):
        raise ReleaseRegularFileError(f"{label} changed while reading")
    return data
