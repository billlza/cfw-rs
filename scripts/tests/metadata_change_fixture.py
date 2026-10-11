"""Metadata-only file-system changes for stability-identity tests."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import time


_UNCHANGED_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
)


def change_only_ctime(target: Path | int) -> None:
    """Advance only the status-change time of a path or open descriptor.

    A same-mode chmod is the portable stand-in for the com.apple.macl and
    provenance extended-attribute writes that macOS makes without touching a
    byte. The change is verified, so a test can never pass vacuously.
    """

    def observe() -> os.stat_result:
        if isinstance(target, int):
            return os.fstat(target)
        return os.stat(target, follow_symlinks=False)

    def keep_mode(mode: int) -> None:
        if isinstance(target, int):
            os.fchmod(target, mode)
        else:
            os.chmod(target, mode, follow_symlinks=False)

    before = observe()
    deadline = time.monotonic() + 1
    while True:
        keep_mode(stat.S_IMODE(before.st_mode))
        after = observe()
        if after.st_ctime_ns != before.st_ctime_ns:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"status-change time did not advance: {target}")
        time.sleep(0.001)
    moved = [
        name
        for name in _UNCHANGED_FIELDS
        if getattr(after, name) != getattr(before, name)
    ]
    if moved:
        raise AssertionError(f"metadata-only change also moved {moved}: {target}")
