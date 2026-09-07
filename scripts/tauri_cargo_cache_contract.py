#!/usr/bin/env python3
"""Validate and normalize the private Cargo cache used to build Tauri CLI.

Cargo keeps dependency bytes under ``registry`` but also creates three root-level
runtime files for cache-use tracking and process coordination.  Those files are
not build inputs and Cargo legitimately recreates or rewrites them even while
offline.  This module removes only those exact runtime names from a private
offline snapshot after first proving that the whole cache has the expected,
owner-bound shape.  The remaining tree can then be sealed without weakening the
registry index, crate archive, or expanded-source boundary.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys
from typing import NoReturn, Sequence


RUNTIME_FILES = (
    ".global-cache",
    ".package-cache",
    ".package-cache-mutate",
)
ALLOWED_TOP_LEVEL = frozenset(("registry", *RUNTIME_FILES))
SQLITE_HEADER = b"SQLite format 3\x00"
MAX_GLOBAL_CACHE_BYTES = 64 * 1024 * 1024
MAX_CACHE_ENTRIES = 250_000
MAX_CACHE_BYTES = 16 * 1024 * 1024 * 1024


class CargoCacheContractError(ValueError):
    """The Cargo cache cannot be trusted as an offline build input."""


def _fail(message: str) -> NoReturn:
    raise CargoCacheContractError(message)


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_uid,
        metadata.st_nlink,
    )


def _require_owned_entry(path: Path, metadata: os.stat_result) -> None:
    if metadata.st_uid != os.getuid():
        _fail(f"Cargo cache entry is not owned by the release user: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        _fail(f"Cargo cache entry is group/other writable: {path}")


def _require_regular_runtime_file(
    root: Path,
    name: str,
    metadata: os.stat_result,
) -> None:
    path = root / name
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        _fail(f"Cargo runtime metadata must be a single-link regular file: {path}")
    _require_owned_entry(path, metadata)
    if name == ".global-cache":
        if metadata.st_size < len(SQLITE_HEADER) or metadata.st_size > MAX_GLOBAL_CACHE_BYTES:
            _fail(f"Cargo global-cache database size is outside its bound: {path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if not hasattr(os, "O_NOFOLLOW"):
            _fail("secure Cargo cache validation requires O_NOFOLLOW")
        flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if _identity(opened) != _identity(metadata):
                _fail(f"Cargo runtime metadata changed while opening: {path}")
            if os.read(descriptor, len(SQLITE_HEADER)) != SQLITE_HEADER:
                _fail(f"Cargo global-cache database has an invalid header: {path}")
        finally:
            os.close(descriptor)
    elif metadata.st_size != 0:
        _fail(f"Cargo cache lock file must be empty: {path}")


def _validate_tree(root: Path) -> None:
    entry_count = 0
    total_bytes = 0

    def reject_walk_error(error: OSError) -> NoReturn:
        raise CargoCacheContractError(
            f"cannot traverse Cargo cache: {error}"
        ) from error

    for current, directories, files in os.walk(
        root,
        topdown=True,
        onerror=reject_walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        for name in [*directories, *files]:
            path = current_path / name
            try:
                metadata = path.lstat()
            except OSError as error:
                raise CargoCacheContractError(
                    f"cannot inspect Cargo cache entry {path}: {error}"
                ) from error
            entry_count += 1
            if entry_count > MAX_CACHE_ENTRIES:
                _fail(f"Cargo cache has more than {MAX_CACHE_ENTRIES} entries")
            if stat.S_ISLNK(metadata.st_mode):
                _fail(f"Cargo cache contains a symlink: {path}")
            _require_owned_entry(path, metadata)
            if stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    _fail(f"Cargo cache contains a hard-linked file: {path}")
                total_bytes += metadata.st_size
                if total_bytes > MAX_CACHE_BYTES:
                    _fail(f"Cargo cache exceeds {MAX_CACHE_BYTES} bytes")
            elif not stat.S_ISDIR(metadata.st_mode):
                _fail(f"Cargo cache contains an unsupported entry: {path}")


def _top_level_names(root: Path) -> set[str]:
    try:
        return {entry.name for entry in root.iterdir()}
    except OSError as error:
        raise CargoCacheContractError(
            f"cannot enumerate Cargo cache root {root}: {error}"
        ) from error


def validate_preparation_cache(root: Path, *, require_registry: bool = False) -> None:
    if not root.is_absolute():
        _fail("Cargo cache root must be absolute")
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise CargoCacheContractError(f"cannot inspect Cargo cache root: {error}") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        _fail("Cargo cache root must be a real directory")
    _require_owned_entry(root, root_metadata)

    names = _top_level_names(root)
    unexpected = sorted(names - ALLOWED_TOP_LEVEL)
    if unexpected:
        _fail(f"Cargo cache has unsafe top-level entries: {unexpected!r}")
    if require_registry and "registry" not in names:
        _fail("offline Cargo cache has no registry directory")

    registry = root / "registry"
    if registry.exists() or registry.is_symlink():
        metadata = registry.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or registry.is_symlink():
            _fail("Cargo registry must be a real directory")
        _require_owned_entry(registry, metadata)

    for name in RUNTIME_FILES:
        path = root / name
        if path.exists() or path.is_symlink():
            _require_regular_runtime_file(root, name, path.lstat())

    _validate_tree(root)


def _unlink_runtime_file(directory_descriptor: int, root: Path, name: str) -> None:
    try:
        expected = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise CargoCacheContractError(
            f"cannot inspect Cargo runtime metadata {root / name}: {error}"
        ) from error
    _require_regular_runtime_file(root, name, expected)

    if not hasattr(os, "O_NOFOLLOW"):
        _fail("secure Cargo cache normalization requires O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as error:
        raise CargoCacheContractError(
            f"cannot open Cargo runtime metadata {root / name}: {error}"
        ) from error
    try:
        if _identity(os.fstat(descriptor)) != _identity(expected):
            _fail(f"Cargo runtime metadata changed before removal: {root / name}")
        try:
            os.unlink(name, dir_fd=directory_descriptor)
        except OSError as error:
            raise CargoCacheContractError(
                f"cannot remove Cargo runtime metadata {root / name}: {error}"
            ) from error
    finally:
        os.close(descriptor)


def normalize_offline_cache(root: Path) -> Path:
    validate_preparation_cache(root, require_registry=True)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        _fail("secure Cargo cache normalization requires O_NOFOLLOW and O_DIRECTORY")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        directory_descriptor = os.open(root, flags)
    except OSError as error:
        raise CargoCacheContractError(f"cannot open Cargo cache root: {error}") from error
    try:
        for name in RUNTIME_FILES:
            _unlink_runtime_file(directory_descriptor, root, name)
    finally:
        os.close(directory_descriptor)

    names = _top_level_names(root)
    if names != {"registry"}:
        _fail(f"normalized Cargo cache has unexpected entries: {sorted(names)!r}")
    validate_preparation_cache(root, require_registry=True)
    return root / "registry"


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation",
        choices=("validate-preparation", "normalize-offline"),
    )
    parser.add_argument("cargo_home", type=Path)
    parsed = parser.parse_args(arguments)
    try:
        if parsed.operation == "validate-preparation":
            validate_preparation_cache(parsed.cargo_home)
        else:
            normalize_offline_cache(parsed.cargo_home)
    except CargoCacheContractError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
