#!/usr/bin/env python3
"""Hash an artifact tree or single-file product without embedding machine-specific
absolute paths.

The v2 release-toolchain contract also rejects links whose final target escapes
the artifact root.  This makes a verified tree relocatable and prevents a
manifest from authenticating bytes that are later loaded from outside it.
"""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Iterable


MAX_ARTIFACT_ENTRIES = 250_000
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024
MAX_SYMLINK_EXPANSIONS = 40


def _descriptor_digest(
    descriptor: int,
    expected_size: int,
    relative: str,
) -> str:
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise ValueError(f"artifact file changed while hashing: {relative}")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ValueError(f"artifact file changed while hashing: {relative}")
    return digest.hexdigest()


SUPPORTED_ALGORITHMS = ("sha256-tree-v1", "sha256-tree-v2")


def tree_sha256_from_records(records: Iterable[dict[str, object]]) -> str:
    """Hash canonical tree records using the artifact-manifest line format."""

    tree_digest = hashlib.sha256()
    for record in records:
        tree_digest.update(
            json.dumps(
                record,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        tree_digest.update(b"\n")
    return tree_digest.hexdigest()


def _mode(metadata: os.stat_result) -> str:
    return f"{stat.S_IMODE(metadata.st_mode):04o}"


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _require_unchanged(
    expected: os.stat_result,
    actual: os.stat_result,
    relative: str,
    operation: str,
) -> None:
    if _identity(expected) != _identity(actual):
        raise ValueError(f"artifact entry changed while {operation}: {relative}")


def _raise_io_error(operation: str, relative: str, error: OSError) -> None:
    reason = error.strerror or error.__class__.__name__
    errno_suffix = f" (errno {error.errno})" if error.errno is not None else ""
    raise ValueError(
        f"failed to {operation} artifact entry {relative}: {reason}{errno_suffix}"
    ) from error


def _secure_open_flags(*, directory: bool) -> int:
    missing = [name for name in ("O_NOFOLLOW", "O_DIRECTORY") if not hasattr(os, name)]
    if missing:
        raise RuntimeError(
            "secure artifact traversal requires " + ", ".join(sorted(missing))
        )
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _stat_relative(
    directory_descriptor: int,
    name: str,
    relative: str,
) -> os.stat_result:
    try:
        return os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        _raise_io_error("inspect", relative, error)
    raise AssertionError("unreachable")


def _open_relative(
    directory_descriptor: int,
    name: str,
    relative: str,
    *,
    directory: bool,
) -> int:
    try:
        return os.open(
            name,
            _secure_open_flags(directory=directory),
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        _raise_io_error("open", relative, error)
    raise AssertionError("unreachable")


def _entry_with_mode(
    entry: dict[str, object],
    metadata: os.stat_result,
    algorithm: str,
) -> dict[str, object]:
    if algorithm == "sha256-tree-v2":
        entry["mode"] = _mode(metadata)
    return entry


def _capture_directory_entries(
    root_descriptor: int,
    root_metadata: os.stat_result,
    algorithm: str,
) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    captured_paths: set[str] = set()
    captured_metadata: dict[str, os.stat_result] = {}
    captured_symlink_targets: dict[str, str] = {}
    total_file_bytes = 0

    def reserve(relative: str) -> None:
        if relative in captured_paths:
            raise ValueError(f"duplicate artifact entry while enumerating: {relative}")
        captured_paths.add(relative)
        if len(captured_paths) > MAX_ARTIFACT_ENTRIES:
            raise ValueError(
                f"artifact has more than {MAX_ARTIFACT_ENTRIES} entries"
            )

    def scan_directory(
        descriptor: int,
        relative: str,
        expected: os.stat_result,
    ) -> None:
        nonlocal total_file_bytes
        try:
            opened = os.fstat(descriptor)
        except OSError as error:
            _raise_io_error("inspect open directory", relative, error)
        _require_unchanged(expected, opened, relative, "opening")

        try:
            iterator = os.scandir(descriptor)
        except OSError as error:
            _raise_io_error("enumerate directory", relative, error)

        with iterator:
            while True:
                try:
                    directory_entry = next(iterator)
                except StopIteration:
                    break
                except OSError as error:
                    _raise_io_error("enumerate directory", relative, error)

                name = directory_entry.name
                child_relative = name if relative == "." else f"{relative}/{name}"
                reserve(child_relative)
                child_metadata = _stat_relative(descriptor, name, child_relative)
                captured_metadata[child_relative] = child_metadata
                child_type = stat.S_IFMT(child_metadata.st_mode)

                if child_type == stat.S_IFLNK:
                    try:
                        target = os.readlink(name, dir_fd=descriptor)
                    except OSError as error:
                        _raise_io_error("read symlink", child_relative, error)
                    symlink_after = _stat_relative(descriptor, name, child_relative)
                    _require_unchanged(
                        child_metadata,
                        symlink_after,
                        child_relative,
                        "reading symlink",
                    )
                    captured_symlink_targets[child_relative] = target
                    entries.append(
                        _entry_with_mode(
                            {
                                "path": child_relative,
                                "type": "symlink",
                                "target": target,
                            },
                            child_metadata,
                            algorithm,
                        )
                    )
                    continue

                if child_type == stat.S_IFDIR:
                    entries.append(
                        _entry_with_mode(
                            {"path": child_relative, "type": "directory"},
                            child_metadata,
                            algorithm,
                        )
                    )
                    child_descriptor = _open_relative(
                        descriptor,
                        name,
                        child_relative,
                        directory=True,
                    )
                    try:
                        scan_directory(
                            child_descriptor,
                            child_relative,
                            child_metadata,
                        )
                    finally:
                        os.close(child_descriptor)
                    rebound = _stat_relative(descriptor, name, child_relative)
                    _require_unchanged(
                        child_metadata,
                        rebound,
                        child_relative,
                        "enumerating directory",
                    )
                    continue

                if child_type == stat.S_IFREG:
                    descriptor_for_file = _open_relative(
                        descriptor,
                        name,
                        child_relative,
                        directory=False,
                    )
                    try:
                        try:
                            file_before = os.fstat(descriptor_for_file)
                        except OSError as error:
                            _raise_io_error("inspect open file", child_relative, error)
                        _require_unchanged(
                            child_metadata,
                            file_before,
                            child_relative,
                            "opening",
                        )
                        if algorithm == "sha256-tree-v2" and file_before.st_nlink != 1:
                            raise ValueError(
                                f"artifact file must not have hard links: {child_relative}"
                            )
                        total_file_bytes += file_before.st_size
                        if total_file_bytes > MAX_ARTIFACT_BYTES:
                            raise ValueError(
                                "artifact file bytes exceed maximum "
                                f"{MAX_ARTIFACT_BYTES}"
                            )
                        try:
                            sha256 = _descriptor_digest(
                                descriptor_for_file,
                                file_before.st_size,
                                child_relative,
                            )
                        except OSError as error:
                            _raise_io_error("hash file", child_relative, error)
                        try:
                            file_after = os.fstat(descriptor_for_file)
                        except OSError as error:
                            _raise_io_error("inspect hashed file", child_relative, error)
                        _require_unchanged(
                            file_before,
                            file_after,
                            child_relative,
                            "hashing",
                        )
                    finally:
                        os.close(descriptor_for_file)

                    rebound = _stat_relative(descriptor, name, child_relative)
                    _require_unchanged(
                        child_metadata,
                        rebound,
                        child_relative,
                        "hashing",
                    )
                    if algorithm == "sha256-tree-v2" and rebound.st_nlink != 1:
                        raise ValueError(
                            f"artifact file must not have hard links: {child_relative}"
                        )
                    entries.append(
                        _entry_with_mode(
                            {
                                "path": child_relative,
                                "type": "file",
                                "size": file_before.st_size,
                                "sha256": sha256,
                            },
                            file_before,
                            algorithm,
                        )
                    )
                    continue

                raise ValueError(f"unsupported artifact entry: {child_relative}")

        try:
            directory_after = os.fstat(descriptor)
        except OSError as error:
            _raise_io_error("inspect enumerated directory", relative, error)
        _require_unchanged(expected, directory_after, relative, "enumerating directory")

    def revalidate_directory(
        descriptor: int,
        relative: str,
        expected: os.stat_result,
        observed: set[str],
    ) -> None:
        try:
            opened = os.fstat(descriptor)
        except OSError as error:
            _raise_io_error("inspect open directory", relative, error)
        _require_unchanged(expected, opened, relative, "final verification")

        try:
            iterator = os.scandir(descriptor)
        except OSError as error:
            _raise_io_error("re-enumerate directory", relative, error)
        with iterator:
            while True:
                try:
                    directory_entry = next(iterator)
                except StopIteration:
                    break
                except OSError as error:
                    _raise_io_error("re-enumerate directory", relative, error)

                name = directory_entry.name
                child_relative = name if relative == "." else f"{relative}/{name}"
                if child_relative in observed:
                    raise ValueError(
                        "duplicate artifact entry during final verification: "
                        f"{child_relative}"
                    )
                expected_child = captured_metadata.get(child_relative)
                if expected_child is None:
                    raise ValueError(
                        "artifact entries changed during final verification: "
                        f"{child_relative}"
                    )
                observed.add(child_relative)
                child_metadata = _stat_relative(descriptor, name, child_relative)
                _require_unchanged(
                    expected_child,
                    child_metadata,
                    child_relative,
                    "final verification",
                )
                child_type = stat.S_IFMT(child_metadata.st_mode)

                if child_type == stat.S_IFLNK:
                    try:
                        target = os.readlink(name, dir_fd=descriptor)
                    except OSError as error:
                        _raise_io_error("reread symlink", child_relative, error)
                    if target != captured_symlink_targets.get(child_relative):
                        raise ValueError(
                            "artifact symlink changed during final verification: "
                            f"{child_relative}"
                        )
                    symlink_after = _stat_relative(descriptor, name, child_relative)
                    _require_unchanged(
                        expected_child,
                        symlink_after,
                        child_relative,
                        "final verification",
                    )
                    continue

                if child_type == stat.S_IFDIR:
                    child_descriptor = _open_relative(
                        descriptor,
                        name,
                        child_relative,
                        directory=True,
                    )
                    try:
                        revalidate_directory(
                            child_descriptor,
                            child_relative,
                            expected_child,
                            observed,
                        )
                    finally:
                        os.close(child_descriptor)
                    rebound = _stat_relative(descriptor, name, child_relative)
                    _require_unchanged(
                        expected_child,
                        rebound,
                        child_relative,
                        "final verification",
                    )
                    continue

                if child_type != stat.S_IFREG:
                    raise ValueError(f"unsupported artifact entry: {child_relative}")

        try:
            directory_after = os.fstat(descriptor)
        except OSError as error:
            _raise_io_error("inspect re-enumerated directory", relative, error)
        _require_unchanged(expected, directory_after, relative, "final verification")

    scan_directory(root_descriptor, ".", root_metadata)
    observed_paths: set[str] = set()
    revalidate_directory(
        root_descriptor,
        ".",
        root_metadata,
        observed_paths,
    )
    if observed_paths != captured_paths:
        raise ValueError("artifact entries changed during final verification")
    return sorted(entries, key=lambda entry: str(entry["path"]))


def _symlink_target_parts(relative: str, target: str) -> list[str]:
    if not target:
        raise ValueError(f"artifact symlink target must not be empty: {relative}")
    parsed = PurePosixPath(target)
    if parsed.is_absolute():
        raise ValueError(f"artifact symlink target must be relative: {relative}")
    return list(parsed.parts)


def _symlink_target_requires_directory(target: str) -> bool:
    return target.endswith("/") or target == "." or target.endswith("/.")


def _require_v2_symlinks_within_root(entries: list[dict[str, object]]) -> None:
    by_path = {str(entry["path"]): entry for entry in entries}
    for source in entries:
        if source["type"] != "symlink":
            continue
        source_path = str(source["path"])
        parent_parts = source_path.split("/")[:-1]
        pending = deque(
            _symlink_target_parts(source_path, str(source["target"]))
        )
        resolved = list(parent_parts)
        followed_states: set[tuple[str, tuple[str, ...], tuple[str, ...]]] = set()
        symlink_expansions = 0
        resolved_type = "directory"

        while pending:
            component = pending.popleft()
            if component in ("", "."):
                continue
            if component == "..":
                if not resolved:
                    raise ValueError(
                        "artifact symlink target must resolve within the artifact "
                        f"root: {source_path}"
                    )
                resolved.pop()
                resolved_type = "directory"
                continue

            candidate = "/".join((*resolved, component))
            target_entry = by_path.get(candidate)
            if target_entry is None:
                raise ValueError(
                    "artifact symlink target must resolve within the artifact "
                    f"root: {source_path}"
                )
            if target_entry["type"] == "symlink":
                state = (candidate, tuple(resolved), tuple(pending))
                symlink_expansions += 1
                if (
                    state in followed_states
                    or symlink_expansions > MAX_SYMLINK_EXPANSIONS
                ):
                    raise ValueError(
                        "artifact symlink target must resolve within the artifact "
                        f"root: {source_path}"
                    )
                followed_states.add(state)
                nested = _symlink_target_parts(
                    candidate,
                    str(target_entry["target"]),
                )
                pending.extendleft(reversed(nested))
                continue

            resolved.append(component)
            resolved_type = str(target_entry["type"])
            if target_entry["type"] != "directory" and pending:
                raise ValueError(
                    "artifact symlink target must resolve within the artifact "
                    f"root: {source_path}"
                )
        if (
            _symlink_target_requires_directory(str(source["target"]))
            and resolved_type != "directory"
        ):
            raise ValueError(
                "artifact symlink target must resolve within the artifact "
                f"root: {source_path}"
            )


def _capture_artifact(
    root: Path,
    algorithm: str,
) -> tuple[os.stat_result, list[dict[str, object]]]:
    try:
        root_metadata = os.stat(root, follow_symlinks=False)
    except FileNotFoundError as error:
        raise ValueError(f"artifact does not exist: {root}") from error
    except OSError as error:
        _raise_io_error("inspect root", ".", error)

    root_type = stat.S_IFMT(root_metadata.st_mode)
    if root_type == stat.S_IFLNK:
        raise ValueError(f"artifact root must not be a symlink: {root}")

    if root_type == stat.S_IFDIR:
        try:
            root_descriptor = os.open(root, _secure_open_flags(directory=True))
        except OSError as error:
            _raise_io_error("open root", ".", error)
        try:
            try:
                opened_root = os.fstat(root_descriptor)
            except OSError as error:
                _raise_io_error("inspect open root", ".", error)
            _require_unchanged(root_metadata, opened_root, ".", "opening")
            entries = _capture_directory_entries(
                root_descriptor,
                root_metadata,
                algorithm,
            )
        finally:
            os.close(root_descriptor)
        try:
            root_after = os.stat(root, follow_symlinks=False)
        except OSError as error:
            _raise_io_error("reinspect root", ".", error)
        _require_unchanged(root_metadata, root_after, ".", "enumerating directory")
        if algorithm == "sha256-tree-v2":
            _require_v2_symlinks_within_root(entries)
        return root_metadata, entries

    if root_type == stat.S_IFREG:
        try:
            descriptor = os.open(root, _secure_open_flags(directory=False))
        except OSError as error:
            _raise_io_error("open root", ".", error)
        try:
            try:
                opened = os.fstat(descriptor)
            except OSError as error:
                _raise_io_error("inspect open root", ".", error)
            _require_unchanged(root_metadata, opened, ".", "opening")
            if algorithm == "sha256-tree-v2" and opened.st_nlink != 1:
                raise ValueError(f"artifact root must not have hard links: {root}")
            if opened.st_size > MAX_ARTIFACT_BYTES:
                raise ValueError(
                    f"artifact file bytes exceed maximum {MAX_ARTIFACT_BYTES}"
                )
            try:
                sha256 = _descriptor_digest(descriptor, opened.st_size, ".")
            except OSError as error:
                _raise_io_error("hash root file", ".", error)
            try:
                after = os.fstat(descriptor)
            except OSError as error:
                _raise_io_error("inspect hashed root", ".", error)
            _require_unchanged(opened, after, ".", "hashing")
        finally:
            os.close(descriptor)
        try:
            rebound = os.stat(root, follow_symlinks=False)
        except OSError as error:
            _raise_io_error("reinspect root", ".", error)
        _require_unchanged(root_metadata, rebound, ".", "hashing")
        if algorithm == "sha256-tree-v2" and rebound.st_nlink != 1:
            raise ValueError(f"artifact root must not have hard links: {root}")
        entry = _entry_with_mode(
            {
                "path": root.name,
                "type": "file",
                "size": opened.st_size,
                "sha256": sha256,
            },
            opened,
            algorithm,
        )
        return root_metadata, [entry]

    raise ValueError(f"unsupported artifact entry: {root}")


def build_manifest(
    root: Path,
    metadata: dict[str, str] | None = None,
    algorithm: str = "sha256-tree-v1",
) -> dict[str, object]:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"unsupported artifact manifest algorithm: {algorithm}")
    root_metadata, entries = _capture_artifact(root, algorithm)

    root_mode: str | None = None
    tree_records: list[dict[str, object]] = []
    if algorithm == "sha256-tree-v2":
        root_mode = _mode(root_metadata)
        root_record = {
            "path": ".",
            "type": "directory"
            if stat.S_ISDIR(root_metadata.st_mode)
            else "file",
            "mode": root_mode,
        }
        tree_records.append(root_record)
    tree_records.extend(entries)

    manifest: dict[str, object] = {
        "algorithm": algorithm,
        "root": root.name,
        "sha256": tree_sha256_from_records(tree_records),
        "entries": entries,
    }
    if root_mode is not None:
        manifest["rootMode"] = root_mode
    if metadata:
        manifest["metadata"] = dict(sorted(metadata.items()))
    return manifest


def parse_metadata(values: list[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key or not item:
            raise ValueError("metadata must use a non-empty key=value form")
        if key in metadata:
            raise ValueError(f"duplicate metadata key: {key}")
        metadata[key] = item
    return metadata


def write_new_manifest(path: Path, encoded: str) -> None:
    if os.path.lexists(path):
        raise FileExistsError(f"refusing to replace existing manifest output: {path}")
    parent = path.parent
    parent_metadata = os.stat(parent, follow_symlinks=False)
    if not stat.S_ISDIR(parent_metadata.st_mode) or parent.is_symlink():
        raise ValueError(f"manifest output parent must be a real directory: {parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_descriptor = os.open(parent, directory_flags)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--metadata", action="append", default=[])
    parser.add_argument("--algorithm", choices=SUPPORTED_ALGORITHMS, default="sha256-tree-v1")
    arguments = parser.parse_args()

    manifest = build_manifest(
        arguments.artifact,
        parse_metadata(arguments.metadata),
        arguments.algorithm,
    )
    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(encoded, end="")
    else:
        write_new_manifest(arguments.output, encoded)


if __name__ == "__main__":
    main()
