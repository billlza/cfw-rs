#!/usr/bin/env python3
"""Verify a sha256-tree artifact and its required metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

if __package__:
    from .hash_artifact import build_manifest, parse_metadata
else:
    from hash_artifact import build_manifest, parse_metadata


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a field name."""


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MODE_RE = re.compile(r"[0-7]{4}\Z")
MAX_MANIFEST_BYTES = 64 * 1024 * 1024


def _manifest_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _read_manifest(path: Path) -> str:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise SystemExit(f"error: cannot inspect artifact manifest: {error}") from error
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit(
            "error: artifact manifest must be a single-link regular non-symlink file"
        )
    if before.st_size <= 0 or before.st_size > MAX_MANIFEST_BYTES:
        raise SystemExit("error: artifact manifest size is outside the accepted range")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(f"error: cannot open artifact manifest: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if _manifest_identity(before) != _manifest_identity(opened):
            raise SystemExit("error: artifact manifest changed while opening")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise SystemExit(
                "error: opened artifact manifest is not a single-link regular file"
            )
        data = bytearray()
        while len(data) <= MAX_MANIFEST_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_MANIFEST_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _manifest_identity(opened) != _manifest_identity(after) or after.st_nlink != 1:
        raise SystemExit("error: artifact manifest changed while reading")
    try:
        rebound = os.lstat(path)
    except OSError as error:
        raise SystemExit("error: artifact manifest changed after reading") from error
    if _manifest_identity(opened) != _manifest_identity(rebound):
        raise SystemExit("error: artifact manifest changed after reading")
    if len(data) != opened.st_size or len(data) > MAX_MANIFEST_BYTES:
        raise SystemExit("error: artifact manifest size changed while reading")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit(f"error: artifact manifest is not UTF-8: {error}") from error


def _validate_shape(manifest: dict[str, object], algorithm: str) -> None:
    top_level = {"algorithm", "root", "sha256", "entries", "metadata"}
    if algorithm == "sha256-tree-v2":
        top_level.add("rootMode")
    if set(manifest) != top_level:
        raise SystemExit("error: artifact manifest has an unexpected top-level field set")
    if not isinstance(manifest.get("root"), str) or not manifest["root"]:
        raise SystemExit("error: artifact manifest root is malformed")
    if not isinstance(manifest.get("sha256"), str) or not _SHA256_RE.fullmatch(
        manifest["sha256"]
    ):
        raise SystemExit("error: artifact manifest digest is malformed")
    if algorithm == "sha256-tree-v2":
        root_mode = manifest.get("rootMode")
        if not isinstance(root_mode, str) or not _MODE_RE.fullmatch(root_mode):
            raise SystemExit("error: artifact manifest root mode is malformed")

    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("error: artifact manifest entries are malformed")
    for entry in entries:
        if not isinstance(entry, dict):
            raise SystemExit("error: artifact manifest entry is malformed")
        entry_type = entry.get("type")
        common = {"path", "type"}
        if algorithm == "sha256-tree-v2":
            common.add("mode")
        if entry_type == "file":
            expected = common | {"size", "sha256"}
        elif entry_type == "symlink":
            expected = common | {"target"}
        elif entry_type == "directory":
            expected = common
        else:
            raise SystemExit("error: artifact manifest entry type is unsupported")
        if set(entry) != expected:
            raise SystemExit("error: artifact manifest entry has an unexpected field set")
        if not isinstance(entry.get("path"), str) or not entry["path"]:
            raise SystemExit("error: artifact manifest entry path is malformed")
        if algorithm == "sha256-tree-v2":
            mode = entry.get("mode")
            if not isinstance(mode, str) or not _MODE_RE.fullmatch(mode):
                raise SystemExit("error: artifact manifest entry mode is malformed")
        if entry_type == "file":
            size = entry.get("size")
            sha256 = entry.get("sha256")
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or not isinstance(sha256, str)
                or not _SHA256_RE.fullmatch(sha256)
            ):
                raise SystemExit("error: artifact manifest file entry is malformed")
        if entry_type == "symlink" and not isinstance(entry.get("target"), str):
            raise SystemExit("error: artifact manifest symlink target is malformed")


def _with_added_files(
    manifest: dict[str, object], specifications: list[str]
) -> dict[str, object]:
    if not specifications:
        return manifest
    if manifest["algorithm"] != "sha256-tree-v1":
        raise SystemExit("error: added-file transforms require sha256-tree-v1")
    entries = manifest["entries"]
    if not isinstance(entries, list):
        raise SystemExit("error: artifact manifest entries are malformed")
    paths = [entry["path"] for entry in entries if isinstance(entry, dict)]
    if len(paths) != len(entries) or len(paths) != len(set(paths)) or paths != sorted(paths):
        raise SystemExit("error: artifact manifest entry paths are not unique and sorted")
    known_directories = {
        entry["path"]
        for entry in entries
        if isinstance(entry, dict) and entry.get("type") == "directory"
    }
    augmented = [dict(entry) for entry in entries if isinstance(entry, dict)]
    added_paths: set[str] = set()
    for specification in specifications:
        relative, separator, identity = specification.partition("=")
        digest, digest_separator, size_text = identity.partition(":")
        relative_path = PurePosixPath(relative)
        if (
            not separator
            or not digest_separator
            or not relative
            or relative_path.is_absolute()
            or relative_path.as_posix() != relative
            or relative_path.name in ("", ".", "..")
            or any(part in ("", ".", "..") for part in relative_path.parts)
        ):
            raise SystemExit("error: added-file path is not canonical and relative")
        if relative in paths or relative in added_paths:
            raise SystemExit("error: added-file path already exists or is duplicated")
        parent = relative_path.parent
        if parent == PurePosixPath(".") or parent.as_posix() not in known_directories:
            raise SystemExit("error: added-file parent is not an existing artifact directory")
        if not _SHA256_RE.fullmatch(digest):
            raise SystemExit("error: added-file digest is malformed")
        if not re.fullmatch(r"0|[1-9][0-9]*", size_text):
            raise SystemExit("error: added-file size is malformed")
        size = int(size_text)
        augmented.append(
            {
                "path": relative,
                "type": "file",
                "size": size,
                "sha256": digest,
            }
        )
        added_paths.add(relative)
    augmented.sort(key=lambda entry: entry["path"])
    tree_digest = hashlib.sha256()
    for entry in augmented:
        tree_digest.update(
            json.dumps(
                entry,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        tree_digest.update(b"\n")
    transformed = dict(manifest)
    transformed["entries"] = augmented
    transformed["sha256"] = tree_digest.hexdigest()
    return transformed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--metadata", action="append", default=[])
    parser.add_argument(
        "--added-file",
        action="append",
        default=[],
        metavar="RELATIVE_PATH=SHA256:SIZE",
    )
    parser.add_argument("--algorithm", choices=("sha256-tree-v1", "sha256-tree-v2"))
    parser.add_argument("--exact-metadata", action="store_true")
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--print-tree-sha256",
        action="store_true",
        help="print only the digest from this successfully verified manifest read",
    )
    output.add_argument(
        "--print-entry",
        metavar="RELATIVE_PATH",
        help="print one verified manifest entry as canonical JSON",
    )
    arguments = parser.parse_args()

    manifest_text = _read_manifest(arguments.manifest)
    try:
        expected = json.loads(
            manifest_text,
            object_pairs_hook=_strict_object,
        )
    except (OSError, json.JSONDecodeError, DuplicateKeyError) as error:
        raise SystemExit(f"error: cannot parse artifact manifest: {error}") from error
    if not isinstance(expected, dict) or expected.get("algorithm") not in (
        "sha256-tree-v1",
        "sha256-tree-v2",
    ):
        raise SystemExit("error: unsupported artifact manifest")
    algorithm = expected["algorithm"]
    if arguments.algorithm is not None and algorithm != arguments.algorithm:
        raise SystemExit("error: artifact manifest algorithm mismatch")
    _validate_shape(expected, algorithm)
    expected = _with_added_files(expected, arguments.added_file)

    actual = build_manifest(arguments.artifact, algorithm=algorithm)
    compared_keys = ["root", "sha256", "entries"]
    if algorithm == "sha256-tree-v2":
        compared_keys.append("rootMode")
    for key in compared_keys:
        if expected.get(key) != actual.get(key):
            raise SystemExit(f"error: artifact manifest {key} mismatch")
    metadata = expected.get("metadata")
    if not isinstance(metadata, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in metadata.items()
    ):
        raise SystemExit("error: artifact manifest has no metadata object")
    required_metadata = parse_metadata(arguments.metadata)
    if arguments.exact_metadata and set(metadata) != set(required_metadata):
        raise SystemExit("error: artifact manifest metadata field set mismatch")
    for key, value in required_metadata.items():
        if metadata.get(key) != value:
            raise SystemExit(f"error: artifact metadata {key} mismatch")
    if _read_manifest(arguments.manifest) != manifest_text:
        raise SystemExit("error: artifact manifest changed during verification")
    if arguments.print_entry is not None:
        relative = PurePosixPath(arguments.print_entry)
        if (
            relative.is_absolute()
            or relative.as_posix() != arguments.print_entry
            or relative.name in ("", ".", "..")
            or any(part in ("", ".", "..") for part in relative.parts)
        ):
            raise SystemExit("error: requested artifact entry path is not canonical")
        entries = expected["entries"]
        matches = [
            entry
            for entry in entries
            if isinstance(entry, dict) and entry.get("path") == arguments.print_entry
        ]
        if len(matches) != 1:
            raise SystemExit("error: requested artifact entry is not unique")
        print(
            json.dumps(
                matches[0],
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    elif arguments.print_tree_sha256:
        print(expected["sha256"])
    else:
        print(f"artifact manifest verified: {arguments.artifact}")


if __name__ == "__main__":
    main()
