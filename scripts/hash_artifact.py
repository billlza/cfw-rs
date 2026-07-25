#!/usr/bin/env python3
"""Hash an artifact tree or single-file product without embedding machine-specific
absolute paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path, metadata: dict[str, str] | None = None) -> dict[str, object]:
    if root.is_symlink():
        raise ValueError(f"artifact root must not be a symlink: {root}")
    if root.is_dir():
        members = [
            (path, path.relative_to(root).as_posix())
            for path in sorted(
                root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
            )
        ]
    elif root.is_file():
        # A bare executable product, such as the launchd Global Authority daemon,
        # is a single-file artifact rather than a bundle tree.
        members = [(root, root.name)]
    else:
        raise ValueError(f"artifact does not exist: {root}")

    entries: list[dict[str, object]] = []
    tree_digest = hashlib.sha256()
    for path, relative in members:
        if path.is_symlink():
            target = os.readlink(path)
            entry = {"path": relative, "type": "symlink", "target": target}
        elif path.is_file():
            size = path.stat().st_size
            sha256 = file_digest(path)
            entry = {
                "path": relative,
                "type": "file",
                "size": size,
                "sha256": sha256,
            }
        elif path.is_dir():
            entry = {"path": relative, "type": "directory"}
        else:
            raise ValueError(f"unsupported artifact entry: {path}")

        encoded = json.dumps(entry, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        tree_digest.update(encoded.encode("utf-8"))
        tree_digest.update(b"\n")
        entries.append(entry)

    manifest: dict[str, object] = {
        "algorithm": "sha256-tree-v1",
        "root": root.name,
        "sha256": tree_digest.hexdigest(),
        "entries": entries,
    }
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--metadata", action="append", default=[])
    arguments = parser.parse_args()

    manifest = build_manifest(arguments.artifact, parse_metadata(arguments.metadata))
    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(encoded, end="")
    else:
        write_new_manifest(arguments.output, encoded)


if __name__ == "__main__":
    main()
