#!/usr/bin/env python3
"""Hash the exact repository inputs used to build native macOS products."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path


INPUTS = (
    "native/macos/Config",
    "native/macos/Headers",
    "native/macos/Sources",
    "native/macos/SystemExtension",
    "native/macos/Dependencies.lock.json",
    "native/macos/Package.swift",
    "native/macos/project.yml",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_files(repository: Path) -> list[Path]:
    files: list[Path] = []
    for relative in INPUTS:
        path = repository / relative
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"native build input must not be a symlink: {relative}")
        if stat.S_ISREG(metadata.st_mode):
            files.append(path)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"unsupported native build input: {relative}")
        for directory, names, filenames in os.walk(path, followlinks=False):
            directory_path = Path(directory)
            for name in names:
                child = directory_path / name
                child_metadata = child.lstat()
                if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISDIR(child_metadata.st_mode):
                    raise ValueError(
                        f"native build input directory contains an unsafe entry: "
                        f"{child.relative_to(repository).as_posix()}"
                    )
            for name in filenames:
                child = directory_path / name
                child_metadata = child.lstat()
                if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISREG(child_metadata.st_mode):
                    raise ValueError(
                        f"native build input is not a regular file: "
                        f"{child.relative_to(repository).as_posix()}"
                    )
                files.append(child)
    return sorted(files, key=lambda path: path.relative_to(repository).as_posix())


def build_digest(repository: Path) -> str:
    digest = hashlib.sha256()
    for path in collect_files(repository):
        entry = {
            "path": path.relative_to(repository).as_posix(),
            "sha256": sha256(path),
            "size": path.stat().st_size,
        }
        encoded = json.dumps(entry, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        digest.update(encoded.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def main() -> None:
    repository = Path(__file__).resolve().parent.parent
    try:
        print(build_digest(repository))
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: cannot hash native build inputs: {error}") from error


if __name__ == "__main__":
    main()
