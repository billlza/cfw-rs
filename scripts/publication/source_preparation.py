from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from .common import (
    PublicationError,
    copy_regular_new,
    enumerate_tree,
    reject_reverse_path,
    regular_file_identity,
    safe_relative,
    tree_digest,
)
from .graph_model import ComponentSeed
if __package__.startswith("scripts."):
    from scripts.release_git import ReleaseGitError, run_release_git
    from scripts.repository_source_identity import RELEASE_PATHS
else:
    from release_git import ReleaseGitError, run_release_git
    from repository_source_identity import RELEASE_PATHS


MAX_COPY_FILE_BYTES = 256 * 1024 * 1024
MAX_COPY_FILES = 250_000
MAX_COPY_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
FORBIDDEN_SOURCE_DIRECTORIES = {".git", ".hg", ".svn", "Libbox.xcframework"}


def select_source(seed: ComponentSeed, review: dict[str, Any]) -> Path:
    override = review["source_override"]
    if override is None:
        source = seed.source_root
    elif isinstance(override, str) and override.startswith("/"):
        candidate = Path(override)
        if candidate.is_symlink():
            raise PublicationError(f"component source override is a symlink: {seed.identifier}")
        source = candidate.resolve(strict=True)
    else:
        raise PublicationError(f"component source override must be null or absolute: {seed.identifier}")
    if source is None or not source.is_dir() or source.is_symlink():
        raise PublicationError(f"component has no real corresponding-source root: {seed.identifier}")
    return source.resolve(strict=True)


def _destination_name(seed: ComponentSeed) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", seed.name).strip("-")[:64] or "component"
    suffix = hashlib.sha256(seed.identifier.encode("utf-8")).hexdigest()[:16]
    return f"{slug}-{suffix}"


def _run_git_files(
    repository: Path,
    source: Path,
    environment: dict[str, str] | None,
) -> list[tuple[Path, PurePosixPath]]:
    relative_root = source.relative_to(repository)
    command = ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--"]
    if relative_root.parts:
        command.append(relative_root.as_posix())
    else:
        command.extend(RELEASE_PATHS)
    try:
        protected_roots = (
            RELEASE_PATHS if not relative_root.parts else (relative_root.parts[0],)
        )
        payload = run_release_git(
            repository,
            command,
            environment=environment,
            protected_roots=protected_roots,
        )
    except ReleaseGitError as error:
        raise PublicationError(
            f"cannot enumerate repository source files: {error}"
        ) from error
    files: list[tuple[Path, PurePosixPath]] = []
    prefix_length = len(relative_root.parts)
    for raw_path in payload.split(b"\0"):
        if not raw_path:
            continue
        try:
            repository_relative = PurePosixPath(raw_path.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise PublicationError("tracked source path is not UTF-8") from error
        if repository_relative.parts and repository_relative.parts[0].casefold() == "reverse":
            continue
        source_path = repository.joinpath(*repository_relative.parts)
        if not source_path.exists() and not source_path.is_symlink():
            # Review templates may describe the prospective dirty migration.
            # Production preparation separately requires clean Git.
            continue
        component_relative = PurePosixPath(*repository_relative.parts[prefix_length:])
        if not component_relative.parts:
            raise PublicationError("tracked source path did not remain below its component root")
        files.append((source_path, component_relative))
    if not files:
        raise PublicationError(f"component has no tracked source files: {source}")
    return sorted(files, key=lambda item: item[1].as_posix())


def _tree_files(source: Path) -> list[tuple[Path, PurePosixPath]]:
    files: list[tuple[Path, PurePosixPath]] = []
    for current, directories, names in os.walk(source, topdown=True, followlinks=False):
        current_path = Path(current)
        relative_current = current_path.relative_to(source)
        directories.sort()
        names.sort()
        for name in list(directories):
            candidate = current_path / name
            metadata = candidate.lstat()
            if name in FORBIDDEN_SOURCE_DIRECTORIES:
                directories.remove(name)
                continue
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise PublicationError(f"corresponding source contains an unsafe directory: {candidate}")
        for name in names:
            candidate = current_path / name
            metadata = candidate.lstat()
            relative = PurePosixPath(*(relative_current.parts + (name,)))
            reject_reverse_path(relative)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise PublicationError(f"corresponding source contains an unsafe file: {candidate}")
            files.append((candidate, relative))
    if not files:
        raise PublicationError(f"component corresponding-source root is empty: {source}")
    return files


def _source_files(
    repository: Path,
    seed: ComponentSeed,
    source_root: Path,
    environment: dict[str, str] | None,
) -> tuple[list[tuple[Path, PurePosixPath]], str]:
    if seed.repository_source and source_root.is_relative_to(repository):
        return _run_git_files(repository, source_root, environment), "git-tracked-files-v1"
    return _tree_files(source_root), "bounded-source-tree-v1"


def source_input_evidence(
    repository: Path,
    seed: ComponentSeed,
    source_root: Path | None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    if seed.external_build_tool:
        return {
            "path": None,
            "sha256": None,
            "method": "external-build-tool-not-distributed",
            "file_count": 0,
            "total_bytes": 0,
        }
    if source_root is None:
        return {
            "path": None,
            "sha256": None,
            "method": "missing-source",
            "file_count": 0,
            "total_bytes": 0,
        }
    files, method = _source_files(repository, seed, source_root, environment)
    entries = []
    total = 0
    for path, relative in files:
        size, digest = regular_file_identity(path)
        total += size
        entries.append(
            {"path": relative.as_posix(), "size": size, "sha256": digest}
        )
    return {
        "path": str(source_root),
        "sha256": tree_digest(entries),
        "method": method,
        "file_count": len(entries),
        "total_bytes": total,
    }


def stage_source(
    repository: Path,
    staging: Path,
    seed: ComponentSeed,
    source_root: Path,
    environment: dict[str, str] | None = None,
) -> tuple[str, list[dict[str, object]]]:
    source_relative = f"source/{seed.ecosystem}/{_destination_name(seed)}"
    destination = staging.joinpath(*PurePosixPath(source_relative).parts)
    destination.mkdir(parents=True)
    files, _ = _source_files(repository, seed, source_root, environment)
    count = 0
    total = 0
    for source, relative in files:
        safe_relative(relative.as_posix(), "component source path")
        reject_reverse_path(relative)
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        size, _ = copy_regular_new(source, target, MAX_COPY_FILE_BYTES)
        count += 1
        total += size
        if count > MAX_COPY_FILES or total > MAX_COPY_TOTAL_BYTES:
            raise PublicationError("corresponding-source preparation exceeded its fixed bounds")
    return source_relative, enumerate_tree(destination)


def stage_licenses(
    staging: Path,
    seed: ComponentSeed,
    source_root: Path,
    raw_paths: list[str],
) -> list[str]:
    license_relative = f"licenses/{seed.ecosystem}/{_destination_name(seed)}"
    destination = staging.joinpath(*PurePosixPath(license_relative).parts)
    destination.mkdir(parents=True)
    copied: list[str] = []
    for index, raw_path in enumerate(raw_paths):
        if raw_path.startswith("/"):
            candidate = Path(raw_path)
            if candidate.is_symlink():
                raise PublicationError("reviewed absolute license path is a symlink")
            candidate = candidate.resolve(strict=True)
            relative = PurePosixPath(candidate.name)
        else:
            relative = safe_relative(raw_path, f"reviewed license_files[{index}]")
            candidate = source_root.joinpath(*relative.parts)
            try:
                candidate.resolve(strict=True).relative_to(source_root)
            except ValueError as error:
                raise PublicationError("reviewed license path escaped its component source") from error
        target = destination / f"{index:03d}-{relative.name}"
        copy_regular_new(candidate, target, MAX_COPY_FILE_BYTES)
        copied.append(f"{license_relative}/{target.name}")
    if not copied:
        raise PublicationError(f"component has no reviewed license text: {seed.identifier}")
    return copied
