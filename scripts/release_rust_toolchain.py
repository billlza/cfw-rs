#!/usr/bin/env python3
"""Verify the complete pinned Rust toolchain surface used by release gates."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tomllib
from typing import Any


TARGET = "aarch64-apple-darwin"
SURFACE_ALGORITHM = "rustup-component-file-tree-v1"
SURFACE_PIN = "RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256"
MAX_SMALL_DOCUMENT_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_TOOLCHAIN_FILES = 50_000
MAX_TOOLCHAIN_FILE_BYTES = 768 * 1024 * 1024
MAX_TOOLCHAIN_TOTAL_BYTES = 1024 * 1024 * 1024
VERSION_RE = re.compile(r"[1-9][0-9]*[.][0-9]+[.][0-9]+")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
EXPECTED_COMPONENTS = tuple(
    sorted(
        {
            f"cargo-{TARGET}",
            f"clippy-preview-{TARGET}",
            f"rust-std-{TARGET}",
            f"rustc-{TARGET}",
            f"rustfmt-preview-{TARGET}",
        }
    )
)


class ReleaseRustToolchainError(RuntimeError):
    """The selected Rust toolchain is not the immutable release toolchain."""


@dataclass(frozen=True)
class VerifiedRustToolchain:
    channel: str
    toolchain: str
    root: Path
    cargo: Path
    rustc: Path
    surface: dict[str, Any]


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseRustToolchainError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ReleaseRustToolchainError(f"{label} is not a release-owned real directory")


def _canonical_root(root: Path) -> Path:
    if not root.is_absolute():
        raise ReleaseRustToolchainError("Rust toolchain root must be absolute")
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ReleaseRustToolchainError("Rust toolchain root is unavailable") from error
    if resolved != root:
        raise ReleaseRustToolchainError("Rust toolchain root is not canonical")
    _require_real_directory(root, "Rust toolchain root")
    return root


def _member(root: Path, relative: str, *, directory: bool) -> Path:
    candidate = PurePosixPath(relative)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or candidate.as_posix() != relative
    ):
        raise ReleaseRustToolchainError("Rust component manifest path is unsafe")
    current = root
    for index, part in enumerate(candidate.parts):
        current /= part
        final = index == len(candidate.parts) - 1
        if not final or directory:
            _require_real_directory(current, "Rust component directory")
    return current


def _open_regular(path: Path, maximum: int, label: str) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise ReleaseRustToolchainError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise ReleaseRustToolchainError(f"{label} is not a bounded release-owned file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseRustToolchainError(f"{label} cannot be opened safely") from error
    opened = os.fstat(descriptor)
    if _stable_file_identity(before) != _stable_file_identity(opened):
        os.close(descriptor)
        raise ReleaseRustToolchainError(f"{label} changed while opening")
    return descriptor, before


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _finish_regular_read(
    descriptor: int,
    before: os.stat_result,
    total: int,
    label: str,
) -> None:
    after = os.fstat(descriptor)
    if total != before.st_size or _stable_file_identity(before) != _stable_file_identity(after):
        raise ReleaseRustToolchainError(f"{label} changed while reading")


def _read_regular(path: Path, maximum: int, label: str) -> tuple[bytes, os.stat_result]:
    descriptor, before = _open_regular(path, maximum, label)
    data = bytearray()
    try:
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > maximum:
            raise ReleaseRustToolchainError(f"{label} exceeded its size bound")
        _finish_regular_read(descriptor, before, len(data), label)
    finally:
        os.close(descriptor)
    return bytes(data), before


def _regular_file_digest(
    path: Path, maximum: int, label: str
) -> tuple[str, int, os.stat_result]:
    descriptor, before = _open_regular(path, maximum, label)
    digest = hashlib.sha256()
    total = 0
    try:
        while total <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        if total > maximum:
            raise ReleaseRustToolchainError(f"{label} exceeded its size bound")
        _finish_regular_read(descriptor, before, total, label)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), total, before


def _require_executable(path: Path, maximum: int, label: str) -> None:
    descriptor, _metadata = _open_regular(path, maximum, label)
    os.close(descriptor)
    if not os.access(path, os.X_OK):
        raise ReleaseRustToolchainError(f"{label} is not executable")


def _text(path: Path, maximum: int, label: str) -> str:
    try:
        return _read_regular(path, maximum, label)[0].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseRustToolchainError(f"{label} is not UTF-8") from error


def _strict_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseRustToolchainError("pinned input manifest repeats a field")
            result[key] = value
        return result

    try:
        value = json.loads(
            _text(path, MAX_MANIFEST_BYTES, "pinned input manifest"),
            object_pairs_hook=reject_duplicates,
        )
    except json.JSONDecodeError as error:
        raise ReleaseRustToolchainError("pinned input manifest is invalid JSON") from error
    if not isinstance(value, dict):
        raise ReleaseRustToolchainError("pinned input manifest is not an object")
    return value


def _pins(repository: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in _text(
        repository / "scripts/dependency_pins.env",
        MAX_SMALL_DOCUMENT_BYTES,
        "release dependency pins",
    ).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.+)", line)
        if match is None or match.group(1) in values:
            raise ReleaseRustToolchainError("release dependency pins are not canonical")
        values[match.group(1)] = match.group(2)
    return values


def _declaration(repository: Path) -> str:
    try:
        document = tomllib.loads(
            _text(
                repository / "rust-toolchain.toml",
                MAX_SMALL_DOCUMENT_BYTES,
                "Rust toolchain declaration",
            )
        )
    except tomllib.TOMLDecodeError as error:
        raise ReleaseRustToolchainError("Rust toolchain declaration is invalid") from error
    expected = {
        "toolchain": {
            "channel": document.get("toolchain", {}).get("channel")
            if isinstance(document.get("toolchain"), dict)
            else None,
            "components": ["rustfmt", "clippy"],
            "profile": "minimal",
        }
    }
    if document != expected:
        raise ReleaseRustToolchainError("Rust toolchain declaration is not exact")
    channel = expected["toolchain"]["channel"]
    if not isinstance(channel, str) or VERSION_RE.fullmatch(channel) is None:
        raise ReleaseRustToolchainError("Rust toolchain channel is not pinned")
    return channel


def pinned_toolchain_contract(repository: Path) -> tuple[str, str]:
    repository = repository.resolve(strict=True)
    channel = _declaration(repository)
    pins = _pins(repository)
    digest = pins.get(SURFACE_PIN)
    if pins.get("RUST_VERSION") != channel or not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise ReleaseRustToolchainError("Rust toolchain pins differ from the declaration")
    tools = _strict_json(repository / "scripts/pinned_build_inputs.json").get("tools")
    if not isinstance(tools, dict) or tools.get("RUST_VERSION") != channel or tools.get(SURFACE_PIN) != digest:
        raise ReleaseRustToolchainError("Rust toolchain pins are not manifest-bound")
    return channel, digest


def _file_record(root: Path, relative: str) -> dict[str, object]:
    path = _member(root, relative, directory=False)
    digest, size, metadata = _regular_file_digest(
        path, MAX_TOOLCHAIN_FILE_BYTES, "Rust toolchain file"
    )
    return {
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "path": relative,
        "sha256": digest,
        "size": size,
    }


def _validate_exact_tree(
    root: Path,
    expected_files: set[str],
    expected_directories: set[str],
) -> None:
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        _require_real_directory(directory, "Rust toolchain directory")
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise ReleaseRustToolchainError(
                "Rust toolchain directory cannot be enumerated"
            ) from error
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ReleaseRustToolchainError(
                    "Rust toolchain member cannot be inspected"
                ) from error
            if entry.is_symlink():
                raise ReleaseRustToolchainError(
                    "Rust toolchain tree contains a symbolic link"
                )
            if stat.S_ISDIR(metadata.st_mode):
                actual_directories.add(relative)
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                if (
                    metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                    or metadata.st_size <= 0
                    or metadata.st_size > MAX_TOOLCHAIN_FILE_BYTES
                ):
                    raise ReleaseRustToolchainError(
                        "Rust toolchain tree contains an unsafe regular file"
                    )
                actual_files.add(relative)
            else:
                raise ReleaseRustToolchainError(
                    "Rust toolchain tree contains a special file"
                )
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ReleaseRustToolchainError(
            "Rust toolchain tree differs from its component manifests"
        )


def build_toolchain_surface(root: Path) -> dict[str, Any]:
    root = _canonical_root(root)
    components_path = _member(root, "lib/rustlib/components", directory=False)
    components = sorted(
        _text(
            components_path,
            MAX_SMALL_DOCUMENT_BYTES,
            "Rust toolchain component inventory",
        ).splitlines()
    )
    if components != list(EXPECTED_COMPONENTS):
        raise ReleaseRustToolchainError("Rust toolchain component inventory is not exact")

    relative_files = {
        "lib/rustlib/components",
        "lib/rustlib/multirust-channel-manifest.toml",
        "lib/rustlib/multirust-config.toml",
        "lib/rustlib/rust-installer-version",
    }
    relative_directories: set[str] = set()
    for component in EXPECTED_COMPONENTS:
        manifest_relative = f"lib/rustlib/manifest-{component}"
        relative_files.add(manifest_relative)
        manifest_path = _member(root, manifest_relative, directory=False)
        lines = _text(
            manifest_path,
            MAX_MANIFEST_BYTES,
            "Rust component manifest",
        ).splitlines()
        if len(lines) != len(set(lines)):
            raise ReleaseRustToolchainError("Rust component manifest repeats an entry")
        for line in lines:
            kind, separator, relative = line.partition(":")
            if not separator or kind not in {"dir", "file"}:
                raise ReleaseRustToolchainError("Rust component manifest entry is malformed")
            member = _member(root, relative, directory=kind == "dir")
            if kind == "file":
                relative_files.add(member.relative_to(root).as_posix())
            else:
                relative_directories.add(member.relative_to(root).as_posix())
    for relative in relative_files | relative_directories:
        for parent in PurePosixPath(relative).parents:
            if parent.as_posix() not in {"", "."}:
                relative_directories.add(parent.as_posix())
    if relative_files & relative_directories:
        raise ReleaseRustToolchainError(
            "Rust component manifests disagree about member types"
        )
    if len(relative_files) + len(relative_directories) > MAX_TOOLCHAIN_FILES:
        raise ReleaseRustToolchainError("Rust toolchain surface contains too many members")
    _validate_exact_tree(root, relative_files, relative_directories)
    records: list[dict[str, object]] = []
    total_size = 0
    for relative in sorted(relative_files):
        record = _file_record(root, relative)
        total_size += int(record["size"])
        if total_size > MAX_TOOLCHAIN_TOTAL_BYTES:
            raise ReleaseRustToolchainError("Rust toolchain surface exceeds its size bound")
        records.append(record)
    return {
        "algorithm": SURFACE_ALGORITHM,
        "components": list(EXPECTED_COMPONENTS),
        "file_count": len(records),
        "sha256": hashlib.sha256(_canonical_json(records)).hexdigest(),
        "total_size": total_size,
    }


def validate_recorded_surface(repository: Path, value: object) -> dict[str, Any]:
    _channel, expected_digest = pinned_toolchain_contract(repository)
    if not isinstance(value, dict) or set(value) != {
        "algorithm",
        "components",
        "file_count",
        "sha256",
        "total_size",
    }:
        raise ReleaseRustToolchainError("recorded Rust toolchain surface has unexpected fields")
    if (
        value.get("algorithm") != SURFACE_ALGORITHM
        or value.get("components") != list(EXPECTED_COMPONENTS)
        or type(value.get("file_count")) is not int
        or not 0 < value["file_count"] <= MAX_TOOLCHAIN_FILES
        or type(value.get("total_size")) is not int
        or not 0 < value["total_size"] <= MAX_TOOLCHAIN_TOTAL_BYTES
        or value.get("sha256") != expected_digest
    ):
        raise ReleaseRustToolchainError("recorded Rust toolchain surface is inconsistent")
    return dict(value)


def verify_pinned_toolchain(repository: Path, root: Path) -> VerifiedRustToolchain:
    repository = repository.resolve(strict=True)
    channel, expected_digest = pinned_toolchain_contract(repository)
    root = _canonical_root(root)
    toolchain = f"{channel}-{TARGET}"
    if root.name != toolchain:
        raise ReleaseRustToolchainError("Rust toolchain root has the wrong identity")
    cargo = _member(root, "bin/cargo", directory=False)
    rustc = _member(root, "bin/rustc", directory=False)
    surface = build_toolchain_surface(root)
    if surface["sha256"] != expected_digest:
        raise ReleaseRustToolchainError(
            "Rust toolchain surface differs from its pin "
            f"(expected_sha256={expected_digest}, "
            f"actual_sha256={surface['sha256']}, "
            f"file_count={surface['file_count']}, "
            f"total_size={surface['total_size']})"
        )
    _require_executable(cargo, MAX_TOOLCHAIN_FILE_BYTES, "Rust Cargo executable")
    _require_executable(rustc, MAX_TOOLCHAIN_FILE_BYTES, "Rust compiler executable")
    return VerifiedRustToolchain(channel, toolchain, root, cargo, rustc, surface)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--repository", type=Path, required=True)
    verify.add_argument("--toolchain-root", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        verify_pinned_toolchain(arguments.repository, arguments.toolchain_root)
    except (OSError, ReleaseRustToolchainError) as error:
        raise SystemExit(f"error: Rust release toolchain: {error}") from error


if __name__ == "__main__":
    main()


__all__ = [
    "EXPECTED_COMPONENTS",
    "ReleaseRustToolchainError",
    "SURFACE_ALGORITHM",
    "TARGET",
    "VerifiedRustToolchain",
    "build_toolchain_surface",
    "pinned_toolchain_contract",
    "validate_recorded_surface",
    "verify_pinned_toolchain",
]
