from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


MAX_JSON_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+@/-]{0,511}$")


class PublicationError(RuntimeError):
    pass


def safe_relative(value: str, label: str = "path") -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise PublicationError(f"{label} is not a canonical relative path")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or any(part in ("", ".", "..") for part in parsed.parts):
        raise PublicationError(f"{label} is not a canonical relative path")
    return parsed


def safe_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise PublicationError(f"{label} is not a bounded canonical identifier")
    return value


def bounded_text(value: object, label: str, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PublicationError(f"{label} is not bounded canonical text")
    return value


def require_exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise PublicationError(f"{label} has an unexpected field set")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise PublicationError(f"{label} is not a canonical SHA-256 digest")
    return value


def open_regular(path: Path):
    try:
        before = path.lstat()
    except OSError as error:
        raise PublicationError(f"cannot inspect {path}: {error}") from error
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise PublicationError(f"required evidence file is not a single-link regular file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PublicationError(f"cannot open {path}: {error}") from error
    opened = os.fstat(descriptor)
    if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
        os.close(descriptor)
        raise PublicationError(f"evidence file changed while opening: {path}")
    return os.fdopen(descriptor, "rb"), opened


def read_regular(path: Path, maximum: int = MAX_JSON_BYTES) -> bytes:
    stream, opened = open_regular(path)
    with stream:
        if opened.st_size <= 0 or opened.st_size > maximum:
            raise PublicationError(f"evidence file size is outside 1..={maximum}: {path}")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(data) > maximum:
        raise PublicationError(f"evidence file exceeds {maximum} bytes: {path}")
    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise PublicationError(f"evidence file changed while reading: {path}")
    return data


def read_prefix(path: Path, length: int) -> bytes:
    if length <= 0:
        raise PublicationError("prefix length must be positive")
    stream, opened = open_regular(path)
    with stream:
        data = stream.read(length)
        after = os.fstat(stream.fileno())
    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise PublicationError(f"evidence file changed while reading: {path}")
    return data


def load_json(path: Path, maximum: int = MAX_JSON_BYTES) -> Any:
    try:
        return json.loads(read_regular(path, maximum))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"invalid JSON evidence {path}: {error}") from error


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_new(path: Path, data: bytes) -> None:
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise PublicationError(f"output parent is not a real directory: {parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def copy_regular_new(source: Path, destination: Path, maximum: int) -> tuple[int, str]:
    if maximum <= 0:
        raise PublicationError("copy bound must be positive")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise PublicationError(f"copy destination parent is not a real directory: {destination.parent}")
    input_stream, opened = open_regular(source)
    if opened.st_size < 0 or opened.st_size > maximum:
        input_stream.close()
        raise PublicationError(f"source file exceeds the fixed copy bound: {source}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    digest = hashlib.sha256()
    copied = 0
    try:
        with input_stream, os.fdopen(descriptor, "wb") as output_stream:
            while chunk := input_stream.read(1024 * 1024):
                copied += len(chunk)
                if copied > maximum:
                    raise PublicationError(f"source file exceeded the fixed copy bound: {source}")
                digest.update(chunk)
                output_stream.write(chunk)
            output_stream.flush()
            os.fsync(output_stream.fileno())
            after = os.fstat(input_stream.fileno())
        if (
            copied != opened.st_size
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise PublicationError(f"source file changed while copying: {source}")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return copied, digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_file_identity(path: Path) -> tuple[int, str]:
    stream, opened = open_regular(path)
    digest = hashlib.sha256()
    with stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise PublicationError(f"file changed while hashing: {path}")
    return opened.st_size, digest.hexdigest()


def sha256_file(path: Path) -> str:
    return regular_file_identity(path)[1]


def enumerate_tree(root: Path) -> list[dict[str, object]]:
    if not root.is_dir() or root.is_symlink():
        raise PublicationError(f"tree root is not a real directory: {root}")
    entries: list[dict[str, object]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in list(directories):
            candidate = current_path / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise PublicationError(f"symlink is forbidden in publication evidence: {candidate}")
            if not stat.S_ISDIR(metadata.st_mode):
                raise PublicationError(f"unsupported evidence tree entry: {candidate}")
            relative = candidate.relative_to(root).as_posix()
            safe_relative(relative)
            entries.append({"path": relative, "type": "directory"})
        for name in files:
            candidate = current_path / name
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise PublicationError(f"unsupported or linked evidence file: {candidate}")
            relative = candidate.relative_to(root).as_posix()
            safe_relative(relative)
            size, digest = regular_file_identity(candidate)
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "size": size,
                    "sha256": digest,
                }
            )
    return sorted(entries, key=lambda entry: str(entry["path"]))


def enumerate_artifact_tree(root: Path) -> list[dict[str, object]]:
    """Hash an artifact tree while preserving only contained relative symlinks."""
    if not root.is_dir() or root.is_symlink():
        raise PublicationError(f"artifact root is not a real directory: {root}")
    entries: list[dict[str, object]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in list(directories):
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            safe_relative(relative)
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                directories.remove(name)
                target = os.readlink(candidate)
                parsed_target = PurePosixPath(target)
                if parsed_target.is_absolute() or ".." in parsed_target.parts:
                    raise PublicationError(f"artifact symlink is not contained: {candidate}")
                entries.append({"path": relative, "type": "symlink", "target": target})
            elif stat.S_ISDIR(metadata.st_mode):
                entries.append({"path": relative, "type": "directory"})
            else:
                raise PublicationError(f"unsupported artifact tree entry: {candidate}")
        for name in files:
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            safe_relative(relative)
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(candidate)
                parsed_target = PurePosixPath(target)
                if parsed_target.is_absolute() or ".." in parsed_target.parts:
                    raise PublicationError(f"artifact symlink is not contained: {candidate}")
                entries.append({"path": relative, "type": "symlink", "target": target})
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                size, digest = regular_file_identity(candidate)
                entries.append(
                    {
                        "path": relative,
                        "type": "file",
                        "size": size,
                        "sha256": digest,
                    }
                )
            else:
                raise PublicationError(f"unsupported or linked artifact file: {candidate}")
    return sorted(entries, key=lambda entry: str(entry["path"]))


def tree_digest(entries: Iterable[dict[str, object]]) -> str:
    return sha256_bytes(canonical_json(list(entries)))


def verify_tree(root: Path, expected_entries: object, expected_digest: object) -> None:
    if not isinstance(expected_entries, list):
        raise PublicationError("tree manifest entries are not an array")
    digest = require_sha256(expected_digest, "tree digest")
    actual = enumerate_tree(root)
    if actual != expected_entries or tree_digest(actual) != digest:
        raise PublicationError(f"publication evidence tree differs from its manifest: {root}")


def reject_reverse_path(relative: PurePosixPath) -> None:
    if relative.parts and relative.parts[0].lower() == "reverse":
        raise PublicationError(f"reference-only reverse payload is forbidden: {relative}")
