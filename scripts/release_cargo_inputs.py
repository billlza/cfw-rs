#!/usr/bin/env python3
"""Prepare and verify the only Cargo source set accepted by release builds.

The preparation boundary downloads ``.crate`` archives into a fresh private
Cargo home.  This module then admits each archive against the repository's
``Cargo.lock`` checksum and extracts the same admitted file descriptor into an
owner-only vendor tree.  Release execution never reads ``registry/src``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile
import tomllib
from typing import Any, Callable, Iterable

if __package__:
    from .hash_artifact import build_manifest, tree_sha256_from_records
    from .publication.common import PublicationError, canonical_json, read_regular
else:
    from hash_artifact import build_manifest, tree_sha256_from_records
    from publication.common import PublicationError, canonical_json, read_regular


CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
DOCUMENT_KIND = "cfw-cargo-workspace-inputs-v1"
MANIFEST_KIND = "cfw-verified-cargo-vendor-v1"
MAX_LOCK_BYTES = 64 * 1024 * 1024
MAX_BINDING_BYTES = 64 * 1024 * 1024
MAX_CRATES = 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 250_000
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_VENDOR_BYTES = 2 * 1024 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CRATE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
CRATE_VERSION_RE = re.compile(r"^[A-Za-z0-9.+-]{1,128}$")


class ReleaseCargoInputsError(RuntimeError):
    """The workspace Cargo input set is absent, mutable, or not lock-bound."""


class _DuplicateFieldError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class LockedCargoPackage:
    name: str
    version: str
    checksum: str
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class WorkspaceCargoInputs:
    root: Path
    archives: Path
    vendor: Path
    cargo_lock_sha256: str
    crates_sha256: str
    vendor_tree_sha256: str
    crate_records: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class AuthenticatedCargoArchive:
    directories: tuple[str, ...]
    files: tuple[tuple[str, int, str, str], ...]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateFieldError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ReleaseCargoInputsError(f"{label} is not a lowercase SHA-256")
    return value


def _require_real_directory(
    path: Path,
    label: str,
    *,
    exact_mode: int | None = None,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseCargoInputsError(f"{label} is unavailable") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or mode & 0o022
        or (exact_mode is not None and mode != exact_mode)
    ):
        raise ReleaseCargoInputsError(
            f"{label} does not satisfy the required owner and POSIX mode contract"
        )
    return metadata


def _require_regular_file(
    path: Path,
    label: str,
    *,
    maximum: int,
    exact_mode: int | None = None,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseCargoInputsError(f"{label} is unavailable") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_size <= 0
        or metadata.st_size > maximum
        or mode & 0o022
        or (exact_mode is not None and mode != exact_mode)
    ):
        raise ReleaseCargoInputsError(
            f"{label} is not a bounded owner-only single-link regular file"
        )
    return metadata


def _read_strict_json(path: Path, label: str) -> dict[str, Any]:
    _require_regular_file(path, label, maximum=MAX_BINDING_BYTES, exact_mode=0o400)
    try:
        value = json.loads(
            read_regular(path, MAX_BINDING_BYTES).decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (
        OSError,
        PublicationError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateFieldError,
    ) as error:
        raise ReleaseCargoInputsError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise ReleaseCargoInputsError(f"{label} is not a JSON object")
    return value


def _read_workspace_lock(
    repository: Path,
) -> tuple[str, list[dict[str, Any]], tuple[LockedCargoPackage, ...]]:
    lock_path = repository / "Cargo.lock"
    try:
        encoded = read_regular(lock_path, MAX_LOCK_BYTES)
        document = tomllib.loads(encoded.decode("utf-8"))
    except (
        OSError,
        PublicationError,
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
        ValueError,
    ) as error:
        raise ReleaseCargoInputsError("Cargo.lock is not bounded canonical TOML") from error
    packages = document.get("package")
    if document.get("version") != 4 or not isinstance(packages, list):
        raise ReleaseCargoInputsError("Cargo.lock must use the v4 package graph")
    identities: set[tuple[str, str, str | None]] = set()
    registry: list[LockedCargoPackage] = []
    parsed: list[dict[str, Any]] = []
    for value in packages:
        if not isinstance(value, dict):
            raise ReleaseCargoInputsError("Cargo.lock contains a malformed package")
        name = value.get("name")
        version = value.get("version")
        source = value.get("source")
        checksum = value.get("checksum")
        dependencies = value.get("dependencies", [])
        if (
            not isinstance(name, str)
            or CRATE_NAME_RE.fullmatch(name) is None
            or not isinstance(version, str)
            or CRATE_VERSION_RE.fullmatch(version) is None
            or (source is not None and not isinstance(source, str))
            or not isinstance(dependencies, list)
            or any(not isinstance(item, str) or not item or len(item) > 1024 for item in dependencies)
        ):
            raise ReleaseCargoInputsError("Cargo.lock package identity is malformed")
        identity = (name, version, source)
        if identity in identities:
            raise ReleaseCargoInputsError("Cargo.lock repeats a package identity")
        identities.add(identity)
        if source is None:
            if checksum is not None:
                raise ReleaseCargoInputsError("a local Cargo.lock package has a checksum")
        else:
            if source != CRATES_IO_SOURCE:
                raise ReleaseCargoInputsError(
                    "Cargo.lock contains a non-crates.io external source"
                )
            registry.append(
                LockedCargoPackage(
                    name=name,
                    version=version,
                    checksum=_require_sha256(
                        checksum, f"{name} {version} Cargo.lock checksum"
                    ),
                    dependencies=tuple(dependencies),
                )
            )
        parsed.append(value)
    if not registry or len(registry) > MAX_CRATES:
        raise ReleaseCargoInputsError("Cargo.lock registry package count is outside its bound")
    registry.sort(key=lambda item: (item.name, item.version, item.checksum))
    if len({(item.name, item.version) for item in registry}) != len(registry):
        raise ReleaseCargoInputsError("Cargo.lock repeats a crates.io name/version archive")
    return _sha256_bytes(encoded), parsed, tuple(registry)


def workspace_input_root(repository: Path, release_home: Path) -> Path:
    canonical_repository = repository.resolve(strict=True)
    canonical_home = release_home.resolve(strict=True)
    _require_real_directory(canonical_repository, "release repository")
    _require_real_directory(canonical_home, "release account home")
    lock_sha256, _packages, _registry = _read_workspace_lock(canonical_repository)
    return (
        canonical_home
        / ".cfm-release-tooling"
        / f"cargo-workspace-{lock_sha256}"
    )


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _open_source_archive(path: Path) -> tuple[int, os.stat_result]:
    metadata = _require_regular_file(
        path,
        "Cargo crate archive",
        maximum=MAX_ARCHIVE_BYTES,
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except OSError as error:
        raise ReleaseCargoInputsError("cannot open Cargo crate archive") from error
    if _stable_file_identity(metadata) != _stable_file_identity(opened):
        os.close(descriptor)
        raise ReleaseCargoInputsError("Cargo crate archive changed while opening")
    return descriptor, opened


def _archive_for(source_cargo_home: Path, crate: LockedCargoPackage) -> Path:
    cache = source_cargo_home / "registry/cache"
    _require_real_directory(cache, "private Cargo archive cache")
    filename = f"{crate.name}-{crate.version}.crate"
    candidates: list[Path] = []
    try:
        cache_directories = sorted(cache.iterdir())
    except OSError as error:
        raise ReleaseCargoInputsError("cannot enumerate private Cargo archive cache") from error
    for directory in cache_directories:
        _require_real_directory(directory, "private Cargo registry cache directory")
        candidate = directory / filename
        if os.path.lexists(candidate):
            candidates.append(candidate)
    if len(candidates) != 1:
        raise ReleaseCargoInputsError(
            f"expected one private archive for {crate.name} {crate.version}"
        )
    return candidates[0]


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ReleaseCargoInputsError("cannot write verified Cargo input")
        view = view[written:]


def _write_private_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    except OSError as error:
        raise ReleaseCargoInputsError(f"cannot create private input file: {path.name}") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _seal_tree(root: Path) -> None:
    try:
        for directory, names, filenames in os.walk(root, topdown=False, followlinks=False):
            directory_path = Path(directory)
            for name in names:
                path = directory_path / name
                metadata = path.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
                    raise ReleaseCargoInputsError("Cargo vendor contains an unsafe directory")
                path.chmod(0o500)
            for name in filenames:
                path = directory_path / name
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ReleaseCargoInputsError("Cargo vendor contains an unsafe file")
                path.chmod(0o500 if metadata.st_mode & 0o111 else 0o400)
        root.chmod(0o500)
    except OSError as error:
        raise ReleaseCargoInputsError("cannot seal verified Cargo inputs") from error


def _validated_archive_member(
    member: tarfile.TarInfo,
    package_root_name: str,
    seen: set[str],
    budget: dict[str, int],
) -> tuple[PurePosixPath | None, str | None]:
    budget["entries"] += 1
    if budget["entries"] > MAX_ARCHIVE_ENTRIES:
        raise ReleaseCargoInputsError("Cargo archives contain too many entries")
    member_path = PurePosixPath(member.name)
    try:
        encoded_length = len(member.name.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as error:
        raise ReleaseCargoInputsError("Cargo crate contains a non-UTF-8 path") from error
    canonical_member_name = member_path.as_posix()
    accepted_member_names = {canonical_member_name}
    if member.isdir():
        accepted_member_names.add(canonical_member_name + "/")
    if (
        member_path.is_absolute()
        or not member_path.parts
        or member_path.parts[0] != package_root_name
        or any(part in {"", ".", ".."} for part in member_path.parts)
        or member.name not in accepted_member_names
        or encoded_length > 4096
    ):
        raise ReleaseCargoInputsError("Cargo crate contains an unsafe path")
    relative = PurePosixPath(*member_path.parts[1:])
    if not relative.parts:
        if not member.isdir():
            raise ReleaseCargoInputsError("Cargo crate root is not a directory")
        return None, None
    rendered = relative.as_posix()
    if rendered == ".cargo-checksum.json" or rendered in seen:
        raise ReleaseCargoInputsError("Cargo crate contains a duplicate reserved path")
    seen.add(rendered)
    return relative, rendered


def _consume_archive_file(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    budget: dict[str, int],
    writer: Callable[[bytes], None] | None = None,
) -> str:
    if (
        member.size < 0
        or member.size > MAX_SOURCE_FILE_BYTES
        or budget["vendor_bytes"] + member.size > MAX_VENDOR_BYTES
    ):
        raise ReleaseCargoInputsError("Cargo source exceeds its fixed bound")
    budget["vendor_bytes"] += member.size
    source_entry = archive.extractfile(member)
    if source_entry is None:
        raise ReleaseCargoInputsError("Cargo source entry cannot be read")
    entry_digest = hashlib.sha256()
    remaining = member.size
    try:
        while remaining:
            chunk = source_entry.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ReleaseCargoInputsError("Cargo source entry is truncated")
            remaining -= len(chunk)
            entry_digest.update(chunk)
            if writer is not None:
                writer(chunk)
        if source_entry.read(1):
            raise ReleaseCargoInputsError(
                "Cargo source entry exceeds its declared size"
            )
    finally:
        source_entry.close()
    return entry_digest.hexdigest()


def _copy_and_extract_archive(
    source: Path,
    destination: Path,
    crate: LockedCargoPackage,
    vendor: Path,
    budget: dict[str, int],
) -> dict[str, str]:
    source_descriptor, source_metadata = _open_source_archive(source)
    output_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        output_flags |= os.O_NOFOLLOW
    destination_descriptor = -1
    try:
        destination_descriptor = os.open(destination, output_flags, 0o600)
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_ARCHIVE_BYTES:
                raise ReleaseCargoInputsError("Cargo crate archive exceeded its bound")
            digest.update(chunk)
            _write_all(destination_descriptor, chunk)
        source_after = os.fstat(source_descriptor)
        if (
            _stable_file_identity(source_metadata)
            != _stable_file_identity(source_after)
            or copied != source_metadata.st_size
        ):
            raise ReleaseCargoInputsError("Cargo crate archive changed while copying")
        if digest.hexdigest() != crate.checksum:
            raise ReleaseCargoInputsError(
                f"Cargo crate archive checksum differs from Cargo.lock: {crate.name} {crate.version}"
            )
        budget["archive_bytes"] += copied
        if budget["archive_bytes"] > MAX_TOTAL_ARCHIVE_BYTES:
            raise ReleaseCargoInputsError("Cargo crate archives exceed their total bound")
        os.fsync(destination_descriptor)
        os.lseek(destination_descriptor, 0, os.SEEK_SET)

        package_root_name = f"{crate.name}-{crate.version}"
        package_root = vendor / package_root_name
        package_root.mkdir(mode=0o700)
        seen: set[str] = set()
        file_digests: dict[str, str] = {}
        archive_stream = os.fdopen(os.dup(destination_descriptor), "rb")
        try:
            with archive_stream, tarfile.open(fileobj=archive_stream, mode="r:gz") as archive:
                for member in archive:
                    relative, rendered = _validated_archive_member(
                        member, package_root_name, seen, budget
                    )
                    if relative is None or rendered is None:
                        continue
                    output_path = package_root.joinpath(*relative.parts)
                    if member.isdir():
                        output_path.mkdir(parents=True, exist_ok=True, mode=0o700)
                        output_path.chmod(0o700)
                        continue
                    if not member.isfile():
                        raise ReleaseCargoInputsError(
                            "Cargo crate contains a non-regular source entry"
                        )
                    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    output_descriptor = -1
                    try:
                        output_descriptor = os.open(output_path, flags, 0o600)
                        entry_digest = _consume_archive_file(
                            archive,
                            member,
                            budget,
                            lambda chunk: _write_all(output_descriptor, chunk),
                        )
                        os.fsync(output_descriptor)
                        os.fchmod(
                            output_descriptor,
                            0o700 if member.mode & 0o111 else 0o600,
                        )
                    finally:
                        if output_descriptor >= 0:
                            os.close(output_descriptor)
                    file_digests[rendered] = entry_digest
        except (OSError, tarfile.TarError) as error:
            raise ReleaseCargoInputsError("cannot extract verified Cargo archive") from error
        if "Cargo.toml" not in file_digests:
            raise ReleaseCargoInputsError("Cargo crate omits Cargo.toml")
        checksum_document = {"files": file_digests, "package": crate.checksum}
        _write_private_file(
            package_root / ".cargo-checksum.json",
            canonical_json(checksum_document),
        )
        _seal_tree(package_root)
        try:
            source_tree_sha256 = str(
                build_manifest(package_root, algorithm="sha256-tree-v2")["sha256"]
            )
        except (OSError, ValueError) as error:
            raise ReleaseCargoInputsError("cannot bind verified Cargo source tree") from error
        os.fchmod(destination_descriptor, 0o400)
        return {
            "crate_sha256": crate.checksum,
            "name": crate.name,
            "source": CRATES_IO_SOURCE,
            "source_tree_sha256": source_tree_sha256,
            "version": crate.version,
        }
    except BaseException:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)


def _authenticated_archive_inventory(
    archive_path: Path,
    crate: LockedCargoPackage,
    budget: dict[str, int],
    ) -> AuthenticatedCargoArchive:
    _require_regular_file(
        archive_path,
        "verified Cargo archive",
        maximum=MAX_ARCHIVE_BYTES,
        exact_mode=0o400,
    )
    descriptor, opened = _open_source_archive(archive_path)
    try:
        archive_digest = hashlib.sha256()
        archive_bytes = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            archive_bytes += len(chunk)
            if archive_bytes > MAX_ARCHIVE_BYTES:
                raise ReleaseCargoInputsError("Cargo crate archive exceeded its bound")
            archive_digest.update(chunk)
        if archive_bytes != opened.st_size or archive_digest.hexdigest() != crate.checksum:
            raise ReleaseCargoInputsError(
                f"verified Cargo archive differs from Cargo.lock: {crate.name} {crate.version}"
            )
        budget["archive_bytes"] += archive_bytes
        if budget["archive_bytes"] > MAX_TOTAL_ARCHIVE_BYTES:
            raise ReleaseCargoInputsError("Cargo crate archives exceed their total bound")
        os.lseek(descriptor, 0, os.SEEK_SET)

        package_root_name = f"{crate.name}-{crate.version}"
        seen: set[str] = set()
        directories: set[str] = set()
        files: dict[str, tuple[int, str, str]] = {}
        archive_stream = os.fdopen(os.dup(descriptor), "rb")
        try:
            with archive_stream, tarfile.open(fileobj=archive_stream, mode="r:gz") as archive:
                for member in archive:
                    relative, rendered = _validated_archive_member(
                        member, package_root_name, seen, budget
                    )
                    if relative is None or rendered is None:
                        continue
                    parents = [
                        PurePosixPath(*relative.parts[:index]).as_posix()
                        for index in range(1, len(relative.parts))
                    ]
                    if any(parent in files for parent in parents):
                        raise ReleaseCargoInputsError(
                            "Cargo crate contains a file/directory path conflict"
                        )
                    directories.update(parents)
                    if member.isdir():
                        if rendered in files:
                            raise ReleaseCargoInputsError(
                                "Cargo crate contains a file/directory path conflict"
                            )
                        directories.add(rendered)
                        continue
                    if not member.isfile():
                        raise ReleaseCargoInputsError(
                            "Cargo crate contains a non-regular source entry"
                        )
                    if rendered in directories:
                        raise ReleaseCargoInputsError(
                            "Cargo crate contains a file/directory path conflict"
                        )
                    files[rendered] = (
                        member.size,
                        _consume_archive_file(archive, member, budget),
                        "0500" if member.mode & 0o111 else "0400",
                    )
        except (OSError, tarfile.TarError) as error:
            raise ReleaseCargoInputsError(
                "cannot inspect verified Cargo archive"
            ) from error
        if "Cargo.toml" not in files:
            raise ReleaseCargoInputsError("Cargo crate omits Cargo.toml")
        checksum_document = canonical_json(
            {
                "files": {path: values[1] for path, values in files.items()},
                "package": crate.checksum,
            }
        )
        files[".cargo-checksum.json"] = (
            len(checksum_document),
            _sha256_bytes(checksum_document),
            "0400",
        )
        after = os.fstat(descriptor)
        try:
            rebound = archive_path.lstat()
        except OSError as error:
            raise ReleaseCargoInputsError(
                "verified Cargo archive changed during inspection"
            ) from error
        if (
            _stable_file_identity(opened) != _stable_file_identity(after)
            or _stable_file_identity(opened) != _stable_file_identity(rebound)
        ):
            raise ReleaseCargoInputsError(
                "verified Cargo archive changed during inspection"
            )
        return AuthenticatedCargoArchive(
            directories=tuple(sorted(directories)),
            files=tuple(
                (path, size, digest, mode)
                for path, (size, digest, mode) in sorted(files.items())
            ),
        )
    finally:
        os.close(descriptor)


def _archive_package_entries(
    inventory: AuthenticatedCargoArchive,
) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = [
        {"mode": "0500", "path": path, "type": "directory"}
        for path in inventory.directories
    ]
    entries.extend(
        {
            "mode": mode,
            "path": path,
            "sha256": digest,
            "size": size,
            "type": "file",
        }
        for path, size, digest, mode in inventory.files
    )
    return sorted(entries, key=lambda entry: str(entry["path"]))


def _verify_vendor_against_archives(
    archives: Path,
    locked: tuple[LockedCargoPackage, ...],
    records: tuple[dict[str, str], ...],
) -> tuple[list[dict[str, object]], dict[str, int]]:
    budget = {"archive_bytes": 0, "entries": 0, "vendor_bytes": 0}
    vendor_entries: list[dict[str, object]] = []
    for crate, record in zip(locked, records, strict=True):
        inventory = _authenticated_archive_inventory(
            archives / f"{crate.name}-{crate.version}.crate",
            crate,
            budget,
        )
        package_root_name = f"{crate.name}-{crate.version}"
        package_entries = _archive_package_entries(inventory)
        package_tree_sha256 = tree_sha256_from_records(
            [
                {"mode": "0500", "path": ".", "type": "directory"},
                *package_entries,
            ]
        )
        if package_tree_sha256 != record["source_tree_sha256"]:
            raise ReleaseCargoInputsError(
                "Cargo vendor package record differs from its authenticated archive: "
                f"{package_root_name}"
            )
        vendor_entries.append(
            {"mode": "0500", "path": package_root_name, "type": "directory"}
        )
        for entry in package_entries:
            prefixed = dict(entry)
            prefixed["path"] = f"{package_root_name}/{entry['path']}"
            vendor_entries.append(prefixed)
    return (
        sorted(vendor_entries, key=lambda entry: str(entry["path"])),
        budget,
    )


def _expected_binding(
    lock_sha256: str,
    records: Iterable[dict[str, str]],
    budget: dict[str, int],
    vendor_tree_sha256: str,
) -> dict[str, Any]:
    crates = list(records)
    crates_sha256 = _sha256_bytes(canonical_json(crates))
    return {
        "algorithm": "crates-io-lock-archive-tree-v1",
        "archive_bytes": budget["archive_bytes"],
        "cargo_lock_sha256": lock_sha256,
        "crate_count": len(crates),
        "crates": crates,
        "crates_sha256": crates_sha256,
        "document": DOCUMENT_KIND,
        "registry": CRATES_IO_SOURCE,
        "schema_version": 1,
        "source_entries": budget["entries"],
        "source_file_bytes": budget["vendor_bytes"],
        "vendor_tree_sha256": vendor_tree_sha256,
    }


def prepare_workspace_cargo_inputs(
    repository: Path,
    source_cargo_home: Path,
    workspace_root: Path,
) -> WorkspaceCargoInputs:
    repository = repository.resolve(strict=True)
    source_cargo_home = source_cargo_home.resolve(strict=True)
    _require_real_directory(repository, "release repository")
    _require_real_directory(source_cargo_home, "private Cargo preparation home", exact_mode=0o700)
    lock_sha256, _packages, locked = _read_workspace_lock(repository)
    if (
        not workspace_root.is_absolute()
        or workspace_root.name != f"cargo-workspace-{lock_sha256}"
        or workspace_root.parent.name != ".cfm-release-tooling"
    ):
        raise ReleaseCargoInputsError("Cargo workspace input root is not the deterministic private path")
    parent = workspace_root.parent
    _require_real_directory(parent, "release tooling root", exact_mode=0o700)
    if os.path.lexists(workspace_root):
        return verify_workspace_cargo_inputs(repository, workspace_root)

    temporary = Path(
        tempfile.mkdtemp(prefix=".cargo-workspace-preparation.", dir=parent)
    )
    temporary.chmod(0o700)
    published = False
    try:
        archives = temporary / "archives"
        vendor = temporary / "verified-vendor"
        archives.mkdir(mode=0o700)
        vendor.mkdir(mode=0o700)
        budget = {"archive_bytes": 0, "entries": 0, "vendor_bytes": 0}
        records: list[dict[str, str]] = []
        for crate in locked:
            records.append(
                _copy_and_extract_archive(
                    _archive_for(source_cargo_home, crate),
                    archives / f"{crate.name}-{crate.version}.crate",
                    crate,
                    vendor,
                    budget,
                )
            )
        _seal_tree(archives)
        vendor.chmod(0o500)
        crates_sha256 = _sha256_bytes(canonical_json(records))
        manifest_metadata = {
            "artifactKind": MANIFEST_KIND,
            "cargoLockSha256": lock_sha256,
            "crateCount": str(len(records)),
            "cratesSha256": crates_sha256,
            "registry": CRATES_IO_SOURCE,
        }
        try:
            vendor_manifest = build_manifest(
                vendor,
                metadata=manifest_metadata,
                algorithm="sha256-tree-v2",
            )
        except (OSError, ValueError) as error:
            raise ReleaseCargoInputsError("cannot bind verified Cargo vendor") from error
        vendor_tree_sha256 = _require_sha256(
            vendor_manifest.get("sha256"), "verified Cargo vendor tree"
        )
        binding = _expected_binding(lock_sha256, records, budget, vendor_tree_sha256)
        _write_private_file(temporary / "binding.json", canonical_json(binding), 0o400)
        _write_private_file(
            temporary / "vendor.manifest.json",
            canonical_json(vendor_manifest),
            0o400,
        )
        temporary.chmod(0o500)
        try:
            os.rename(temporary, workspace_root)
        except FileExistsError as error:
            raise ReleaseCargoInputsError(
                "refusing to replace an existing Cargo workspace input root"
            ) from error
        published = True
        return verify_workspace_cargo_inputs(repository, workspace_root)
    finally:
        if not published and temporary.exists() and temporary.parent == parent:
            import shutil

            for directory, _names, filenames in os.walk(
                temporary, topdown=False, followlinks=False
            ):
                directory_path = Path(directory)
                for filename in filenames:
                    try:
                        (directory_path / filename).chmod(0o600)
                    except OSError:
                        pass
                try:
                    directory_path.chmod(0o700)
                except OSError:
                    pass
            shutil.rmtree(temporary)


def _validated_records(
    binding: dict[str, Any], locked: tuple[LockedCargoPackage, ...]
) -> tuple[dict[str, str], ...]:
    values = binding.get("crates")
    if not isinstance(values, list) or len(values) != len(locked):
        raise ReleaseCargoInputsError("Cargo input binding has the wrong crate set")
    records: list[dict[str, str]] = []
    for value, crate in zip(values, locked, strict=True):
        expected_keys = {
            "crate_sha256",
            "name",
            "source",
            "source_tree_sha256",
            "version",
        }
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise ReleaseCargoInputsError("Cargo input crate record is malformed")
        record = {
            "crate_sha256": _require_sha256(value.get("crate_sha256"), "crate archive"),
            "name": value.get("name"),
            "source": value.get("source"),
            "source_tree_sha256": _require_sha256(
                value.get("source_tree_sha256"), "crate source tree"
            ),
            "version": value.get("version"),
        }
        if (
            record["name"] != crate.name
            or record["version"] != crate.version
            or record["source"] != CRATES_IO_SOURCE
            or record["crate_sha256"] != crate.checksum
        ):
            raise ReleaseCargoInputsError("Cargo input crate record differs from Cargo.lock")
        records.append(record)
    return tuple(records)


def verify_workspace_cargo_inputs(
    repository: Path,
    workspace_root: Path,
) -> WorkspaceCargoInputs:
    repository = repository.resolve(strict=True)
    _require_real_directory(repository, "release repository")
    lock_sha256, _packages, locked = _read_workspace_lock(repository)
    if (
        not workspace_root.is_absolute()
        or workspace_root.name != f"cargo-workspace-{lock_sha256}"
        or workspace_root.parent.name != ".cfm-release-tooling"
    ):
        raise ReleaseCargoInputsError("Cargo workspace input root is not deterministic")
    _require_real_directory(workspace_root, "Cargo workspace input root", exact_mode=0o500)
    try:
        top_level = {entry.name for entry in workspace_root.iterdir()}
    except OSError as error:
        raise ReleaseCargoInputsError("cannot enumerate Cargo workspace input root") from error
    if top_level != {"archives", "binding.json", "vendor.manifest.json", "verified-vendor"}:
        raise ReleaseCargoInputsError("Cargo workspace input root has unexpected entries")
    archives = workspace_root / "archives"
    vendor = workspace_root / "verified-vendor"
    _require_real_directory(archives, "verified Cargo archives", exact_mode=0o500)
    _require_real_directory(vendor, "verified Cargo vendor", exact_mode=0o500)
    binding = _read_strict_json(workspace_root / "binding.json", "Cargo input binding")
    manifest = _read_strict_json(
        workspace_root / "vendor.manifest.json", "Cargo vendor manifest"
    )
    expected_binding_keys = {
        "algorithm",
        "archive_bytes",
        "cargo_lock_sha256",
        "crate_count",
        "crates",
        "crates_sha256",
        "document",
        "registry",
        "schema_version",
        "source_entries",
        "source_file_bytes",
        "vendor_tree_sha256",
    }
    if set(binding) != expected_binding_keys:
        raise ReleaseCargoInputsError("Cargo input binding has an unexpected field set")
    if (
        binding.get("document") != DOCUMENT_KIND
        or binding.get("schema_version") != 1
        or binding.get("algorithm") != "crates-io-lock-archive-tree-v1"
        or binding.get("registry") != CRATES_IO_SOURCE
        or binding.get("cargo_lock_sha256") != lock_sha256
        or binding.get("crate_count") != len(locked)
    ):
        raise ReleaseCargoInputsError("Cargo input binding differs from its contract")
    for name, maximum in (
        ("archive_bytes", MAX_TOTAL_ARCHIVE_BYTES),
        ("source_entries", MAX_ARCHIVE_ENTRIES),
        ("source_file_bytes", MAX_VENDOR_BYTES),
    ):
        value = binding.get(name)
        if not isinstance(value, int) or value <= 0 or value > maximum:
            raise ReleaseCargoInputsError(f"Cargo input binding {name} is outside its bound")
    records = _validated_records(binding, locked)
    crates_sha256 = _sha256_bytes(canonical_json(list(records)))
    if binding.get("crates_sha256") != crates_sha256:
        raise ReleaseCargoInputsError("Cargo input crate record digest is invalid")
    expected_archives = {f"{crate.name}-{crate.version}.crate" for crate in locked}
    try:
        actual_archives = {entry.name for entry in archives.iterdir()}
    except OSError as error:
        raise ReleaseCargoInputsError("cannot enumerate verified Cargo archives") from error
    if actual_archives != expected_archives:
        raise ReleaseCargoInputsError("verified Cargo archive set differs from Cargo.lock")
    authenticated_vendor_entries, authenticated_budget = (
        _verify_vendor_against_archives(archives, locked, records)
    )
    for binding_name, budget_name in (
        ("archive_bytes", "archive_bytes"),
        ("source_entries", "entries"),
        ("source_file_bytes", "vendor_bytes"),
    ):
        if binding.get(binding_name) != authenticated_budget[budget_name]:
            raise ReleaseCargoInputsError(
                f"verified Cargo {binding_name} differs from the authenticated archives"
            )
    manifest_metadata = {
        "artifactKind": MANIFEST_KIND,
        "cargoLockSha256": lock_sha256,
        "crateCount": str(len(records)),
        "cratesSha256": crates_sha256,
        "registry": CRATES_IO_SOURCE,
    }
    try:
        actual_manifest = build_manifest(
            vendor,
            metadata=manifest_metadata,
            algorithm="sha256-tree-v2",
        )
    except (OSError, ValueError) as error:
        raise ReleaseCargoInputsError("cannot verify Cargo vendor tree") from error
    if (
        actual_manifest.get("algorithm") != "sha256-tree-v2"
        or actual_manifest.get("root") != "verified-vendor"
        or actual_manifest.get("rootMode") != "0500"
        or actual_manifest.get("entries") != authenticated_vendor_entries
    ):
        raise ReleaseCargoInputsError(
            "Cargo vendor tree differs from its authenticated archives"
        )
    if actual_manifest != manifest:
        raise ReleaseCargoInputsError("Cargo vendor tree differs from its recorded manifest")
    vendor_tree_sha256 = _require_sha256(
        actual_manifest.get("sha256"), "verified Cargo vendor tree"
    )
    if binding.get("vendor_tree_sha256") != vendor_tree_sha256:
        raise ReleaseCargoInputsError("Cargo vendor digest differs from its binding")
    return WorkspaceCargoInputs(
        root=workspace_root,
        archives=archives,
        vendor=vendor,
        cargo_lock_sha256=lock_sha256,
        crates_sha256=crates_sha256,
        vendor_tree_sha256=vendor_tree_sha256,
        crate_records=records,
    )


def _cargo_configuration(vendor: Path) -> bytes:
    rendered_vendor = json.dumps(str(vendor), ensure_ascii=True)
    return (
        "[net]\n"
        "offline = true\n\n"
        "[source.crates-io]\n"
        'replace-with = "cfw-verified-vendor"\n\n'
        "[source.cfw-verified-vendor]\n"
        f"directory = {rendered_vendor}\n"
    ).encode("utf-8")


def reject_ambient_cargo_configuration(
    repository: Path,
    *,
    working_directories: Iterable[str] = (".", "apps/cfw-tauri-shell"),
    additional_working_directories: Iterable[Path] = (),
) -> None:
    repository = repository.resolve(strict=True)
    _require_real_directory(repository, "release repository")
    candidates: set[Path] = set()
    resolved_working_directories: list[Path] = []
    for relative_text in working_directories:
        relative = Path(relative_text)
        if relative.is_absolute() or ".." in relative.parts:
            raise ReleaseCargoInputsError("Cargo working directory must be repository-relative")
        candidate = repository / relative
        if not candidate.exists():
            continue
        working = candidate.resolve(strict=True)
        try:
            working.relative_to(repository)
        except ValueError as error:
            raise ReleaseCargoInputsError("Cargo working directory escaped the repository") from error
        resolved_working_directories.append(working)
    for additional in additional_working_directories:
        if not additional.is_absolute():
            raise ReleaseCargoInputsError(
                "additional Cargo working directory must be absolute"
            )
        try:
            working = additional.resolve(strict=True)
        except OSError as error:
            raise ReleaseCargoInputsError(
                "additional Cargo working directory cannot be resolved"
            ) from error
        _require_real_directory(working, "additional Cargo working directory")
        resolved_working_directories.append(working)
    for working in resolved_working_directories:
        for directory in (working, *working.parents):
            candidates.add(directory / ".cargo/config")
            candidates.add(directory / ".cargo/config.toml")
    for candidate in sorted(candidates):
        if os.path.lexists(candidate):
            raise ReleaseCargoInputsError(
                f"release tooling refuses an ambient Cargo configuration: {candidate}"
            )


def create_runtime_cargo_home(
    repository: Path,
    workspace_inputs: WorkspaceCargoInputs,
    cargo_home: Path,
    *,
    additional_working_directories: Iterable[Path] = (),
) -> None:
    reject_ambient_cargo_configuration(
        repository,
        additional_working_directories=additional_working_directories,
    )
    _require_real_directory(cargo_home, "runtime Cargo home", exact_mode=0o700)
    try:
        if any(cargo_home.iterdir()):
            raise ReleaseCargoInputsError("runtime Cargo home is not empty")
    except OSError as error:
        raise ReleaseCargoInputsError("cannot inspect runtime Cargo home") from error
    _write_private_file(
        cargo_home / "config.toml",
        _cargo_configuration(workspace_inputs.vendor),
        0o400,
    )
    verify_runtime_cargo_home(
        repository,
        workspace_inputs,
        cargo_home,
        additional_working_directories=additional_working_directories,
    )


def verify_runtime_cargo_home(
    repository: Path,
    workspace_inputs: WorkspaceCargoInputs,
    cargo_home: Path,
    *,
    additional_working_directories: Iterable[Path] = (),
) -> None:
    reject_ambient_cargo_configuration(
        repository,
        additional_working_directories=additional_working_directories,
    )
    _require_real_directory(cargo_home, "runtime Cargo home", exact_mode=0o700)
    config = cargo_home / "config.toml"
    _require_regular_file(
        config,
        "runtime Cargo configuration",
        maximum=64 * 1024,
        exact_mode=0o400,
    )
    try:
        if read_regular(config, 64 * 1024) != _cargo_configuration(workspace_inputs.vendor):
            raise ReleaseCargoInputsError("runtime Cargo configuration differs from its contract")
    except (PublicationError, ValueError) as error:
        raise ReleaseCargoInputsError("cannot read runtime Cargo configuration") from error
    forbidden = (cargo_home / "config", cargo_home / "registry/src")
    if any(os.path.lexists(path) for path in forbidden):
        raise ReleaseCargoInputsError("runtime Cargo home contains a forbidden source or configuration")


def release_verifier_dependency_records(
    repository: Path,
    inputs: WorkspaceCargoInputs,
) -> dict[str, object]:
    _lock_sha, packages, _locked = _read_workspace_lock(repository)
    indexed: dict[str, list[dict[str, Any]]] = {}
    by_identity: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for package in packages:
        identity = (str(package["name"]), str(package["version"]), package.get("source"))
        by_identity[identity] = package
        indexed.setdefault(str(package["name"]), []).append(package)
    roots = [
        value
        for value in indexed.get("cfw-release-verifier", [])
        if value.get("source") is None and value.get("version") == "0.4.0"
    ]
    if len(roots) != 1:
        raise ReleaseCargoInputsError("Cargo.lock lacks the exact release verifier root")

    def resolve(rendered: object) -> dict[str, Any]:
        if not isinstance(rendered, str) or not rendered or len(rendered) > 1024:
            raise ReleaseCargoInputsError("Cargo.lock dependency reference is malformed")
        name, separator, remainder = rendered.partition(" ")
        candidates = indexed.get(name, [])
        if separator:
            version, source_separator, source_text = remainder.partition(" (")
            candidates = [item for item in candidates if item.get("version") == version]
            if source_separator:
                if not source_text.endswith(")"):
                    raise ReleaseCargoInputsError("Cargo.lock dependency source is malformed")
                candidates = [
                    item for item in candidates if item.get("source") == source_text[:-1]
                ]
        if len(candidates) != 1:
            raise ReleaseCargoInputsError(
                f"Cargo.lock dependency is ambiguous or absent: {rendered}"
            )
        return candidates[0]

    record_index = {
        (record["name"], record["version"], record["crate_sha256"]): record
        for record in inputs.crate_records
    }
    pending = [roots[0]]
    visited: set[tuple[str, str, str | None]] = set()
    records: list[dict[str, str]] = []
    while pending:
        package = pending.pop()
        identity = (str(package["name"]), str(package["version"]), package.get("source"))
        if identity in visited:
            continue
        visited.add(identity)
        if len(visited) > MAX_CRATES:
            raise ReleaseCargoInputsError("release verifier dependency graph is too large")
        if package is not roots[0]:
            checksum = _require_sha256(package.get("checksum"), "release verifier crate")
            key = (str(package["name"]), str(package["version"]), checksum)
            record = record_index.get(key)
            if record is None:
                raise ReleaseCargoInputsError("release verifier crate is absent from verified vendor")
            records.append(record)
        pending.extend(resolve(item) for item in package.get("dependencies", []))
    records.sort(key=lambda item: (item["name"], item["version"], item["crate_sha256"]))
    return {
        "algorithm": "crates-io-lock-archive-tree-v1",
        "crates": records,
        "sha256": _sha256_bytes(canonical_json(records)),
    }


def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("locate", "verify", "reject-ambient"):
        command = subparsers.add_parser(name)
        command.add_argument("--repository", required=True, type=Path)
        command.add_argument("--release-home", required=True, type=Path)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--repository", required=True, type=Path)
    prepare.add_argument("--release-home", required=True, type=Path)
    prepare.add_argument("--source-cargo-home", required=True, type=Path)
    runtime = subparsers.add_parser("create-runtime")
    runtime.add_argument("--repository", required=True, type=Path)
    runtime.add_argument("--release-home", required=True, type=Path)
    runtime.add_argument("--cargo-home", required=True, type=Path)
    runtime_verify = subparsers.add_parser("verify-runtime")
    runtime_verify.add_argument("--repository", required=True, type=Path)
    runtime_verify.add_argument("--release-home", required=True, type=Path)
    runtime_verify.add_argument("--cargo-home", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        root = workspace_input_root(arguments.repository, arguments.release_home)
        if arguments.command == "locate":
            print(root)
            return
        if arguments.command == "reject-ambient":
            reject_ambient_cargo_configuration(arguments.repository)
            return
        if arguments.command == "prepare":
            inputs = prepare_workspace_cargo_inputs(
                arguments.repository,
                arguments.source_cargo_home,
                root,
            )
        else:
            inputs = verify_workspace_cargo_inputs(arguments.repository, root)
        if arguments.command == "create-runtime":
            create_runtime_cargo_home(arguments.repository, inputs, arguments.cargo_home)
            return
        if arguments.command == "verify-runtime":
            verify_runtime_cargo_home(arguments.repository, inputs, arguments.cargo_home)
            return
        if arguments.command in {"prepare", "verify"}:
            print(
                "\t".join(
                    (
                        str(inputs.root),
                        str(inputs.vendor),
                        inputs.cargo_lock_sha256,
                        inputs.vendor_tree_sha256,
                    )
                )
            )
    except (OSError, ReleaseCargoInputsError, ValueError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    _main()


__all__ = [
    "CRATES_IO_SOURCE",
    "LockedCargoPackage",
    "ReleaseCargoInputsError",
    "WorkspaceCargoInputs",
    "create_runtime_cargo_home",
    "prepare_workspace_cargo_inputs",
    "reject_ambient_cargo_configuration",
    "release_verifier_dependency_records",
    "verify_runtime_cargo_home",
    "verify_workspace_cargo_inputs",
    "workspace_input_root",
]
