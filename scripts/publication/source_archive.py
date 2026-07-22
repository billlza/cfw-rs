from __future__ import annotations

import gzip
import hashlib
import os
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

from .common import (
    PublicationError,
    enumerate_tree,
    open_regular,
    reject_reverse_path,
    require_exact_keys,
    require_sha256,
    safe_relative,
    sha256_file,
    tree_digest,
)


MAX_SOURCE_FILES = 100_000
MAX_SOURCE_FILE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 8 * 1024 * 1024 * 1024


def _reject_component_reverse_path(relative: PurePosixPath) -> None:
    reject_reverse_path(relative)
    if any(part.casefold() == "reverse" for part in relative.parts):
        raise PublicationError(f"reference-only reverse payload is forbidden: {relative}")


def build_source_manifest(root: Path) -> dict[str, Any]:
    entries = enumerate_tree(root)
    file_entries = [entry for entry in entries if entry["type"] == "file"]
    if len(file_entries) > MAX_SOURCE_FILES:
        raise PublicationError("corresponding-source candidate contains too many files")
    total = 0
    for entry in file_entries:
        size = entry["size"]
        if not isinstance(size, int) or size < 0 or size > MAX_SOURCE_FILE_BYTES:
            raise PublicationError("corresponding-source file exceeds the fixed bound")
        total += size
        if total > MAX_SOURCE_TOTAL_BYTES:
            raise PublicationError("corresponding-source candidate exceeds the fixed total bound")
        _reject_component_reverse_path(
            safe_relative(str(entry["path"]), "corresponding-source path")
        )
    return {
        "schema_version": 1,
        "algorithm": "sha256-tree-v1",
        "root": "corresponding-source",
        "entries": entries,
        "sha256": tree_digest(entries),
        "total_file_bytes": total,
    }


def write_source_archive(root: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise PublicationError(f"refusing to replace source archive: {output}")
    entries = enumerate_tree(root)
    with output.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for entry in entries:
                    relative = safe_relative(str(entry["path"]), "corresponding-source path")
                    _reject_component_reverse_path(relative)
                    source = root.joinpath(*relative.parts)
                    info = tarfile.TarInfo(f"corresponding-source/{relative.as_posix()}")
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    if entry["type"] == "directory":
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        archive.addfile(info)
                    else:
                        info.type = tarfile.REGTYPE
                        info.mode = 0o644
                        info.size = int(entry["size"])
                        stream, opened = open_regular(source)
                        expected_size = int(entry["size"])
                        expected_digest = require_sha256(
                            entry["sha256"], f"corresponding-source digest for {relative}"
                        )
                        if opened.st_size != expected_size:
                            stream.close()
                            raise PublicationError(
                                f"corresponding-source file changed before archiving: {source}"
                            )
                        digesting = _DigestingReader(stream, expected_size)
                        try:
                            archive.addfile(info, digesting)
                            after = os.fstat(stream.fileno())
                        finally:
                            stream.close()
                        if (
                            digesting.bytes_read != expected_size
                            or digesting.digest.hexdigest() != expected_digest
                            or (
                                opened.st_dev,
                                opened.st_ino,
                                opened.st_size,
                                opened.st_mtime_ns,
                            )
                            != (
                                after.st_dev,
                                after.st_ino,
                                after.st_size,
                                after.st_mtime_ns,
                            )
                        ):
                            raise PublicationError(
                                f"corresponding-source file changed while archiving: {source}"
                            )


class _DigestingReader:
    def __init__(self, stream: Any, maximum: int) -> None:
        self.stream = stream
        self.maximum = maximum
        self.bytes_read = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self.stream.read(size)
        self.bytes_read += len(data)
        if self.bytes_read > self.maximum:
            raise PublicationError("corresponding-source file exceeded its declared size")
        self.digest.update(data)
        return data


def verify_source_archive(
    archive_path: Path, manifest: object, expected_archive_sha256: object
) -> None:
    expected = require_exact_keys(
        manifest,
        {"schema_version", "algorithm", "root", "entries", "sha256", "total_file_bytes"},
        "corresponding-source manifest",
    )
    if (
        expected["schema_version"] != 1
        or expected["algorithm"] != "sha256-tree-v1"
        or expected["root"] != "corresponding-source"
    ):
        raise PublicationError("unsupported corresponding-source manifest")
    require_sha256(expected["sha256"], "corresponding-source tree digest")
    archive_digest = require_sha256(expected_archive_sha256, "corresponding-source archive digest")
    if sha256_file(archive_path) != archive_digest:
        raise PublicationError("corresponding-source archive digest mismatch")
    entries = expected["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_SOURCE_FILES * 2:
        raise PublicationError("corresponding-source manifest has an invalid entry count")
    expected_by_path: dict[str, dict[str, Any]] = {}
    declared_total = 0
    file_count = 0
    for index, raw_entry in enumerate(entries):
        if not isinstance(raw_entry, dict):
            raise PublicationError("corresponding-source manifest entry is not an object")
        entry_type = raw_entry.get("type")
        fields = {"path", "type"} if entry_type == "directory" else {
            "path",
            "type",
            "size",
            "sha256",
        }
        entry = require_exact_keys(raw_entry, fields, f"corresponding-source entry[{index}]")
        path = safe_relative(entry["path"], f"corresponding-source entry[{index}].path")
        _reject_component_reverse_path(path)
        key = path.as_posix()
        if key in expected_by_path:
            raise PublicationError("corresponding-source manifest repeats a path")
        if entry_type == "file":
            size = entry["size"]
            if not isinstance(size, int) or size < 0 or size > MAX_SOURCE_FILE_BYTES:
                raise PublicationError("corresponding-source manifest file exceeds its bound")
            require_sha256(entry["sha256"], f"corresponding-source entry[{index}].sha256")
            declared_total += size
            file_count += 1
            if file_count > MAX_SOURCE_FILES or declared_total > MAX_SOURCE_TOTAL_BYTES:
                raise PublicationError("corresponding-source manifest exceeds its fixed bounds")
        elif entry_type != "directory":
            raise PublicationError("corresponding-source manifest has an unsupported entry type")
        expected_by_path[key] = entry
    if expected.get("total_file_bytes") != declared_total:
        raise PublicationError("corresponding-source manifest total differs from its entries")
    if tree_digest(entries) != expected["sha256"]:
        raise PublicationError("corresponding-source manifest tree digest mismatch")
    total = 0
    observed: set[str] = set()
    with tarfile.open(archive_path, mode="r|gz") as archive:
        member_count = 0
        for member in archive:
            member_count += 1
            if member_count > MAX_SOURCE_FILES * 2:
                raise PublicationError("corresponding-source archive has too many entries")
            path = safe_relative(member.name, "source archive path")
            if not path.parts or path.parts[0] != "corresponding-source" or len(path.parts) < 2:
                raise PublicationError("source archive entry is outside its canonical root")
            relative = PurePosixPath(*path.parts[1:])
            _reject_component_reverse_path(relative)
            key = relative.as_posix()
            if key in observed:
                raise PublicationError("source archive repeats an entry")
            observed.add(key)
            expected_entry = expected_by_path.get(key)
            if expected_entry is None:
                raise PublicationError("source archive contains an unmanifested entry")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise PublicationError("source archive contains an unsafe entry type")
            if member.isdir():
                if expected_entry != {"path": key, "type": "directory"}:
                    raise PublicationError("source archive directory differs from its manifest")
                continue
            if not member.isfile() or expected_entry.get("type") != "file":
                raise PublicationError("source archive entry type differs from its manifest")
            if member.size < 0 or member.size > MAX_SOURCE_FILE_BYTES:
                raise PublicationError("source archive file exceeds its bound")
            total += member.size
            if total > MAX_SOURCE_TOTAL_BYTES:
                raise PublicationError("source archive exceeds its total bound")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise PublicationError("source archive regular file is unreadable")
            digest = hashlib.sha256()
            read = 0
            while chunk := extracted.read(1024 * 1024):
                read += len(chunk)
                if read > member.size:
                    raise PublicationError("source archive file exceeded its declared size")
                digest.update(chunk)
            if (
                read != member.size
                or expected_entry.get("size") != member.size
                or expected_entry.get("sha256") != digest.hexdigest()
            ):
                raise PublicationError("source archive file differs from its manifest")
    if observed != set(expected_by_path) or total != expected["total_file_bytes"]:
        raise PublicationError("source archive closure differs from its manifest")
