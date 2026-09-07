#!/usr/bin/env python3
"""Validate the bounded, canonical macOS updater tar contract."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import posixpath
import tarfile
from pathlib import PurePosixPath
import zlib

MAX_ENTRY_COUNT = 50_000
MAX_SINGLE_FILE_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_PATH_BYTES = 1024
MAX_EXTENSION_ENTRY_BYTES = 64 * 1024
MAX_TOTAL_EXTENSION_BYTES = 32 * 1024 * 1024
RAW_ENTRY_MULTIPLIER = 4
TAR_STREAM_FIXED_OVERHEAD = 4 * 1024 * 1024
TAR_STREAM_ENTRY_OVERHEAD = 4 * 1024
TAR_BLOCK_BYTES = 512


class ArchiveContractError(ValueError):
    pass


class BoundedReader(io.RawIOBase):
    def __init__(self, source: gzip.GzipFile, maximum: int) -> None:
        self._source = source
        self._remaining = maximum

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray) -> int:
        if self._remaining <= 0:
            raise ArchiveContractError("decompressed tar stream exceeds its fixed limit")
        maximum = min(len(buffer), self._remaining)
        data = self._source.read(maximum)
        count = len(data)
        buffer[:count] = data
        self._remaining -= count
        return count


class StrictSingleMemberGzipReader(io.RawIOBase):
    """Stream one bounded gzip member and reject every compressed suffix.

    ``gzip.GzipFile`` intentionally accepts concatenated members.  Release
    archives need a stronger contract: one member, one tar stream, and no
    bytes after that member.  This reader also limits decompression before a
    caller starts interpreting tar headers.
    """

    def __init__(self, source: io.BufferedReader, maximum: int) -> None:
        if maximum <= 0:
            raise ArchiveContractError("gzip stream limit must be positive")
        self._source = source
        self._decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
        self._compressed_pending = b""
        self._decompressed_pending = bytearray()
        self._remaining = maximum
        self._finished = False

    def readable(self) -> bool:
        return True

    def _fill(self, requested: int) -> None:
        while not self._decompressed_pending and not self._finished:
            if self._decoder.eof:
                if self._decoder.unused_data or self._compressed_pending:
                    raise ArchiveContractError(
                        "gzip archive contains a concatenated member or trailing bytes"
                    )
                if self._source.read(1):
                    raise ArchiveContractError(
                        "gzip archive contains a concatenated member or trailing bytes"
                    )
                self._finished = True
                return

            compressed = self._compressed_pending
            self._compressed_pending = b""
            if not compressed:
                compressed = self._source.read(64 * 1024)
                if not compressed:
                    raise ArchiveContractError("gzip archive is truncated")

            maximum_output = min(
                max(requested, 64 * 1024), self._remaining + 1
            )
            try:
                decompressed = self._decoder.decompress(
                    compressed, maximum_output
                )
            except zlib.error as error:
                raise ArchiveContractError("gzip archive is malformed") from error
            self._compressed_pending = self._decoder.unconsumed_tail
            if self._decoder.unused_data:
                raise ArchiveContractError(
                    "gzip archive contains a concatenated member or trailing bytes"
                )
            if len(decompressed) > self._remaining:
                raise ArchiveContractError(
                    "decompressed tar stream exceeds its fixed limit"
                )
            self._remaining -= len(decompressed)
            self._decompressed_pending.extend(decompressed)

    def readinto(self, buffer: bytearray) -> int:
        if not buffer:
            return 0
        self._fill(len(buffer))
        count = min(len(buffer), len(self._decompressed_pending))
        buffer[:count] = self._decompressed_pending[:count]
        del self._decompressed_pending[:count]
        return count


def _read_exact(
    source: io.BufferedReader, size: int, *, allow_initial_eof: bool = False
) -> bytes | None:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = source.read(min(remaining, 64 * 1024))
        if not chunk:
            if allow_initial_eof and remaining == size:
                return None
            raise ArchiveContractError("decompressed tar stream is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _discard_exact(source: io.BufferedReader, size: int) -> None:
    remaining = size
    while remaining:
        chunk = source.read(min(remaining, 64 * 1024))
        if not chunk:
            raise ArchiveContractError("decompressed tar entry is truncated")
        remaining -= len(chunk)


def validate_strict_tar_gzip_stream(
    path: str,
    *,
    maximum_stream: int,
    maximum_entries: int,
    maximum_extension_entry_bytes: int = MAX_EXTENSION_ENTRY_BYTES,
    maximum_total_extension_bytes: int = MAX_TOTAL_EXTENSION_BYTES,
) -> None:
    """Validate raw tar framing and consume the exact single gzip member.

    Tar readers stop at the first two zero blocks.  We deliberately keep
    consuming after that logical EOF and accept only zero padding until the
    gzip member itself ends.  A second member, compressed suffix, second tar,
    or any other non-zero decompressed payload is therefore rejected rather
    than remaining outside the semantic tree manifest.
    """
    if maximum_entries <= 0:
        raise ArchiveContractError("raw archive entry limit must be positive")
    extension_types = {
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
    }
    entry_count = 0
    extension_bytes = 0
    zero_blocks = 0
    terminated = False
    with open(path, "rb") as compressed:
        strict_decoder = StrictSingleMemberGzipReader(compressed, maximum_stream)
        with io.BufferedReader(strict_decoder) as source:
            while True:
                header = _read_exact(
                    source, TAR_BLOCK_BYTES, allow_initial_eof=True
                )
                if header is None:
                    break
                if header == bytes(TAR_BLOCK_BYTES):
                    zero_blocks += 1
                    if zero_blocks == 2:
                        terminated = True
                        break
                    continue
                zero_blocks = 0
                entry_count += 1
                if entry_count > maximum_entries:
                    raise ArchiveContractError(
                        "archive contains too many raw entries"
                    )
                member = tarfile.TarInfo.frombuf(
                    header, encoding="utf-8", errors="surrogateescape"
                )
                if member.type in extension_types:
                    if member.size > maximum_extension_entry_bytes:
                        raise ArchiveContractError(
                            "archive extension metadata entry exceeds its fixed limit"
                        )
                    extension_bytes += member.size
                    if extension_bytes > maximum_total_extension_bytes:
                        raise ArchiveContractError(
                            "archive extension metadata exceeds its aggregate limit"
                        )
                padded_size = (
                    (member.size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES
                ) * TAR_BLOCK_BYTES
                _discard_exact(source, padded_size)
            if not terminated:
                raise ArchiveContractError(
                    "tar archive omits its two zero termination blocks"
                )
            while trailing := source.read(64 * 1024):
                if any(trailing):
                    raise ArchiveContractError(
                        "tar archive contains non-zero data after its termination blocks"
                    )


def _validate_raw_metadata(path: str, maximum_stream: int) -> None:
    validate_strict_tar_gzip_stream(
        path,
        maximum_stream=maximum_stream,
        maximum_entries=MAX_ENTRY_COUNT * RAW_ENTRY_MULTIPLIER,
    )


def _canonical_name(member: tarfile.TarInfo, expected_root: str) -> str:
    name = member.name
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ArchiveContractError("entry path is not UTF-8") from error
    if not encoded or len(encoded) > MAX_PATH_BYTES:
        raise ArchiveContractError("entry path length is outside the accepted range")
    if name.startswith("/") or "\\" in name or "//" in name:
        raise ArchiveContractError("entry path is not canonical")
    canonical = name[:-1] if member.isdir() and name.endswith("/") else name
    parts = canonical.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ArchiveContractError("entry path contains a forbidden component")
    if any(part.startswith("._") or part == ".DS_Store" for part in parts):
        raise ArchiveContractError("entry path contains AppleDouble or Finder metadata")
    if parts[0] != expected_root:
        raise ArchiveContractError("entry is outside the fixed application root")
    return "/".join(parts[1:])


def _validate_symlink(relative: str, target: str) -> None:
    try:
        encoded = target.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ArchiveContractError("symlink target is not UTF-8") from error
    if (
        not encoded
        or len(encoded) > MAX_PATH_BYTES
        or target.startswith("/")
        or "\\" in target
        or "//" in target
    ):
        raise ArchiveContractError("symlink target is not canonical")
    resolved: list[str] = list(PurePosixPath(relative).parent.parts)
    if resolved == ["."]:
        resolved = []
    for component in target.split("/"):
        if component in {"", "."}:
            raise ArchiveContractError("symlink target is not canonical")
        if component == "..":
            if not resolved:
                raise ArchiveContractError("symlink target escapes the app root")
            resolved.pop()
        else:
            resolved.append(component)


def _tree_sha256(root_mode: str, entries: list[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    root_record = {
        "mode": root_mode,
        "path": ".",
        "type": "directory",
    }
    for entry in [root_record, *entries]:
        digest.update(
            json.dumps(
                entry,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def _inspect_archive(
    path: str, expected_root: str
) -> tuple[int, int, dict[str, object]]:
    paths: dict[str, str] = {}
    required_directories: set[str] = set()
    manifest_entries: list[dict[str, object]] = []
    root_mode: str | None = None
    expanded = 0
    count = 0

    maximum_stream = (
        MAX_EXPANDED_BYTES
        + MAX_ENTRY_COUNT * TAR_STREAM_ENTRY_OVERHEAD
        + TAR_STREAM_FIXED_OVERHEAD
    )
    _validate_raw_metadata(path, maximum_stream)
    with open(path, "rb") as compressed:
        decoder = gzip.GzipFile(fileobj=compressed, mode="rb")
        bounded = io.BufferedReader(BoundedReader(decoder, maximum_stream))
        archive = tarfile.open(fileobj=bounded, mode="r|")
        for member in archive:
            count += 1
            if count > MAX_ENTRY_COUNT:
                raise ArchiveContractError("archive contains too many entries")
            if not set(member.pax_headers).issubset({"path", "linkpath"}):
                raise ArchiveContractError(
                    "archive contains unbound extended metadata"
                )
            relative = _canonical_name(member, expected_root)
            if relative in paths:
                raise ArchiveContractError("archive contains a duplicate path")
            if member.isdir():
                kind = "directory"
            elif member.isreg():
                kind = "file"
            elif member.issym():
                kind = "symlink"
            else:
                raise ArchiveContractError("archive contains a forbidden entry type")
            mode = member.mode
            if mode & ~0o777 or (kind != "symlink" and mode & 0o022):
                raise ArchiveContractError("archive entry permissions are unsafe")
            if kind == "directory" and mode & 0o500 != 0o500:
                raise ArchiveContractError("archive directory is not owner-readable and traversable")
            if relative == "Contents/Info.plist" and mode & 0o400 == 0:
                raise ArchiveContractError("Info.plist is not owner-readable")
            if relative == "Contents/MacOS/clash-for-mac" and mode & 0o500 != 0o500:
                raise ArchiveContractError("main executable is not owner-readable and executable")
            if kind != "file" and member.size != 0:
                raise ArchiveContractError("non-file archive entry has payload bytes")
            if kind == "file":
                if member.size > MAX_SINGLE_FILE_BYTES:
                    raise ArchiveContractError("archive entry exceeds the single-file limit")
                expanded += member.size
                if expanded > MAX_EXPANDED_BYTES:
                    raise ArchiveContractError("archive exceeds the expanded-size limit")
            if kind == "symlink":
                _validate_symlink(relative, member.linkname)

            parent = posixpath.dirname(relative)
            while parent:
                if paths.get(parent) not in {None, "directory"}:
                    raise ArchiveContractError("archive path descends through a non-directory")
                required_directories.add(parent)
                parent = posixpath.dirname(parent)
            if kind != "directory" and relative in required_directories:
                raise ArchiveContractError("archive path conflicts with an existing descendant")
            paths[relative] = kind
            rendered_mode = f"{mode:04o}"
            if not relative:
                if kind != "directory":
                    raise ArchiveContractError("application root is not a directory")
                root_mode = rendered_mode
                continue
            manifest_entry: dict[str, object] = {
                "mode": rendered_mode,
                "path": relative,
                "type": kind,
            }
            if kind == "file":
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ArchiveContractError("archive file entry cannot be read")
                digest = hashlib.sha256()
                remaining = member.size
                while remaining:
                    chunk = extracted.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ArchiveContractError("archive file entry is truncated")
                    remaining -= len(chunk)
                    digest.update(chunk)
                if extracted.read(1):
                    raise ArchiveContractError("archive file entry exceeds its header size")
                manifest_entry.update(
                    {"sha256": digest.hexdigest(), "size": member.size}
                )
            elif kind == "symlink":
                manifest_entry["target"] = member.linkname
            manifest_entries.append(manifest_entry)
        archive.close()

    if count == 0:
        raise ArchiveContractError("archive is empty")
    required_layout = {
        "": "directory",
        "Contents": "directory",
        "Contents/MacOS": "directory",
        "Contents/Info.plist": "file",
        "Contents/MacOS/clash-for-mac": "file",
    }
    if any(paths.get(name) != kind for name, kind in required_layout.items()):
        raise ArchiveContractError("archive omits the canonical app bundle layout")
    if any(paths.get(name) != "directory" for name in required_directories):
        raise ArchiveContractError("archive omits an explicit parent directory")
    if root_mode is None:
        raise ArchiveContractError("archive omits the explicit application root")
    manifest_entries.sort(key=lambda entry: str(entry["path"]))
    manifest = {
        "algorithm": "sha256-tree-v2",
        "entries": manifest_entries,
        "root": expected_root,
        "rootMode": root_mode,
        "sha256": _tree_sha256(root_mode, manifest_entries),
    }
    return count, expanded, manifest


def validate_archive(path: str, expected_root: str) -> tuple[int, int]:
    count, expanded, _manifest = _inspect_archive(path, expected_root)
    return count, expanded


def build_archive_app_manifest(path: str, expected_root: str) -> dict[str, object]:
    """Return the exact v2 app-tree identity reconstructed from archive bytes."""
    _count, _expanded, manifest = _inspect_archive(path, expected_root)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument("expected_root")
    arguments = parser.parse_args()
    try:
        count, expanded = validate_archive(arguments.archive, arguments.expected_root)
    except (ArchiveContractError, tarfile.TarError, OSError) as error:
        raise SystemExit(f"error: updater archive contract failed: {error}") from error
    print(
        f"==> archive OK ({count} entries, {expanded} expanded bytes under "
        f"{arguments.expected_root})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
