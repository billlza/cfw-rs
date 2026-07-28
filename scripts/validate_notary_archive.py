#!/usr/bin/env python3
"""Validate that a notarization ZIP is a byte-faithful, bounded app archive."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import struct
import time
import zipfile
import zlib


MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ENTRY_COUNT = 50_000
MAX_SINGLE_FILE_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_PATH_BYTES = 1024
MAX_SYMLINK_BYTES = 4096
_EOCD = struct.Struct("<4s4H2LH")
_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")
_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
_DATA_DESCRIPTOR = struct.Struct("<4s3L")
_EOCD_SIGNATURE = b"PK\x05\x06"
_CENTRAL_HEADER_SIGNATURE = b"PK\x01\x02"
_LOCAL_FILE_SIGNATURE = b"PK\x03\x04"
_DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
_ALLOWED_FLAG_BITS = 0x0008 | 0x0800
_DITTO_UNIX_EXTRA_FIELD = 0x5855


class NotaryArchiveError(ValueError):
    """The archive is not the exact bounded projection of the signed app."""


@dataclass(frozen=True)
class NotaryArchiveInventory:
    entry_count: int
    expanded_bytes: int
    archive_bytes: int


@dataclass(frozen=True)
class _SourceEntry:
    path: Path
    kind: str
    mode: int
    size: int
    mtime: int
    uid: int
    gid: int


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _canonical_components(name: str) -> list[str]:
    try:
        encoded = name.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise NotaryArchiveError("entry path is not UTF-8") from error
    if not encoded or len(encoded) > MAX_PATH_BYTES or "\0" in name:
        raise NotaryArchiveError("entry path length is outside the accepted range")
    if name.startswith("/") or "\\" in name or "//" in name:
        raise NotaryArchiveError("entry path is not canonical")
    components = name.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise NotaryArchiveError("entry path contains a forbidden component")
    if any(
        component == "__MACOSX"
        or component == ".DS_Store"
        or component.startswith("._")
        for component in components
    ):
        raise NotaryArchiveError("entry path contains AppleDouble or Finder metadata")
    return components


def _validate_symlink_target(relative: str, target: str) -> bytes:
    try:
        encoded = target.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise NotaryArchiveError("symlink target is not UTF-8") from error
    if (
        not encoded
        or len(encoded) > MAX_SYMLINK_BYTES
        or target.startswith("/")
        or "\\" in target
        or "//" in target
        or "\0" in target
    ):
        raise NotaryArchiveError("symlink target is not canonical")
    # Resolve relative to the app root, which is the first component of every
    # canonical archive path.  Popping beyond this list would escape the app.
    resolved = relative.split("/")[1:-1]
    for component in target.split("/"):
        if component in {"", "."}:
            raise NotaryArchiveError("symlink target is not canonical")
        if component == "..":
            if not resolved:
                raise NotaryArchiveError("symlink target escapes the app root")
            resolved.pop()
        else:
            resolved.append(component)
    return encoded


def _source_inventory(app: Path) -> tuple[dict[str, _SourceEntry], int]:
    if not app.is_absolute() or app.is_symlink():
        raise NotaryArchiveError("source app must be an absolute real directory")
    try:
        root_metadata = os.lstat(app)
    except OSError as error:
        raise NotaryArchiveError("source app is unavailable") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise NotaryArchiveError("source app is not a directory")
    _canonical_components(app.name)

    inventory: dict[str, _SourceEntry] = {}
    expanded = 0
    pending: list[tuple[Path, str]] = [(app, app.name)]
    discovered = 1
    while pending:
        path, relative = pending.pop()
        _canonical_components(relative)
        try:
            metadata = os.lstat(path)
        except OSError as error:
            raise NotaryArchiveError("source app inventory changed while reading") from error
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
            size = 0
            if mode & ~0o777 or mode & 0o022 or mode & 0o500 != 0o500:
                raise NotaryArchiveError("source app directory permissions are unsafe")
        elif stat.S_ISREG(metadata.st_mode):
            kind = "file"
            size = metadata.st_size
            if metadata.st_nlink != 1 or mode & ~0o777 or mode & 0o022:
                raise NotaryArchiveError("source app file identity or permissions are unsafe")
            if size > MAX_SINGLE_FILE_BYTES:
                raise NotaryArchiveError("source app file exceeds the single-file limit")
            expanded += size
            if expanded > MAX_EXPANDED_BYTES:
                raise NotaryArchiveError("source app exceeds the expanded-size limit")
        elif stat.S_ISLNK(metadata.st_mode):
            kind = "symlink"
            try:
                target = os.readlink(path)
            except OSError as error:
                raise NotaryArchiveError("source app symlink cannot be read") from error
            size = len(_validate_symlink_target(relative, target))
            expanded += size
            if expanded > MAX_EXPANDED_BYTES:
                raise NotaryArchiveError("source app exceeds the expanded-size limit")
        else:
            raise NotaryArchiveError("source app contains a forbidden entry type")
        mtime = int(metadata.st_mtime)
        uid = metadata.st_uid
        gid = metadata.st_gid
        if (
            not 0 <= mtime <= 0xFFFFFFFF
            or not 0 <= uid <= 0xFFFF
            or not 0 <= gid <= 0xFFFF
        ):
            raise NotaryArchiveError("source app metadata is outside the ZIP range")
        inventory[relative] = _SourceEntry(
            path,
            kind,
            mode,
            size,
            mtime,
            uid,
            gid,
        )

        if kind == "directory":
            try:
                with os.scandir(path) as directory:
                    for child in directory:
                        discovered += 1
                        if discovered > MAX_ENTRY_COUNT:
                            raise NotaryArchiveError(
                                "source app contains too many entries"
                            )
                        pending.append(
                            (
                                Path(child.path),
                                f"{relative}/{child.name}",
                            )
                        )
            except OSError as error:
                raise NotaryArchiveError(
                    "source app directory cannot be enumerated"
                ) from error
    return inventory, expanded


def _validate_extra_fields(
    extra: bytes,
    entry: _SourceEntry | None,
    *,
    local: bool,
) -> None:
    # A metadata-free entry is a safe projection.  If ditto emits its standard
    # Unix metadata field, its stable fields must be bound to the source inode.
    if not extra:
        return
    if entry is None or entry.kind == "symlink":
        raise NotaryArchiveError("ZIP contains unsupported or unbound extra metadata")
    expected_payload_size = 12 if local else 8
    if len(extra) != 4 + expected_payload_size:
        raise NotaryArchiveError("ZIP contains unsupported or unbound extra metadata")
    identifier, payload_size = struct.unpack("<HH", extra[:4])
    if (
        identifier != _DITTO_UNIX_EXTRA_FIELD
        or payload_size != expected_payload_size
    ):
        raise NotaryArchiveError("ZIP contains unsupported or unbound extra metadata")
    if local:
        _atime, mtime, uid, gid = struct.unpack("<IIHH", extra[4:])
        if mtime != entry.mtime or uid != entry.uid or gid != entry.gid:
            raise NotaryArchiveError("ZIP Unix metadata differs from the signed app")
    else:
        _atime, mtime = struct.unpack("<II", extra[4:])
        if mtime != entry.mtime:
            raise NotaryArchiveError("ZIP Unix metadata differs from the signed app")


def _dos_values(date_time: tuple[int, ...]) -> tuple[int, int]:
    year, month, day, hour, minute, second = date_time
    if not 1980 <= year <= 2107 or second % 2:
        raise NotaryArchiveError("source app timestamp is outside the DOS ZIP range")
    dos_time = (hour << 11) | (minute << 5) | (second // 2)
    dos_date = ((year - 1980) << 9) | (month << 5) | day
    return dos_time, dos_date


def _dos_datetime(entry: _SourceEntry) -> tuple[int, int, tuple[int, ...]]:
    # ditto rounds an odd mtime second upward to the next representable DOS
    # second.  Adding before localtime also handles minute/day rollover.
    rounded_timestamp = entry.mtime + entry.mtime % 2
    rounded = time.localtime(rounded_timestamp)[:6]
    dos_time, dos_date = _dos_values(rounded)
    return dos_time, dos_date, rounded


def _read_eocd(archive_file, archive_size: int) -> tuple[int, int]:
    if archive_size < _EOCD.size:
        raise NotaryArchiveError("ZIP is truncated")
    archive_file.seek(0)
    if archive_file.read(4) != _LOCAL_FILE_SIGNATURE:
        raise NotaryArchiveError("ZIP has a prefix or no local file header")
    archive_file.seek(archive_size - _EOCD.size)
    values = _EOCD.unpack(archive_file.read(_EOCD.size))
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = values
    if signature != _EOCD_SIGNATURE or comment_size != 0:
        raise NotaryArchiveError("ZIP has a malformed end record or archive comment")
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        raise NotaryArchiveError("multi-disk ZIP archives are forbidden")
    if total_entries in {0, 0xFFFF} or total_entries > MAX_ENTRY_COUNT:
        raise NotaryArchiveError("ZIP entry count is outside the accepted range")
    if central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise NotaryArchiveError("ZIP64 notarization archives are forbidden")
    if central_offset + central_size != archive_size - _EOCD.size:
        raise NotaryArchiveError("ZIP central directory is not canonical")
    return total_entries, central_offset


def _encoded_zip_name(info: zipfile.ZipInfo) -> bytes:
    encoding = "utf-8" if info.flag_bits & 0x0800 else "cp437"
    try:
        return info.filename.encode(encoding, errors="strict")
    except UnicodeError as error:
        raise NotaryArchiveError("ZIP entry name cannot be encoded canonically") from error


def _validate_central_records(
    archive_file,
    infos: list[zipfile.ZipInfo],
    central_offset: int,
    central_end: int,
) -> None:
    cursor = central_offset
    for info in infos:
        if cursor + _CENTRAL_HEADER.size > central_end:
            raise NotaryArchiveError("ZIP central-directory header is truncated")
        archive_file.seek(cursor)
        header = archive_file.read(_CENTRAL_HEADER.size)
        if len(header) != _CENTRAL_HEADER.size:
            raise NotaryArchiveError("ZIP central-directory header is truncated")
        (
            signature,
            version_made_by,
            version_needed,
            flags,
            compression,
            modified_time,
            modified_date,
            crc32,
            compressed_size,
            expanded_size,
            name_size,
            extra_size,
            comment_size,
            disk_start,
            internal_attributes,
            external_attributes,
            local_header_offset,
        ) = _CENTRAL_HEADER.unpack(header)
        record_end = (
            cursor
            + _CENTRAL_HEADER.size
            + name_size
            + extra_size
            + comment_size
        )
        if record_end > central_end:
            raise NotaryArchiveError("ZIP central-directory record exceeds its boundary")
        name = archive_file.read(name_size)
        extra = archive_file.read(extra_size)
        comment = archive_file.read(comment_size)
        expected_time, expected_date = _dos_values(info.date_time)
        if (
            signature != _CENTRAL_HEADER_SIGNATURE
            or version_made_by
            != ((info.create_system << 8) | info.create_version)
            or version_needed != info.extract_version
            or flags != info.flag_bits
            or compression != info.compress_type
            or modified_time != expected_time
            or modified_date != expected_date
            or crc32 != info.CRC
            or compressed_size != info.compress_size
            or expanded_size != info.file_size
            or name != _encoded_zip_name(info)
            or extra != info.extra
            or comment != info.comment
            or disk_start != info.volume
            or internal_attributes != info.internal_attr
            or external_attributes != info.external_attr
            or local_header_offset != info.header_offset
        ):
            raise NotaryArchiveError(
                "ZIP central-directory record differs from its parsed entry"
            )
        cursor = record_end
    if cursor != central_end:
        raise NotaryArchiveError(
            "ZIP central-directory records do not exactly cover their boundary"
        )


def _validate_local_records(
    archive_file,
    infos: list[zipfile.ZipInfo],
    central_offset: int,
    source: dict[str, _SourceEntry],
) -> dict[str, int]:
    ordered = sorted(infos, key=lambda candidate: candidate.header_offset)
    payload_offsets: dict[str, int] = {}
    for index, info in enumerate(ordered):
        archive_file.seek(info.header_offset)
        header = archive_file.read(_LOCAL_HEADER.size)
        if len(header) != _LOCAL_HEADER.size:
            raise NotaryArchiveError("ZIP local file header is truncated")
        (
            signature,
            version_needed,
            flags,
            compression,
            modified_time,
            modified_date,
            crc32,
            compressed_size,
            expanded_size,
            name_size,
            extra_size,
        ) = _LOCAL_HEADER.unpack(header)
        if signature != _LOCAL_FILE_SIGNATURE:
            raise NotaryArchiveError("ZIP local file header signature is invalid")
        name = archive_file.read(name_size)
        extra = archive_file.read(extra_size)
        if len(name) != name_size or len(extra) != extra_size:
            raise NotaryArchiveError("ZIP local file header metadata is truncated")
        if (
            name != _encoded_zip_name(info)
            or version_needed != info.extract_version
            or flags != info.flag_bits
            or compression != info.compress_type
        ):
            raise NotaryArchiveError(
                "ZIP local file header differs from the central directory"
            )
        canonical_name = info.filename[:-1] if info.filename.endswith("/") else info.filename
        source_entry = source.get(canonical_name)
        _validate_extra_fields(extra, source_entry, local=True)
        if bool(extra) != bool(info.extra) or (
            extra and info.extra[4:12] != extra[4:12]
        ):
            raise NotaryArchiveError(
                "ZIP local and central Unix metadata disagree"
            )
        if source_entry is not None:
            expected_time, expected_date, _ = _dos_datetime(source_entry)
            if modified_time != expected_time or modified_date != expected_date:
                raise NotaryArchiveError(
                    "ZIP local timestamp differs from the signed app"
                )
        payload_start = info.header_offset + _LOCAL_HEADER.size + name_size + extra_size
        payload_offsets[info.filename] = payload_start
        payload_end = payload_start + info.compress_size
        if flags & 0x0008:
            if info.is_dir() or any((crc32, compressed_size, expanded_size)):
                raise NotaryArchiveError("ZIP data descriptor contract is malformed")
            archive_file.seek(payload_end)
            descriptor = archive_file.read(_DATA_DESCRIPTOR.size)
            if len(descriptor) != _DATA_DESCRIPTOR.size:
                raise NotaryArchiveError("ZIP data descriptor is truncated")
            descriptor_signature, descriptor_crc, descriptor_compressed, descriptor_size = (
                _DATA_DESCRIPTOR.unpack(descriptor)
            )
            if (
                descriptor_signature != _DATA_DESCRIPTOR_SIGNATURE
                or descriptor_crc != info.CRC
                or descriptor_compressed != info.compress_size
                or descriptor_size != info.file_size
            ):
                raise NotaryArchiveError(
                    "ZIP data descriptor differs from the central directory"
                )
            record_end = payload_end + _DATA_DESCRIPTOR.size
        else:
            if (
                crc32 != info.CRC
                or compressed_size != info.compress_size
                or expanded_size != info.file_size
            ):
                raise NotaryArchiveError(
                    "ZIP local file sizes differ from the central directory"
                )
            record_end = payload_end
        expected_end = (
            ordered[index + 1].header_offset
            if index + 1 < len(ordered)
            else central_offset
        )
        if record_end != expected_end:
            raise NotaryArchiveError(
                "ZIP local records do not canonically cover the archive payload"
            )
    return payload_offsets


def _zip_kind(info: zipfile.ZipInfo) -> tuple[str, int]:
    if info.create_system != 3:
        raise NotaryArchiveError("ZIP entry lacks canonical Unix metadata")
    if (
        info.create_version not in {20, 21}
        or info.reserved != 0
        or info.internal_attr != 0
        or info.external_attr & 0xFFFF not in {0, 0x4000}
    ):
        raise NotaryArchiveError("ZIP entry has unsupported central metadata")
    encoded_mode = (info.external_attr >> 16) & 0xFFFF
    mode = stat.S_IMODE(encoded_mode)
    if stat.S_ISDIR(encoded_mode):
        kind = "directory"
    elif stat.S_ISREG(encoded_mode):
        kind = "file"
    elif stat.S_ISLNK(encoded_mode):
        kind = "symlink"
    else:
        raise NotaryArchiveError("ZIP contains a forbidden entry type")
    if kind != "symlink" and (mode & ~0o777 or mode & 0o022):
        raise NotaryArchiveError("ZIP entry permissions are unsafe")
    if kind == "directory" and mode & 0o500 != 0o500:
        raise NotaryArchiveError("ZIP directory is not owner-readable and traversable")
    return kind, mode


def _validate_central_metadata(
    info: zipfile.ZipInfo,
    source_entry: _SourceEntry | None,
) -> None:
    if info.compress_type == zipfile.ZIP_DEFLATED:
        if info.extract_version != 20:
            raise NotaryArchiveError("deflated ZIP entry has an invalid version")
    elif info.compress_type == zipfile.ZIP_STORED:
        if info.extract_version not in {10, 20}:
            raise NotaryArchiveError("stored ZIP entry has an invalid version")
    else:
        raise NotaryArchiveError("ZIP entry uses unsupported compression")
    _validate_extra_fields(info.extra, source_entry, local=False)
    if source_entry is not None:
        _, _, expected_date_time = _dos_datetime(source_entry)
        if info.date_time != expected_date_time:
            raise NotaryArchiveError("ZIP timestamp differs from the signed app")


def _hash_source_file(entry: _SourceEntry) -> str:
    before = os.lstat(entry.path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(entry.path, flags)
    except OSError as error:
        raise NotaryArchiveError("source app file cannot be opened") from error
    try:
        opened = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(opened):
            raise NotaryArchiveError("source app file changed while opening")
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise NotaryArchiveError("source app file changed while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NotaryArchiveError("source app file changed while hashing")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _file_identity(opened) != _file_identity(after):
        raise NotaryArchiveError("source app file changed while hashing")
    try:
        rebound = os.lstat(entry.path)
    except OSError as error:
        raise NotaryArchiveError("source app file changed after hashing") from error
    if _file_identity(opened) != _file_identity(rebound):
        raise NotaryArchiveError("source app file changed after hashing")
    return digest.hexdigest()


def _consume_entry_output(
    body: bytes,
    *,
    info: zipfile.ZipInfo,
    digest,
    collected: bytearray | None,
    observed: int,
    crc32: int,
) -> tuple[int, int]:
    observed += len(body)
    if observed > info.file_size or observed > MAX_SINGLE_FILE_BYTES:
        raise NotaryArchiveError("ZIP entry expands beyond its declared limit")
    digest.update(body)
    crc32 = zlib.crc32(body, crc32)
    if collected is not None:
        if observed > MAX_SYMLINK_BYTES:
            raise NotaryArchiveError("ZIP symlink payload exceeds its fixed limit")
        collected.extend(body)
    return observed, crc32


def _read_zip_entry_strict(
    archive_file,
    info: zipfile.ZipInfo,
    payload_offset: int,
    *,
    collect: bool,
) -> tuple[str, bytes | None]:
    digest = hashlib.sha256()
    observed = 0
    crc32 = 0
    collected = bytearray() if collect else None
    archive_file.seek(payload_offset)
    compressed_remaining = info.compress_size
    if info.compress_type == zipfile.ZIP_STORED:
        if info.compress_size != info.file_size:
            raise NotaryArchiveError("stored ZIP entry has inconsistent sizes")
        while compressed_remaining:
            chunk = archive_file.read(min(1024 * 1024, compressed_remaining))
            if not chunk:
                raise NotaryArchiveError("stored ZIP entry payload is truncated")
            compressed_remaining -= len(chunk)
            observed, crc32 = _consume_entry_output(
                chunk,
                info=info,
                digest=digest,
                collected=collected,
                observed=observed,
                crc32=crc32,
            )
    elif info.compress_type == zipfile.ZIP_DEFLATED:
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        while compressed_remaining:
            chunk = archive_file.read(min(64 * 1024, compressed_remaining))
            if not chunk:
                raise NotaryArchiveError("deflated ZIP entry payload is truncated")
            compressed_remaining -= len(chunk)
            pending = chunk
            while pending:
                maximum = min(1024 * 1024, info.file_size - observed + 1)
                body = decoder.decompress(pending, maximum)
                observed, crc32 = _consume_entry_output(
                    body,
                    info=info,
                    digest=digest,
                    collected=collected,
                    observed=observed,
                    crc32=crc32,
                )
                if decoder.unused_data:
                    raise NotaryArchiveError(
                        "deflated ZIP entry has bytes after the compressed stream"
                    )
                next_pending = decoder.unconsumed_tail
                if next_pending == pending and not body:
                    raise NotaryArchiveError("deflated ZIP entry made no progress")
                pending = next_pending
        maximum = min(1024 * 1024, info.file_size - observed + 1)
        body = decoder.flush(maximum)
        observed, crc32 = _consume_entry_output(
            body,
            info=info,
            digest=digest,
            collected=collected,
            observed=observed,
            crc32=crc32,
        )
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise NotaryArchiveError(
                "deflated ZIP entry did not consume one exact compressed stream"
            )
    else:
        raise NotaryArchiveError("ZIP entry uses unsupported compression")
    if observed != info.file_size:
        raise NotaryArchiveError("ZIP entry size differs from its central directory")
    if crc32 & 0xFFFFFFFF != info.CRC:
        raise NotaryArchiveError("ZIP entry CRC differs from its central directory")
    return digest.hexdigest(), bytes(collected) if collected is not None else None


def validate_notarization_zip(
    archive_path: Path,
    expected_app: Path,
) -> NotaryArchiveInventory:
    """Require an exact, clean ZIP projection of ``expected_app``."""

    archive_path = archive_path.absolute()
    expected_app = expected_app.absolute()
    source, source_expanded = _source_inventory(expected_app)
    try:
        before = os.lstat(archive_path)
    except OSError as error:
        raise NotaryArchiveError("notarization ZIP is unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_ARCHIVE_BYTES
    ):
        raise NotaryArchiveError("notarization ZIP identity or size is unsafe")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(archive_path, flags)
    except OSError as error:
        raise NotaryArchiveError("notarization ZIP cannot be opened") from error
    try:
        opened = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(opened):
            raise NotaryArchiveError("notarization ZIP changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as archive_file:
            expected_entries, central_offset = _read_eocd(
                archive_file, opened.st_size
            )
            archive_file.seek(0)
            try:
                notarization_zip = zipfile.ZipFile(archive_file, mode="r")
            except (OSError, zipfile.BadZipFile) as error:
                raise NotaryArchiveError("notarization ZIP cannot be parsed") from error
            with notarization_zip:
                if notarization_zip.comment:
                    raise NotaryArchiveError("ZIP archive comment is forbidden")
                infos = notarization_zip.infolist()
                if len(infos) != expected_entries:
                    raise NotaryArchiveError("ZIP entry count differs from its end record")
                _validate_central_records(
                    archive_file,
                    infos,
                    central_offset,
                    opened.st_size - _EOCD.size,
                )
                observed: dict[str, tuple[zipfile.ZipInfo, str, int]] = {}
                expanded = 0
                header_offsets: set[int] = set()
                for info in infos:
                    if info.orig_filename != info.filename:
                        raise NotaryArchiveError("ZIP entry path contains a NUL byte")
                    raw_name = info.filename
                    is_directory_name = raw_name.endswith("/")
                    canonical_name = raw_name[:-1] if is_directory_name else raw_name
                    components = _canonical_components(canonical_name)
                    if components[0] != expected_app.name:
                        raise NotaryArchiveError("ZIP entry is outside the fixed app root")
                    if canonical_name in observed:
                        raise NotaryArchiveError("ZIP contains a duplicate canonical path")
                    kind, mode = _zip_kind(info)
                    if is_directory_name != (kind == "directory"):
                        raise NotaryArchiveError("ZIP entry name and type disagree")
                    if info.flag_bits & ~_ALLOWED_FLAG_BITS:
                        raise NotaryArchiveError("ZIP entry has unsupported or encrypted flags")
                    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                        raise NotaryArchiveError("ZIP entry uses unsupported compression")
                    if info.volume != 0:
                        raise NotaryArchiveError("multi-disk ZIP entry is forbidden")
                    if info.comment:
                        raise NotaryArchiveError("ZIP entry comment is forbidden")
                    _validate_central_metadata(info, source.get(canonical_name))
                    if (
                        info.header_offset < 0
                        or info.header_offset >= central_offset
                        or info.header_offset in header_offsets
                    ):
                        raise NotaryArchiveError("ZIP local header offsets are not unique")
                    header_offsets.add(info.header_offset)
                    if info.file_size > MAX_SINGLE_FILE_BYTES:
                        raise NotaryArchiveError("ZIP entry exceeds the single-file limit")
                    if kind == "directory" and (
                        info.file_size != 0
                        or info.compress_size != 0
                        or info.CRC != 0
                    ):
                        raise NotaryArchiveError("ZIP directory entry contains payload bytes")
                    if kind in {"file", "symlink"}:
                        expanded += info.file_size
                        if expanded > MAX_EXPANDED_BYTES:
                            raise NotaryArchiveError("ZIP exceeds the expanded-size limit")
                    observed[canonical_name] = (info, kind, mode)

                if not header_offsets or min(header_offsets) != 0:
                    raise NotaryArchiveError("ZIP has data before its first local header")
                payload_offsets = _validate_local_records(
                    archive_file,
                    infos,
                    central_offset,
                    source,
                )
                if set(observed) != set(source):
                    raise NotaryArchiveError("ZIP inventory differs from the signed app")
                if expanded != source_expanded:
                    raise NotaryArchiveError("ZIP expanded size differs from the signed app")

                for name, source_entry in source.items():
                    info, kind, mode = observed[name]
                    if (
                        kind != source_entry.kind
                        or mode != source_entry.mode
                        or info.file_size != source_entry.size
                    ):
                        raise NotaryArchiveError("ZIP entry metadata differs from the signed app")
                    if kind == "file":
                        archive_digest, _ = _read_zip_entry_strict(
                            archive_file,
                            info,
                            payload_offsets[info.filename],
                            collect=False,
                        )
                        if archive_digest != _hash_source_file(source_entry):
                            raise NotaryArchiveError(
                                "ZIP file content differs from the signed app"
                            )
                    elif kind == "symlink":
                        try:
                            target = os.readlink(source_entry.path)
                        except OSError as error:
                            raise NotaryArchiveError(
                                "source app symlink changed while validating"
                            ) from error
                        expected_target = _validate_symlink_target(name, target)
                        try:
                            resolved_target = source_entry.path.resolve(strict=True)
                            resolved_target.relative_to(expected_app.resolve(strict=True))
                        except (OSError, RuntimeError, ValueError) as error:
                            raise NotaryArchiveError(
                                "source app symlink is dangling or escapes the app root"
                            ) from error
                        _, observed_target = _read_zip_entry_strict(
                            archive_file,
                            info,
                            payload_offsets[info.filename],
                            collect=True,
                        )
                        if observed_target != expected_target:
                            raise NotaryArchiveError(
                                "ZIP symlink target differs from the signed app"
                            )
            after = os.fstat(descriptor)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise NotaryArchiveError("notarization ZIP validation failed") from error
    finally:
        os.close(descriptor)
    if _file_identity(opened) != _file_identity(after):
        raise NotaryArchiveError("notarization ZIP changed while validating")
    try:
        rebound = os.lstat(archive_path)
    except OSError as error:
        raise NotaryArchiveError("notarization ZIP changed after validating") from error
    if _file_identity(opened) != _file_identity(rebound):
        raise NotaryArchiveError("notarization ZIP changed after validating")
    return NotaryArchiveInventory(len(source), source_expanded, opened.st_size)


__all__ = [
    "NotaryArchiveError",
    "NotaryArchiveInventory",
    "validate_notarization_zip",
]
