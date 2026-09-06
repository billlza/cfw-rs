from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Final
import uuid


PRIVATE_DIRECTORY_MODE: Final = 0o700
PRIVATE_FILE_MODE: Final = 0o600
DEFAULT_MAXIMUM_BYTES: Final = 256 * 1024 * 1024
MAX_PATH_COMPONENT_BYTES: Final = 128
MAX_RELATIVE_PATH_BYTES: Final = 512

RENAME_EXCL: Final = 0x00000004
RENAME_NOFOLLOW_ANY: Final = 0x00000010

_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PENDING_RE = re.compile(
    r"^[.](?P<final>[A-Za-z0-9][A-Za-z0-9._-]{0,127})"
    r"[.]pending-(?P<nonce>[0-9a-f]{32})$"
)


class PhysicalCaptureArchiveError(RuntimeError):
    """A private archive path, object, or durability operation is unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ArchivedFile:
    relative_path: str
    size: int
    sha256: str

    def descriptor(self, kind: str) -> dict[str, object]:
        if not isinstance(kind, str) or not _COMPONENT_RE.fullmatch(kind):
            raise PhysicalCaptureArchiveError(
                "invalid_artifact_kind", "artifact kind is not a bounded identifier"
            )
        return {
            "kind": kind,
            "path": self.relative_path,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class PendingFile:
    relative_path: str
    final_relative_path: str


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _relative_parts(value: str | PurePosixPath, label: str) -> tuple[str, ...]:
    text = value.as_posix() if isinstance(value, PurePosixPath) else value
    if (
        not isinstance(text, str)
        or not text
        or "\\" in text
        or "\x00" in text
        or len(text.encode("utf-8")) > MAX_RELATIVE_PATH_BYTES
    ):
        raise PhysicalCaptureArchiveError(
            "invalid_relative_path", f"{label} is not a bounded POSIX relative path"
        )
    parsed = PurePosixPath(text)
    if parsed.is_absolute() or parsed.as_posix() != text:
        raise PhysicalCaptureArchiveError(
            "invalid_relative_path", f"{label} must be canonical and relative"
        )
    parts = parsed.parts
    if not parts or any(
        part in {"", ".", ".."}
        or len(part.encode("utf-8")) > MAX_PATH_COMPONENT_BYTES
        or _COMPONENT_RE.fullmatch(part) is None
        for part in parts
    ):
        raise PhysicalCaptureArchiveError(
            "invalid_relative_path", f"{label} contains an unsafe path component"
        )
    return parts


def _validate_directory(
    metadata: os.stat_result, *, label: str, private: bool
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise PhysicalCaptureArchiveError(
            "unsafe_directory", f"{label} is not an owner-controlled directory"
        )
    if private:
        if mode != PRIVATE_DIRECTORY_MODE:
            raise PhysicalCaptureArchiveError(
                "unsafe_directory_mode", f"{label} mode must be 0700"
            )
    elif mode & 0o022:
        raise PhysicalCaptureArchiveError(
            "unsafe_directory_mode", f"{label} must not be group/world writable"
        )


def _validate_private_file(metadata: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
    ):
        raise PhysicalCaptureArchiveError(
            "unsafe_private_file",
            f"{label} must be an owner-only regular single-link file",
        )


def _open_directory_at(parent_fd: int, name: str, *, private: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        code = (
            "directory_not_found"
            if error.errno == errno.ENOENT
            else "directory_open_failed"
        )
        raise PhysicalCaptureArchiveError(
            code, f"cannot securely open directory {name!r}"
        ) from error
    try:
        _validate_directory(
            os.fstat(descriptor), label=f"directory {name!r}", private=private
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _fsync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise PhysicalCaptureArchiveError(
            "directory_fsync_failed", "cannot make archive directory durable"
        ) from error


def _exclusive_rename_at(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    if sys.platform != "darwin":
        raise PhysicalCaptureArchiveError(
            "unsupported_atomic_platform",
            "exclusive physical archive publication requires macOS renameatx_np",
        )
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renameatx_np
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    result = rename(
        source_parent_fd,
        os.fsencode(source_name),
        destination_parent_fd,
        os.fsencode(destination_name),
        RENAME_EXCL | RENAME_NOFOLLOW_ANY,
    )
    if result == 0:
        return
    code = ctypes.get_errno()
    failure = "archive_destination_exists" if code == errno.EEXIST else "atomic_rename_failed"
    raise PhysicalCaptureArchiveError(
        failure, f"cannot exclusively publish archive file {destination_name!r}"
    )


class SecureArchive:
    """Descriptor-relative private archive rooted below one repository target/."""

    def __init__(
        self,
        repository: Path,
        root_relative_to_target: str,
        root_fd: int,
    ) -> None:
        self.repository = repository
        self.root_relative_to_target = root_relative_to_target
        self._root_parts = _relative_parts(
            root_relative_to_target, "archive root"
        )
        self._root_fd: int | None = root_fd
        self._root_identity = _directory_identity(os.fstat(root_fd))
        self._sealed_prefixes: tuple[tuple[str, ...], ...] = ()

    @classmethod
    def create(
        cls, repository: Path, root_relative_to_target: str
    ) -> SecureArchive:
        root_parts = _relative_parts(root_relative_to_target, "archive root")
        repository = cls._validated_repository(repository)
        target_fd = cls._open_target(repository)
        current_fd = target_fd
        try:
            for component in root_parts[:-1]:
                next_fd = cls._open_or_create_private_directory(current_fd, component)
                if current_fd != target_fd:
                    os.close(current_fd)
                current_fd = next_fd
            final = root_parts[-1]
            try:
                os.mkdir(final, PRIVATE_DIRECTORY_MODE, dir_fd=current_fd)
            except FileExistsError as error:
                raise PhysicalCaptureArchiveError(
                    "archive_exists", "physical capture archive already exists"
                ) from error
            except OSError as error:
                raise PhysicalCaptureArchiveError(
                    "archive_create_failed", "cannot create physical capture archive"
                ) from error
            root_fd = _open_directory_at(current_fd, final, private=True)
            try:
                _fsync_directory(current_fd)
            except BaseException:
                os.close(root_fd)
                raise
            return cls(repository, root_relative_to_target, root_fd)
        finally:
            if current_fd != target_fd:
                os.close(current_fd)
            os.close(target_fd)

    @classmethod
    def open(
        cls, repository: Path, root_relative_to_target: str
    ) -> SecureArchive:
        root_parts = _relative_parts(root_relative_to_target, "archive root")
        repository = cls._validated_repository(repository)
        target_fd = cls._open_target(repository)
        current_fd = target_fd
        try:
            for component in root_parts:
                next_fd = _open_directory_at(current_fd, component, private=True)
                if current_fd != target_fd:
                    os.close(current_fd)
                current_fd = next_fd
            root_fd = os.dup(current_fd)
            return cls(repository, root_relative_to_target, root_fd)
        finally:
            if current_fd != target_fd:
                os.close(current_fd)
            os.close(target_fd)

    @staticmethod
    def _validated_repository(repository: Path) -> Path:
        absolute = repository.absolute()
        if not absolute.is_absolute():
            raise PhysicalCaptureArchiveError(
                "invalid_repository", "repository path must be absolute"
            )
        try:
            before = os.lstat(absolute)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            descriptor = os.open(absolute, flags)
        except OSError as error:
            raise PhysicalCaptureArchiveError(
                "invalid_repository", "repository is not a secure directory"
            ) from error
        try:
            opened = os.fstat(descriptor)
            _validate_directory(opened, label="repository", private=False)
            if _directory_identity(before) != _directory_identity(opened):
                raise PhysicalCaptureArchiveError(
                    "repository_race", "repository changed while opening"
                )
        finally:
            os.close(descriptor)
        return absolute

    @staticmethod
    def _open_target(repository: Path) -> int:
        repository_fd = os.open(
            repository,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            return _open_directory_at(repository_fd, "target", private=False)
        finally:
            os.close(repository_fd)

    @staticmethod
    def _open_or_create_private_directory(parent_fd: int, name: str) -> int:
        try:
            return _open_directory_at(parent_fd, name, private=True)
        except PhysicalCaptureArchiveError as error:
            if error.code != "directory_not_found":
                raise
        try:
            os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=parent_fd)
        except FileExistsError:
            return _open_directory_at(parent_fd, name, private=True)
        except OSError as error:
            raise PhysicalCaptureArchiveError(
                "directory_create_failed", f"cannot create private directory {name!r}"
            ) from error
        descriptor = _open_directory_at(parent_fd, name, private=True)
        _fsync_directory(parent_fd)
        return descriptor

    def __enter__(self) -> SecureArchive:
        self._require_open()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def _require_open(self) -> int:
        if self._root_fd is None:
            raise PhysicalCaptureArchiveError(
                "archive_closed", "physical capture archive is closed"
            )
        return self._root_fd

    def seal_prefixes(self, prefixes: tuple[str, ...]) -> None:
        """Irreversibly reject mutations below exact archive path prefixes."""

        self._require_open()
        if not isinstance(prefixes, tuple) or not prefixes:
            raise PhysicalCaptureArchiveError(
                "invalid_sealed_prefixes",
                "sealed archive prefixes must be a non-empty tuple",
            )
        normalized = tuple(
            sorted({_relative_parts(prefix, "sealed archive prefix") for prefix in prefixes})
        )
        if len(normalized) != len(prefixes) or any(
            candidate[: len(prefix)] == prefix
            for index, prefix in enumerate(normalized)
            for candidate in normalized[index + 1 :]
        ):
            raise PhysicalCaptureArchiveError(
                "invalid_sealed_prefixes",
                "sealed archive prefixes must be unique and non-overlapping",
            )
        if self._sealed_prefixes and self._sealed_prefixes != normalized:
            raise PhysicalCaptureArchiveError(
                "sealed_prefix_drift",
                "archive prefixes cannot be changed after they are sealed",
            )
        self._sealed_prefixes = normalized

    def _require_mutable(self, relative: str, label: str) -> None:
        parts = _relative_parts(relative, label)
        if any(
            parts[: len(prefix)] == prefix for prefix in self._sealed_prefixes
        ):
            raise PhysicalCaptureArchiveError(
                "archive_namespace_sealed",
                "manifest-bound observation namespace is immutable",
            )

    def _check_root_binding(self) -> None:
        target_fd = self._open_target(self.repository)
        current_fd = target_fd
        try:
            for component in self._root_parts:
                next_fd = _open_directory_at(current_fd, component, private=True)
                if current_fd != target_fd:
                    os.close(current_fd)
                current_fd = next_fd
            if _directory_identity(os.fstat(current_fd)) != self._root_identity:
                raise PhysicalCaptureArchiveError(
                    "archive_root_drift", "archive root path changed after opening"
                )
        finally:
            if current_fd != target_fd:
                os.close(current_fd)
            os.close(target_fd)

    def _open_relative_directory(
        self, parts: tuple[str, ...], *, create: bool
    ) -> int:
        self._check_root_binding()
        current_fd = os.dup(self._require_open())
        try:
            for component in parts:
                next_fd = (
                    self._open_or_create_private_directory(current_fd, component)
                    if create
                    else _open_directory_at(current_fd, component, private=True)
                )
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except BaseException:
            os.close(current_fd)
            raise

    def ensure_directory(self, relative: str) -> None:
        self._require_mutable(relative, "archive directory")
        parts = _relative_parts(relative, "archive directory")
        descriptor = self._open_relative_directory(parts, create=True)
        os.close(descriptor)

    def _parent_and_name(
        self, relative: str, *, create_parents: bool
    ) -> tuple[int, str]:
        parts = _relative_parts(relative, "archive file")
        parent = self._open_relative_directory(parts[:-1], create=create_parents)
        return parent, parts[-1]

    @staticmethod
    def _new_pending_name(final_name: str) -> str:
        return f".{final_name}.pending-{uuid.uuid4().hex}"

    @staticmethod
    def _open_new_private(parent_fd: int, name: str, *, read_write: bool = False) -> int:
        access = os.O_RDWR if read_write else os.O_WRONLY
        flags = access | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
        except OSError as error:
            raise PhysicalCaptureArchiveError(
                "private_file_create_failed", f"cannot create private file {name!r}"
            ) from error
        try:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            _validate_private_file(os.fstat(descriptor), f"private file {name!r}")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError(errno.EIO, "short archive write")
            offset += written

    @staticmethod
    def _read_opened(
        descriptor: int, metadata: os.stat_result, maximum: int
    ) -> tuple[bytes, os.stat_result]:
        if metadata.st_size < 1 or metadata.st_size > maximum:
            raise PhysicalCaptureArchiveError(
                "archive_file_size", "archive file size is outside the accepted bound"
            )
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise PhysicalCaptureArchiveError(
                    "archive_short_read", "archive file ended before its recorded size"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PhysicalCaptureArchiveError(
                "archive_grew", "archive file grew while reading"
            )
        return b"".join(chunks), os.fstat(descriptor)

    @staticmethod
    def _open_existing_private_at(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except OSError as error:
            raise PhysicalCaptureArchiveError(
                "archive_file_open_failed", f"cannot securely open archive file {name!r}"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            _validate_private_file(metadata, f"archive file {name!r}")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, metadata

    def _verify_published_at(
        self, parent_fd: int, name: str, *, maximum: int, expected: ArchivedFile
    ) -> ArchivedFile:
        descriptor, before = self._open_existing_private_at(parent_fd, name)
        try:
            data, after = self._read_opened(descriptor, before, maximum)
        finally:
            os.close(descriptor)
        if _file_identity(before) != _file_identity(after):
            raise PhysicalCaptureArchiveError(
                "archive_file_race", "published archive file changed while verifying"
            )
        observed = ArchivedFile(
            relative_path=expected.relative_path,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        if observed != expected:
            raise PhysicalCaptureArchiveError(
                "archive_publish_mismatch", "published archive bytes differ from the source"
            )
        return observed

    def write_bytes(
        self, relative: str, data: bytes, *, maximum: int = DEFAULT_MAXIMUM_BYTES
    ) -> ArchivedFile:
        self._require_mutable(relative, "archive file")
        if not isinstance(data, bytes) or not data or len(data) > maximum:
            raise PhysicalCaptureArchiveError(
                "invalid_archive_bytes", "archive bytes are empty or exceed the fixed bound"
            )
        parent_fd, final_name = self._parent_and_name(relative, create_parents=True)
        pending_name = self._new_pending_name(final_name)
        published = False
        descriptor = -1
        try:
            descriptor = self._open_new_private(parent_fd, pending_name)
            self._write_all(descriptor, data)
            os.fsync(descriptor)
            _validate_private_file(os.fstat(descriptor), "pending archive file")
            os.close(descriptor)
            descriptor = -1
            expected = ArchivedFile(
                relative_path=relative,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
            _exclusive_rename_at(parent_fd, pending_name, parent_fd, final_name)
            published = True
            _fsync_directory(parent_fd)
            return self._verify_published_at(
                parent_fd, final_name, maximum=maximum, expected=expected
            )
        except BaseException:
            if not published:
                try:
                    os.unlink(pending_name, dir_fd=parent_fd)
                    _fsync_directory(parent_fd)
                except FileNotFoundError:
                    pass
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_fd)

    def write_or_reopen_exact(
        self,
        relative: str,
        data: bytes,
        *,
        maximum: int = DEFAULT_MAXIMUM_BYTES,
    ) -> ArchivedFile:
        self._require_mutable(relative, "archive file")
        parts = _relative_parts(relative, "archive file")
        if len(parts) < 2:
            raise PhysicalCaptureArchiveError(
                "exact_archive_parent_required",
                "exact archive recovery requires a named private subdirectory",
            )
        if not isinstance(data, bytes) or not data or len(data) > maximum:
            raise PhysicalCaptureArchiveError(
                "invalid_archive_bytes",
                "exact archive bytes are empty or exceed the fixed bound",
            )
        parent_relative = PurePosixPath(*parts[:-1]).as_posix()
        final_name = parts[-1]
        parent_fd = self._open_relative_directory(parts[:-1], create=True)
        try:
            names = os.listdir(parent_fd)
        except OSError as error:
            os.close(parent_fd)
            raise PhysicalCaptureArchiveError(
                "directory_list_failed",
                "cannot enumerate exact archive parent",
            ) from error
        os.close(parent_fd)
        if any(
            not isinstance(name, str) or not name or "/" in name or "\x00" in name
            for name in names
        ):
            raise PhysicalCaptureArchiveError(
                "unsafe_directory_entry",
                "exact archive parent contains an unsafe entry",
            )
        pending: list[PendingFile] = []
        for name in names:
            match = _PENDING_RE.fullmatch(name)
            if match is not None:
                pending.append(
                    PendingFile(
                        relative_path=f"{parent_relative}/{name}",
                        final_relative_path=(
                            f"{parent_relative}/{match.group('final')}"
                        ),
                    )
                )
            elif name.startswith("."):
                raise PhysicalCaptureArchiveError(
                    "unexpected_pending_archive_file",
                    "exact archive parent contains a malformed hidden file",
                )
        target_pending = tuple(
            item for item in pending if item.final_relative_path == relative
        )
        if len(pending) > 1:
            raise PhysicalCaptureArchiveError(
                "ambiguous_pending_archive_file",
                "exact archive parent contains multiple pending files",
            )
        expected = ArchivedFile(
            relative_path=relative,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        final_exists = final_name in names
        if final_exists:
            observed = self.read_bytes(relative, maximum=maximum)
            if observed != data:
                raise PhysicalCaptureArchiveError(
                    "archive_publish_mismatch",
                    "published exact archive bytes differ from the source",
                )
            if target_pending:
                candidate = target_pending[0]
                interrupted = self.read_pending_fragment(
                    candidate, maximum=maximum
                )
                if not data.startswith(interrupted):
                    raise PhysicalCaptureArchiveError(
                        "pending_archive_mismatch",
                        "pending exact archive bytes are not a source prefix",
                    )
                self.discard_pending(candidate)
            return self._verify_exact_descriptor(relative, expected, maximum)
        if pending and not target_pending:
            raise PhysicalCaptureArchiveError(
                "ambiguous_pending_archive_file",
                "exact archive target is preceded by another pending stage",
            )
        if target_pending:
            candidate = target_pending[0]
            interrupted = self.read_pending_fragment(
                candidate, maximum=maximum
            )
            if interrupted == data:
                self.publish_pending(candidate)
                return self._verify_exact_descriptor(relative, expected, maximum)
            if not data.startswith(interrupted):
                raise PhysicalCaptureArchiveError(
                    "pending_archive_mismatch",
                    "pending exact archive bytes are not a source prefix",
                )
            self.discard_pending(candidate)
        archived = self.write_bytes(relative, data, maximum=maximum)
        if archived != expected:
            raise PhysicalCaptureArchiveError(
                "archive_publish_mismatch",
                "published exact archive descriptor differs from the source",
            )
        return archived

    def _verify_exact_descriptor(
        self,
        relative: str,
        expected: ArchivedFile,
        maximum: int,
    ) -> ArchivedFile:
        observed = self.describe_file(relative, maximum=maximum)
        if observed != expected:
            raise PhysicalCaptureArchiveError(
                "archive_publish_mismatch",
                "reopened exact archive descriptor differs from the source",
            )
        return observed

    @staticmethod
    def _open_source(source: Path) -> tuple[int, os.stat_result]:
        if not source.is_absolute():
            raise PhysicalCaptureArchiveError(
                "source_not_absolute", "archive copy source must be absolute"
            )
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        try:
            before_path = os.lstat(source)
            descriptor = os.open(source, flags)
        except OSError as error:
            raise PhysicalCaptureArchiveError(
                "source_open_failed", "archive copy source is not safely openable"
            ) from error
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise PhysicalCaptureArchiveError(
                    "unsafe_copy_source", "archive copy source must be a regular single-link file"
                )
            if _file_identity(before_path) != _file_identity(opened):
                raise PhysicalCaptureArchiveError(
                    "source_open_race", "archive copy source changed while opening"
                )
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, opened

    @staticmethod
    def _reopen_source(source: Path) -> os.stat_result:
        descriptor, metadata = SecureArchive._open_source(source)
        os.close(descriptor)
        return metadata

    def copy_file(
        self,
        source: Path,
        relative: str,
        *,
        maximum: int = DEFAULT_MAXIMUM_BYTES,
    ) -> ArchivedFile:
        self._require_mutable(relative, "archive file")
        if type(maximum) is not int or maximum <= 0:
            raise PhysicalCaptureArchiveError(
                "invalid_copy_bound", "archive copy bound must be positive"
            )
        source_fd = -1
        parent_fd = -1
        output_fd = -1
        pending_name = ""
        published = False
        digest = hashlib.sha256()
        copied = 0
        try:
            source_fd, source_before = self._open_source(source)
            if source_before.st_size < 1 or source_before.st_size > maximum:
                raise PhysicalCaptureArchiveError(
                    "source_size", "archive copy source size exceeds the fixed bound"
                )
            parent_fd, final_name = self._parent_and_name(
                relative, create_parents=True
            )
            pending_name = self._new_pending_name(final_name)
            output_fd = self._open_new_private(parent_fd, pending_name)
            while True:
                chunk = os.read(source_fd, min(1024 * 1024, maximum - copied + 1))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > maximum:
                    raise PhysicalCaptureArchiveError(
                        "source_size", "archive copy source exceeded the fixed bound"
                    )
                digest.update(chunk)
                self._write_all(output_fd, chunk)
            source_after = os.fstat(source_fd)
            if copied != source_before.st_size or _file_identity(source_before) != _file_identity(
                source_after
            ):
                raise PhysicalCaptureArchiveError(
                    "source_copy_race", "archive copy source changed while copying"
                )
            source_reopened = self._reopen_source(source)
            if _file_identity(source_before) != _file_identity(source_reopened):
                raise PhysicalCaptureArchiveError(
                    "source_path_race", "archive copy source path changed while copying"
                )
            os.fsync(output_fd)
            _validate_private_file(os.fstat(output_fd), "pending copied archive file")
            os.close(output_fd)
            output_fd = -1
            expected = ArchivedFile(relative, copied, digest.hexdigest())
            _exclusive_rename_at(parent_fd, pending_name, parent_fd, final_name)
            published = True
            _fsync_directory(parent_fd)
            return self._verify_published_at(
                parent_fd, final_name, maximum=maximum, expected=expected
            )
        except BaseException:
            if parent_fd >= 0 and pending_name and not published:
                try:
                    os.unlink(pending_name, dir_fd=parent_fd)
                    _fsync_directory(parent_fd)
                except FileNotFoundError:
                    pass
            raise
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            if output_fd >= 0:
                os.close(output_fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    def read_bytes(
        self, relative: str, *, maximum: int = DEFAULT_MAXIMUM_BYTES
    ) -> bytes:
        parent_fd, name = self._parent_and_name(relative, create_parents=False)
        try:
            descriptor, before = self._open_existing_private_at(parent_fd, name)
            try:
                data, after = self._read_opened(descriptor, before, maximum)
            finally:
                os.close(descriptor)
            if _file_identity(before) != _file_identity(after):
                raise PhysicalCaptureArchiveError(
                    "archive_file_race", "archive file changed while reading"
                )
            reopened, rebound = self._open_existing_private_at(parent_fd, name)
            os.close(reopened)
            if _file_identity(before) != _file_identity(rebound):
                raise PhysicalCaptureArchiveError(
                    "archive_path_race", "archive path changed while reading"
                )
            return data
        finally:
            os.close(parent_fd)

    def describe_file(
        self, relative: str, *, maximum: int = DEFAULT_MAXIMUM_BYTES
    ) -> ArchivedFile:
        data = self.read_bytes(relative, maximum=maximum)
        return ArchivedFile(relative, len(data), hashlib.sha256(data).hexdigest())

    def list_names(self, relative_directory: str) -> tuple[str, ...]:
        parts = _relative_parts(relative_directory, "archive directory")
        descriptor = self._open_relative_directory(parts, create=False)
        try:
            names = os.listdir(descriptor)
        except OSError as error:
            raise PhysicalCaptureArchiveError(
                "directory_list_failed", "cannot enumerate archive directory"
            ) from error
        finally:
            os.close(descriptor)
        if any(
            not isinstance(name, str) or not name or "/" in name or "\x00" in name
            for name in names
        ):
            raise PhysicalCaptureArchiveError(
                "unsafe_directory_entry", "archive directory contains an unsafe entry name"
            )
        return tuple(sorted(names))

    def list_root_names(self) -> tuple[str, ...]:
        self._check_root_binding()
        descriptor = os.dup(self._require_open())
        try:
            names = os.listdir(descriptor)
        except OSError as error:
            raise PhysicalCaptureArchiveError(
                "directory_list_failed", "cannot enumerate archive root"
            ) from error
        finally:
            os.close(descriptor)
        if any(
            not isinstance(name, str) or not name or "/" in name or "\x00" in name
            for name in names
        ):
            raise PhysicalCaptureArchiveError(
                "unsafe_directory_entry",
                "archive root contains an unsafe entry name",
            )
        return tuple(sorted(names))

    def create_lock_file(self, relative: str) -> int:
        self._require_mutable(relative, "archive lock file")
        parent_fd, name = self._parent_and_name(relative, create_parents=True)
        descriptor = -1
        created = False
        try:
            descriptor = self._open_new_private(parent_fd, name, read_write=True)
            created = True
            os.fsync(descriptor)
            _fsync_directory(parent_fd)
            return descriptor
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
                descriptor = -1
            if created:
                try:
                    os.unlink(name, dir_fd=parent_fd)
                    _fsync_directory(parent_fd)
                except FileNotFoundError:
                    pass
            raise
        finally:
            os.close(parent_fd)

    def open_lock_file(self, relative: str) -> int:
        self._require_mutable(relative, "archive lock file")
        parent_fd, name = self._parent_and_name(relative, create_parents=False)
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            _validate_private_file(os.fstat(descriptor), "session lock file")
            return descriptor
        except BaseException:
            if "descriptor" in locals():
                os.close(descriptor)
            raise
        finally:
            os.close(parent_fd)

    def pending_files(self, relative_directory: str) -> tuple[PendingFile, ...]:
        pending: list[PendingFile] = []
        for name in self.list_names(relative_directory):
            match = _PENDING_RE.fullmatch(name)
            if match is None:
                continue
            base = PurePosixPath(relative_directory)
            pending.append(
                PendingFile(
                    relative_path=(base / name).as_posix(),
                    final_relative_path=(base / match.group("final")).as_posix(),
                )
            )
        return tuple(pending)

    def read_pending(
        self, pending: PendingFile, *, maximum: int = DEFAULT_MAXIMUM_BYTES
    ) -> bytes:
        pending_path = PurePosixPath(pending.relative_path)
        if _PENDING_RE.fullmatch(pending_path.name) is None:
            raise PhysicalCaptureArchiveError(
                "invalid_pending_name", "pending archive name is malformed"
            )
        parent = self._open_relative_directory(pending_path.parts[:-1], create=False)
        try:
            descriptor, before = self._open_existing_private_at(parent, pending_path.name)
            try:
                data, after = self._read_opened(descriptor, before, maximum)
            finally:
                os.close(descriptor)
            if _file_identity(before) != _file_identity(after):
                raise PhysicalCaptureArchiveError(
                    "pending_file_race", "pending archive file changed while reading"
                )
            return data
        finally:
            os.close(parent)

    def read_pending_fragment(
        self,
        pending: PendingFile,
        *,
        maximum: int = DEFAULT_MAXIMUM_BYTES,
    ) -> bytes:
        pending_path = PurePosixPath(pending.relative_path)
        if _PENDING_RE.fullmatch(pending_path.name) is None:
            raise PhysicalCaptureArchiveError(
                "invalid_pending_name", "pending archive name is malformed"
            )
        parent = self._open_relative_directory(
            pending_path.parts[:-1], create=False
        )
        try:
            descriptor, before = self._open_existing_private_at(
                parent, pending_path.name
            )
            try:
                if before.st_size > maximum:
                    raise PhysicalCaptureArchiveError(
                        "archive_file_size",
                        "pending archive fragment exceeds the accepted bound",
                    )
                chunks: list[bytes] = []
                remaining = before.st_size
                while remaining:
                    chunk = os.read(descriptor, min(1024 * 1024, remaining))
                    if not chunk:
                        raise PhysicalCaptureArchiveError(
                            "archive_short_read",
                            "pending archive fragment ended before its recorded size",
                        )
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(descriptor, 1):
                    raise PhysicalCaptureArchiveError(
                        "archive_grew",
                        "pending archive fragment grew while reading",
                    )
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if _file_identity(before) != _file_identity(after):
                raise PhysicalCaptureArchiveError(
                    "pending_file_race",
                    "pending archive fragment changed while reading",
                )
            return b"".join(chunks)
        finally:
            os.close(parent)

    def publish_pending(self, pending: PendingFile) -> None:
        self._require_mutable(pending.final_relative_path, "pending archive target")
        pending_path = PurePosixPath(pending.relative_path)
        final_path = PurePosixPath(pending.final_relative_path)
        match = _PENDING_RE.fullmatch(pending_path.name)
        if (
            match is None
            or pending_path.parent != final_path.parent
            or match.group("final") != final_path.name
        ):
            raise PhysicalCaptureArchiveError(
                "invalid_pending_binding", "pending archive target binding is malformed"
            )
        parent = self._open_relative_directory(pending_path.parts[:-1], create=False)
        try:
            descriptor, metadata = self._open_existing_private_at(parent, pending_path.name)
            os.close(descriptor)
            _validate_private_file(metadata, "pending archive file")
            _exclusive_rename_at(parent, pending_path.name, parent, final_path.name)
            _fsync_directory(parent)
        finally:
            os.close(parent)

    def discard_pending(self, pending: PendingFile) -> None:
        self._require_mutable(pending.final_relative_path, "pending archive target")
        pending_path = PurePosixPath(pending.relative_path)
        if _PENDING_RE.fullmatch(pending_path.name) is None:
            raise PhysicalCaptureArchiveError(
                "invalid_pending_name", "pending archive name is malformed"
            )
        parent = self._open_relative_directory(pending_path.parts[:-1], create=False)
        try:
            descriptor, metadata = self._open_existing_private_at(parent, pending_path.name)
            os.close(descriptor)
            _validate_private_file(metadata, "pending archive file")
            os.unlink(pending_path.name, dir_fd=parent)
            _fsync_directory(parent)
        finally:
            os.close(parent)


__all__ = [
    "ArchivedFile",
    "DEFAULT_MAXIMUM_BYTES",
    "PRIVATE_DIRECTORY_MODE",
    "PRIVATE_FILE_MODE",
    "PendingFile",
    "PhysicalCaptureArchiveError",
    "SecureArchive",
]
