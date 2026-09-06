"""Durable, fail-closed primitives for private publication pending files.

The helpers in this module own only filesystem transaction mechanics.  They do
not interpret evidence payloads or decide whether a pending document is valid
for a particular release state machine.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import stat
import sys
from typing import Iterator
import uuid

from .common import PublicationError
if __package__ and __package__.startswith("scripts."):
    from ..macos_durability import full_fsync
else:
    from macos_durability import full_fsync


RENAME_EXCL = 0x00000004
RENAME_NOFOLLOW_ANY = 0x00000010
_RENAME_FLAGS = RENAME_EXCL | RENAME_NOFOLLOW_ANY
_COPY_CHUNK_SIZE = 64 * 1024


class DurabilityOutcomeUnknown(PublicationError):
    """A namespace mutation succeeded but its stable-storage barrier did not."""


class RootedDirectoryChanged(PublicationError):
    """A descriptor-rooted directory path changed while a transaction was active."""


def _sync_regular_file(path: Path, expected: os.stat_result) -> None:
    flags = (
        os.O_RDONLY
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            _metadata_identity(opened) != _metadata_identity(expected)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
        ):
            raise PublicationError(
                f"durable tree file is not a single-link regular file: {path}"
            )
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        rebound = path.stat(follow_symlinks=False)
        if (
            _metadata_identity(after) != _metadata_identity(expected)
            or _metadata_identity(rebound) != _metadata_identity(expected)
        ):
            raise RootedDirectoryChanged(
                f"durable tree file changed while synchronizing: {path}"
            )
    finally:
        os.close(descriptor)


def _private_tree_snapshot(root: Path) -> dict[str, tuple[os.stat_result, str | None]]:
    snapshot: dict[str, tuple[os.stat_result, str | None]] = {}

    def walk_error(error: OSError) -> None:
        raise PublicationError(
            f"cannot enumerate private durable tree: {root}"
        ) from error

    try:
        root_metadata = root.lstat()
        for current, names, files in os.walk(
            root,
            topdown=True,
            onerror=walk_error,
            followlinks=False,
        ):
            names.sort()
            files.sort()
            current_path = Path(current)
            relative_current = current_path.relative_to(root).as_posix() or "."
            current_metadata = current_path.lstat()
            if (
                not stat.S_ISDIR(current_metadata.st_mode)
                or current_path.is_symlink()
                or current_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(current_metadata.st_mode) & 0o022
            ):
                raise PublicationError(
                    f"private durable tree directory is unsafe: {current_path}"
                )
            prior = snapshot.get(relative_current)
            if prior is not None and _metadata_identity(prior[0]) != _metadata_identity(
                current_metadata
            ):
                raise RootedDirectoryChanged(
                    f"private durable tree directory changed while walking: {current_path}"
                )
            snapshot[relative_current] = (current_metadata, None)
            for name in (*names, *files):
                path = current_path / name
                relative = path.relative_to(root).as_posix()
                metadata = path.lstat()
                target: str | None = None
                if stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(path)
                    target_path = Path(target)
                    if (
                        target_path.is_absolute()
                        or not target
                        or "\x00" in target
                        or ".." in target_path.parts
                    ):
                        raise PublicationError(
                            f"private durable tree symlink target is unsafe: {path}"
                        )
                elif stat.S_ISDIR(metadata.st_mode):
                    pass
                elif (
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_nlink == 1
                    and metadata.st_uid == os.geteuid()
                    and not stat.S_IMODE(metadata.st_mode) & 0o022
                ):
                    pass
                else:
                    raise PublicationError(
                        f"private durable tree contains an unsupported entry: {path}"
                    )
                snapshot[relative] = (metadata, target)
    except PublicationError:
        raise
    except OSError as error:
        raise PublicationError(
            f"cannot capture private durable tree identity: {root}"
        ) from error
    observed_root = snapshot.get(".")
    if observed_root is None or _metadata_identity(
        observed_root[0]
    ) != _metadata_identity(root_metadata):
        raise RootedDirectoryChanged(
            f"private durable tree root changed while enumerating: {root}"
        )
    return snapshot


def _same_tree_snapshot(
    first: dict[str, tuple[os.stat_result, str | None]],
    second: dict[str, tuple[os.stat_result, str | None]],
) -> bool:
    if set(first) != set(second):
        return False
    return all(
        _metadata_identity(first[name][0]) == _metadata_identity(second[name][0])
        and first[name][1] == second[name][1]
        for name in first
    )


def fsync_private_tree(root: Path) -> None:
    """Synchronize one complete private tree before an atomic directory publish."""

    root = Path(root).absolute()
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise PublicationError(f"cannot inspect private durable tree: {root}") from error
    _require_private_directory_metadata(root_metadata, root)
    snapshot = _private_tree_snapshot(root)
    try:
        for relative, (metadata, _target) in sorted(snapshot.items()):
            if stat.S_ISREG(metadata.st_mode):
                _sync_regular_file(root / relative, metadata)
        directories = sorted(
            (
                (relative, metadata)
                for relative, (metadata, _target) in snapshot.items()
                if stat.S_ISDIR(metadata.st_mode)
            ),
            key=lambda item: (len(Path(item[0]).parts), item[0]),
            reverse=True,
        )
        for relative, expected in directories:
            directory = root if relative == "." else root / relative
            descriptor = _open_owned_directory(directory)
            try:
                if _metadata_identity(os.fstat(descriptor)) != _metadata_identity(
                    expected
                ):
                    raise RootedDirectoryChanged(
                        f"private durable tree directory changed: {directory}"
                    )
                if directory == root:
                    _full_fsync_directory_descriptor(descriptor, directory)
                else:
                    os.fsync(descriptor)
                rebound = directory.stat(follow_symlinks=False)
                if _metadata_identity(rebound) != _metadata_identity(expected):
                    raise RootedDirectoryChanged(
                        f"private durable tree directory changed: {directory}"
                    )
            finally:
                os.close(descriptor)
    except PublicationError:
        raise
    except OSError as error:
        raise PublicationError(f"cannot synchronize private durable tree: {root}") from error

    rebound = _private_tree_snapshot(root)
    if not _same_tree_snapshot(snapshot, rebound):
        raise RootedDirectoryChanged(
            f"private durable tree changed after synchronization: {root}"
        )


def _rename_directory_exclusive(source: Path, destination: Path) -> None:
    if sys.platform != "darwin":
        raise PublicationError(
            "atomic private-directory publication requires macOS renamex_np"
        )
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(
        os.fsencode(source),
        os.fsencode(destination),
        _RENAME_FLAGS,
    )
    if result == 0:
        return
    code = ctypes.get_errno()
    if code == errno.EEXIST:
        message = "private-directory publication destination already exists"
    elif code == errno.EXDEV:
        message = "private-directory publication crossed filesystems"
    else:
        message = "exclusive private-directory rename failed"
    raise PublicationError(message)


def publish_private_directory_exclusive(source: Path, destination: Path) -> None:
    """Durably publish one private tree with a non-overwriting atomic rename."""

    source = Path(source).absolute()
    destination = Path(destination).absolute()
    if source == destination:
        raise PublicationError("private-directory publication paths are invalid")
    try:
        source.relative_to(destination)
    except ValueError:
        pass
    else:
        raise PublicationError(
            "private-directory publication paths have an ancestor relationship"
        )
    try:
        destination.relative_to(source)
    except ValueError:
        pass
    else:
        raise PublicationError(
            "private-directory publication paths have an ancestor relationship"
        )
    source_metadata = source.lstat()
    _require_private_directory_metadata(source_metadata, source)
    destination_parent = destination.parent
    parent_metadata = destination_parent.lstat()
    _require_owned_directory(parent_metadata, destination_parent)
    if os.path.lexists(destination):
        raise PublicationError(
            f"private-directory publication destination already exists: {destination}"
        )
    if source_metadata.st_dev != parent_metadata.st_dev:
        raise PublicationError("private-directory publication crossed filesystems")

    fsync_private_tree(source)
    source_parent = source.parent
    _rename_directory_exclusive(source, destination)
    try:
        fsync_directory(destination_parent)
        if source_parent != destination_parent:
            fsync_directory(source_parent)
    except (OSError, PublicationError) as error:
        raise DurabilityOutcomeUnknown(
            "private-directory publication completed but durability is unknown"
        ) from error


def confirm_private_directory_published(source: Path, destination: Path) -> None:
    """Resolve rename reply loss only when the destination is the sole survivor."""

    source = Path(source).absolute()
    destination = Path(destination).absolute()
    if os.path.lexists(source) or not os.path.lexists(destination):
        raise PublicationError(
            "private-directory publication cannot be confirmed from namespace state"
        )
    fsync_private_tree(destination)
    fsync_directory(destination.parent)
    if source.parent != destination.parent:
        fsync_directory(source.parent)


def _required_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if not isinstance(value, int):
        raise PublicationError(f"durable private-file operations require {name}")
    return value


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | _required_open_flag("O_DIRECTORY")
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
    )


def _private_file_open_flags() -> int:
    return (
        os.O_RDONLY
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
    )


def _private_file_create_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
    )


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_owned_directory(metadata: os.stat_result, path: Path) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise PublicationError(f"publication directory is not a real directory: {path}")
    if metadata.st_uid != os.geteuid():
        raise PublicationError(f"publication directory is not owned by the effective user: {path}")


def _require_private_directory_metadata(metadata: os.stat_result, path: Path) -> None:
    _require_owned_directory(metadata, path)
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PublicationError(f"private publication directory mode is not 0700: {path}")


def _open_owned_directory(path: Path) -> int:
    path = Path(path)
    try:
        before = path.lstat()
    except OSError as error:
        raise PublicationError(f"cannot inspect publication directory {path}: {error}") from error
    _require_owned_directory(before, path)
    if stat.S_ISLNK(before.st_mode):
        raise PublicationError(f"publication directory is a symlink: {path}")

    try:
        descriptor = os.open(path, _directory_open_flags())
    except OSError as error:
        raise PublicationError(f"cannot open publication directory {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        rebound = path.stat(follow_symlinks=False)
        _require_owned_directory(opened, path)
        _require_owned_directory(rebound, path)
        if (
            before.st_dev,
            before.st_ino,
        ) != (
            opened.st_dev,
            opened.st_ino,
        ) or (
            opened.st_dev,
            opened.st_ino,
        ) != (
            rebound.st_dev,
            rebound.st_ino,
        ):
            raise PublicationError(f"publication directory changed while opening: {path}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_owned_directory_beneath(
    root_descriptor: int,
    components: tuple[str, ...],
    path: Path,
) -> tuple[int, ...]:
    descriptors: list[int] = []
    try:
        for component in components:
            if component in {"", ".", ".."} or "/" in component or "\x00" in component:
                raise PublicationError(
                    f"publication directory has an unsafe rooted component: {path}"
                )
            parent_descriptor = (
                descriptors[-1] if descriptors else root_descriptor
            )
            try:
                before = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                next_descriptor = os.open(
                    component,
                    _directory_open_flags(),
                    dir_fd=parent_descriptor,
                )
            except OSError as error:
                raise PublicationError(
                    f"cannot open rooted publication directory {path}: {error}"
                ) from error
            try:
                opened = os.fstat(next_descriptor)
                _require_owned_directory(before, path)
                _require_owned_directory(opened, path)
                if (before.st_dev, before.st_ino) != (
                    opened.st_dev,
                    opened.st_ino,
                ):
                    raise PublicationError(
                        f"rooted publication directory changed while opening: {path}"
                    )
            except BaseException:
                os.close(next_descriptor)
                raise
            descriptors.append(next_descriptor)
        return tuple(descriptors)
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _open_rooted_directory(
    root: Path,
    directory: Path,
    *,
    require_private: bool = False,
) -> tuple[int, ...]:
    root = Path(root).absolute()
    directory = Path(directory).absolute()
    try:
        relative = directory.relative_to(root)
    except ValueError as error:
        raise PublicationError(
            f"publication directory is outside its trusted root: {directory}"
        ) from error
    root_descriptor = _open_owned_directory(root)
    descendant_descriptors: tuple[int, ...] = ()
    try:
        descendant_descriptors = _open_owned_directory_beneath(
            root_descriptor,
            tuple(relative.parts),
            directory,
        )
        descriptors = (root_descriptor, *descendant_descriptors)
        if require_private:
            _require_private_directory_metadata(os.fstat(descriptors[-1]), directory)
    except BaseException:
        for descriptor in reversed(descendant_descriptors):
            os.close(descriptor)
        os.close(root_descriptor)
        raise
    return descriptors


def _inspect_private_directory_at(
    parent_descriptor: int,
    name: str,
    path: Path,
) -> tuple[int, os.stat_result]:
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        raise PublicationError(f"cannot inspect private publication directory {path}: {error}") from error
    _require_private_directory_metadata(before, path)

    try:
        descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_descriptor)
    except OSError as error:
        raise PublicationError(f"cannot open private publication directory {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        _require_private_directory_metadata(opened, path)
        if _metadata_identity(before) != _metadata_identity(opened):
            raise PublicationError(
                f"private publication directory changed while opening: {path}"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _require_simple_name(path: Path, label: str) -> str:
    name = path.name
    if not name or name in {".", ".."} or "\x00" in name:
        raise PublicationError(f"{label} must have one canonical file name")
    return name


def _require_maximum(maximum: int) -> None:
    if type(maximum) is not int or maximum < 0:
        raise PublicationError("private pending read maximum must be a non-negative integer")


def _require_private_metadata(
    metadata: os.stat_result,
    path: Path,
    *,
    maximum: int | None,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise PublicationError(f"private pending path is not a regular file: {path}")
    if metadata.st_nlink != 1:
        raise PublicationError(f"private pending file is not single-link: {path}")
    if metadata.st_uid != os.geteuid():
        raise PublicationError(f"private pending file is not owned by the effective user: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PublicationError(f"private pending file mode is not 0600: {path}")
    if maximum is not None and metadata.st_size > maximum:
        raise PublicationError(f"private pending file exceeds {maximum} bytes: {path}")


def _inspect_private_pending_at(
    directory_descriptor: int,
    name: str,
    path: Path,
    *,
    maximum: int | None,
) -> tuple[int, os.stat_result]:
    try:
        before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as error:
        raise PublicationError(f"cannot inspect private pending file {path}: {error}") from error
    _require_private_metadata(before, path, maximum=maximum)

    try:
        descriptor = os.open(
            name,
            _private_file_open_flags(),
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        raise PublicationError(f"cannot open private pending file {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        _require_private_metadata(opened, path, maximum=maximum)
        if _metadata_identity(before) != _metadata_identity(opened):
            raise PublicationError(f"private pending file changed while opening: {path}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _open_and_read_private_pending_at(
    directory_descriptor: int,
    name: str,
    path: Path,
    maximum: int,
) -> tuple[int, bytes, os.stat_result]:
    descriptor, opened = _inspect_private_pending_at(
        directory_descriptor,
        name,
        path,
        maximum=maximum,
    )
    try:
        remaining = maximum + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(_COPY_CHUNK_SIZE, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        rebound = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        _require_private_metadata(after, path, maximum=maximum)
        _require_private_metadata(rebound, path, maximum=maximum)
        if len(data) > maximum:
            raise PublicationError(f"private pending file exceeds {maximum} bytes: {path}")
        if len(data) != opened.st_size:
            raise PublicationError(f"private pending file returned a short read: {path}")
        identity = _metadata_identity(opened)
        if identity != _metadata_identity(after) or identity != _metadata_identity(rebound):
            raise PublicationError(f"private pending file changed while reading: {path}")
    except OSError as error:
        os.close(descriptor)
        raise PublicationError(f"cannot read private pending file {path}: {error}") from error
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, data, opened


def _read_private_pending_at(
    directory_descriptor: int,
    name: str,
    path: Path,
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    descriptor, data, opened = _open_and_read_private_pending_at(
        directory_descriptor,
        name,
        path,
        maximum,
    )
    os.close(descriptor)
    return data, opened


def _full_fsync_descriptor(descriptor: int, path: Path, subject: str) -> None:
    """Issue the macOS stable-storage barrier required for ordered publication."""

    try:
        full_fsync(descriptor)
    except OSError as error:
        raise PublicationError(
            f"{subject} stable-storage durability is unknown: {path}"
        ) from error


def _full_fsync_directory_descriptor(descriptor: int, path: Path) -> None:
    _full_fsync_descriptor(descriptor, path, "publication directory")


@contextmanager
def exclusive_directory_lock(directory: Path) -> Iterator[int]:
    """Hold a non-blocking exclusive lock on one owned, real directory."""

    directory = Path(directory)
    descriptor = _open_owned_directory(directory)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise PublicationError(
                    f"publication directory lock is already held: {directory}"
                ) from error
            raise PublicationError(
                f"cannot lock publication directory {directory}: {error}"
            ) from error
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def exclusive_rooted_directory_lock(
    root: Path,
    directory: Path,
    *,
    require_private: bool = False,
) -> Iterator[int]:
    """Lock a directory reached component-by-component below one trusted root."""

    root = Path(root).absolute()
    directory = Path(directory).absolute()
    descriptors = _open_rooted_directory(
        root,
        directory,
        require_private=require_private,
    )
    descriptor = descriptors[-1]
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise PublicationError(
                    f"publication directory lock is already held: {directory}"
                ) from error
            raise PublicationError(
                f"cannot lock publication directory {directory}: {error}"
            ) from error
        yield descriptor

        try:
            fresh_descriptors = _open_rooted_directory(
                root,
                directory,
                require_private=require_private,
            )
        except PublicationError as error:
            raise RootedDirectoryChanged(
                f"rooted publication directory changed while locked: {directory}"
            ) from error
        try:
            original_identities = tuple(
                (metadata.st_dev, metadata.st_ino)
                for metadata in map(os.fstat, descriptors)
            )
            fresh_identities = tuple(
                (metadata.st_dev, metadata.st_ino)
                for metadata in map(os.fstat, fresh_descriptors)
            )
        finally:
            for fresh_descriptor in reversed(fresh_descriptors):
                os.close(fresh_descriptor)
        if original_identities != fresh_identities:
            raise RootedDirectoryChanged(
                f"rooted publication directory changed while locked: {directory}"
            )
    finally:
        for opened_descriptor in reversed(descriptors):
            os.close(opened_descriptor)


def fsync_directory(path: Path) -> None:
    """Synchronize one owned, real directory and fail if durability is unknown."""

    path = Path(path)
    descriptor = _open_owned_directory(path)
    try:
        _full_fsync_directory_descriptor(descriptor, path)
    finally:
        os.close(descriptor)


def _require_private_directory_expectations(
    maximum_files: dict[str, int],
) -> None:
    if not isinstance(maximum_files, dict) or not maximum_files:
        raise PublicationError("private publication directory must contain expected files")
    for name, maximum in maximum_files.items():
        if type(name) is not str or type(maximum) is not int or maximum < 0:
            raise PublicationError("private publication directory expectations are malformed")
        if _require_simple_name(Path(name), "private publication entry") != name:
            raise PublicationError(f"private publication entry name is unsafe: {name!r}")


def _read_private_directory_contents_at(
    parent_descriptor: int,
    directory_name: str,
    directory: Path,
    maximum_files: dict[str, int],
    parent_barrier_path: Path,
) -> dict[str, bytes]:
    _require_private_directory_expectations(maximum_files)
    descriptor = -1
    opened_files: dict[str, tuple[int, os.stat_result]] = {}
    contents: dict[str, bytes] = {}
    try:
        descriptor, opened_directory = _inspect_private_directory_at(
            parent_descriptor,
            directory_name,
            directory,
        )
        actual_names = os.listdir(descriptor)
        if len(actual_names) != len(maximum_files) or set(actual_names) != set(maximum_files):
            raise PublicationError(
                f"private publication directory entries differ from the expected set: {directory}"
            )

        for entry_name in sorted(maximum_files):
            entry_path = directory / entry_name
            file_descriptor, data, metadata = _open_and_read_private_pending_at(
                descriptor,
                entry_name,
                entry_path,
                maximum_files[entry_name],
            )
            opened_files[entry_name] = (file_descriptor, metadata)
            contents[entry_name] = data
            _full_fsync_descriptor(
                file_descriptor,
                entry_path,
                "private publication file",
            )
            synchronized = os.fstat(file_descriptor)
            rebound = os.stat(
                entry_name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if (
                _metadata_identity(metadata) != _metadata_identity(synchronized)
                or _metadata_identity(metadata) != _metadata_identity(rebound)
            ):
                raise PublicationError(
                    f"private publication file changed while synchronizing: {entry_path}"
                )

        before_barrier = os.fstat(descriptor)
        rebound_directory = os.stat(
            directory_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _metadata_identity(opened_directory) != _metadata_identity(before_barrier)
            or _metadata_identity(opened_directory)
            != _metadata_identity(rebound_directory)
        ):
            raise PublicationError(
                f"private publication directory changed while verifying: {directory}"
            )
        _full_fsync_directory_descriptor(descriptor, directory)

        if set(os.listdir(descriptor)) != set(maximum_files):
            raise PublicationError(
                f"private publication directory changed after fsync: {directory}"
            )
        after_barrier = os.fstat(descriptor)
        rebound_after_barrier = os.stat(
            directory_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _metadata_identity(opened_directory) != _metadata_identity(after_barrier)
            or _metadata_identity(opened_directory)
            != _metadata_identity(rebound_after_barrier)
        ):
            raise PublicationError(
                f"private publication directory changed after fsync: {directory}"
            )
        for entry_name, (file_descriptor, metadata) in opened_files.items():
            after = os.fstat(file_descriptor)
            rebound = os.stat(
                entry_name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if (
                _metadata_identity(metadata) != _metadata_identity(after)
                or _metadata_identity(metadata) != _metadata_identity(rebound)
            ):
                raise PublicationError(
                    "private publication file changed after directory fsync: "
                    f"{directory / entry_name}"
                )
        fsync_locked_directory(parent_descriptor, parent_barrier_path)
        if set(os.listdir(descriptor)) != set(maximum_files):
            raise PublicationError(
                f"private publication directory changed after parent fsync: {directory}"
            )
        after_parent_barrier = os.fstat(descriptor)
        rebound_after_parent_barrier = os.stat(
            directory_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _metadata_identity(opened_directory)
            != _metadata_identity(after_parent_barrier)
            or _metadata_identity(opened_directory)
            != _metadata_identity(rebound_after_parent_barrier)
        ):
            raise PublicationError(
                f"private publication directory changed after parent fsync: {directory}"
            )
        for entry_name, (file_descriptor, metadata) in opened_files.items():
            after_parent_barrier = os.fstat(file_descriptor)
            rebound_after_parent_barrier = os.stat(
                entry_name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if (
                _metadata_identity(metadata)
                != _metadata_identity(after_parent_barrier)
                or _metadata_identity(metadata)
                != _metadata_identity(rebound_after_parent_barrier)
            ):
                raise PublicationError(
                    "private publication file changed after parent fsync: "
                    f"{directory / entry_name}"
                )
        return contents
    except OSError as error:
        raise PublicationError(
            f"cannot verify private publication directory {directory}: {error}"
        ) from error
    finally:
        for file_descriptor, _metadata in opened_files.values():
            os.close(file_descriptor)
        if descriptor >= 0:
            os.close(descriptor)


def read_private_directory_contents(
    directory: Path,
    maximum_files: dict[str, int],
) -> dict[str, bytes]:
    """Read and synchronize one exact private directory without following links."""

    directory = Path(directory).absolute()
    name = _require_simple_name(directory, "private publication directory")
    parent_descriptor = _open_owned_directory(directory.parent)
    try:
        return _read_private_directory_contents_at(
            parent_descriptor,
            name,
            directory,
            maximum_files,
            directory.parent,
        )
    finally:
        os.close(parent_descriptor)


def read_private_directory_contents_locked(
    parent_descriptor: int,
    parent: Path,
    directory_name: str,
    maximum_files: dict[str, int],
) -> dict[str, bytes]:
    """Read an exact private child through a caller-held parent descriptor."""

    if type(parent_descriptor) is not int or parent_descriptor < 0:
        raise PublicationError("locked publication directory descriptor is invalid")
    if (
        type(directory_name) is not str
        or _require_simple_name(Path(directory_name), "private publication directory")
        != directory_name
    ):
        raise PublicationError("private publication directory name is unsafe")
    parent = Path(parent).absolute()
    contents = _read_private_directory_contents_at(
        parent_descriptor,
        directory_name,
        parent / directory_name,
        maximum_files,
        parent,
    )
    return contents


def verify_private_directory_contents(
    directory: Path,
    expected_files: dict[str, bytes],
) -> None:
    """Verify exact private bytes and stable-storage ordering."""

    if not isinstance(expected_files, dict) or any(
        type(name) is not str or not isinstance(data, bytes)
        for name, data in expected_files.items()
    ):
        raise PublicationError("private publication directory expectations are malformed")
    observed = read_private_directory_contents(
        directory,
        {name: len(data) for name, data in expected_files.items()},
    )
    if observed != expected_files:
        raise PublicationError(
            f"private publication directory differs from the expected bytes: {directory}"
        )


def fsync_locked_directory(descriptor: int, path: Path) -> None:
    """Synchronize the exact owned directory inode held by an outer lock."""

    if type(descriptor) is not int or descriptor < 0:
        raise PublicationError("locked publication directory descriptor is invalid")
    path = Path(path).absolute()
    try:
        locked = os.fstat(descriptor)
    except OSError as error:
        raise PublicationError(
            f"cannot inspect locked publication directory {path}: {error}"
        ) from error
    _require_owned_directory(locked, path)

    rebound_descriptor = _open_owned_directory(path)
    try:
        rebound = os.fstat(rebound_descriptor)
    finally:
        os.close(rebound_descriptor)
    if (locked.st_dev, locked.st_ino) != (rebound.st_dev, rebound.st_ino):
        raise PublicationError(
            f"locked publication directory path changed while in use: {path}"
        )
    _full_fsync_directory_descriptor(descriptor, path)

    try:
        after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise PublicationError(
            f"locked publication directory path changed after fsync: {path}"
        ) from error
    if (locked.st_dev, locked.st_ino) != (after.st_dev, after.st_ino):
        raise PublicationError(
            f"locked publication directory path changed after fsync: {path}"
        )


def ensure_private_directory_locked(
    parent_descriptor: int,
    parent: Path,
    name: str,
) -> None:
    """Create or validate one private child through a locked parent descriptor."""

    if type(name) is not str or _require_simple_name(Path(name), "private directory") != name:
        raise PublicationError("private directory name is unsafe")
    parent = Path(parent).absolute()
    path = parent / name
    try:
        metadata = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
            metadata = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise PublicationError(
                f"cannot create private publication directory {path}: {error}"
            ) from error
    except OSError as error:
        raise PublicationError(
            f"cannot inspect private publication directory {path}: {error}"
        ) from error
    _require_private_directory_metadata(metadata, path)
    descriptor, opened = _inspect_private_directory_at(parent_descriptor, name, path)
    try:
        if _metadata_identity(metadata) != _metadata_identity(opened):
            raise PublicationError(f"private publication directory changed: {path}")
        fsync_locked_directory(parent_descriptor, parent)
        after_parent_barrier = os.fstat(descriptor)
        rebound_after_parent_barrier = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _require_private_directory_metadata(after_parent_barrier, path)
        _require_private_directory_metadata(rebound_after_parent_barrier, path)
        if (
            _metadata_identity(opened) != _metadata_identity(after_parent_barrier)
            or _metadata_identity(opened)
            != _metadata_identity(rebound_after_parent_barrier)
        ):
            raise PublicationError(
                f"private publication directory changed after parent fsync: {path}"
            )
    finally:
        os.close(descriptor)


def read_private_pending(path: Path, maximum: int) -> bytes:
    """Read one stable private pending file, including an empty partial file."""

    _require_maximum(maximum)
    path = Path(path).absolute()
    name = _require_simple_name(path, "private pending path")
    directory_descriptor = _open_owned_directory(path.parent)
    try:
        data, _metadata = _read_private_pending_at(
            directory_descriptor,
            name,
            path,
            maximum,
        )
        return data
    finally:
        os.close(directory_descriptor)


def read_private_pending_locked(
    directory_descriptor: int,
    directory: Path,
    name: str,
    maximum: int,
) -> bytes:
    """Read and synchronize a private file through a locked parent descriptor."""

    _require_maximum(maximum)
    if type(name) is not str or _require_simple_name(Path(name), "private file") != name:
        raise PublicationError("private file name is unsafe")
    directory = Path(directory).absolute()
    path = directory / name
    descriptor, data, metadata = _open_and_read_private_pending_at(
        directory_descriptor,
        name,
        path,
        maximum,
    )
    try:
        _full_fsync_descriptor(descriptor, path, "private publication file")
        after = os.fstat(descriptor)
        rebound = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            _metadata_identity(metadata) != _metadata_identity(after)
            or _metadata_identity(metadata) != _metadata_identity(rebound)
        ):
            raise PublicationError(
                f"private publication file changed while synchronizing: {path}"
            )
        fsync_locked_directory(directory_descriptor, directory)
        after_parent_barrier = os.fstat(descriptor)
        rebound_after_parent_barrier = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            _metadata_identity(metadata) != _metadata_identity(after_parent_barrier)
            or _metadata_identity(metadata)
            != _metadata_identity(rebound_after_parent_barrier)
        ):
            raise PublicationError(
                f"private publication file changed after parent fsync: {path}"
            )
    finally:
        os.close(descriptor)
    return data


def _remove_created_pending(
    directory_descriptor: int,
    name: str,
    path: Path,
    identity: tuple[int, int],
) -> None:
    try:
        rebound = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise PublicationError(f"cannot inspect failed private pending write {path}") from error
    if (
        (rebound.st_dev, rebound.st_ino) != identity
        or not stat.S_ISREG(rebound.st_mode)
        or rebound.st_nlink != 1
        or rebound.st_uid != os.geteuid()
    ):
        raise PublicationError(f"cannot safely clean up failed private pending write: {path}")
    try:
        os.unlink(name, dir_fd=directory_descriptor)
        _full_fsync_directory_descriptor(directory_descriptor, path.parent)
    except OSError as error:
        raise PublicationError(
            f"cannot durably clean up failed private pending write: {path}"
        ) from error


def _write_private_pending_at(
    directory_descriptor: int,
    name: str,
    path: Path,
    data: bytes,
) -> None:
    if not isinstance(data, bytes):
        raise PublicationError("private pending payload must be bytes")
    descriptor = -1
    verification_descriptor = -1
    created_identity: tuple[int, int] | None = None
    preserve_for_recovery = False
    try:
        try:
            descriptor = os.open(
                name,
                _private_file_create_flags(),
                0o600,
                dir_fd=directory_descriptor,
            )
        except FileExistsError as error:
            raise PublicationError(f"private pending file already exists: {path}") from error
        opened = os.fstat(descriptor)
        created_identity = (opened.st_dev, opened.st_ino)
        _require_private_metadata(opened, path, maximum=None)

        payload = memoryview(data)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise PublicationError(f"private pending write made no progress: {path}")
            offset += written
        _full_fsync_descriptor(descriptor, path, "private pending file")
        after = os.fstat(descriptor)
        if _metadata_identity(opened)[:6] != _metadata_identity(after)[:6]:
            raise PublicationError(f"private pending identity changed while writing: {path}")
        if after.st_size != len(data):
            raise PublicationError(f"private pending size differs after writing: {path}")
        os.close(descriptor)
        descriptor = -1

        verification_descriptor, observed, metadata = _open_and_read_private_pending_at(
            directory_descriptor,
            name,
            path,
            len(data),
        )
        if observed != data or (metadata.st_dev, metadata.st_ino) != created_identity:
            raise PublicationError(f"private pending content changed after writing: {path}")
        preserve_for_recovery = True
        try:
            fsync_locked_directory(directory_descriptor, path.parent)
        except PublicationError as error:
            raise PublicationError(
                f"private pending write outcome is unknown after directory fsync failure: {path}"
            ) from error
        after_parent_barrier = os.fstat(verification_descriptor)
        rebound_after_parent_barrier = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            _metadata_identity(metadata) != _metadata_identity(after_parent_barrier)
            or _metadata_identity(metadata)
            != _metadata_identity(rebound_after_parent_barrier)
        ):
            raise PublicationError(
                f"private pending file changed after directory fsync: {path}"
            )
    except Exception as error:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if verification_descriptor >= 0:
            os.close(verification_descriptor)
            verification_descriptor = -1
        if created_identity is not None and not preserve_for_recovery:
            try:
                _remove_created_pending(
                    directory_descriptor,
                    name,
                    path,
                    created_identity,
                )
            except PublicationError as cleanup_error:
                raise cleanup_error from error
        if isinstance(error, PublicationError):
            raise
        raise PublicationError(f"cannot write private pending file {path}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if verification_descriptor >= 0:
            os.close(verification_descriptor)


def write_private_pending(path: Path, data: bytes) -> None:
    """Create and durably write one private pending file without replacement."""

    path = Path(path).absolute()
    name = _require_simple_name(path, "private pending path")
    directory_descriptor = _open_owned_directory(path.parent)
    try:
        _write_private_pending_at(directory_descriptor, name, path, data)
    finally:
        os.close(directory_descriptor)


def write_private_pending_locked(
    directory_descriptor: int,
    directory: Path,
    name: str,
    data: bytes,
) -> None:
    """Create one private file through a locked parent descriptor."""

    if type(name) is not str or _require_simple_name(Path(name), "private file") != name:
        raise PublicationError("private file name is unsafe")
    directory = Path(directory).absolute()
    _write_private_pending_at(
        directory_descriptor,
        name,
        directory / name,
        data,
    )


def discard_private_pending(path: Path, maximum: int) -> None:
    """Safely remove one bounded private pending file and sync its directory."""

    _require_maximum(maximum)
    path = Path(path).absolute()
    name = _require_simple_name(path, "private pending path")
    directory_descriptor = _open_owned_directory(path.parent)
    try:
        _data, metadata = _read_private_pending_at(
            directory_descriptor,
            name,
            path,
            maximum,
        )
        rebound = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if _metadata_identity(metadata) != _metadata_identity(rebound):
            raise PublicationError(f"private pending file changed before discard: {path}")
        os.unlink(name, dir_fd=directory_descriptor)
        try:
            _full_fsync_directory_descriptor(directory_descriptor, path.parent)
        except PublicationError as error:
            raise PublicationError(
                f"private pending discard outcome is unknown after directory fsync failure: {path}"
            ) from error
    except PublicationError:
        raise
    except OSError as error:
        raise PublicationError(f"cannot discard private pending file {path}: {error}") from error
    finally:
        os.close(directory_descriptor)


def _renameatx_np(
    source_directory_descriptor: int,
    source_name: str,
    destination_directory_descriptor: int,
    destination_name: str,
    flags: int,
) -> None:
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameatx_np
    except AttributeError as error:
        raise PublicationError(
            "durable pending promotion requires macOS renameatx_np"
        ) from error
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    result = rename(
        source_directory_descriptor,
        os.fsencode(source_name),
        destination_directory_descriptor,
        os.fsencode(destination_name),
        flags,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


def promote_private_pending(pending: Path, destination: Path) -> None:
    """Atomically promote one private pending file without replacing a target."""

    pending = Path(pending).absolute()
    destination = Path(destination).absolute()
    if pending.parent != destination.parent:
        raise PublicationError("private pending and destination must share one parent directory")
    if pending == destination:
        raise PublicationError("private pending and destination must be different paths")
    pending_name = _require_simple_name(pending, "private pending path")
    destination_name = _require_simple_name(destination, "private destination path")

    directory_descriptor = _open_owned_directory(pending.parent)
    descriptor = -1
    try:
        descriptor, pending_metadata = _inspect_private_pending_at(
            directory_descriptor,
            pending_name,
            pending,
            maximum=None,
        )
        try:
            _full_fsync_descriptor(descriptor, pending, "private pending file")
            synchronized = os.fstat(descriptor)
        except PublicationError as error:
            raise PublicationError(
                f"cannot make private pending durable before promotion: {pending}"
            ) from error
        if _metadata_identity(pending_metadata) != _metadata_identity(synchronized):
            raise PublicationError(
                f"private pending changed while synchronizing before promotion: {pending}"
            )
        try:
            os.stat(
                destination_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise PublicationError(f"cannot inspect private destination {destination}") from error
        else:
            raise PublicationError(f"private destination already exists: {destination}")

        rebound = os.stat(
            pending_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if _metadata_identity(pending_metadata) != _metadata_identity(rebound):
            raise PublicationError(f"private pending changed before promotion: {pending}")

        try:
            _renameatx_np(
                directory_descriptor,
                pending_name,
                directory_descriptor,
                destination_name,
                _RENAME_FLAGS,
            )
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise PublicationError(
                    f"private destination already exists: {destination}"
                ) from error
            raise PublicationError(
                f"cannot atomically promote private pending file {pending}: {error}"
            ) from error

        try:
            _full_fsync_descriptor(
                descriptor,
                destination,
                "promoted private file",
            )
            synchronized_after_rename = os.fstat(descriptor)
            promoted = os.stat(
                destination_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                _metadata_identity(synchronized)[:-1]
                != _metadata_identity(synchronized_after_rename)[:-1]
                or _metadata_identity(synchronized_after_rename)
                != _metadata_identity(promoted)
            ):
                raise PublicationError(
                    f"promoted private file changed during rename: {destination}"
                )
            fsync_locked_directory(directory_descriptor, pending.parent)
            after_parent_barrier = os.fstat(descriptor)
            rebound_after_parent_barrier = os.stat(
                destination_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                _metadata_identity(synchronized_after_rename)
                != _metadata_identity(after_parent_barrier)
                or _metadata_identity(synchronized_after_rename)
                != _metadata_identity(rebound_after_parent_barrier)
            ):
                raise PublicationError(
                    f"promoted private file changed after parent fsync: {destination}"
                )
        except (OSError, PublicationError) as error:
            raise DurabilityOutcomeUnknown(
                f"private pending promotion outcome is unknown after rename: {destination}"
            ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_descriptor)


def _promote_private_directory_at(
    parent_descriptor: int,
    parent: Path,
    pending_name: str,
    destination_name: str,
) -> None:
    pending = parent / pending_name
    destination = parent / destination_name
    pending_descriptor = -1
    opened_files: dict[str, tuple[int, os.stat_result]] = {}
    try:
        pending_descriptor, pending_metadata = _inspect_private_directory_at(
            parent_descriptor,
            pending_name,
            pending,
        )
        try:
            entry_names = os.listdir(pending_descriptor)
            if len(entry_names) != len(set(entry_names)):
                raise PublicationError(
                    f"private pending directory has duplicate entries: {pending}"
                )
            for entry_name in sorted(entry_names):
                if _require_simple_name(
                    Path(entry_name), "private pending directory entry"
                ) != entry_name:
                    raise PublicationError(
                        f"private pending directory entry is unsafe: {entry_name!r}"
                    )
                entry_path = pending / entry_name
                file_descriptor, file_metadata = _inspect_private_pending_at(
                    pending_descriptor,
                    entry_name,
                    entry_path,
                    maximum=None,
                )
                opened_files[entry_name] = (file_descriptor, file_metadata)
                _full_fsync_descriptor(
                    file_descriptor,
                    entry_path,
                    "private pending directory file",
                )
                synchronized_file = os.fstat(file_descriptor)
                rebound_file = os.stat(
                    entry_name,
                    dir_fd=pending_descriptor,
                    follow_symlinks=False,
                )
                if (
                    _metadata_identity(file_metadata)
                    != _metadata_identity(synchronized_file)
                    or _metadata_identity(file_metadata)
                    != _metadata_identity(rebound_file)
                ):
                    raise PublicationError(
                        "private pending directory file changed while synchronizing: "
                        f"{entry_path}"
                    )
            _full_fsync_directory_descriptor(pending_descriptor, pending)
            synchronized = os.fstat(pending_descriptor)
            if set(os.listdir(pending_descriptor)) != set(opened_files):
                raise PublicationError(
                    f"private pending directory entries changed while synchronizing: {pending}"
                )
            for entry_name, (file_descriptor, file_metadata) in opened_files.items():
                synchronized_file = os.fstat(file_descriptor)
                rebound_file = os.stat(
                    entry_name,
                    dir_fd=pending_descriptor,
                    follow_symlinks=False,
                )
                if (
                    _metadata_identity(file_metadata)
                    != _metadata_identity(synchronized_file)
                    or _metadata_identity(file_metadata)
                    != _metadata_identity(rebound_file)
                ):
                    raise PublicationError(
                        "private pending directory file changed after directory fsync: "
                        f"{pending / entry_name}"
                    )
        except (OSError, PublicationError) as error:
            raise PublicationError(
                f"cannot make private pending directory durable before promotion: {pending}"
            ) from error
        if _metadata_identity(pending_metadata) != _metadata_identity(synchronized):
            raise PublicationError(
                f"private pending directory changed while synchronizing: {pending}"
            )

        try:
            os.stat(
                destination_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise PublicationError(
                f"cannot inspect private destination directory {destination}"
            ) from error
        else:
            raise PublicationError(
                f"private destination directory already exists: {destination}"
            )

        rebound = os.stat(
            pending_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if _metadata_identity(pending_metadata) != _metadata_identity(rebound):
            raise PublicationError(
                f"private pending directory changed before promotion: {pending}"
            )

        try:
            _renameatx_np(
                parent_descriptor,
                pending_name,
                parent_descriptor,
                destination_name,
                _RENAME_FLAGS,
            )
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise PublicationError(
                    f"private destination directory already exists: {destination}"
                ) from error
            raise PublicationError(
                f"cannot atomically promote private pending directory {pending}: {error}"
            ) from error

        try:
            synchronized_after_rename = os.fstat(pending_descriptor)
            promoted = os.stat(
                destination_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            _require_private_directory_metadata(synchronized_after_rename, destination)
            _require_private_directory_metadata(promoted, destination)
            if (
                _metadata_identity(synchronized)[:-1]
                != _metadata_identity(synchronized_after_rename)[:-1]
                or _metadata_identity(synchronized_after_rename)
                != _metadata_identity(promoted)
            ):
                raise PublicationError(
                    f"destination identity changed after directory promotion: {destination}"
                )
            if set(os.listdir(pending_descriptor)) != set(opened_files):
                raise PublicationError(
                    f"destination entries changed after directory promotion: {destination}"
                )
            for entry_name, (file_descriptor, file_metadata) in opened_files.items():
                after_rename = os.fstat(file_descriptor)
                rebound_after_rename = os.stat(
                    entry_name,
                    dir_fd=pending_descriptor,
                    follow_symlinks=False,
                )
                if (
                    _metadata_identity(file_metadata)
                    != _metadata_identity(after_rename)
                    or _metadata_identity(file_metadata)
                    != _metadata_identity(rebound_after_rename)
                ):
                    raise PublicationError(
                        "promoted private directory file changed after rename: "
                        f"{destination / entry_name}"
                    )
            fsync_locked_directory(parent_descriptor, parent)
            descriptor_after_barrier = os.fstat(pending_descriptor)
            after_barrier = os.stat(
                destination_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            _require_private_directory_metadata(descriptor_after_barrier, destination)
            _require_private_directory_metadata(after_barrier, destination)
            if (
                _metadata_identity(synchronized_after_rename)
                != _metadata_identity(descriptor_after_barrier)
                or _metadata_identity(synchronized_after_rename)
                != _metadata_identity(after_barrier)
            ):
                raise PublicationError(
                    f"destination identity changed after directory fsync: {destination}"
                )
            if set(os.listdir(pending_descriptor)) != set(opened_files):
                raise PublicationError(
                    f"destination entries changed after parent fsync: {destination}"
                )
            for entry_name, (file_descriptor, file_metadata) in opened_files.items():
                after_parent_barrier = os.fstat(file_descriptor)
                rebound_after_parent_barrier = os.stat(
                    entry_name,
                    dir_fd=pending_descriptor,
                    follow_symlinks=False,
                )
                if (
                    _metadata_identity(file_metadata)
                    != _metadata_identity(after_parent_barrier)
                    or _metadata_identity(file_metadata)
                    != _metadata_identity(rebound_after_parent_barrier)
                ):
                    raise PublicationError(
                        "promoted private directory file changed after parent fsync: "
                        f"{destination / entry_name}"
                    )
        except (OSError, PublicationError) as error:
            raise DurabilityOutcomeUnknown(
                "private directory promotion outcome is unknown after rename: "
                f"{destination}"
            ) from error
    finally:
        for file_descriptor, _metadata in opened_files.values():
            os.close(file_descriptor)
        if pending_descriptor >= 0:
            os.close(pending_descriptor)


def promote_private_directory(pending: Path, destination: Path) -> None:
    """Atomically promote one private 0700 directory without replacement."""

    pending = Path(pending).absolute()
    destination = Path(destination).absolute()
    if pending.parent != destination.parent:
        raise PublicationError(
            "private pending directory and destination must share one parent directory"
        )
    if pending == destination:
        raise PublicationError(
            "private pending directory and destination must be different paths"
        )
    pending_name = _require_simple_name(pending, "private pending directory")
    destination_name = _require_simple_name(destination, "private destination directory")
    parent_descriptor = _open_owned_directory(pending.parent)
    try:
        _promote_private_directory_at(
            parent_descriptor,
            pending.parent,
            pending_name,
            destination_name,
        )
    finally:
        os.close(parent_descriptor)


def _remove_private_directory_at(
    parent_descriptor: int,
    directory_name: str,
    directory: Path,
    expected_identity: tuple[int, int],
) -> None:
    descriptor, metadata = _inspect_private_directory_at(
        parent_descriptor,
        directory_name,
        directory,
    )
    try:
        if (metadata.st_dev, metadata.st_ino) != expected_identity:
            raise PublicationError(
                f"refusing to clean a changed private publication directory: {directory}"
            )
        for entry_name in os.listdir(descriptor):
            entry_path = directory / entry_name
            entry = os.stat(
                entry_name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            _require_private_metadata(entry, entry_path, maximum=None)
            os.unlink(entry_name, dir_fd=descriptor)
        _full_fsync_directory_descriptor(descriptor, directory)
    except OSError as error:
        raise PublicationError(
            f"cannot clean private publication directory {directory}: {error}"
        ) from error
    finally:
        os.close(descriptor)
    try:
        rebound = os.stat(
            directory_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (rebound.st_dev, rebound.st_ino) != expected_identity:
            raise PublicationError(
                f"refusing to remove a changed private publication directory: {directory}"
            )
        os.rmdir(directory_name, dir_fd=parent_descriptor)
        _full_fsync_directory_descriptor(parent_descriptor, directory.parent)
    except OSError as error:
        raise PublicationError(
            f"cannot remove private publication directory {directory}: {error}"
        ) from error


def publish_private_directory_locked(
    parent_descriptor: int,
    parent: Path,
    destination_name: str,
    files: dict[str, bytes],
) -> None:
    """Publish exact private files through one caller-held parent descriptor."""

    if type(parent_descriptor) is not int or parent_descriptor < 0:
        raise PublicationError("locked publication directory descriptor is invalid")
    parent = Path(parent).absolute()
    _require_owned_directory(os.fstat(parent_descriptor), parent)
    if (
        type(destination_name) is not str
        or _require_simple_name(Path(destination_name), "private destination directory")
        != destination_name
    ):
        raise PublicationError("private destination directory name is unsafe")
    if not isinstance(files, dict) or any(
        type(name) is not str or not isinstance(data, bytes)
        for name, data in files.items()
    ):
        raise PublicationError("private publication directory expectations are malformed")
    maximum_files = {name: len(data) for name, data in files.items()}
    _require_private_directory_expectations(maximum_files)

    try:
        os.stat(
            destination_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        pass
    except OSError as error:
        raise PublicationError(
            f"cannot inspect private destination directory {parent / destination_name}"
        ) from error
    else:
        raise PublicationError(
            f"private destination directory already exists: {parent / destination_name}"
        )

    staging_name = ""
    staging_identity: tuple[int, int] | None = None
    for _attempt in range(128):
        candidate = f".publication-pending-{uuid.uuid4().hex}"
        try:
            os.mkdir(candidate, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        except OSError as error:
            raise PublicationError(
                f"cannot create private publication staging directory in {parent}: {error}"
            ) from error
        staging_name = candidate
        created = os.stat(
            staging_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _require_private_directory_metadata(created, parent / staging_name)
        staging_identity = (created.st_dev, created.st_ino)
        break
    if staging_identity is None:
        raise PublicationError(
            f"cannot allocate a private publication staging directory in {parent}"
        )

    staging_path = parent / staging_name
    staging_descriptor = -1
    renamed = False
    try:
        staging_descriptor, opened = _inspect_private_directory_at(
            parent_descriptor,
            staging_name,
            staging_path,
        )
        if (opened.st_dev, opened.st_ino) != staging_identity:
            raise PublicationError(
                f"private publication staging identity changed: {staging_path}"
            )
        for entry_name in sorted(files):
            _write_private_pending_at(
                staging_descriptor,
                entry_name,
                staging_path / entry_name,
                files[entry_name],
            )
        os.close(staging_descriptor)
        staging_descriptor = -1

        observed = _read_private_directory_contents_at(
            parent_descriptor,
            staging_name,
            staging_path,
            maximum_files,
            parent,
        )
        if observed != files:
            raise PublicationError(
                f"private publication staging bytes changed: {staging_path}"
            )
        _promote_private_directory_at(
            parent_descriptor,
            parent,
            staging_name,
            destination_name,
        )
        renamed = True
        published = _read_private_directory_contents_at(
            parent_descriptor,
            destination_name,
            parent / destination_name,
            maximum_files,
            parent,
        )
        if published != files:
            raise PublicationError(
                f"private publication destination bytes changed: {parent / destination_name}"
            )
    except DurabilityOutcomeUnknown:
        raise
    except BaseException as error:
        if not renamed:
            try:
                _remove_private_directory_at(
                    parent_descriptor,
                    staging_name,
                    staging_path,
                    staging_identity,
                )
            except PublicationError as cleanup_error:
                raise cleanup_error from error
        raise
    finally:
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
