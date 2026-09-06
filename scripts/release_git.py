"""Fail-closed Git execution for release-source identity and publication.

Release evidence must not depend on a caller's PATH, Git directory overrides,
or user/system ignore configuration.  This module owns the one fixed Git
driver and the derived, bounded environment used by all release-source reads.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import os
from pathlib import Path
import re
import stat
import subprocess

if __package__:
    from .publication.bounded_process import BoundedProcessError, run_bounded_process
else:
    from publication.bounded_process import BoundedProcessError, run_bounded_process


GIT_EXECUTABLE = "/usr/bin/git"
GIT_TIMEOUT_SECONDS = 600
MAX_GIT_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_LOCAL_EXCLUDE_BYTES = 256 * 1024
_SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_UNSAFE_PATTERN_COMPONENT = re.compile(r"[?*\[\]\\]")


class ReleaseGitError(RuntimeError):
    """A fixed release Git query could not be completed safely."""


def _closed_environment(source: Mapping[str, str] | None) -> dict[str, str]:
    """Derive Git's environment without carrying ambient Git controls."""

    provided = {} if source is None else dict(source)
    environment = {
        "HOME": provided.get("HOME", "/var/empty"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": _SYSTEM_PATH,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    if not environment["HOME"].startswith("/"):
        raise ReleaseGitError("release Git HOME must be absolute")
    return environment


def _read_regular_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return b""
    except OSError as error:
        raise ReleaseGitError(f"cannot inspect {label}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > maximum
    ):
        raise ReleaseGitError(f"{label} is not a bounded single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseGitError(f"cannot open {label}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise ReleaseGitError(f"{label} changed while opening")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) > maximum:
        raise ReleaseGitError(f"{label} exceeds its size bound")
    if (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(data) != opened.st_size:
        raise ReleaseGitError(f"{label} changed while reading")
    return bytes(data)


def _command(repository: Path, arguments: Sequence[str]) -> list[str]:
    return [
        GIT_EXECUTABLE,
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.ignoreCase=false",
        "-c",
        "core.precomposeUnicode=true",
        "-c",
        "core.symlinks=true",
        "-c",
        "core.untrackedCache=false",
        "-C",
        str(repository),
        f"--work-tree={repository}",
        *arguments,
    ]


def _invoke(
    repository: Path,
    arguments: Sequence[str],
    environment: Mapping[str, str] | None,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = run_bounded_process(
            _command(repository, arguments),
            cwd=repository,
            environment=_closed_environment(environment),
            timeout=GIT_TIMEOUT_SECONDS,
            output_limit=MAX_GIT_OUTPUT_BYTES,
            input_bytes=input_bytes,
        )
    except (OSError, BoundedProcessError) as error:
        raise ReleaseGitError(f"cannot execute fixed release Git: {error}") from error
    if completed.returncode == 0 and completed.stderr:
        raise ReleaseGitError("successful release Git emitted diagnostics")
    return completed


def _single_absolute_path(payload: bytes, label: str) -> Path:
    try:
        decoded = payload.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise ReleaseGitError(f"{label} is not UTF-8") from error
    path = Path(decoded)
    if not decoded or "\n" in decoded or not path.is_absolute():
        raise ReleaseGitError(f"{label} is not one absolute path")
    return path


def _common_git_path(
    repository: Path,
    relative: str,
    label: str,
    environment: Mapping[str, str] | None,
) -> Path:
    common_result = _invoke(
        repository,
        ["rev-parse", "--path-format=absolute", "--git-common-dir"],
        environment,
    )
    path_result = _invoke(
        repository,
        ["rev-parse", "--path-format=absolute", "--git-path", relative],
        environment,
    )
    if common_result.returncode != 0 or path_result.returncode != 0:
        raise ReleaseGitError("cannot resolve the release repository control paths")
    try:
        common = _single_absolute_path(
            common_result.stdout, "release Git common directory"
        ).resolve(strict=True)
        path = _single_absolute_path(path_result.stdout, label)
    except OSError as error:
        raise ReleaseGitError("cannot resolve the release Git common directory") from error
    expected = common.joinpath(*Path(relative).parts)
    if path != expected:
        raise ReleaseGitError(f"{label} escaped the common directory")
    return path


def _validate_local_excludes(
    repository: Path,
    protected_roots: Sequence[str],
    environment: Mapping[str, str] | None,
) -> None:
    protected = {Path(root).parts[0].casefold() for root in protected_roots}
    if not protected or any(not root for root in protected):
        raise ReleaseGitError("release Git protected roots are empty or invalid")
    exclude = _common_git_path(
        repository,
        "info/exclude",
        "release Git local exclude path",
        environment,
    )
    payload = _read_regular_file(
        exclude,
        MAX_LOCAL_EXCLUDE_BYTES,
        "release Git local exclude file",
    )
    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseGitError("release Git local exclude file is not UTF-8") from error
    for line_number, raw in enumerate(lines, 1):
        pattern = raw.strip()
        if not pattern or pattern.startswith("#"):
            continue
        if pattern.startswith(("!", "\\")):
            raise ReleaseGitError(
                f"release Git local exclude line {line_number} is not safely scoped"
            )
        rooted = pattern.removeprefix("/").rstrip("/")
        components = rooted.split("/")
        first = components[0]
        if (
            len(components) < 2
            or not first
            or first in {".", ".."}
            or any(component in {"", ".", ".."} for component in components)
            or _UNSAFE_PATTERN_COMPONENT.search(first)
            or first.casefold() in protected
        ):
            raise ReleaseGitError(
                f"release Git local exclude line {line_number} can affect the protected source closure"
            )


def _validate_local_attributes(
    repository: Path,
    environment: Mapping[str, str] | None,
) -> None:
    attributes = _common_git_path(
        repository,
        "info/attributes",
        "release Git local attributes path",
        environment,
    )
    payload = _read_regular_file(
        attributes,
        MAX_LOCAL_EXCLUDE_BYTES,
        "release Git local attributes file",
    )
    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseGitError("release Git local attributes file is not UTF-8") from error
    for line_number, raw in enumerate(lines, 1):
        value = raw.strip()
        if value and not value.startswith("#"):
            raise ReleaseGitError(
                f"release Git local attributes line {line_number} can affect source interpretation"
            )


def _validate_local_filters(
    repository: Path,
    environment: Mapping[str, str] | None,
) -> None:
    result = _invoke(
        repository,
        ["config", "--includes", "--show-origin", "--get-regexp", r"^filter\."],
        environment,
    )
    if result.returncode == 0:
        raise ReleaseGitError("release Git refuses effective local filter configuration")
    if result.returncode != 1 or len(result.stdout) > MAX_LOCAL_EXCLUDE_BYTES:
        raise ReleaseGitError("cannot determine whether release Git has local filters")


def _validate_local_worktree_configuration(
    repository: Path,
    environment: Mapping[str, str] | None,
) -> None:
    result = _invoke(
        repository,
        ["config", "--includes", "--show-origin", "--get-all", "core.worktree"],
        environment,
    )
    if result.returncode == 0:
        raise ReleaseGitError(
            "release Git refuses an effective local core.worktree configuration"
        )
    if result.returncode != 1 or len(result.stdout) > MAX_LOCAL_EXCLUDE_BYTES:
        raise ReleaseGitError(
            "cannot determine whether release Git has a local core.worktree configuration"
        )


def run_release_git(
    repository: Path,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
    protected_roots: Sequence[str],
    input_bytes: bytes | None = None,
) -> bytes:
    """Run one read-only release Git query through the fixed system binary."""

    if not repository.is_absolute():
        raise ReleaseGitError("release Git repository path must be absolute")
    try:
        canonical_repository = repository.resolve(strict=True)
    except OSError as error:
        raise ReleaseGitError("release Git repository path cannot be resolved") from error
    if (
        canonical_repository != repository
        or not repository.is_dir()
        or repository.is_symlink()
    ):
        raise ReleaseGitError(
            "release Git repository path must be a canonical real directory"
        )
    _validate_local_worktree_configuration(repository, environment)
    _validate_local_filters(repository, environment)
    _validate_local_attributes(repository, environment)
    _validate_local_excludes(repository, protected_roots, environment)
    completed = _invoke(repository, arguments, environment, input_bytes)
    if completed.returncode != 0:
        detail = completed.stderr[-8192:].decode("utf-8", errors="replace").strip()
        raise ReleaseGitError(
            f"fixed release Git failed with exit {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    if len(completed.stdout) > MAX_GIT_OUTPUT_BYTES:
        raise ReleaseGitError("fixed release Git output exceeded its bound")
    return completed.stdout
