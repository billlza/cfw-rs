#!/usr/bin/env python3
"""Derive the exact repository identity used by a release build."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

if __package__:
    from .release_git import ReleaseGitError, run_release_git
else:
    from release_git import ReleaseGitError, run_release_git


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_HISTORICAL_BATCH_BYTES = 4 * 1024 * 1024

# These paths are the complete reviewed product, test, packaging, and release
# closure. Git supplies tracked files plus non-ignored new files, so generated
# output, dependency caches, local credentials, and workspace scratch data are
# never read into the source identity.
RELEASE_PATHS = (
    ".github",
    ".gitignore",
    ".tauri/cfw-rs.key.pub",
    "CHANGELOG.md",
    "Cargo.lock",
    "Cargo.toml",
    "LICENSE",
    "README.md",
    "RELEASE.md",
    "apps",
    "contracts",
    "crates",
    "deny.toml",
    "docs",
    "fixtures",
    "native",
    "rust-toolchain.toml",
    "scripts",
    "tools",
)


class SourceIdentityError(RuntimeError):
    """The repository cannot supply a trustworthy release-source identity."""


def _run_git(
    repository: Path,
    arguments: list[str],
    environment: Mapping[str, str] | None = None,
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    try:
        return run_release_git(
            repository,
            arguments,
            environment=environment,
            protected_roots=RELEASE_PATHS,
            input_bytes=input_bytes,
        )
    except ReleaseGitError as error:
        raise SourceIdentityError(
            f"cannot query the release repository identity: {error}"
        ) from error


def repository_commit(
    repository: Path, environment: Mapping[str, str] | None = None
) -> str:
    commit = _run_git(
        repository, ["rev-parse", "--verify", "HEAD^{commit}"], environment
    )
    try:
        decoded = commit.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise SourceIdentityError("repository HEAD is not an ASCII commit identity") from error
    if not COMMIT_RE.fullmatch(decoded):
        raise SourceIdentityError("repository HEAD is not a canonical 40-hex commit identity")
    return decoded


def _clean_repository_identity(
    repository: Path, environment: Mapping[str, str] | None = None
) -> dict[str, str]:
    index_records = _run_git(
        repository,
        ["ls-files", "-v", "-z", "--cached", "--", *RELEASE_PATHS],
        environment,
    )
    for record in (item for item in index_records.split(b"\0") if item):
        if len(record) < 3 or record[1:2] != b" " or record[:1] != b"H":
            raise SourceIdentityError(
                "release repository index contains non-default visibility flags"
            )
    commit = repository_commit(repository, environment)
    observed = {
        "repositoryCommit": commit,
        "releaseSourceSha256": release_source_digest(repository, environment),
    }
    historical = identity_at_commit(repository, commit, environment)
    if observed != historical:
        raise SourceIdentityError("release repository contains tracked or untracked changes")
    repeated = {
        "repositoryCommit": repository_commit(repository, environment),
        "releaseSourceSha256": release_source_digest(repository, environment),
    }
    if repeated != observed:
        raise SourceIdentityError("release repository changed while deriving its identity")
    return observed


def require_clean_repository(
    repository: Path, environment: Mapping[str, str] | None = None
) -> None:
    _clean_repository_identity(repository, environment)


def _source_paths(
    repository: Path, environment: Mapping[str, str] | None = None
) -> list[Path]:
    arguments = [
        "--",
        *RELEASE_PATHS,
    ]
    encoded = _run_git(
        repository,
        [
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            *arguments,
        ],
        environment,
    )
    deleted = set(
        name
        for name in _run_git(
            repository,
            ["ls-files", "-z", "--deleted", *arguments],
            environment,
        ).split(b"\0")
        if name
    )
    relative_names = [name for name in encoded.split(b"\0") if name]
    if not relative_names:
        raise SourceIdentityError("release source closure is empty")

    paths: list[Path] = []
    seen: set[str] = set()
    for raw_name in relative_names:
        if raw_name in deleted:
            continue
        relative = Path(os.fsdecode(raw_name))
        if relative.is_absolute() or ".." in relative.parts:
            raise SourceIdentityError("release source closure contains an unsafe path")
        canonical_name = relative.as_posix()
        if canonical_name in seen:
            raise SourceIdentityError(f"release source path is repeated: {canonical_name}")
        seen.add(canonical_name)
        path = repository / relative
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise SourceIdentityError(
                f"release source input is not a regular file: {canonical_name}"
            )
        if metadata.st_nlink != 1:
            raise SourceIdentityError(
                f"release source input has multiple hard links: {canonical_name}"
            )
        paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(repository).as_posix())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_source_digest(
    repository: Path, environment: Mapping[str, str] | None = None
) -> str:
    digest = hashlib.sha256()
    for path in _source_paths(repository, environment):
        metadata = path.stat()
        entry = {
            "executable": bool(metadata.st_mode & stat.S_IXUSR),
            "path": path.relative_to(repository).as_posix(),
            "sha256": _sha256(path),
            "size": metadata.st_size,
        }
        encoded = json.dumps(entry, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        digest.update(encoded.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _historical_release_paths(
    repository: Path,
    commit: str,
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Read the target commit's literal source-closure policy without executing it."""
    try:
        source = _run_git(
            repository,
            ["cat-file", "blob", f"{commit}:scripts/repository_source_identity.py"],
            environment,
        ).decode("utf-8", errors="strict")
    except (SourceIdentityError, UnicodeDecodeError) as error:
        raise SourceIdentityError(
            "historical release identity policy blob is unavailable or invalid"
        ) from error
    try:
        module = ast.parse(source, filename="scripts/repository_source_identity.py")
    except SyntaxError as error:
        raise SourceIdentityError(
            "historical release identity policy is not valid Python"
        ) from error

    assignments: list[ast.expr] = []
    for statement in module.body:
        if isinstance(statement, ast.Assign):
            if any(
                isinstance(target, ast.Name) and target.id == "RELEASE_PATHS"
                for target in statement.targets
            ):
                if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
                    raise SourceIdentityError(
                        "historical RELEASE_PATHS must have one direct assignment"
                    )
                assignments.append(statement.value)
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "RELEASE_PATHS"
        ):
            if statement.value is None:
                raise SourceIdentityError("historical RELEASE_PATHS has no value")
            assignments.append(statement.value)
    if len(assignments) != 1:
        raise SourceIdentityError(
            "historical release identity policy must define RELEASE_PATHS exactly once"
        )
    value = assignments[0]
    if not isinstance(value, (ast.Tuple, ast.List)):
        raise SourceIdentityError("historical RELEASE_PATHS is not a literal sequence")

    paths: list[str] = []
    for element in value.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            raise SourceIdentityError("historical RELEASE_PATHS contains a non-literal path")
        relative = Path(element.value)
        if (
            not element.value
            or element.value == "."
            or "\\" in element.value
            or "\0" in element.value
            or relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != element.value
        ):
            raise SourceIdentityError("historical RELEASE_PATHS contains an unsafe path")
        paths.append(element.value)
    if not paths:
        raise SourceIdentityError("historical RELEASE_PATHS is empty")
    if len(paths) != len(set(paths)):
        raise SourceIdentityError("historical RELEASE_PATHS contains duplicate paths")
    return tuple(paths)


@dataclass(frozen=True, slots=True)
class _HistoricalSourceFile:
    path: str
    executable: bool
    object_id: bytes
    size: int


def _read_historical_blob_batch(
    repository: Path,
    objects: list[tuple[bytes, int]],
    environment: Mapping[str, str] | None,
) -> dict[bytes, str]:
    payload = _run_git(
        repository, ["cat-file", "--batch"], environment,
        input_bytes=b"".join(object_id + b"\n" for object_id, _size in objects),
    )
    cursor = 0
    digests: dict[bytes, str] = {}
    for object_id, size in objects:
        header = object_id + b" blob " + str(size).encode("ascii") + b"\n"
        if not payload.startswith(header, cursor):
            raise SourceIdentityError("historical Git batch header differs from its requested blob")
        start = cursor + len(header)
        end = start + size
        if end >= len(payload) or payload[end:end + 1] != b"\n":
            raise SourceIdentityError("historical Git batch contains a truncated blob")
        digests[object_id] = hashlib.sha256(payload[start:end]).hexdigest()
        cursor = end + 1
    if cursor != len(payload):
        raise SourceIdentityError("historical Git batch contains unrequested trailing bytes")
    return digests


def _historical_blob_digests(
    repository: Path,
    files: list[_HistoricalSourceFile],
    environment: Mapping[str, str] | None,
) -> dict[bytes, str]:
    sizes: dict[bytes, int] = {}
    for entry in files:
        if entry.object_id in sizes and sizes[entry.object_id] != entry.size:
            raise SourceIdentityError("historical Git object has inconsistent sizes")
        sizes[entry.object_id] = entry.size
    digests: dict[bytes, str] = {}
    batch: list[tuple[bytes, int]] = []
    batch_bytes = 0
    for object_id, size in sizes.items():
        response_bytes = len(object_id) + len(str(size)) + 8 + size
        if batch and batch_bytes + response_bytes > MAX_HISTORICAL_BATCH_BYTES:
            digests.update(_read_historical_blob_batch(repository, batch, environment))
            batch = []
            batch_bytes = 0
        if response_bytes > MAX_HISTORICAL_BATCH_BYTES:
            # A large individual object keeps the existing scalar bound; small
            # objects share a bounded batch without changing their byte digest.
            blob = _run_git(
                repository, ["cat-file", "blob", object_id.decode("ascii")], environment
            )
            if len(blob) != size:
                raise SourceIdentityError("historical Git blob size differs from its tree")
            digests[object_id] = hashlib.sha256(blob).hexdigest()
        else:
            batch.append((object_id, size))
            batch_bytes += response_bytes
    if batch:
        digests.update(_read_historical_blob_batch(repository, batch, environment))
    return digests


def identity_at_commit(
    repository: Path,
    commit: str,
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Recompute a clean historical release identity from immutable Git blobs.

    Notarization recovery may be performed by a later clean checkout.  Its
    receipt binds that recovery-tool commit and release-source digest, but the
    original checkout path is intentionally not persisted.  This reader proves
    the exact historical bytes from the current repository's object database
    without checking out, executing, or trusting a caller-supplied worktree.
    """
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise SourceIdentityError("historical release commit is not canonical")
    resolved = _run_git(
        repository,
        ["rev-parse", "--verify", f"{commit}^{{commit}}"],
        environment,
    )
    if resolved.decode("ascii", errors="strict").strip() != commit:
        raise SourceIdentityError("historical release commit is unavailable")
    release_paths = _historical_release_paths(repository, commit, environment)
    listing = _run_git(
        repository,
        ["ls-tree", "-rlz", "--full-tree", commit, "--", *release_paths],
        environment,
    )
    files: list[_HistoricalSourceFile] = []
    seen: set[str] = set()
    for raw in (record for record in listing.split(b"\0") if record):
        try:
            metadata, raw_name = raw.split(b"\t", 1)
            mode, kind, object_id, size_text = metadata.split()
        except ValueError as error:
            raise SourceIdentityError("historical release tree is malformed") from error
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise SourceIdentityError("historical release tree contains a non-regular input")
        if (
            re.fullmatch(rb"[0-9a-f]{40}", object_id) is None
            or len(size_text) > 20
            or re.fullmatch(rb"0|[1-9][0-9]*", size_text) is None
        ):
            raise SourceIdentityError("historical release tree has an invalid object identity or size")
        relative = Path(os.fsdecode(raw_name))
        if relative.is_absolute() or ".." in relative.parts:
            raise SourceIdentityError("historical release tree contains an unsafe path")
        canonical_name = relative.as_posix()
        if canonical_name in seen:
            raise SourceIdentityError(
                f"historical release source path is repeated: {canonical_name}"
            )
        seen.add(canonical_name)
        files.append(
            _HistoricalSourceFile(canonical_name, mode == b"100755", object_id, int(size_text))
        )
    if not files:
        raise SourceIdentityError("historical release source closure is empty")
    blob_digests = _historical_blob_digests(repository, files, environment)
    digest = hashlib.sha256()
    for entry in sorted(files, key=lambda value: value.path):
        digest.update(
            json.dumps(
                {
                    "executable": entry.executable,
                    "path": entry.path,
                    "sha256": blob_digests[entry.object_id],
                    "size": entry.size,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        digest.update(b"\n")
    return {"repositoryCommit": commit, "releaseSourceSha256": digest.hexdigest()}


def current_identity(
    repository: Path,
    *,
    require_clean: bool = False,
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    if require_clean:
        return _clean_repository_identity(repository, environment)
    return {
        "repositoryCommit": repository_commit(repository, environment),
        "releaseSourceSha256": release_source_digest(repository, environment),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        identity = current_identity(repository, require_clean=arguments.require_clean)
    except (OSError, SourceIdentityError) as error:
        raise SystemExit(f"error: cannot derive release source identity: {error}") from error
    if arguments.json:
        print(json.dumps(identity, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print(f"{identity['repositoryCommit']} {identity['releaseSourceSha256']}")


if __name__ == "__main__":
    main()
