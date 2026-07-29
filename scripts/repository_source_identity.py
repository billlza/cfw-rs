#!/usr/bin/env python3
"""Derive the exact repository identity used by a release build."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

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
)


class SourceIdentityError(RuntimeError):
    """The repository cannot supply a trustworthy release-source identity."""


def _run_git(repository: Path, arguments: list[str]) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise SourceIdentityError("cannot query the release repository identity")
    return result.stdout


def repository_commit(repository: Path) -> str:
    commit = _run_git(repository, ["rev-parse", "--verify", "HEAD^{commit}"])
    try:
        decoded = commit.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise SourceIdentityError("repository HEAD is not an ASCII commit identity") from error
    if not COMMIT_RE.fullmatch(decoded):
        raise SourceIdentityError("repository HEAD is not a canonical 40-hex commit identity")
    return decoded


def require_clean_repository(repository: Path) -> None:
    status = _run_git(
        repository,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    if status:
        raise SourceIdentityError("release repository contains tracked or untracked changes")


def _source_paths(repository: Path) -> list[Path]:
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
    )
    deleted = set(
        name
        for name in _run_git(repository, ["ls-files", "-z", "--deleted", *arguments]).split(
            b"\0"
        )
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


def release_source_digest(repository: Path) -> str:
    digest = hashlib.sha256()
    for path in _source_paths(repository):
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


def _historical_release_paths(repository: Path, commit: str) -> tuple[str, ...]:
    """Read the target commit's literal source-closure policy without executing it."""
    try:
        source = _run_git(
            repository,
            ["cat-file", "blob", f"{commit}:scripts/repository_source_identity.py"],
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


def identity_at_commit(repository: Path, commit: str) -> dict[str, str]:
    """Recompute a clean historical release identity from immutable Git blobs.

    Notarization recovery may be performed by a later clean checkout.  Its
    receipt binds that recovery-tool commit and release-source digest, but the
    original checkout path is intentionally not persisted.  This reader proves
    the exact historical bytes from the current repository's object database
    without checking out, executing, or trusting a caller-supplied worktree.
    """
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise SourceIdentityError("historical release commit is not canonical")
    resolved = _run_git(repository, ["rev-parse", "--verify", f"{commit}^{{commit}}"])
    if resolved.decode("ascii", errors="strict").strip() != commit:
        raise SourceIdentityError("historical release commit is unavailable")
    release_paths = _historical_release_paths(repository, commit)
    listing = _run_git(
        repository,
        ["ls-tree", "-rz", "--full-tree", commit, "--", *release_paths],
    )
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in (record for record in listing.split(b"\0") if record):
        try:
            metadata, raw_name = raw.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
        except ValueError as error:
            raise SourceIdentityError("historical release tree is malformed") from error
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise SourceIdentityError("historical release tree contains a non-regular input")
        relative = Path(os.fsdecode(raw_name))
        if relative.is_absolute() or ".." in relative.parts:
            raise SourceIdentityError("historical release tree contains an unsafe path")
        canonical_name = relative.as_posix()
        if canonical_name in seen:
            raise SourceIdentityError(
                f"historical release source path is repeated: {canonical_name}"
            )
        seen.add(canonical_name)
        blob = _run_git(repository, ["cat-file", "blob", object_id.decode("ascii")])
        records.append(
            {
                "executable": mode == b"100755",
                "path": canonical_name,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
            }
        )
    if not records:
        raise SourceIdentityError("historical release source closure is empty")
    digest = hashlib.sha256()
    for entry in sorted(records, key=lambda value: str(value["path"])):
        digest.update(
            json.dumps(
                entry,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        digest.update(b"\n")
    return {"repositoryCommit": commit, "releaseSourceSha256": digest.hexdigest()}


def current_identity(repository: Path, *, require_clean: bool = False) -> dict[str, str]:
    if require_clean:
        require_clean_repository(repository)
    return {
        "repositoryCommit": repository_commit(repository),
        "releaseSourceSha256": release_source_digest(repository),
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
