"""Identify clean evidence executors independently of frozen product sources.

Existing Git/source digests detect accidental source selection or drift. They
do not authenticate against the release account or change product provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
from typing import Callable, Final

if __package__:
    from .publication.common import PublicationError
    from .release_build_identity import frozen_ga_repository
    from .repository_source_identity import (
        SourceIdentityError,
        current_identity,
        identity_at_commit,
    )
else:
    from publication.common import PublicationError
    from release_build_identity import frozen_ga_repository
    from repository_source_identity import (
        SourceIdentityError,
        current_identity,
        identity_at_commit,
    )


COMMIT_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
SourceReader = Callable[[Path], dict[str, str]]
HistoricalSourceReader = Callable[[Path, str], dict[str, str]]


class ExecutorSourceError(PublicationError):
    """A clean executor source or its historical identity cannot be proven."""


@dataclass(frozen=True, slots=True)
class ExecutorSource:
    repository: Path
    repository_commit: str
    release_source_sha256: str

    @property
    def identity(self) -> dict[str, str]:
        return {
            "repositoryCommit": self.repository_commit,
            "releaseSourceSha256": self.release_source_sha256,
        }


@dataclass(frozen=True, slots=True)
class FrozenReleaseSources:
    """Distinct tool and artifact source identities for post-freeze operations."""

    executor: ExecutorSource
    artifact: ExecutorSource


def read_clean_source(repository: Path) -> dict[str, str]:
    return current_identity(repository, require_clean=True)


def validate_source_identity(identity: dict[str, str], label: str) -> None:
    if (
        type(identity) is not dict
        or set(identity) != {"repositoryCommit", "releaseSourceSha256"}
        or type(identity["repositoryCommit"]) is not str
        or COMMIT_RE.fullmatch(identity["repositoryCommit"]) is None
        or type(identity["releaseSourceSha256"]) is not str
        or SHA256_RE.fullmatch(identity["releaseSourceSha256"]) is None
    ):
        raise ExecutorSourceError(f"{label} source identity is malformed")


def capture_executor_source(
    repository: Path,
    *,
    source_reader: SourceReader = read_clean_source,
) -> ExecutorSource:
    try:
        metadata = repository.lstat()
        if (
            not repository.is_absolute()
            or repository.resolve(strict=True) != repository
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ExecutorSourceError(
                "release executor must be one canonical owned source directory"
            )
        identity = source_reader(repository)
    except (OSError, SourceIdentityError, ValueError) as error:
        raise ExecutorSourceError("clean release executor source is unavailable") from error
    validate_source_identity(identity, "release executor")
    return ExecutorSource(
        repository, identity["repositoryCommit"], identity["releaseSourceSha256"]
    )


def require_executor_unchanged(
    executor: ExecutorSource,
    *,
    source_reader: SourceReader = read_clean_source,
) -> None:
    if capture_executor_source(executor.repository, source_reader=source_reader) != executor:
        raise ExecutorSourceError("release executor source changed")


def require_historical_executor(
    artifact_repository: Path,
    executor: ExecutorSource,
    *,
    historical_reader: HistoricalSourceReader = identity_at_commit,
) -> None:
    validate_source_identity(executor.identity, "release executor")
    try:
        historical = historical_reader(artifact_repository, executor.repository_commit)
    except (OSError, SourceIdentityError, ValueError) as error:
        raise ExecutorSourceError(
            "executor source is absent from the artifact repository's Git objects"
        ) from error
    validate_source_identity(historical, "historical executor")
    if historical != executor.identity:
        raise ExecutorSourceError("executor Git objects differ from its clean source")


def capture_frozen_release_sources(
    executor_repository: Path,
    *,
    source_reader: SourceReader = read_clean_source,
    historical_reader: HistoricalSourceReader = identity_at_commit,
) -> FrozenReleaseSources:
    """Admit clean fixed checkouts without changing the frozen product identity.

    This reuses the existing Level 1 Git/source identities to detect accidental
    source selection or drift. It is not an authentication mechanism. Callers
    must still validate the candidate freeze and every stage's product inputs.
    """

    executor = capture_executor_source(executor_repository, source_reader=source_reader)
    try:
        artifact = capture_executor_source(
            frozen_ga_repository(executor_repository), source_reader=source_reader
        )
    except ExecutorSourceError as error:
        raise ExecutorSourceError("fixed frozen artifact source is unavailable") from error
    require_historical_executor(
        artifact.repository, executor, historical_reader=historical_reader
    )
    sources = FrozenReleaseSources(executor=executor, artifact=artifact)
    require_frozen_sources_unchanged(sources, source_reader=source_reader)
    return sources


def require_frozen_sources_unchanged(
    sources: FrozenReleaseSources,
    *,
    source_reader: SourceReader = read_clean_source,
) -> None:
    for label, source in (("executor", sources.executor), ("artifact", sources.artifact)):
        try:
            require_executor_unchanged(source, source_reader=source_reader)
        except ExecutorSourceError as error:
            raise ExecutorSourceError(f"{label} source changed or is no longer clean") from error


def main() -> None:
    import argparse
    import json

    if __package__:
        from .release_python_runtime import (
            ReleasePythonRuntimeError,
            require_closed_release_runtime,
        )
    else:
        from release_python_runtime import (
            ReleasePythonRuntimeError,
            require_closed_release_runtime,
        )

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument("--print-frozen-artifact-repository", action="store_true")
    commands.add_argument("--describe-frozen-sources", action="store_true")
    arguments = parser.parse_args()
    try:
        require_closed_release_runtime()
        sources = capture_frozen_release_sources(Path(__file__).resolve().parent.parent)
    except (ExecutorSourceError, ReleasePythonRuntimeError) as error:
        raise SystemExit(f"error: frozen release sources: {error}") from error
    if arguments.print_frozen_artifact_repository:
        print(sources.artifact.repository)
    else:
        print(
            json.dumps(
                {
                    "artifact_source": sources.artifact.identity,
                    "executor_source": sources.executor.identity,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )


if __name__ == "__main__":
    main()
