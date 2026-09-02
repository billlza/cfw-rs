"""Bind a first notarization executor to an unchanged, frozen application.

The existing Git/source digests identify the two checkouts and detect
accidental source selection or drift. They do not authenticate against the
release account. This module never signs, submits, installs or launches code.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
from typing import Callable, Final

if __package__:
    from .publication.common import PublicationError, canonical_json
    from .publication.durable_file import (
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from .release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
    from .repository_source_identity import (
        SourceIdentityError,
        current_identity,
        identity_at_commit,
    )
else:
    from publication.common import PublicationError, canonical_json
    from publication.durable_file import (
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
    from repository_source_identity import (
        SourceIdentityError,
        current_identity,
        identity_at_commit,
    )


DOCUMENT: Final = "cfm-notarization-executor-v1"
BINDING_NAME: Final = "notarization-executor.json"
MAX_BINDING_BYTES: Final = 4096
COMMIT_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
SourceReader = Callable[[Path], dict[str, str]]
HistoricalSourceReader = Callable[[Path, str], dict[str, str]]


class NotarizationExecutorError(PublicationError):
    """The executor source or its immutable candidate binding is unavailable."""


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


def read_clean_source(repository: Path) -> dict[str, str]:
    return current_identity(repository, require_clean=True)


def _require_identity(identity: dict[str, str], label: str) -> None:
    if (
        type(identity) is not dict
        or set(identity) != {"repositoryCommit", "releaseSourceSha256"}
        or type(identity["repositoryCommit"]) is not str
        or COMMIT_RE.fullmatch(identity["repositoryCommit"]) is None
        or type(identity["releaseSourceSha256"]) is not str
        or SHA256_RE.fullmatch(identity["releaseSourceSha256"]) is None
    ):
        raise NotarizationExecutorError(f"{label} source identity is malformed")


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
            raise NotarizationExecutorError(
                "notarization executor must be one canonical owned source directory"
            )
        identity = source_reader(repository)
    except (OSError, SourceIdentityError, ValueError) as error:
        raise NotarizationExecutorError(
            "clean notarization executor source is unavailable"
        ) from error
    _require_identity(identity, "notarization executor")
    return ExecutorSource(
        repository, identity["repositoryCommit"], identity["releaseSourceSha256"]
    )


def require_executor_unchanged(
    executor: ExecutorSource,
    *,
    source_reader: SourceReader = read_clean_source,
) -> None:
    if capture_executor_source(executor.repository, source_reader=source_reader) != executor:
        raise NotarizationExecutorError("notarization executor source changed")


def bind_executor(
    artifact_repository: Path,
    executor: ExecutorSource,
    *,
    artifact_identity: dict[str, str],
    candidate_freeze_intent_sha256: str,
    signing_transformation_receipt_sha256: str,
    historical_reader: HistoricalSourceReader = identity_at_commit,
) -> Path:
    """Create or re-open the same deterministic binding; never replace one.

    This is a source binding, not a submission or success receipt. Transaction
    admission verifies the frozen candidate and signing transformation before
    this write, while holding the existing notary transaction lock.
    """

    _require_identity(artifact_identity, "artifact")
    _require_identity(executor.identity, "notarization executor")
    for digest in (
        candidate_freeze_intent_sha256,
        signing_transformation_receipt_sha256,
    ):
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise NotarizationExecutorError("frozen candidate binding is malformed")
    try:
        historical = historical_reader(artifact_repository, executor.repository_commit)
    except (OSError, SourceIdentityError, ValueError) as error:
        raise NotarizationExecutorError(
            "executor source is absent from the artifact repository's Git objects"
        ) from error
    _require_identity(historical, "historical executor")
    if historical != executor.identity:
        raise NotarizationExecutorError("executor Git objects differ from its clean source")
    data = canonical_json(
        {
            "schema_version": 1,
            "document": DOCUMENT,
            "product": {
                "version": ACTIVE_RELEASE_IDENTITY.product_version,
                "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            },
            "artifact_source": artifact_identity,
            "executor_source": executor.identity,
            "candidate_freeze_intent_sha256": candidate_freeze_intent_sha256,
            "signing_transformation_receipt_sha256": signing_transformation_receipt_sha256,
        }
    )
    candidate = ga_root(artifact_repository)
    stage_inputs = candidate / "stage-inputs"
    try:
        with exclusive_rooted_directory_lock(
            artifact_repository, candidate, require_private=True
        ) as descriptor:
            ensure_private_directory_locked(descriptor, candidate, stage_inputs.name)
        with exclusive_rooted_directory_lock(
            artifact_repository, stage_inputs, require_private=True
        ) as descriptor:
            try:
                os.stat(BINDING_NAME, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                write_private_pending_locked(descriptor, stage_inputs, BINDING_NAME, data)
            observed = read_private_pending_locked(
                descriptor, stage_inputs, BINDING_NAME, MAX_BINDING_BYTES
            )
            if observed != data:
                raise NotarizationExecutorError(
                    "existing notarization executor binding differs; it cannot be replaced"
                )
    except NotarizationExecutorError:
        raise
    except (OSError, PublicationError) as error:
        raise NotarizationExecutorError(
            "cannot durably bind the notarization executor to the frozen candidate"
        ) from error
    return stage_inputs / BINDING_NAME
