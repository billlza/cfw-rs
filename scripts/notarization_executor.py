"""Bind a first notarization executor to an unchanged, frozen application.

The existing Git/source digests identify the two checkouts and detect
accidental source selection or drift. They do not authenticate against the
release account. This module never signs, submits, installs or launches code.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

if __package__:
    from .publication.common import PublicationError, canonical_json
    from .publication.durable_file import (
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from .release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
    from .release_executor_source import (
        ExecutorSource,
        ExecutorSourceError,
        HistoricalSourceReader,
        SHA256_RE,
        require_historical_executor,
        validate_source_identity,
    )
    from .repository_source_identity import identity_at_commit
else:
    from publication.common import PublicationError, canonical_json
    from publication.durable_file import (
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
    from release_executor_source import (
        ExecutorSource,
        ExecutorSourceError,
        HistoricalSourceReader,
        SHA256_RE,
        require_historical_executor,
        validate_source_identity,
    )
    from repository_source_identity import identity_at_commit


DOCUMENT: Final = "cfm-notarization-executor-v1"
BINDING_NAME: Final = "notarization-executor.json"
MAX_BINDING_BYTES: Final = 4096


class NotarizationExecutorError(PublicationError):
    """The executor source or its immutable candidate binding is unavailable."""


def _require_identity(identity: dict[str, str], label: str) -> None:
    try:
        validate_source_identity(identity, label)
    except ExecutorSourceError as error:
        raise NotarizationExecutorError(str(error)) from error


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
        require_historical_executor(
            artifact_repository, executor, historical_reader=historical_reader
        )
    except ExecutorSourceError as error:
        raise NotarizationExecutorError(str(error)) from error
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
