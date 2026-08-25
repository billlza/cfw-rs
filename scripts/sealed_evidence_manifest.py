#!/usr/bin/env python3
"""Seal and verify the immutable outer Evidence Manifest and publication gate.

This is the CLI front end for ``publication.sealed_manifest`` (Task 12.3). It
extends the existing offline release tooling and composes, as black boxes, the
P0 source/boundary gates, the deterministic unsigned-CI lanes, the wave-11
physical/signed-installed aggregate, the task-12.1 sealed source/license/
vulnerability/SBOM closure, the task-12.2 final-candidate notarization/installed
binding, and the path/name-only workspace secret-material blocker.

The seal is immutable: ``seal`` refuses to overwrite an existing manifest, and
``verify`` re-derives every derived field so a hand-edited manifest is rejected.
Publication is fail closed: ``publication-gate`` permits creating publication
artifacts only when every gate passes and every capability has reached
``Sealed_Release_Evidence``. There is no override flag and no fallback; an
unavailable input is reported ``not-run`` and keeps publication refused. The
workspace updater key is referenced by path and name only and is never opened.

Usage:
    sealed_evidence_manifest.py collect-source-gates --output p0-source-gates.json [--journal DIR]
    sealed_evidence_manifest.py ci-toolchain-binding
    sealed_evidence_manifest.py collect-ci-lanes --output local-ci-lanes.json
    sealed_evidence_manifest.py seal --request request.json --output manifest.json [--fixture]
    sealed_evidence_manifest.py verify --manifest manifest.json [--fixture] [--require-sealed]
    sealed_evidence_manifest.py publication-gate [--manifest manifest.json]
    sealed_evidence_manifest.py status [--evidence-dir DIR]
    sealed_evidence_manifest.py self-check
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

if __name__ == "__main__":
    requested_command = sys.argv[1] if len(sys.argv) > 1 else ""
    requires_closed_runtime = requested_command in {
        "collect-source-gates",
        "ci-toolchain-binding",
        "collect-ci-lanes",
        "publication-gate",
        "status",
    } or (
        requested_command in {"seal", "verify"} and "--fixture" not in sys.argv[2:]
    )
    if requires_closed_runtime:
        from release_python_runtime import (
            ReleasePythonRuntimeError,
            require_closed_release_runtime,
        )

        try:
            require_closed_release_runtime()
        except ReleasePythonRuntimeError as error:
            raise SystemExit(f"error: sealed evidence manifest: {error}") from error

if __package__:
    from .publication.ci_lanes import (
        DEFAULT_LIBBOX_OUTPUT,
        DEFAULT_LIBBOX_SOURCE_TEMPLATE,
        LANES,
        collect_ci_lanes,
        derive_toolchain_binding,
    )
    from .publication.bounded_process import (
        BoundedProcessError,
        run_bounded_process,
    )
    from .publication.common import (
        PublicationError,
        canonical_json,
        read_regular,
        require_exact_keys,
        require_sha256,
    )
    from .publication.graph_model import load_pins
    from .publication.durable_file import (
        discard_private_pending,
        exclusive_directory_lock,
        fsync_directory,
        fsync_locked_directory,
        promote_private_pending,
        read_private_pending,
        write_private_pending,
    )
    from .publication.release_environment import release_tool_environment
    from .publication.sealed_manifest import (
        DEFAULT_MANIFEST_PATH,
        GATE_ORDER,
        REQUIRED_SOURCE_GATES,
        SOURCE_GATE_DOCUMENT,
        SOURCE_GATE_COMPLETED,
        SOURCE_GATE_MAX_ATTEMPTS,
        SOURCE_GATE_MAX_DOCUMENT_BYTES,
        SOURCE_GATE_OUTCOME_UNKNOWN,
        SOURCE_GATE_SCHEMA_VERSION,
        authorize_publication_artifacts,
        build_sealed_evidence_manifest,
        environment_status,
        load_sealed_manifest,
        seal_manifest,
        self_check,
        validate_source_gate_document,
        validate_sealed_evidence_manifest,
    )
    from .repository_source_identity import SourceIdentityError, current_identity
else:
    from publication.ci_lanes import (
        DEFAULT_LIBBOX_OUTPUT,
        DEFAULT_LIBBOX_SOURCE_TEMPLATE,
        LANES,
        collect_ci_lanes,
        derive_toolchain_binding,
    )
    from publication.bounded_process import (
        BoundedProcessError,
        run_bounded_process,
    )
    from publication.common import (
        PublicationError,
        canonical_json,
        read_regular,
        require_exact_keys,
        require_sha256,
    )
    from publication.graph_model import load_pins
    from publication.durable_file import (
        discard_private_pending,
        exclusive_directory_lock,
        fsync_directory,
        fsync_locked_directory,
        promote_private_pending,
        read_private_pending,
        write_private_pending,
    )
    from publication.release_environment import release_tool_environment
    from publication.sealed_manifest import (
        DEFAULT_MANIFEST_PATH,
        GATE_ORDER,
        REQUIRED_SOURCE_GATES,
        SOURCE_GATE_DOCUMENT,
        SOURCE_GATE_COMPLETED,
        SOURCE_GATE_MAX_ATTEMPTS,
        SOURCE_GATE_MAX_DOCUMENT_BYTES,
        SOURCE_GATE_OUTCOME_UNKNOWN,
        SOURCE_GATE_SCHEMA_VERSION,
        authorize_publication_artifacts,
        build_sealed_evidence_manifest,
        environment_status,
        load_sealed_manifest,
        seal_manifest,
        self_check,
        validate_source_gate_document,
        validate_sealed_evidence_manifest,
    )
    from repository_source_identity import SourceIdentityError, current_identity

# The fixed per-gate wall-clock bound. A gate that exceeds it is recorded as
# ``timeout`` - a non-passing result - and is never masked into a pass.
GATE_TIMEOUT_SECONDS = 900
MAX_SOURCE_GATE_OUTPUT_BYTES = 8 * 1024 * 1024
SOURCE_GATE_ATTEMPT_NAME = re.compile(r"^attempt-([0-9]{4})\.json$")
SOURCE_GATE_PENDING_NAME = re.compile(r"^[.]attempt-([0-9]{4})\.json\.pending$")
SOURCE_GATE_INTENT_NAME = re.compile(r"^intent-([0-9]{4})\.json$")
SOURCE_GATE_INTENT_PENDING_NAME = re.compile(
    r"^[.]intent-([0-9]{4})\.json\.pending$"
)
SOURCE_GATE_INTENT_SCHEMA_VERSION = 1
SOURCE_GATE_INTENT_DOCUMENT = "p0-source-gate-attempt-intent-v1"
SOURCE_GATE_MAX_INTENT_BYTES = 16 * 1024


@dataclass(frozen=True)
class _SourceGateAttempt:
    number: int
    path: Path
    payload: bytes
    document: dict[str, Any]
    failures: tuple[str, ...]


@dataclass(frozen=True)
class _SourceGateIntent:
    number: int
    path: Path
    payload: bytes
    prior_attempt_sha256s: tuple[str, ...]


@dataclass(frozen=True)
class _SourceGateJournal:
    attempts: tuple[_SourceGateAttempt, ...]
    intents: tuple[_SourceGateIntent, ...]
    intent_pending: Path | None
    attempt_pending: Path | None


def _repository() -> Path:
    return Path(__file__).resolve().parent.parent


def _repository_output_path(repository: Path, requested: Path, label: str) -> Path:
    if "\x00" in os.fspath(requested) or any(part == ".." for part in requested.parts):
        raise PublicationError(f"{label} is not a canonical repository path")
    candidate = requested if requested.is_absolute() else repository / requested
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(repository)
    except ValueError as error:
        raise PublicationError(f"{label} escapes the release repository") from error
    if not relative.parts:
        raise PublicationError(f"{label} must name a path below the release repository")
    return candidate


def _require_real_directory_chain(
    repository: Path, directory: Path, label: str
) -> None:
    try:
        relative = directory.relative_to(repository)
    except ValueError as error:
        raise PublicationError(f"{label} escapes the release repository") from error
    current = repository
    for component in relative.parts:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise PublicationError(f"{label} is unavailable: {current}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PublicationError(f"{label} is not a real directory: {current}")


def _ensure_source_gate_journal(
    repository: Path, output: Path, journal: Path
) -> tuple[Path, Path]:
    """Resolve one private journal whose namespace cannot contain its output."""
    output = _repository_output_path(repository, output, "source gate output")
    journal = _repository_output_path(repository, journal, "source gate journal")
    _require_real_directory_chain(repository, output.parent, "source gate output parent")
    _require_real_directory_chain(repository, journal.parent, "source gate journal parent")
    if output == journal or output.is_relative_to(journal) or journal.is_relative_to(output):
        raise PublicationError(
            "source gate output and journal namespaces must be disjoint"
        )

    created = False
    try:
        journal.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    try:
        metadata = journal.lstat()
    except OSError as error:
        raise PublicationError("source gate journal cannot be inspected") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PublicationError(
            f"source gate journal is not an owner-private real directory: {journal}"
        )
    if created:
        fsync_directory(journal.parent)
    return output, journal


def _attempt_digests(attempts: list[_SourceGateAttempt]) -> tuple[str, ...]:
    return tuple(hashlib.sha256(attempt.payload).hexdigest() for attempt in attempts)


def _read_private_committed(path: Path, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PublicationError(f"cannot inspect private journal file {path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise PublicationError(
            f"private journal file is not an owner-private single-link regular file: {path}"
        )
    return read_regular(path, maximum)


def _source_gate_intent_from_payload(
    path: Path,
    number: int,
    source_identity: dict[str, str],
    expected_prior_attempt_sha256s: tuple[str, ...],
    payload: bytes,
) -> _SourceGateIntent:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(
            f"source gate intent {path.name} is not valid JSON"
        ) from error
    document = require_exact_keys(
        value,
        {
            "schema_version",
            "document",
            "attempt_number",
            "repository_commit",
            "release_source_sha256",
            "prior_attempt_sha256s",
        },
        "p0 source gate attempt intent",
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SOURCE_GATE_INTENT_SCHEMA_VERSION
        or document["document"] != SOURCE_GATE_INTENT_DOCUMENT
    ):
        raise PublicationError("p0 source gate attempt intent has an unsupported schema")
    if type(document["attempt_number"]) is not int or document["attempt_number"] != number:
        raise PublicationError(
            f"source gate intent {path.name} has a different attempt number"
        )
    if document["repository_commit"] != source_identity["repositoryCommit"]:
        raise PublicationError("source gate intent is bound to a different commit")
    release_source_sha256 = require_sha256(
        document["release_source_sha256"],
        "p0 source gate attempt intent release_source_sha256",
    )
    if release_source_sha256 != source_identity["releaseSourceSha256"]:
        raise PublicationError("source gate intent is bound to a different release source")
    raw_prior = document["prior_attempt_sha256s"]
    if not isinstance(raw_prior, list):
        raise PublicationError("source gate intent prior-attempt closure is malformed")
    prior = tuple(
        require_sha256(value, f"p0 source gate intent prior attempt {index} SHA-256")
        for index, value in enumerate(raw_prior, start=1)
    )
    if prior != expected_prior_attempt_sha256s:
        raise PublicationError("source gate intent prior-attempt closure differs from the journal")
    normalized = {
        "schema_version": SOURCE_GATE_INTENT_SCHEMA_VERSION,
        "document": SOURCE_GATE_INTENT_DOCUMENT,
        "attempt_number": number,
        "repository_commit": source_identity["repositoryCommit"],
        "release_source_sha256": release_source_sha256,
        "prior_attempt_sha256s": list(prior),
    }
    if payload != canonical_json(normalized):
        raise PublicationError(
            f"source gate intent {path.name} is not canonical or was changed"
        )
    return _SourceGateIntent(number, path, payload, prior)


def _source_gate_attempt_from_payload(
    repository: Path,
    path: Path,
    number: int,
    source_identity: dict[str, str],
    expected_prior_attempt_sha256s: tuple[str, ...],
    payload: bytes,
) -> _SourceGateAttempt:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(
            f"source gate attempt {path.name} is not valid JSON"
        ) from error
    normalized, failures = validate_source_gate_document(
        repository,
        value,
        source_identity["repositoryCommit"],
        source_identity["releaseSourceSha256"],
    )
    if normalized["attempt_number"] != number:
        raise PublicationError(
            f"source gate attempt {path.name} has a different attempt number"
        )
    if tuple(normalized["prior_attempt_sha256s"]) != expected_prior_attempt_sha256s:
        raise PublicationError(
            f"source gate attempt {path.name} prior-attempt closure differs from the journal"
        )
    normalized_payload = canonical_json(normalized)
    if payload != normalized_payload:
        raise PublicationError(
            f"source gate attempt {path.name} is not canonical or was changed"
        )
    return _SourceGateAttempt(
        number=number,
        path=path,
        payload=payload,
        document=normalized,
        failures=tuple(failures),
    )


def _read_source_gate_intent(
    path: Path,
    number: int,
    source_identity: dict[str, str],
    expected_prior_attempt_sha256s: tuple[str, ...],
) -> _SourceGateIntent:
    return _source_gate_intent_from_payload(
        path,
        number,
        source_identity,
        expected_prior_attempt_sha256s,
        _read_private_committed(path, SOURCE_GATE_MAX_INTENT_BYTES),
    )


def _read_source_gate_attempt(
    repository: Path,
    path: Path,
    number: int,
    source_identity: dict[str, str],
    expected_prior_attempt_sha256s: tuple[str, ...],
) -> _SourceGateAttempt:
    payload = _read_private_committed(path, SOURCE_GATE_MAX_DOCUMENT_BYTES)
    return _source_gate_attempt_from_payload(
        repository,
        path,
        number,
        source_identity,
        expected_prior_attempt_sha256s,
        payload,
    )


def _read_source_gate_journal(
    repository: Path,
    journal: Path,
    source_identity: dict[str, str],
) -> _SourceGateJournal:
    attempt_paths: dict[int, Path] = {}
    intent_paths: dict[int, Path] = {}
    attempt_pending: tuple[int, Path] | None = None
    intent_pending: tuple[int, Path] | None = None
    for entry in journal.iterdir():
        attempt_match = SOURCE_GATE_ATTEMPT_NAME.fullmatch(entry.name)
        intent_match = SOURCE_GATE_INTENT_NAME.fullmatch(entry.name)
        attempt_pending_match = SOURCE_GATE_PENDING_NAME.fullmatch(entry.name)
        intent_pending_match = SOURCE_GATE_INTENT_PENDING_NAME.fullmatch(entry.name)
        matches = tuple(
            match
            for match in (
                attempt_match,
                intent_match,
                attempt_pending_match,
                intent_pending_match,
            )
            if match is not None
        )
        if len(matches) != 1:
            raise PublicationError(
                f"source gate journal contains an unexpected entry: {entry.name}"
            )
        number = int(matches[0].group(1))
        if number == 0 or number > SOURCE_GATE_MAX_ATTEMPTS:
            raise PublicationError("source gate journal contains an out-of-range attempt number")
        if attempt_pending_match is not None:
            if attempt_pending is not None:
                raise PublicationError("source gate journal contains multiple pending attempts")
            attempt_pending = (number, entry)
        elif intent_pending_match is not None:
            if intent_pending is not None:
                raise PublicationError("source gate journal contains multiple pending intents")
            intent_pending = (number, entry)
        elif attempt_match is not None:
            if number in attempt_paths:
                raise PublicationError("source gate journal repeats an attempt number")
            attempt_paths[number] = entry
        else:
            if number in intent_paths:
                raise PublicationError("source gate journal repeats an intent number")
            intent_paths[number] = entry

    attempt_numbers = sorted(attempt_paths)
    if attempt_numbers != list(range(1, len(attempt_numbers) + 1)):
        raise PublicationError("source gate journal attempt numbering has a gap")
    intent_numbers = sorted(intent_paths)
    closed_intents = list(range(1, len(attempt_numbers) + 1))
    open_intents = list(range(1, len(attempt_numbers) + 2))
    if intent_numbers != closed_intents and intent_numbers != open_intents:
        raise PublicationError("source gate journal intent/attempt numbering is inconsistent")
    next_number = len(attempt_numbers) + 1
    if attempt_pending is not None:
        if attempt_pending[0] != next_number or next_number not in intent_paths:
            raise PublicationError("source gate pending attempt is not paired with the next intent")
    if intent_pending is not None:
        if intent_pending[0] != next_number or next_number in intent_paths:
            raise PublicationError("source gate pending intent number is not next")
    if attempt_pending is not None and intent_pending is not None:
        raise PublicationError("source gate journal contains overlapping pending states")

    attempts: list[_SourceGateAttempt] = []
    intents: list[_SourceGateIntent] = []
    passing_number: int | None = None
    for number in intent_numbers:
        prior = _attempt_digests(attempts)
        intent = _read_source_gate_intent(
            intent_paths[number], number, source_identity, prior
        )
        intents.append(intent)
        if number not in attempt_paths:
            continue
        attempt = _read_source_gate_attempt(
            repository,
            attempt_paths[number],
            number,
            source_identity,
            prior,
        )
        if not attempt.failures:
            if passing_number is not None:
                raise PublicationError("source gate journal repeats a passing attempt")
            passing_number = number
        elif passing_number is not None:
            raise PublicationError(
                "source gate journal contains an attempt after its passing attempt"
            )
        attempts.append(attempt)
    if len(attempts) != len(attempt_paths):
        raise PublicationError("source gate journal contains an attempt without its intent")
    if passing_number is not None and (
        len(intents) != len(attempts)
        or attempt_pending is not None
        or intent_pending is not None
    ):
        raise PublicationError("source gate journal contains state after its passing attempt")
    return _SourceGateJournal(
        tuple(attempts),
        tuple(intents),
        None if intent_pending is None else intent_pending[1],
        None if attempt_pending is None else attempt_pending[1],
    )


def _promote_or_rebuild_source_gate_intent(
    journal: Path,
    state: _SourceGateJournal,
    source_identity: dict[str, str],
) -> tuple[_SourceGateJournal, bool]:
    """Recover a never-authoritative intent staging write; no gate ran yet."""
    pending = state.intent_pending
    if pending is None:
        return state, False
    number = len(state.attempts) + 1
    prior = _attempt_digests(list(state.attempts))
    payload = read_private_pending(pending, SOURCE_GATE_MAX_INTENT_BYTES)
    try:
        staged = _source_gate_intent_from_payload(
            pending, number, source_identity, prior, payload
        )
    except PublicationError as error:
        try:
            json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            discard_private_pending(pending, SOURCE_GATE_MAX_INTENT_BYTES)
            return _SourceGateJournal(state.attempts, state.intents, None, None), False
        raise error
    destination = journal / f"intent-{number:04d}.json"
    promote_private_pending(pending, destination)
    committed = _read_source_gate_intent(
        destination, number, source_identity, prior
    )
    if committed.payload != staged.payload:
        raise PublicationError("source gate pending intent changed during recovery")
    return _SourceGateJournal(
        state.attempts, (*state.intents, committed), None, None
    ), True


def _create_source_gate_intent(
    journal: Path,
    attempts: list[_SourceGateAttempt],
    source_identity: dict[str, str],
) -> _SourceGateIntent:
    number = len(attempts) + 1
    prior = _attempt_digests(attempts)
    document = {
        "schema_version": SOURCE_GATE_INTENT_SCHEMA_VERSION,
        "document": SOURCE_GATE_INTENT_DOCUMENT,
        "attempt_number": number,
        "repository_commit": source_identity["repositoryCommit"],
        "release_source_sha256": source_identity["releaseSourceSha256"],
        "prior_attempt_sha256s": list(prior),
    }
    payload = canonical_json(document)
    if len(payload) > SOURCE_GATE_MAX_INTENT_BYTES:
        raise PublicationError("source gate intent exceeds its fixed size bound")
    pending = journal / f".intent-{number:04d}.json.pending"
    destination = journal / f"intent-{number:04d}.json"
    write_private_pending(pending, payload)
    _source_gate_intent_from_payload(
        pending,
        number,
        source_identity,
        prior,
        read_private_pending(pending, SOURCE_GATE_MAX_INTENT_BYTES),
    )
    promote_private_pending(pending, destination)
    return _read_source_gate_intent(destination, number, source_identity, prior)


def _require_source_gate_journal_unchanged(
    journal: Path,
    attempts: list[_SourceGateAttempt],
    intents: list[_SourceGateIntent],
) -> None:
    expected_names = sorted(
        [f"attempt-{attempt.number:04d}.json" for attempt in attempts]
        + [f"intent-{intent.number:04d}.json" for intent in intents]
    )
    observed_names = sorted(entry.name for entry in journal.iterdir())
    if observed_names != expected_names:
        raise PublicationError("source gate journal changed while it was in use")
    for attempt in attempts:
        if _read_private_committed(attempt.path, SOURCE_GATE_MAX_DOCUMENT_BYTES) != attempt.payload:
            raise PublicationError(
                f"source gate attempt changed while it was in use: {attempt.path.name}"
            )
    for intent in intents:
        if _read_private_committed(intent.path, SOURCE_GATE_MAX_INTENT_BYTES) != intent.payload:
            raise PublicationError(
                f"source gate intent changed while it was in use: {intent.path.name}"
            )


def _validate_source_gate_canonical(
    output: Path,
    journal: Path,
    journal_descriptor: int,
    attempts: list[_SourceGateAttempt],
    intents: list[_SourceGateIntent],
) -> bool:
    """Validate an existing canonical output or report that none exists."""
    pending = output.with_name(f".{output.name}.pending")
    if os.path.lexists(output) and os.path.lexists(pending):
        raise PublicationError(
            "source gate canonical output and pending file both exist"
        )
    if output.is_symlink():
        raise PublicationError(f"source gate canonical output is a symlink: {output}")
    if not os.path.lexists(output):
        return False
    payload = read_regular(output, SOURCE_GATE_MAX_DOCUMENT_BYTES)
    if not attempts:
        raise PublicationError(
            "source gate canonical output exists without an attempt journal"
        )
    passing = attempts[-1]
    if passing.failures:
        raise PublicationError(
            "source gate canonical output exists but the latest attempt failed"
        )
    if payload != passing.payload:
        raise PublicationError(
            "source gate canonical output differs from its passing attempt"
        )
    _require_source_gate_journal_unchanged(journal, attempts, intents)
    fsync_locked_directory(journal_descriptor, journal)
    fsync_directory(output.parent)
    return True


def _publish_source_gate_canonical(
    output: Path,
    attempt: _SourceGateAttempt,
) -> None:
    """Promote the exact passing attempt bytes into the canonical path once."""
    if attempt.failures:
        raise PublicationError("refusing to publish a failed source gate attempt")
    if os.path.lexists(output):
        raise PublicationError("source gate canonical output already exists")
    attempt_payload = _read_private_committed(
        attempt.path, SOURCE_GATE_MAX_DOCUMENT_BYTES
    )
    if attempt_payload != attempt.payload:
        raise PublicationError(
            f"source gate attempt changed before promotion: {attempt.path.name}"
        )
    pending = output.with_name(f".{output.name}.pending")
    if os.path.lexists(pending):
        pending_payload = read_private_pending(
            pending, SOURCE_GATE_MAX_DOCUMENT_BYTES
        )
        if pending_payload != attempt_payload:
            try:
                json.loads(pending_payload)
            except (UnicodeDecodeError, json.JSONDecodeError):
                discard_private_pending(pending, SOURCE_GATE_MAX_DOCUMENT_BYTES)
            else:
                raise PublicationError(
                    "source gate canonical pending file differs from its passing attempt"
                )
    if not os.path.lexists(pending):
        write_private_pending(pending, attempt_payload)
    if (
        read_private_pending(pending, SOURCE_GATE_MAX_DOCUMENT_BYTES)
        != attempt_payload
    ):
        raise PublicationError("source gate canonical pending file changed")
    promote_private_pending(pending, output)
    if read_regular(output, SOURCE_GATE_MAX_DOCUMENT_BYTES) != attempt_payload:
        raise PublicationError("source gate canonical output changed while publishing")
    if _read_private_committed(attempt.path, SOURCE_GATE_MAX_DOCUMENT_BYTES) != attempt_payload:
        raise PublicationError("source gate passing attempt changed while publishing")


def _append_source_gate_attempt(
    repository: Path,
    journal: Path,
    number: int,
    source_identity: dict[str, str],
    expected_prior_attempt_sha256s: tuple[str, ...],
    payload: bytes,
) -> _SourceGateAttempt:
    destination = journal / f"attempt-{number:04d}.json"
    pending = journal / f".attempt-{number:04d}.json.pending"
    if os.path.lexists(destination) or os.path.lexists(pending):
        raise PublicationError("source gate attempt destination is already occupied")
    write_private_pending(pending, payload)
    staged_payload = read_private_pending(pending, SOURCE_GATE_MAX_DOCUMENT_BYTES)
    staged = _source_gate_attempt_from_payload(
        repository,
        pending,
        number,
        source_identity,
        expected_prior_attempt_sha256s,
        staged_payload,
    )
    if staged.payload != payload:
        raise PublicationError("source gate attempt changed while being staged")
    promote_private_pending(pending, destination)
    recorded = _read_source_gate_attempt(
        repository,
        destination,
        number,
        source_identity,
        expected_prior_attempt_sha256s,
    )
    if recorded.payload != payload or recorded.document != staged.document:
        raise PublicationError("source gate attempt changed while being appended")
    return recorded


def _append_outcome_unknown_attempt(
    repository: Path,
    journal: Path,
    attempts: list[_SourceGateAttempt],
    source_identity: dict[str, str],
) -> _SourceGateAttempt:
    number = len(attempts) + 1
    prior = _attempt_digests(attempts)
    normalized, failures = validate_source_gate_document(
        repository,
        {
            "schema_version": SOURCE_GATE_SCHEMA_VERSION,
            "document": SOURCE_GATE_DOCUMENT,
            "attempt_number": number,
            "attempt_outcome": SOURCE_GATE_OUTCOME_UNKNOWN,
            "prior_attempt_sha256s": list(prior),
            "repository_commit": source_identity["repositoryCommit"],
            "release_source_sha256": source_identity["releaseSourceSha256"],
            "gates": [],
        },
        source_identity["repositoryCommit"],
        source_identity["releaseSourceSha256"],
    )
    if failures != [SOURCE_GATE_OUTCOME_UNKNOWN]:
        raise PublicationError("outcome-unknown source gate attempt normalized incorrectly")
    return _append_source_gate_attempt(
        repository,
        journal,
        number,
        source_identity,
        prior,
        canonical_json(normalized),
    )


def _recover_source_gate_attempt_pending(
    repository: Path,
    journal: Path,
    state: _SourceGateJournal,
    source_identity: dict[str, str],
) -> _SourceGateAttempt:
    pending = state.attempt_pending
    if pending is None or len(state.intents) != len(state.attempts) + 1:
        raise PublicationError("source gate attempt recovery lacks its durable intent")
    number = len(state.attempts) + 1
    prior = _attempt_digests(list(state.attempts))
    payload = read_private_pending(pending, SOURCE_GATE_MAX_DOCUMENT_BYTES)
    try:
        staged = _source_gate_attempt_from_payload(
            repository,
            pending,
            number,
            source_identity,
            prior,
            payload,
        )
    except PublicationError as error:
        try:
            json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            # The durable intent proves a gate attempt may have begun. Preserve
            # that uncertainty explicitly; never turn a partial result into a rerun.
            discard_private_pending(pending, SOURCE_GATE_MAX_DOCUMENT_BYTES)
            return _append_outcome_unknown_attempt(
                repository, journal, list(state.attempts), source_identity
            )
        raise error
    destination = journal / f"attempt-{number:04d}.json"
    promote_private_pending(pending, destination)
    committed = _read_source_gate_attempt(
        repository,
        destination,
        number,
        source_identity,
        prior,
    )
    if committed.payload != staged.payload:
        raise PublicationError("source gate pending attempt changed during recovery")
    return committed


def command_collect_source_gates(arguments: argparse.Namespace) -> None:
    """Run the repository P0 source/boundary gates and record their exact results.

    Each gate's combined output is content-addressed and its real exit status is
    recorded. A nonzero exit or timeout is recorded as a non-passing attempt;
    a structurally missing gate cannot form a valid attempt and fails before
    execution. A durable intent is appended before any gate starts. Every
    complete attempt is then durably appended before a passing attempt is
    promoted byte-for-byte to the canonical output. If an intended attempt has
    no complete result, it becomes ``outcome-unknown`` and a later retry
    requires explicit operator acknowledgement.
    """
    repository = _repository()
    requested_output = arguments.output
    requested_journal = (
        requested_output.parent / "source-gate-journal"
        if getattr(arguments, "journal", None) is None
        else arguments.journal
    )
    pins = load_pins(repository / "scripts/dependency_pins.env")
    environment = release_tool_environment(repository, pins)
    try:
        source_identity = current_identity(
            repository,
            require_clean=True,
            environment=environment,
        )
    except (OSError, SourceIdentityError) as error:
        raise PublicationError(
            "P0 source gates require one clean, readable release source identity"
        ) from error
    output_path, journal = _ensure_source_gate_journal(
        repository, requested_output, requested_journal
    )
    with exclusive_directory_lock(journal) as journal_descriptor:
        _collect_source_gates_locked(
            repository,
            output_path,
            journal,
            environment,
            source_identity,
            journal_descriptor=journal_descriptor,
            retry_after_outcome_unknown=getattr(
                arguments, "retry_after_outcome_unknown", False
            ),
        )


def _collect_source_gates_locked(
    repository: Path,
    output_path: Path,
    journal: Path,
    environment: dict[str, str],
    source_identity: dict[str, str],
    *,
    journal_descriptor: int,
    retry_after_outcome_unknown: bool,
) -> None:
    state = _read_source_gate_journal(repository, journal, source_identity)
    fsync_locked_directory(journal_descriptor, journal)
    state, safe_recovered_intent = _promote_or_rebuild_source_gate_intent(
        journal, state, source_identity
    )
    attempts = list(state.attempts)
    intents = list(state.intents)

    recovered: _SourceGateAttempt | None = None
    if state.attempt_pending is not None:
        recovered = _recover_source_gate_attempt_pending(
            repository, journal, state, source_identity
        )
        attempts.append(recovered)
    elif len(intents) == len(attempts) + 1 and not safe_recovered_intent:
        recovered = _append_outcome_unknown_attempt(
            repository, journal, attempts, source_identity
        )
        attempts.append(recovered)

    if recovered is not None:
        print(
            f"p0 source gate attempt recovered: {recovered.path.resolve(strict=True)} "
            f"gates={len(recovered.document['gates'])} "
            f"failed={list(recovered.failures)}"
        )
        if recovered.failures:
            if recovered.document["attempt_outcome"] == SOURCE_GATE_OUTCOME_UNKNOWN:
                raise PublicationError(
                    "P0 source gate attempt outcome is unknown; inspect the retained "
                    "journal and use --retry-after-outcome-unknown for a new attempt"
                )
            raise PublicationError(
                f"P0 source gates did not pass: {list(recovered.failures)}"
            )

    if _validate_source_gate_canonical(
        output_path, journal, journal_descriptor, attempts, intents
    ):
        passing = attempts[-1]
        print(
            f"p0 source gate record already verified: "
            f"{output_path.resolve(strict=True)} "
            f"attempt={passing.number:04d} gates={len(passing.document['gates'])}"
        )
        return
    if attempts and not attempts[-1].failures:
        # The append completed but canonical publication did not. Recheck the
        # clean source immediately before promotion, then recover without a
        # second execution that could fabricate a replacement pass.
        try:
            recovery_identity = current_identity(
                repository,
                require_clean=True,
                environment=environment,
            )
        except (OSError, SourceIdentityError) as error:
            raise PublicationError(
                "release source changed or became unreadable before P0 recovery"
            ) from error
        if recovery_identity != source_identity:
            raise PublicationError(
                "release source identity changed before P0 attempt recovery"
            )
        passing = attempts[-1]
        _require_source_gate_journal_unchanged(journal, attempts, intents)
        fsync_locked_directory(journal_descriptor, journal)
        _publish_source_gate_canonical(output_path, passing)
        print(
            f"p0 source gate record recovered: {output_path.resolve(strict=True)} "
            f"attempt={passing.number:04d} gates={len(passing.document['gates'])}"
        )
        return
    if (
        attempts
        and attempts[-1].document["attempt_outcome"] == SOURCE_GATE_OUTCOME_UNKNOWN
        and not retry_after_outcome_unknown
    ):
        raise PublicationError(
            "latest P0 source gate attempt outcome is unknown; inspect the retained "
            "journal and use --retry-after-outcome-unknown for a new attempt"
        )
    if len(attempts) >= SOURCE_GATE_MAX_ATTEMPTS:
        raise PublicationError("source gate journal exhausted its bounded attempt sequence")

    prepared_gates: list[tuple[str, str, list[str]]] = []
    for identifier in sorted(REQUIRED_SOURCE_GATES):
        script = REQUIRED_SOURCE_GATES[identifier]
        path = repository / script
        if path.is_symlink() or not path.is_file():
            raise PublicationError(f"p0 source gate script is missing: {script}")
        command = (
            ["/bin/bash", "-p", str(path)]
            if script.endswith(".sh")
            else [
                "/bin/bash",
                "-p",
                "-c",
                'source "$1/scripts/release_python_launcher.sh"; '
                'cfw_run_release_python_script "$1" "$2"',
                "source-gate-python",
                str(repository),
                str(path),
            ]
        )
        prepared_gates.append((identifier, script, command))

    if len(intents) == len(attempts):
        intent = _create_source_gate_intent(journal, attempts, source_identity)
        intents.append(intent)
    elif len(intents) == len(attempts) + 1 and safe_recovered_intent:
        intent = intents[-1]
    else:
        raise PublicationError("source gate journal has no usable next-attempt intent")
    _require_source_gate_journal_unchanged(journal, attempts, intents)

    commit = source_identity["repositoryCommit"]
    release_source_sha256 = source_identity["releaseSourceSha256"]
    next_number = len(attempts) + 1
    gates: list[dict[str, Any]] = []
    try:
        for identifier, script, command in prepared_gates:
            try:
                completed = run_bounded_process(
                    command,
                    cwd=repository,
                    environment=environment,
                    timeout=GATE_TIMEOUT_SECONDS,
                    output_limit=MAX_SOURCE_GATE_OUTPUT_BYTES,
                )
                output = completed.stdout + completed.stderr
                exit_code = completed.returncode
                status = "passed" if exit_code == 0 else "failed"
            except BoundedProcessError as error:
                if error.reason != "timeout":
                    raise PublicationError(
                        f"p0 source gate {identifier} violated its process boundary"
                    ) from error
                output = error.stdout + error.stderr
                exit_code = 124
                status = "timeout"
            if exit_code < 0 or exit_code > 255:
                exit_code = 255
                status = "failed"
            gates.append(
                {
                    "id": identifier,
                    "script": script,
                    "status": status,
                    "exit_code": exit_code,
                    "log_sha256": hashlib.sha256(output).hexdigest(),
                    "commit": commit,
                    "release_source_sha256": release_source_sha256,
                }
            )

        completed_identity = current_identity(
            repository,
            require_clean=True,
            environment=environment,
        )
        if completed_identity != source_identity:
            raise PublicationError("release source identity changed while P0 gates ran")
        document = {
            "schema_version": SOURCE_GATE_SCHEMA_VERSION,
            "document": SOURCE_GATE_DOCUMENT,
            "attempt_number": next_number,
            "attempt_outcome": SOURCE_GATE_COMPLETED,
            "prior_attempt_sha256s": list(_attempt_digests(attempts)),
            "repository_commit": commit,
            "release_source_sha256": release_source_sha256,
            "gates": gates,
        }
        normalized, failed = validate_source_gate_document(
            repository,
            document,
            commit,
            release_source_sha256,
        )
    except Exception as error:
        try:
            unknown = _append_outcome_unknown_attempt(
                repository, journal, attempts, source_identity
            )
            _require_source_gate_journal_unchanged(
                journal, [*attempts, unknown], intents
            )
        except Exception as record_error:
            raise PublicationError(
                "P0 source gate execution outcome is unknown and its journal record "
                "could not be made durable"
            ) from record_error
        if isinstance(error, (OSError, SourceIdentityError)):
            raise PublicationError(
                "release source changed or became unreadable while P0 gates ran"
            ) from error
        raise

    _require_source_gate_journal_unchanged(journal, attempts, intents)
    payload = canonical_json(normalized)
    if len(payload) > SOURCE_GATE_MAX_DOCUMENT_BYTES:
        raise PublicationError("source gate attempt exceeds its fixed size bound")
    recorded = _append_source_gate_attempt(
        repository,
        journal,
        next_number,
        source_identity,
        _attempt_digests(attempts),
        payload,
    )
    _require_source_gate_journal_unchanged(
        journal, [*attempts, recorded], intents
    )
    fsync_locked_directory(journal_descriptor, journal)
    print(
        f"p0 source gate attempt appended: {recorded.path.resolve(strict=True)} "
        f"gates={len(gates)} failed={list(recorded.failures)}"
    )
    if failed:
        raise PublicationError(f"P0 source gates did not pass: {failed}")
    _publish_source_gate_canonical(output_path, recorded)
    print(
        f"p0 source gate record written: {output_path.resolve(strict=True)} "
        f"attempt={recorded.number:04d} gates={len(gates)} failed=[]"
    )


def command_ci_toolchain_binding(_arguments: argparse.Namespace) -> None:
    """Print the single toolchain binding the unsigned-CI lanes are bound to."""
    digest, identity = derive_toolchain_binding(_repository())
    print(canonical_json(identity).decode("utf-8"), end="")
    print(f"toolchain_sha256: {digest}")


def command_collect_ci_lanes(arguments: argparse.Namespace) -> None:
    """Run the required deterministic local lanes and record their exact results.

    Each lane's combined output is content-addressed and its real exit status is
    recorded, bound to one commit and one toolchain digest. A nonzero exit is
    ``failed``, exceeding the lane's wall-clock bound is ``timeout``, and neither
    can be written as ``passed``.
    """
    repository = _repository()
    source_identity = current_identity(repository)
    result = collect_ci_lanes(
        repository,
        commit=source_identity["repositoryCommit"],
        release_source_sha256=source_identity["releaseSourceSha256"],
        output=arguments.output,
        journal=(
            arguments.output.parent / "ci-lane-journal"
            if arguments.journal is None
            else arguments.journal
        ),
        only=frozenset(arguments.only or ()),
        rerun=frozenset(arguments.rerun or ()),
        assemble_only=arguments.assemble_only,
        libbox_source=arguments.libbox_source,
        libbox_output=arguments.libbox_output,
    )
    for lane in result["document"]["lanes"]:
        print(f"  lane {lane['id']}: {lane['status']} (exit {lane['exit_code']})")
    print(
        f"local deterministic CI lane record: {Path(result['output']).resolve(strict=True)} "
        f"toolchain_sha256={result['toolchain_sha256']} failed={result['failures']}"
    )
    if result["failures"]:
        # The record is written exactly as observed; the gate refuses it.
        raise SystemExit(
            "error: sealed evidence manifest: local deterministic CI lanes did not "
            f"pass: {result['failures']}"
        )


def command_seal(arguments: argparse.Namespace) -> None:
    request = load_sealed_manifest(arguments.request.resolve(strict=True))
    manifest = build_sealed_evidence_manifest(
        _repository(), request, fixture=arguments.fixture
    )
    seal_manifest(arguments.output, manifest)
    print(
        f"sealed evidence manifest written: {arguments.output.resolve(strict=True)} "
        f"status={manifest['status']} blocked={manifest['blocked_inputs']}"
    )
    for name in GATE_ORDER:
        print(f"  gate {name}: {manifest['gates'][name]['status']}")
    for capability in manifest["capabilities"]:
        print(f"  capability {capability['id']}: {capability['highest_level']}")
    decision = manifest["publication"]
    print(
        f"publication artifacts permitted: {decision['artifacts_permitted']} "
        f"refusals={decision['refusals']}"
    )


def command_verify(arguments: argparse.Namespace) -> None:
    document = load_sealed_manifest(arguments.manifest.resolve(strict=True))
    result = validate_sealed_evidence_manifest(
        _repository(),
        document,
        fixture=arguments.fixture,
        require_sealed=arguments.require_sealed,
    )
    print(
        f"sealed evidence manifest verified: status={result['status']} "
        f"blocked={result['blocked_inputs']} "
        f"publication={result['publication']['artifacts_permitted']}"
    )


def command_publication_gate(arguments: argparse.Namespace) -> None:
    repository = _repository()
    manifest_path = (
        repository / DEFAULT_MANIFEST_PATH if arguments.manifest is None else arguments.manifest
    )
    if manifest_path.is_symlink() or not manifest_path.is_file():
        # Absence is never success: without a sealed manifest, publication
        # artifacts may not be created.
        raise PublicationError(
            f"publication is blocked: no sealed Evidence Manifest at {manifest_path}"
        )
    document = load_sealed_manifest(manifest_path.resolve(strict=True))
    result = authorize_publication_artifacts(repository, document)
    print(
        "publication artifacts authorized by the sealed Evidence Manifest: "
        f"{result['bindings']['final_candidate_sha256']}"
    )


def command_status(arguments: argparse.Namespace) -> None:
    report = environment_status(
        _repository(),
        evidence_directory=arguments.evidence_dir.resolve() if arguments.evidence_dir else None,
    )
    print(f"sealed manifest inputs under {report['evidence_directory']}")
    for name in sorted(report["inputs"]):
        entry = report["inputs"][name]
        print(f"  {name}: {entry['state']} ({entry['path']})")
    for block in report["workspace_secret_blocks"]:
        # Path and name only; the key is never opened (Requirement 8.1).
        print(
            f"  release secret blocker: {block['path']} (name={block['name']}) "
            f"kind={block['credential_kind']} "
            f"relocate to {block['relocation_target']}; "
            f"rotation_required={block['rotation_required']} "
            f"action={block['required_trust_action']}"
        )
    print(f"  sealed manifest: {report['manifest_state']} ({report['manifest_path']})")
    print(f"sealed manifest status: {report['status']} blocked={report['blocked_inputs']}")


def command_self_check(_arguments: argparse.Namespace) -> None:
    self_check()
    print("sealed outer evidence manifest self-check ok")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect-source-gates")
    collect.add_argument("--output", type=Path, required=True)
    collect.add_argument(
        "--journal",
        type=Path,
        default=None,
        help="append-only attempt journal (default: OUTPUT parent/source-gate-journal)",
    )
    collect.add_argument(
        "--retry-after-outcome-unknown",
        action="store_true",
        help=(
            "start a new numbered attempt after explicitly reviewing a retained "
            "outcome-unknown attempt"
        ),
    )
    collect.set_defaults(handler=command_collect_source_gates)
    binding = commands.add_parser("ci-toolchain-binding")
    binding.set_defaults(handler=command_ci_toolchain_binding)
    lanes = commands.add_parser("collect-ci-lanes")
    lanes.add_argument("--output", type=Path, required=True)
    lanes.add_argument("--journal", type=Path, default=None)
    lanes.add_argument(
        "--only",
        action="append",
        choices=sorted(lane.identifier for lane in LANES),
        help="run only these lanes; every other lane must already be recorded",
    )
    lanes.add_argument(
        "--rerun",
        action="append",
        choices=sorted(lane.identifier for lane in LANES),
        help="re-run these lanes even when they are already recorded",
    )
    lanes.add_argument(
        "--assemble-only",
        action="store_true",
        help="assemble the document from recorded lanes without running anything",
    )
    lanes.add_argument(
        "--libbox-source",
        type=Path,
        default=None,
        help=f"patched sing-box tree (default: {DEFAULT_LIBBOX_SOURCE_TEMPLATE})",
    )
    lanes.add_argument(
        "--libbox-output",
        type=Path,
        default=None,
        help=f"libbox build lane output (default: {DEFAULT_LIBBOX_OUTPUT})",
    )
    lanes.set_defaults(handler=command_collect_ci_lanes)
    seal = commands.add_parser("seal")
    seal.add_argument("--request", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    seal.add_argument("--fixture", action="store_true")
    seal.set_defaults(handler=command_seal)
    verify = commands.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--fixture", action="store_true")
    verify.add_argument("--require-sealed", action="store_true")
    verify.set_defaults(handler=command_verify)
    gate = commands.add_parser("publication-gate")
    gate.add_argument("--manifest", type=Path, default=None)
    gate.set_defaults(handler=command_publication_gate)
    status = commands.add_parser("status")
    status.add_argument("--evidence-dir", type=Path, default=None)
    status.set_defaults(handler=command_status)
    check = commands.add_parser("self-check")
    check.set_defaults(handler=command_self_check)
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        arguments.handler(arguments)
    except (PublicationError, SourceIdentityError, OSError) as error:
        raise SystemExit(f"error: sealed evidence manifest: {error}") from error


if __name__ == "__main__":
    main()
