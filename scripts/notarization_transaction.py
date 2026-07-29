#!/usr/bin/env python3
"""Run the durable app-notarization and atomic publication transaction.

The build shell owns compilation and inside-out signing.  This module takes the
already signed Host app and owns the first irreversible remote side effect:
notary submission.  A build/lane attempt is claimed exactly once, the exact
submitted app and archive survive every failure, untrusted command output is
only parsed in memory, and the public ``signed`` directory appears in one
non-overwriting rename after every verification and manifest is complete.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import ctypes
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import errno
import fcntl
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Iterator
import uuid

if __package__:
    from .candidate_artifact_binding import (
        TOOLCHAIN_METADATA_ORDER,
        derive_candidate_toolchain_metadata,
    )
    from .gatekeeper_assessment import (
        capture as capture_gatekeeper,
        validate_evidence as validate_gatekeeper_evidence,
    )
    from .hash_artifact import build_manifest, write_new_manifest
    from .release_build_identity import canonical_build_version
    from .repository_source_identity import (
        SourceIdentityError,
        current_identity,
        identity_at_commit,
    )
    from .verify_notary_log import (
        NotaryLogError,
        validate_documents,
        validate_normalized_documents,
    )
    from .verify_artifact_manifest import MAX_MANIFEST_BYTES
    from .validate_notary_archive import (
        NotaryArchiveError,
        validate_notarization_zip,
    )
else:
    from candidate_artifact_binding import (
        TOOLCHAIN_METADATA_ORDER,
        derive_candidate_toolchain_metadata,
    )
    from gatekeeper_assessment import (
        capture as capture_gatekeeper,
        validate_evidence as validate_gatekeeper_evidence,
    )
    from hash_artifact import build_manifest, write_new_manifest
    from release_build_identity import canonical_build_version
    from repository_source_identity import (
        SourceIdentityError,
        current_identity,
        identity_at_commit,
    )
    from verify_notary_log import (
        NotaryLogError,
        validate_documents,
        validate_normalized_documents,
    )
    from verify_artifact_manifest import MAX_MANIFEST_BYTES
    from validate_notary_archive import (
        NotaryArchiveError,
        validate_notarization_zip,
    )


VERSION = "0.4.0"
EXPECTED_TEAM_ID = "YKUPL7Z869"
EXPECTED_DEPLOYMENT_TARGET = "15.0"
ATTEMPT_DOCUMENT = "cfw-notarization-attempt-v1"
EVENT_DOCUMENT = "cfw-notarization-event-v1"
EVENT_DOCUMENT_V2 = "cfw-notarization-event-v2"
SUBMISSION_DOCUMENT = "cfw-notarization-submission-receipt-v2"
SUBMISSION_OBSERVATION_DOCUMENT = "cfw-notarization-submission-observation-v1"
RECEIPT_DOCUMENT = "cfw-notarization-publish-ready-receipt-v3"
RECOVERY_DOCUMENT = "cfw-notarization-recovery-intent-v1"
RECOVERY_CONTINUATION_DOCUMENT = (
    "cfw-notarization-recovery-tool-continuation-v1"
)
RECOVERY_CONTINUATION_PENDING_FILENAME = "recovery-continuation.pending"
PUBLISH_READY_RECEIPT_PENDING_FILENAME = "receipt.pending"
RENAME_EXCL = 0x00000004
RENAME_NOFOLLOW_ANY = 0x00000010
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_EVENT_DOCUMENTS = 4096
MAX_FINALIZATION_RUNS = 8
MAX_FINALIZATION_RUNS_BYTES = 4 * 1024 * 1024 * 1024
MAX_FINALIZATION_TREE_ENTRIES = 250_000
FAILED_FINALIZATION_CLEANUP_MIN_BYTES = 512 * 1024 * 1024
RECOVERY_SUCCESS_EVENT_RESERVE = 12
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
EVENT_PENDING_RE = re.compile(r"^([0-9]{8})[.]pending$")
DEPLOYMENT_TARGET_RE = re.compile(r"^[0-9]+\.[0-9]+$")
TOOLCHAIN_METADATA_KEYS = set(TOOLCHAIN_METADATA_ORDER)
EVENT_FIELDS = {
    "schema_version",
    "document",
    "sequence",
    "previous_event_sha256",
    "intent_sha256",
    "state",
    "recorded_at",
    "submission_id",
    "failure_code",
    "exit_code",
}
EVENT_V2_FIELDS = EVENT_FIELDS | {"evidence_sha256"}
EVIDENCE_EVENT_STATES = {
    "direct_finalization_preparing",
    "direct_finalization_ready",
    "recovery_intent_anchored",
    "recovery_tool_continued",
}
RECOVERY_FIELDS = {
    "schema_version",
    "document",
    "attempt_id",
    "submission_id",
    "intent_sha256",
    "prior_event_sha256",
    "archive_sha256",
    "submission_observation_sha256",
    "artifact_repository_commit",
    "artifact_release_source_sha256",
    "recovery_tool_repository_commit",
    "recovery_tool_release_source_sha256",
    "requested_at",
}
RECOVERY_CONTINUATION_FIELDS = {
    "schema_version",
    "document",
    "attempt_id",
    "submission_id",
    "recovery_intent_sha256",
    "prior_recovery_tool_repository_commit",
    "prior_recovery_tool_release_source_sha256",
    "continuation_tool_repository_commit",
    "continuation_tool_release_source_sha256",
    "prior_event_sha256",
    "prior_failure_code",
    "requested_at",
}
SUBMISSION_OBSERVATION_FIELDS = {
    "schema_version",
    "document",
    "attempt_id",
    "submission_id",
    "intent_sha256",
    "archive_name",
    "archive_sha256",
    "path_binding",
    "observed_at",
}
SUBMISSION_RECEIPT_FIELDS = {
    "schema_version",
    "document",
    "attempt_id",
    "submission_id",
    "acquisition",
    "archive_name",
    "submission_observation_sha256",
    "recovery_intent_sha256",
    "notary_created_at",
    "causal_binding",
    "archive_sha256",
    "observed_at",
}
PUBLISH_READY_RECEIPT_FIELDS = {
    "schema_version",
    "document",
    "attempt_id",
    "submission_id",
    "intent_sha256",
    "preseal_event_sha256",
    "submission_receipt_sha256",
    "recovery_intent_sha256",
    "recovery_continuation_sha256",
    "accepted_notary_log_sha256",
    "notarization_result_sha256",
    "archive_sha256",
    "pre_staple_app_tree_sha256",
    "post_staple_app_tree_sha256",
    "gatekeeper_evidence_sha256",
    "app_manifest_sha256",
    "archive_manifest_sha256",
    "state",
    "sealed_at",
}
INTENT_FIELDS = {
    "schema_version",
    "document",
    "attempt_id",
    "lane",
    "build_number",
    "version",
    "repository_commit",
    "release_source_sha256",
    "team_id",
    "archive_name",
    "archive_sha256",
    "archive_size",
    "pre_staple_app_tree_sha256",
    "prepared_at",
}
RECOVERABLE_SUBMIT_FAILURE_CODES = {
    "command_output_invalid_utf8",
    "invalid_command_output",
    "invalid_notary_response",
    "invalid_submission_id",
    "notary_submit_path_mismatch",
    "submit_execution_failed",
    "submit_failed",
    "submit_stderr",
    "submission_observation_failed",
    "submission_receipt_failed",
}
RECOVERABLE_WAIT_FAILURE_CODES = {
    "command_output_invalid_utf8",
    "invalid_command_output",
    "invalid_notary_response",
    "invalid_notary_status",
    "notary_wait_incomplete",
    "submission_id_mismatch",
    "wait_execution_failed",
    "wait_failed",
    "wait_stderr",
}
FINALIZATION_EVENT_STATES = (
    "accepted",
    "log_verified",
    "stapling",
    "stapled",
    "gatekeeper_verified",
    "app_verified",
    "distribution_verified",
    "sealed",
)
FINALIZATION_TERMINAL_STATES = {"failed", "outcome_unknown", "rejected"}
DIRECT_FINALIZATION_EVENT_RESERVE = 3 + len(FINALIZATION_EVENT_STATES) + 1
DIRECT_BOUNDARY_RECOVERY_EVENT_RESERVE = 2 + RECOVERY_SUCCESS_EVENT_RESERVE
RECOVERY_RETRYABLE_READ_FAILURE_CODES = {
    "command_output_invalid_utf8",
    "fetch-log_execution_failed",
    "fetch-log_failed",
    "fetch-log_stderr",
    "history_execution_failed",
    "history_failed",
    "history_stderr",
    "info_execution_failed",
    "info_failed",
    "info_stderr",
    "invalid_command_output",
    "invalid_notary_response",
    "invalid_notary_status",
}
FINAL_INVENTORY_TEMPLATE = {
    "Clash for Mac.app",
    "Clash for Mac.app.manifest.json",
    "notarization.json",
    "notarization-log.json",
    "gatekeeper.json",
}
_SINGLE_SIGNATURE_DIAGNOSTIC_PREFIX = "Only one signature found in "
_SINGLE_SIGNATURE_DIAGNOSTIC_SUFFIX = ", skipping dual signature check\n"
_KNOWN_NOTARY_FALSE_POSITIVE_LONG_ERROR = (
    "Gatekeeper rejected this file. If there isn't a more descriptive error "
    "elsewhere in this output, please file a Feedback through Feedback "
    "Assistant.app so we can continue to improve syspolicy_check. Please include "
    "the app bundle you are checking and a sysdiagnose taken immediately after "
    "running syspolicy_check."
)
_MISSING_TICKET_LONG_ERROR = (
    "A Notarization ticket is not stapled to this application."
)
_MISSING_TICKET_ADVICE = (
    "If this application has already been uploaded to the Apple notary service, "
    "please make sure to attach the ticket with the `stapler staple` command. If "
    "not, please upload to the Apple notary service using Xcode or via "
    "`notarytool`. "
)
_SUBMIT_SUCCESS_MESSAGE = "Successfully uploaded file"
_WAIT_COMPLETE_MESSAGE = "Processing complete"
_INFO_SUCCESS_MESSAGE = "Successfully received submission info"
_HISTORY_SUCCESS_MESSAGE = "Successfully received submission history."


class TransactionError(RuntimeError):
    """The notarization transaction failed without claiming success."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        terminal_state: str = "failed",
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.terminal_state = terminal_state
        self.exit_code = exit_code


class DuplicateKeyError(ValueError):
    """A command returned a JSON object with repeated fields."""


class CommandRole(Enum):
    NOTARY_READINESS = "notary-readiness"
    NOTARY_READINESS_CORROBORATION = "notary-readiness-corroboration"
    SUBMIT = "submit"
    INFO = "info"
    HISTORY = "history"
    WAIT = "wait"
    FETCH_LOG = "fetch-log"
    STAPLE = "staple"
    STAPLE_VALIDATE = "staple-validate"
    FINAL_VERIFY = "final-verify"
    DISTRIBUTION_CHECK = "distribution-check"


class PreSubmissionPolicyMode(Enum):
    NATIVE = "native"
    MACOS_27_26A5388G_COMPATIBILITY = "macos-27-26A5388g-compatibility"


class AttemptPhase(Enum):
    SUBMISSION_RECOVERABLE = "submission-recoverable"
    DIRECT_SOURCE_PREPARING = "direct-source-preparing"
    DIRECT_FINALIZATION_READY = "direct-finalization-ready"
    RECONCILIATION_INCOMPLETE = "reconciliation-incomplete"
    RECONCILED = "reconciled"
    FINALIZATION_INCOMPLETE = "finalization-incomplete"
    FINALIZATION_FAILED = "finalization-failed"
    SEALED = "sealed"
    DIRECT_SEALED = "direct-sealed"


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class HostSystemIdentity:
    product_name: str
    product_version: str
    build_version: str
    kernel_name: str
    kernel_release: str
    architecture: str


KNOWN_MACOS_27_COMPATIBILITY_IDENTITY = HostSystemIdentity(
    product_name="macOS",
    product_version="27.0",
    build_version="26A5388g",
    kernel_name="Darwin",
    kernel_release="27.0.0",
    architecture="arm64",
)


@dataclass(frozen=True)
class PersistedEvidenceSnapshot:
    gatekeeper: dict[str, Any]
    notarization_sha256: str
    notary_log_sha256: str
    gatekeeper_sha256: str


@dataclass(frozen=True)
class AttemptEventReduction:
    phase: AttemptPhase
    submit_window_start: datetime
    submit_window_end: datetime
    prior_event_sha256: str
    recovery_event_start: int
    submission_id: str | None
    boundary_submission_id: str | None
    submitted_receipt_expected: bool
    direct_evidence_required: bool
    direct_finalization_ready: bool
    direct_source_preparation_incomplete: bool
    reconciled: bool = False
    recovery_anchor_present: bool = False
    finalization_attempt_count: int = 0


@dataclass(frozen=True)
class AttemptInventory:
    entries: frozenset[str]
    source: Path | None
    finalization_runs: tuple[Path, ...]
    finalization_logical_bytes: int
    direct_publish_ready: Path | None
    final_exists: bool
    receipt_exists: bool
    receipt_pending_exists: bool


@dataclass(frozen=True)
class PreparedAttempt:
    context: TransactionContext
    work: Path
    work_app: Path
    archive: Path
    archive_manifest: Path
    archive_metadata: dict[str, str]
    archive_sha256: str
    archive_size: int
    pre_staple_app_sha256: str
    attempt_id: str
    intent: dict[str, Any]
    intent_path: Path
    intent_sha256: str
    submission_id: str
    submission_receipt: dict[str, Any]
    submission_receipt_path: Path
    recovery_intent: dict[str, Any] | None
    recovery_intent_path: Path | None
    recovery_continuation: dict[str, Any] | None
    recovery_continuation_path: Path | None
    recovery_tool_repository: Path | None
    recovery_tool_identity: dict[str, str] | None
    recovery_tool_identity_reader: SourceIdentityReader | None


@dataclass(frozen=True)
class PublishedTransactionEvidence:
    receipt: dict[str, Any]
    receipt_path: Path
    prepared_at: str


@dataclass(frozen=True)
class RecoverableAttempt:
    context: TransactionContext
    work: Path
    work_app: Path
    archive: Path
    archive_manifest: Path
    archive_metadata: dict[str, str]
    archive_sha256: str
    archive_size: int
    pre_staple_app_sha256: str
    attempt_id: str
    intent: dict[str, Any]
    intent_path: Path
    intent_sha256: str
    journal: EventJournal
    submit_window_start: datetime
    submit_window_end: datetime
    submit_window_end_rendered: str
    prior_event_sha256: str
    recovery_event_start: int
    journal_submission_id: str | None
    observed_submission_id: str | None
    submission_observation_sha256: str | None
    existing_submission_receipt: dict[str, Any] | None
    existing_submission_receipt_path: Path | None
    direct_finalization_ready: bool
    direct_source_preparation_incomplete: bool


@dataclass(frozen=True)
class TransactionContext:
    repository: Path
    build_kind: str
    build_number: str
    staged_app: Path | None
    native_products: Path
    notary_profile: str
    repository_commit: str
    release_source_sha256: str
    deployment_target: str
    toolchain_metadata: dict[str, str]

    @property
    def candidate_base(self) -> Path:
        return self.repository / "target/candidates/0.4.0"

    @property
    def build_root(self) -> Path:
        if self.build_kind == "validation":
            return self.candidate_base / "validation" / self.build_number
        return self.candidate_base / "release-build" / self.build_number

    @property
    def attempt_root(self) -> Path:
        return (
            self.candidate_base
            / "notary-attempts"
            / self.build_kind
            / self.build_number
        )

    @property
    def final_root(self) -> Path:
        if self.build_kind == "validation":
            return self.build_root / "signed"
        return self.candidate_base / "signed"

    @property
    def artifact_kind(self) -> str:
        if self.build_kind == "validation":
            return "notarized-validation-candidate-v1"
        return "notarized-release-v1"

    @property
    def archive_name(self) -> str:
        return f"Clash.for.Mac_{VERSION}_{self.build_number}_notary.zip"

    @property
    def source_identity(self) -> dict[str, str]:
        return {
            "repositoryCommit": self.repository_commit,
            "releaseSourceSha256": self.release_source_sha256,
        }


CommandRunner = Callable[[CommandRole, list[str], float], CommandResult]
ArchiveBuilder = Callable[[Path, Path], None]
ArchiveValidator = Callable[[Path, Path], None]
GatekeeperCapture = Callable[[Path, str], dict[str, Any]]
ManifestWriter = Callable[[Path, Path, dict[str, str]], None]
ManifestVerifier = Callable[[Path, Path, dict[str, str]], None]
SourceIdentityReader = Callable[[Path], dict[str, str]]
ToolchainMetadataReader = Callable[[Path], dict[str, str]]
Publisher = Callable[[Path, Path], None]
Clock = Callable[[], str]
AttemptIdFactory = Callable[[], str]
HostSystemIdentityReader = Callable[[], HostSystemIdentity]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON field: {key}")
        value[key] = child
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def _transaction_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _hash_regular_file(path: Path) -> tuple[str, int]:
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise TransactionError(
            "unsafe_file",
            f"transaction file must be a single-link regular file: {path.name}",
        )
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _transaction_file_identity(metadata) != _transaction_file_identity(opened):
            raise TransactionError("file_race", f"file changed while opening: {path.name}")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise TransactionError(
                "unsafe_file", f"opened transaction file is unsafe: {path.name}"
            )
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise TransactionError(
                    "file_race", f"file changed while hashing: {path.name}"
                )
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TransactionError(
                "file_race", f"file changed while hashing: {path.name}"
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _transaction_file_identity(opened) != _transaction_file_identity(after)
        or after.st_nlink != 1
    ):
        raise TransactionError("file_race", f"file changed while hashing: {path.name}")
    try:
        rebound = os.lstat(path)
    except OSError as error:
        raise TransactionError(
            "file_race", f"file changed after hashing: {path.name}"
        ) from error
    if _transaction_file_identity(opened) != _transaction_file_identity(rebound):
        raise TransactionError("file_race", f"file changed after hashing: {path.name}")
    return digest.hexdigest(), opened.st_size


def _sha256_file(path: Path) -> str:
    return _hash_regular_file(path)[0]


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_regular_file(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TransactionError(
                "unsafe_fsync_target", f"fsync target is not a regular file: {path.name}"
            )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _exclusive_recovery_lock(path: Path) -> Iterator[None]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TransactionError(
            "recovery_lock_failed", "cannot open the recovery intent lock"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TransactionError(
                "unsafe_recovery_lock",
                "recovery intent lock is not a private single-link regular file",
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise TransactionError(
                "recovery_in_progress",
                "another process is already recovering this notarization attempt",
            ) from error
        rebound = os.lstat(path)
        if _transaction_file_identity(metadata) != _transaction_file_identity(rebound):
            raise TransactionError(
                "recovery_lock_race", "recovery intent changed while locking"
            )
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextmanager
def _exclusive_attempt_recovery_lock(context: TransactionContext) -> Iterator[None]:
    canonical_build_version(context.build_number, "build number")
    lock_parent = context.attempt_root.parent
    _require_real_directory(lock_parent, trusted=True)
    lock_path = lock_parent / f".{context.build_number}.recovery.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise TransactionError(
            "recovery_lock_failed",
            "cannot create or open the attempt recovery lock",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        rebound = os.lstat(lock_path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or _transaction_file_identity(metadata)
            != _transaction_file_identity(rebound)
        ):
            raise TransactionError(
                "unsafe_recovery_lock",
                "attempt recovery lock is not a private single-link regular file",
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise TransactionError(
                "recovery_in_progress",
                "another process is already recovering this notarization attempt",
            ) from error
        rebound_after_lock = os.lstat(lock_path)
        if _transaction_file_identity(metadata) != _transaction_file_identity(
            rebound_after_lock
        ):
            raise TransactionError(
                "recovery_lock_race",
                "attempt recovery lock changed while acquiring it",
            )
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _serialize_recovery(function: Callable[..., Path]) -> Callable[..., Path]:
    @wraps(function)
    def serialized(
        context: TransactionContext,
        *args: Any,
        **kwargs: Any,
    ) -> Path:
        with _exclusive_attempt_recovery_lock(context):
            return function(context, *args, **kwargs)

    return serialized


def _fsync_tree(root: Path) -> None:
    _require_real_directory(root, private=True)
    directories: list[Path] = []

    def walk_error(error: OSError) -> None:
        raise TransactionError(
            "publish_tree_walk_failed", "cannot enumerate the complete publish tree"
        ) from error

    for current, names, files in os.walk(
        root,
        topdown=True,
        onerror=walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        directories.append(current_path)
        names[:] = [
            name
            for name in names
            if not (current_path / name).is_symlink()
        ]
        for name in files:
            path = current_path / name
            metadata = os.lstat(path)
            if stat.S_ISREG(metadata.st_mode):
                _fsync_regular_file(path)
            elif not stat.S_ISLNK(metadata.st_mode):
                raise TransactionError(
                    "unsafe_publish_entry",
                    f"publish tree contains an unsupported entry: {path.name}",
                )
    for directory in reversed(directories):
        _fsync_directory(directory)


def _require_real_directory(
    path: Path,
    *,
    private: bool = False,
    trusted: bool = False,
) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise TransactionError("missing_directory", f"directory is absent: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise TransactionError("unsafe_directory", f"path is not a real directory: {path}")
    if trusted or private:
        if metadata.st_uid != os.geteuid():
            raise TransactionError("unsafe_owner", f"directory owner differs: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise TransactionError(
                "unsafe_mode", f"directory is group/world writable: {path}"
            )
    if private:
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise TransactionError("unsafe_mode", f"private directory mode is not 0700: {path}")


def _mkdir_private(path: Path, *, exclusive: bool) -> None:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError as error:
        if exclusive:
            raise TransactionError(
                "attempt_exists",
                "this lane/build already has a notarization attempt and must not be resubmitted",
            ) from error
        _require_real_directory(path, private=True)
        return
    except OSError as error:
        raise TransactionError(
            "mkdir_failed", f"cannot create private directory: {path}"
        ) from error
    _require_real_directory(path, private=True)
    _fsync_directory(path.parent)


def _write_json_exclusive(path: Path, value: object) -> None:
    encoded = _canonical_json(value)
    try:
        write_new_manifest(path, encoded)
    except (OSError, ValueError) as error:
        raise TransactionError(
            "evidence_write_failed", f"cannot persist transaction evidence: {path.name}"
        ) from error


def _read_private_pending_bytes(path: Path) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise TransactionError(
            "pending_evidence_missing",
            f"pending evidence is absent: {path.name}",
        ) from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size > MAX_JSON_BYTES
    ):
        raise TransactionError(
            "unsafe_pending_evidence",
            f"pending evidence is not a private single-link file: {path.name}",
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TransactionError(
            "unsafe_pending_evidence",
            f"pending evidence cannot be opened safely: {path.name}",
        ) from error
    try:
        opened = os.fstat(descriptor)
        if _transaction_file_identity(before) != _transaction_file_identity(opened):
            raise TransactionError(
                "pending_evidence_race",
                f"pending evidence changed while opening: {path.name}",
            )
        remaining = opened.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise TransactionError(
                    "pending_evidence_race",
                    f"pending evidence changed while reading: {path.name}",
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TransactionError(
                "pending_evidence_race",
                f"pending evidence grew while reading: {path.name}",
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        rebound = os.lstat(path)
    except OSError as error:
        raise TransactionError(
            "pending_evidence_race",
            f"pending evidence disappeared while reading: {path.name}",
        ) from error
    if (
        _transaction_file_identity(opened) != _transaction_file_identity(after)
        or _transaction_file_identity(opened)
        != _transaction_file_identity(rebound)
    ):
        raise TransactionError(
            "pending_evidence_race",
            f"pending evidence changed while reading: {path.name}",
        )
    return b"".join(chunks)


def _write_private_pending(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise TransactionError(
            "pending_evidence_write_failed",
            f"cannot create pending evidence: {path.name}",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TransactionError(
                "unsafe_pending_evidence",
                f"new pending evidence is unsafe: {path.name}",
            )
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError(errno.EIO, "short pending evidence write")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        raise
    finally:
        os.close(descriptor)


def _rename_exclusive_no_follow(source: Path, destination: Path) -> None:
    if sys.platform != "darwin":
        raise TransactionError(
            "unsupported_atomic_evidence_platform",
            "atomic evidence publication requires macOS renamex_np",
        )
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(
        os.fsencode(source),
        os.fsencode(destination),
        RENAME_EXCL | RENAME_NOFOLLOW_ANY,
    )
    if result != 0:
        code = ctypes.get_errno()
        failure_code = (
            "atomic_evidence_destination_exists"
            if code == errno.EEXIST
            else "atomic_evidence_rename_failed"
        )
        raise TransactionError(
            failure_code,
            f"cannot atomically publish evidence: {destination.name}",
        )


def _discard_partial_pending(path: Path) -> None:
    before = os.lstat(path)
    _read_private_pending_bytes(path)
    rebound = os.lstat(path)
    if _transaction_file_identity(before) != _transaction_file_identity(rebound):
        raise TransactionError(
            "pending_evidence_race",
            f"pending evidence changed before cleanup: {path.name}",
        )
    try:
        os.unlink(path)
        _fsync_directory(path.parent)
    except OSError as error:
        raise TransactionError(
            "pending_evidence_cleanup_failed",
            f"cannot remove incomplete pending evidence: {path.name}",
        ) from error


def _publish_pending_evidence(
    *,
    pending_path: Path,
    destination_path: Path,
    data: bytes,
    allow_partial_rebuild: bool,
) -> None:
    if os.path.lexists(destination_path):
        raise TransactionError(
            "atomic_evidence_destination_exists",
            f"evidence destination already exists: {destination_path.name}",
        )
    if os.path.lexists(pending_path):
        pending_data = _read_private_pending_bytes(pending_path)
        if pending_data != data:
            if not allow_partial_rebuild:
                raise TransactionError(
                    "pending_evidence_identity_drift",
                    f"pending evidence differs: {pending_path.name}",
                )
            if pending_data:
                try:
                    _decode_json_bytes(pending_data, pending_path)
                except TransactionError:
                    pass
                else:
                    raise TransactionError(
                        "pending_evidence_identity_drift",
                        f"complete pending JSON differs: {pending_path.name}",
                    )
            _discard_partial_pending(pending_path)
    if not os.path.lexists(pending_path):
        try:
            _write_private_pending(pending_path, data)
        except TransactionError:
            raise
        except OSError as error:
            raise TransactionError(
                "pending_evidence_write_failed",
                f"cannot write pending evidence: {pending_path.name}",
            ) from error
    if _read_private_pending_bytes(pending_path) != data:
        raise TransactionError(
            "pending_evidence_identity_drift",
            f"pending evidence differs before publication: {pending_path.name}",
        )
    _rename_exclusive_no_follow(pending_path, destination_path)
    try:
        _fsync_directory(destination_path.parent)
    except OSError as error:
        raise TransactionError(
            "atomic_evidence_durability_unknown",
            f"evidence was renamed but directory durability is unknown: {destination_path.name}",
            terminal_state="outcome_unknown",
        ) from error


def _read_regular_bytes(path: Path, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise TransactionError("evidence_missing", f"evidence is absent: {path.name}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise TransactionError(
            "unsafe_evidence", f"evidence is not a bounded regular file: {path.name}"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _transaction_file_identity(before) != _transaction_file_identity(opened):
            raise TransactionError("evidence_race", f"evidence changed: {path.name}")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise TransactionError("unsafe_evidence", f"opened evidence is unsafe: {path.name}")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _transaction_file_identity(opened) != _transaction_file_identity(after)
        or after.st_nlink != 1
    ):
        raise TransactionError("evidence_race", f"evidence changed: {path.name}")
    if len(data) != opened.st_size or len(data) > maximum:
        raise TransactionError("evidence_race", f"evidence size changed: {path.name}")
    try:
        rebound = os.lstat(path)
    except OSError as error:
        raise TransactionError(
            "evidence_race", f"evidence changed after reading: {path.name}"
        ) from error
    if _transaction_file_identity(opened) != _transaction_file_identity(rebound):
        raise TransactionError(
            "evidence_race", f"evidence changed after reading: {path.name}"
        )
    return bytes(data)


def _decode_json_bytes(data: bytes, path: Path) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (UnicodeError, json.JSONDecodeError, DuplicateKeyError) as error:
        raise TransactionError(
            "invalid_evidence_json", f"evidence is not strict UTF-8 JSON: {path.name}"
        ) from error


def _read_exact_json_document(
    path: Path,
    expected: dict[str, Any],
    *,
    drift_code: str,
    drift_message: str,
) -> tuple[dict[str, Any], str]:
    data = _read_regular_bytes(path)
    expected_data = _canonical_json(expected).encode("utf-8")
    if data != expected_data:
        raise TransactionError(drift_code, drift_message)
    value = _decode_json_bytes(data, path)
    if not isinstance(value, dict) or value != expected:
        raise TransactionError(drift_code, drift_message)
    return value, hashlib.sha256(data).hexdigest()


def _parse_command_json(output: str) -> Any:
    try:
        encoded = output.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise TransactionError("invalid_command_output", "command output is not UTF-8") from error
    if not encoded or len(encoded) > MAX_COMMAND_OUTPUT_BYTES or b"\0" in encoded:
        raise TransactionError("invalid_command_output", "command output is empty or oversized")
    try:
        return json.loads(output, object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, DuplicateKeyError) as error:
        raise TransactionError(
            "invalid_command_output", "command output is not strict JSON"
        ) from error


def _canonical_uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise TransactionError("invalid_submission_id", f"{label} is not a UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise TransactionError("invalid_submission_id", f"{label} is not a UUID") from error
    if str(parsed) != value:
        raise TransactionError("invalid_submission_id", f"{label} is not canonical UUID text")
    return value


def _bounded_command_string(
    value: object,
    label: str,
    *,
    maximum: int = 4096,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\0" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TransactionError(
            "invalid_notary_response", f"notarytool {label} is malformed"
        )
    return value


def _parse_utc_timestamp(value: object, label: str) -> tuple[str, datetime]:
    rendered = _bounded_command_string(value, label, maximum=64)
    if not rendered.endswith("Z"):
        raise TransactionError(
            "invalid_notary_response", f"notarytool {label} is not UTC"
        )
    try:
        parsed = datetime.fromisoformat(rendered[:-1] + "+00:00")
    except ValueError as error:
        raise TransactionError(
            "invalid_notary_response",
            f"notarytool {label} is not ISO-8601",
        ) from error
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise TransactionError(
            "invalid_notary_response", f"notarytool {label} is not UTC"
        )
    return rendered, parsed


def _timestamp_within_recorded_window(
    value: datetime,
    *,
    window_start: datetime,
    window_end: datetime,
    window_end_rendered: str,
) -> bool:
    if value < window_start:
        return False
    if "." not in window_end_rendered:
        return value < window_end + timedelta(seconds=1)
    return value <= window_end


def _parse_notary_submit_response(output: str, archive: Path) -> str:
    value = _parse_command_json(output)
    if not isinstance(value, dict) or set(value) != {"id", "message", "path"}:
        raise TransactionError(
            "invalid_notary_response",
            "notarytool submit response has an unexpected field set",
        )
    if value["message"] != _SUBMIT_SUCCESS_MESSAGE:
        raise TransactionError(
            "invalid_notary_response",
            "notarytool submit response did not confirm a completed upload",
        )
    response_path = _bounded_command_string(value["path"], "submit path")
    if response_path != str(archive):
        raise TransactionError(
            "notary_submit_path_mismatch",
            "notarytool submit response path differs from the exact archive",
        )
    return _canonical_uuid(value["id"], "notarytool submission id")


def _project_notary_submit_identity(output: str, archive: Path) -> str:
    value = _parse_command_json(output)
    if not isinstance(value, dict) or not {"id", "path"}.issubset(value):
        raise TransactionError(
            "invalid_notary_response",
            "notarytool submit response lacks a safely projectable identity",
        )
    response_path = _bounded_command_string(value["path"], "submit path")
    if response_path != str(archive):
        raise TransactionError(
            "notary_submit_path_mismatch",
            "notarytool submit response path differs from the exact archive",
        )
    return _canonical_uuid(value["id"], "notarytool submission id")


def _parse_notary_wait_response(
    output: str,
    *,
    allowed_statuses: set[str],
) -> tuple[str, str]:
    value = _parse_command_json(output)
    if not isinstance(value, dict) or set(value) != {"id", "message", "status"}:
        raise TransactionError(
            "invalid_notary_response",
            "notarytool wait response has an unexpected field set",
        )
    message = _bounded_command_string(value["message"], "wait message")
    status_value = value["status"]
    if not isinstance(status_value, str) or status_value not in allowed_statuses:
        raise TransactionError("invalid_notary_status", "notarytool status is unsupported")
    if status_value in {"Accepted", "Invalid", "Rejected"} and message != _WAIT_COMPLETE_MESSAGE:
        raise TransactionError(
            "invalid_notary_response",
            "notarytool wait terminal response has an unexpected message",
        )
    return _canonical_uuid(value["id"], "notarytool submission id"), status_value


def _parse_notary_info_response(
    output: str,
    *,
    submission_id: str,
    archive_name: str,
    allowed_statuses: set[str],
) -> tuple[str, str]:
    value = _parse_command_json(output)
    if not isinstance(value, dict) or set(value) != {
        "createdDate",
        "id",
        "message",
        "name",
        "status",
    }:
        raise TransactionError(
            "invalid_notary_response",
            "notarytool info response has an unexpected field set",
        )
    if value["message"] != _INFO_SUCCESS_MESSAGE:
        raise TransactionError(
            "invalid_notary_response",
            "notarytool info response has an unexpected message",
        )
    observed_id = _canonical_uuid(value["id"], "notarytool info submission id")
    if observed_id != submission_id:
        raise TransactionError(
            "submission_id_mismatch",
            "notarytool info returned a different submission id",
        )
    if value["name"] != archive_name:
        raise TransactionError(
            "notary_info_archive_mismatch",
            "notarytool info archive name differs from the retained archive",
        )
    status_value = value["status"]
    if not isinstance(status_value, str) or status_value not in allowed_statuses:
        raise TransactionError("invalid_notary_status", "notarytool info status is unsupported")
    created_at, _ = _parse_utc_timestamp(value["createdDate"], "info createdDate")
    return status_value, created_at


def _require_unique_history_binding(
    output: str,
    *,
    submission_id: str,
    archive_name: str,
    window_start: datetime,
    window_end: datetime,
    window_end_rendered: str,
    info_created_at: str,
) -> None:
    value = _parse_command_json(output)
    if not isinstance(value, dict) or set(value) != {"history", "message"}:
        raise TransactionError(
            "invalid_notary_response",
            "notarytool history response has an unexpected field set",
        )
    if value["message"] != _HISTORY_SUCCESS_MESSAGE:
        raise TransactionError(
            "invalid_notary_response",
            "notarytool history response has an unexpected message",
        )
    history = value["history"]
    if not isinstance(history, list) or not history or len(history) > 100:
        raise TransactionError(
            "invalid_notary_response", "notarytool history is malformed"
        )
    candidates: list[tuple[str, str, str]] = []
    identifiers: set[str] = set()
    previous_created: datetime | None = None
    oldest_created: datetime | None = None
    for entry in history:
        if not isinstance(entry, dict) or set(entry) != {
            "createdDate",
            "id",
            "name",
            "status",
        }:
            raise TransactionError(
                "invalid_notary_response",
                "notarytool history entry has an unexpected field set",
            )
        identifier = _canonical_uuid(entry["id"], "notarytool history submission id")
        if identifier in identifiers:
            raise TransactionError(
                "invalid_notary_response",
                "notarytool history contains a duplicate submission id",
            )
        identifiers.add(identifier)
        name = _bounded_command_string(entry["name"], "history name")
        status_value = entry["status"]
        if status_value not in {"In Progress", "Accepted", "Invalid", "Rejected"}:
            raise TransactionError(
                "invalid_notary_status", "notarytool history status is unsupported"
            )
        created_at, created = _parse_utc_timestamp(
            entry["createdDate"], "history createdDate"
        )
        if previous_created is not None and created > previous_created:
            raise TransactionError(
                "invalid_notary_response",
                "notarytool history is not ordered newest first",
            )
        previous_created = created
        oldest_created = created
        if name == archive_name and _timestamp_within_recorded_window(
            created,
            window_start=window_start,
            window_end=window_end,
            window_end_rendered=window_end_rendered,
        ):
            candidates.append((identifier, created_at, status_value))
    if (
        len(history) == 100
        and oldest_created is not None
        and oldest_created >= window_start
    ):
        raise TransactionError(
            "submission_causal_binding_unproven",
            "notarytool history does not cover the complete submit window",
        )
    if candidates != [(submission_id, info_created_at, "Accepted")]:
        raise TransactionError(
            "submission_causal_binding_unproven",
            "notarytool history does not uniquely bind the recovery id to the submit window",
        )


def _run_bounded_process(
    command: list[str],
    timeout: float,
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
) -> CommandResult:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise TransactionError(
            "command_start_failed",
            "release command could not start",
        ) from error
    if process.stdout is None or process.stderr is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise TransactionError("command_pipe_failed", "release command pipes are absent")
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    selector = selectors.DefaultSelector()
    buffers = {
        stdout_fd: bytearray(),
        stderr_fd: bytearray(),
    }
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransactionError(
                    "command_timeout", "release command exceeded its time limit"
                )
            for key, _events in selector.select(min(remaining, 1.0)):
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.fd].extend(chunk)
                if sum(len(buffer) for buffer in buffers.values()) > MAX_COMMAND_OUTPUT_BYTES:
                    raise TransactionError(
                        "command_output_oversized",
                        "release command output exceeded the safety limit",
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransactionError(
                "command_timeout", "release command exceeded its time limit"
            )
        returncode = process.wait(timeout=remaining)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            os.killpg(process.pid, signal.SIGKILL)
            raise TransactionError(
                "command_descendant_survived",
                "release command left a descendant process running",
            )
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise TransactionError(
            "command_timeout", "release command exceeded its time limit"
        ) from error
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    try:
        stdout = bytes(buffers[stdout_fd]).decode("utf-8", errors="strict")
        stderr = bytes(buffers[stderr_fd]).decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise TransactionError(
            "command_output_invalid_utf8", "release command output is not UTF-8"
        ) from error
    return CommandResult(returncode, stdout, stderr)


def production_command_runner(
    _role: CommandRole,
    command: list[str],
    timeout: float,
) -> CommandResult:
    return _run_bounded_process(command, timeout)


def production_archive_builder(app: Path, archive: Path) -> None:
    if app.parent != archive.parent:
        raise TransactionError(
            "unsafe_archive_path",
            "notarization archive must share the signed app staging directory",
        )
    if os.path.lexists(archive):
        raise TransactionError(
            "archive_exists",
            "notarization archive destination already exists",
        )
    environment = dict(os.environ)
    environment["COPYFILE_DISABLE"] = "1"
    try:
        completed = _run_bounded_process(
            [
                "/usr/bin/ditto",
                "-c",
                "-k",
                "--keepParent",
                "--norsrc",
                "--noextattr",
                "--noqtn",
                "--noacl",
                app.name,
                archive.name,
            ],
            cwd=app.parent,
            timeout=1800,
            environment=environment,
        )
    except TransactionError as error:
        raise TransactionError(
            "archive_creation_failed", "notarization archive creation did not complete"
        ) from error
    if completed.returncode != 0:
        raise TransactionError(
            "archive_creation_failed",
            "notarization archive creation failed",
            exit_code=completed.returncode,
        )
    os.chmod(archive, 0o600, follow_symlinks=False)
    _fsync_directory(archive.parent)


def production_archive_validator(archive: Path, app: Path) -> None:
    try:
        validate_notarization_zip(archive, app)
    except (NotaryArchiveError, OSError) as error:
        raise TransactionError(
            "archive_validation_failed",
            "notarization archive differs from the signed application",
        ) from error


def _read_exact_system_identity_value(
    command: list[str],
    label: str,
) -> str:
    result = _run_bounded_process(command, 30)
    if result.returncode != 0 or result.stderr:
        raise TransactionError(
            "host_system_identity_unavailable",
            f"cannot read the release host {label}",
            exit_code=result.returncode,
        )
    if (
        not result.stdout.endswith("\n")
        or result.stdout.count("\n") != 1
        or len(result.stdout) > 256
        or "\0" in result.stdout
    ):
        raise TransactionError(
            "host_system_identity_invalid",
            f"release host {label} is malformed",
        )
    value = result.stdout[:-1]
    if not value or any(character.isspace() for character in value):
        raise TransactionError(
            "host_system_identity_invalid",
            f"release host {label} is malformed",
        )
    return value


def production_host_system_identity_reader() -> HostSystemIdentity:
    return HostSystemIdentity(
        product_name=_read_exact_system_identity_value(
            ["/usr/bin/sw_vers", "-productName"], "product name"
        ),
        product_version=_read_exact_system_identity_value(
            ["/usr/bin/sw_vers", "-productVersion"], "product version"
        ),
        build_version=_read_exact_system_identity_value(
            ["/usr/bin/sw_vers", "-buildVersion"], "build version"
        ),
        kernel_name=_read_exact_system_identity_value(
            ["/usr/bin/uname", "-s"], "kernel name"
        ),
        kernel_release=_read_exact_system_identity_value(
            ["/usr/bin/uname", "-r"], "kernel release"
        ),
        architecture=_read_exact_system_identity_value(
            ["/usr/bin/uname", "-m"], "architecture"
        ),
    )


def production_gatekeeper_capture(app: Path, tree_sha256: str) -> dict[str, Any]:
    if _app_tree_sha256(
        app,
        failure_code="gatekeeper_target_mismatch",
        failure_message="Gatekeeper target identity cannot be derived before capture",
    ) != tree_sha256:
        raise TransactionError(
            "gatekeeper_target_mismatch",
            "Gatekeeper target changed before evidence capture",
        )
    core = capture_gatekeeper(
        app,
        "execute",
        primary_signature_context=False,
    )
    if core.get("target_signed_app_tree_sha256") != tree_sha256:
        raise TransactionError(
            "gatekeeper_target_mismatch",
            "Gatekeeper capture differs from the independently derived app identity",
        )
    if _app_tree_sha256(
        app,
        failure_code="gatekeeper_target_mismatch",
        failure_message="Gatekeeper target identity cannot be derived after capture",
    ) != tree_sha256:
        raise TransactionError(
            "gatekeeper_target_mismatch",
            "Gatekeeper target changed during evidence capture",
        )
    return validate_gatekeeper_evidence(
        {
            **core,
            "captured_at": _utc_now(),
        },
        expected_assessment_type="execute",
        expected_primary_signature_context=False,
        expected_target=app,
    )


def production_manifest_writer(
    artifact: Path,
    manifest: Path,
    metadata: dict[str, str],
) -> None:
    try:
        document = build_manifest(
            artifact,
            metadata,
            algorithm="sha256-tree-v2",
        )
        write_new_manifest(manifest, json.dumps(document, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError) as error:
        raise TransactionError(
            "manifest_write_failed", f"cannot write artifact manifest: {manifest.name}"
        ) from error


def production_manifest_verifier(
    artifact: Path,
    manifest: Path,
    metadata: dict[str, str],
) -> None:
    try:
        manifest_bytes = _read_regular_bytes(manifest, MAX_MANIFEST_BYTES)
        value = _decode_json_bytes(manifest_bytes, manifest)
        if not isinstance(value, dict) or value.get("algorithm") != "sha256-tree-v2":
            raise TransactionError(
                "manifest_verification_failed",
                f"artifact manifest is not sha256-tree-v2: {manifest.name}",
            )
        actual = build_manifest(
            artifact,
            metadata,
            algorithm="sha256-tree-v2",
        )
    except TransactionError:
        raise
    except (OSError, ValueError) as error:
        raise TransactionError(
            "manifest_verification_failed",
            f"cannot verify artifact manifest: {manifest.name}",
        ) from error
    if value != actual:
        raise TransactionError(
            "manifest_verification_failed",
            f"artifact manifest differs from the exact artifact: {manifest.name}",
        )
    if _read_regular_bytes(manifest, MAX_MANIFEST_BYTES) != manifest_bytes:
        raise TransactionError(
            "manifest_verification_failed",
            f"artifact manifest changed during verification: {manifest.name}",
        )


def _run_manifest_verification_barrier(
    configured_verifier: ManifestVerifier,
    verifications: tuple[tuple[Path, Path, dict[str, str]], ...],
) -> None:
    _run_configured_manifest_verification_hooks(
        configured_verifier,
        verifications,
    )
    _run_production_manifest_verifications(verifications)


def _run_configured_manifest_verification_hooks(
    configured_verifier: ManifestVerifier,
    verifications: tuple[tuple[Path, Path, dict[str, str]], ...],
) -> None:
    if configured_verifier is not production_manifest_verifier:
        for artifact, manifest, metadata in verifications:
            configured_verifier(artifact, manifest, metadata)


def _run_production_manifest_verifications(
    verifications: tuple[tuple[Path, Path, dict[str, str]], ...],
) -> None:
    for artifact, manifest, metadata in verifications:
        production_manifest_verifier(artifact, manifest, metadata)


def _app_tree_sha256(
    app: Path,
    *,
    failure_code: str,
    failure_message: str,
) -> str:
    try:
        value = build_manifest(app, algorithm="sha256-tree-v2")["sha256"]
    except (OSError, ValueError) as error:
        raise TransactionError(failure_code, failure_message) from error
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise TransactionError(failure_code, failure_message)
    return value


def production_source_identity_reader(repository: Path) -> dict[str, str]:
    return current_identity(repository, require_clean=True)


def production_toolchain_metadata_reader(repository: Path) -> dict[str, str]:
    return derive_candidate_toolchain_metadata(repository)


def publish_exclusive(source: Path, destination: Path) -> None:
    if not source.is_absolute() or not destination.is_absolute():
        raise TransactionError("unsafe_publish_path", "publish paths must be absolute")
    _require_real_directory(source, private=True)
    _require_real_directory(destination.parent, trusted=True)
    if os.path.lexists(destination):
        raise TransactionError("publish_destination_exists", "signed output already exists")
    source_parent = source.parent
    if os.lstat(source).st_dev != os.lstat(destination.parent).st_dev:
        raise TransactionError("cross_device_publish", "atomic publication requires one volume")
    if sys.platform != "darwin":
        raise TransactionError("unsupported_publish_platform", "RENAME_EXCL requires macOS")
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(
        os.fsencode(source),
        os.fsencode(destination),
        RENAME_EXCL | RENAME_NOFOLLOW_ANY,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            failure = "publish_destination_exists"
        elif code == errno.EXDEV:
            failure = "cross_device_publish"
        else:
            failure = "atomic_publish_failed"
        raise TransactionError(failure, "exclusive atomic directory publication failed")
    try:
        _fsync_directory(destination.parent)
        if source_parent != destination.parent:
            _fsync_directory(source_parent)
    except OSError as error:
        raise TransactionError(
            "publish_durability_unknown",
            "signed output was atomically published but parent durability is unconfirmed",
            terminal_state="outcome_unknown",
        ) from error


def confirm_published_tree_durable(source: Path, destination: Path) -> None:
    """Close an atomic-rename durability ambiguity without assuming its reply.

    A successful re-read proves bytes, not crash durability.  Confirmation
    therefore requires the source name to be gone, the complete destination
    tree to be fsynced, and both directory entries participating in a
    cross-parent rename to be fsynced before a caller may report success.
    """
    if not source.is_absolute() or not destination.is_absolute():
        raise TransactionError(
            "unsafe_publish_path", "durability confirmation paths must be absolute"
        )
    if os.path.lexists(source) or not os.path.lexists(destination):
        raise TransactionError(
            "publish_result_ambiguous",
            "atomic publication did not leave exactly one destination tree",
            terminal_state="outcome_unknown",
        )
    try:
        _fsync_tree(destination)
        _fsync_directory(destination.parent)
        if source.parent != destination.parent:
            _fsync_directory(source.parent)
    except OSError as error:
        raise TransactionError(
            "publish_durability_unknown",
            "published tree or rename directories could not be made durable",
            terminal_state="outcome_unknown",
        ) from error


def _validate_event_document(
    value: Any,
    data: bytes,
    *,
    sequence: int,
    previous_sha256: str | None,
    intent_sha256: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TransactionError(
            "event_journal_identity_drift",
            "notarization event has an unexpected field set",
        )
    if (
        type(value.get("schema_version")) is int
        and value.get("schema_version") == 1
        and value.get("document") == EVENT_DOCUMENT
        and set(value) == EVENT_FIELDS
    ):
        evidence_sha256 = None
    elif (
        type(value.get("schema_version")) is int
        and value.get("schema_version") == 2
        and value.get("document") == EVENT_DOCUMENT_V2
        and set(value) == EVENT_V2_FIELDS
        and value.get("state") in EVIDENCE_EVENT_STATES
        and isinstance(value.get("evidence_sha256"), str)
        and SHA256_RE.fullmatch(value["evidence_sha256"])
    ):
        evidence_sha256 = value["evidence_sha256"]
    else:
        raise TransactionError(
            "event_journal_identity_drift",
            "notarization event has an unexpected schema or field set",
        )
    if data != _canonical_json(value).encode("utf-8"):
        raise TransactionError(
            "event_journal_identity_drift",
            "notarization event is not canonical JSON",
        )
    if (
        value["sequence"] != sequence
        or isinstance(value["sequence"], bool)
        or value["previous_event_sha256"] != previous_sha256
        or value["intent_sha256"] != intent_sha256
    ):
        raise TransactionError(
            "event_journal_identity_drift",
            "notarization event chain is inconsistent",
        )
    state = value["state"]
    if (
        not isinstance(state, str)
        or not state
        or len(state) > 128
        or not re.fullmatch(r"[a-z0-9_-]+", state)
    ):
        raise TransactionError(
            "event_journal_identity_drift",
            "notarization event state is malformed",
        )
    _parse_utc_timestamp(value["recorded_at"], "event recorded_at")
    event_submission_id = value["submission_id"]
    if event_submission_id is not None:
        _canonical_uuid(event_submission_id, "event submission id")
    failure_code = value["failure_code"]
    if failure_code is not None and (
        not isinstance(failure_code, str)
        or not failure_code
        or len(failure_code) > 128
        or not re.fullmatch(r"[a-z0-9_-]+", failure_code)
    ):
        raise TransactionError(
            "event_journal_identity_drift",
            "notarization event failure code is malformed",
        )
    exit_code = value["exit_code"]
    if exit_code is not None and (
        not isinstance(exit_code, int) or isinstance(exit_code, bool)
    ):
        raise TransactionError(
            "event_journal_identity_drift",
            "notarization event exit code is malformed",
        )
    if evidence_sha256 is not None and (
        failure_code is not None or exit_code is not None
    ):
        raise TransactionError(
            "event_journal_identity_drift",
            "evidence-bound notarization event contains terminal fields",
        )
    return value


class EventJournal:
    def __init__(self, directory: Path, intent_sha256: str, clock: Clock) -> None:
        self.directory = directory
        self.intent_sha256 = intent_sha256
        self.clock = clock
        self.sequence = 0
        self.previous_event_sha256: str | None = None
        self.documents: list[dict[str, Any]] = []

    @classmethod
    def load_existing(
        cls,
        directory: Path,
        intent_sha256: str,
        clock: Clock,
    ) -> EventJournal:
        _require_real_directory(directory, private=True)
        try:
            names = sorted(path.name for path in directory.iterdir())
        except OSError as error:
            raise TransactionError(
                "event_journal_identity_drift",
                "cannot enumerate the notarization event journal",
            ) from error
        pending_names = [name for name in names if EVENT_PENDING_RE.fullmatch(name)]
        json_names = [name for name in names if name.endswith(".json")]
        if (
            (not json_names and not pending_names)
            or len(pending_names) > 1
            or set(names) != set(json_names) | set(pending_names)
            or json_names
            != [
                f"{sequence:08d}.json"
                for sequence in range(1, len(json_names) + 1)
            ]
            or len(json_names) + len(pending_names) > MAX_EVENT_DOCUMENTS
        ):
            raise TransactionError(
                "event_journal_identity_drift",
                "notarization event journal inventory is not contiguous",
            )
        journal = cls(directory, intent_sha256, clock)
        previous_sha256: str | None = None
        for sequence, name in enumerate(json_names, start=1):
            path = directory / name
            data = _read_regular_bytes(path)
            value = _decode_json_bytes(data, path)
            value = _validate_event_document(
                value,
                data,
                sequence=sequence,
                previous_sha256=previous_sha256,
                intent_sha256=intent_sha256,
            )
            previous_sha256 = hashlib.sha256(data).hexdigest()
            journal.sequence = sequence
            journal.previous_event_sha256 = previous_sha256
            journal.documents.append(value)
        if pending_names:
            pending_name = pending_names[0]
            match = EVENT_PENDING_RE.fullmatch(pending_name)
            if match is None:
                raise TransactionError(
                    "event_journal_identity_drift",
                    "event pending name is malformed",
                )
            pending_sequence = int(match.group(1))
            if pending_sequence != journal.sequence + 1:
                raise TransactionError(
                    "event_journal_identity_drift",
                    "event pending sequence is not the next journal sequence",
                )
            pending_path = directory / pending_name
            pending_data = _read_private_pending_bytes(pending_path)
            try:
                pending_value = _decode_json_bytes(pending_data, pending_path)
            except TransactionError:
                _discard_partial_pending(pending_path)
            else:
                pending_value = _validate_event_document(
                    pending_value,
                    pending_data,
                    sequence=pending_sequence,
                    previous_sha256=previous_sha256,
                    intent_sha256=intent_sha256,
                )
                destination = directory / f"{pending_sequence:08d}.json"
                _rename_exclusive_no_follow(pending_path, destination)
                try:
                    _fsync_directory(directory)
                except OSError as error:
                    raise TransactionError(
                        "atomic_evidence_durability_unknown",
                        "event was renamed but journal durability is unknown",
                        terminal_state="outcome_unknown",
                    ) from error
                previous_sha256 = hashlib.sha256(pending_data).hexdigest()
                journal.sequence = pending_sequence
                journal.previous_event_sha256 = previous_sha256
                journal.documents.append(pending_value)
        journal.verify()
        return journal

    def append(
        self,
        state: str,
        *,
        submission_id: str | None = None,
        failure_code: str | None = None,
        exit_code: int | None = None,
        recorded_at: str | None = None,
        evidence_sha256: str | None = None,
    ) -> None:
        next_sequence = self.sequence + 1
        if next_sequence > MAX_EVENT_DOCUMENTS:
            raise TransactionError(
                "event_journal_capacity_exceeded",
                "notarization event journal reached its bounded capacity",
            )
        if evidence_sha256 is None:
            schema_version = 1
            document_kind = EVENT_DOCUMENT
        elif (
            state not in EVIDENCE_EVENT_STATES
            or not SHA256_RE.fullmatch(evidence_sha256)
            or failure_code is not None
            or exit_code is not None
        ):
            raise TransactionError(
                "invalid_evidence_event",
                "evidence-bound event is malformed",
            )
        else:
            schema_version = 2
            document_kind = EVENT_DOCUMENT_V2
        document = {
            "schema_version": schema_version,
            "document": document_kind,
            "sequence": next_sequence,
            "previous_event_sha256": self.previous_event_sha256,
            "intent_sha256": self.intent_sha256,
            "state": state,
            "recorded_at": self.clock() if recorded_at is None else recorded_at,
            "submission_id": submission_id,
            "failure_code": failure_code,
            "exit_code": exit_code,
        }
        if evidence_sha256 is not None:
            document["evidence_sha256"] = evidence_sha256
        path = self.directory / f"{next_sequence:08d}.json"
        pending_path = self.directory / f"{next_sequence:08d}.pending"
        _publish_pending_evidence(
            pending_path=pending_path,
            destination_path=path,
            data=_canonical_json(document).encode("utf-8"),
            allow_partial_rebuild=False,
        )
        event_sha256 = _sha256_file(path)
        self.sequence = next_sequence
        self.previous_event_sha256 = event_sha256
        self.documents.append(document)

    def verify(self) -> str:
        expected_names = {
            f"{sequence:08d}.json"
            for sequence in range(1, len(self.documents) + 1)
        }
        try:
            observed_names = {path.name for path in self.directory.iterdir()}
        except OSError as error:
            raise TransactionError(
                "event_journal_identity_drift",
                "cannot enumerate the notarization event journal",
            ) from error
        if observed_names != expected_names:
            raise TransactionError(
                "event_journal_identity_drift",
                "notarization event journal inventory changed",
            )

        previous_sha256: str | None = None
        previous_recorded_at: datetime | None = None
        for sequence, expected in enumerate(self.documents, start=1):
            recorded_at = _parse_utc_timestamp(
                expected["recorded_at"],
                "event recorded_at",
            )[1]
            if (
                expected["sequence"] != sequence
                or expected["previous_event_sha256"] != previous_sha256
                or expected["intent_sha256"] != self.intent_sha256
                or (
                    previous_recorded_at is not None
                    and recorded_at < previous_recorded_at
                )
            ):
                raise TransactionError(
                    "event_journal_identity_drift",
                    "in-memory notarization event chain is inconsistent",
                )
            _, event_sha256 = _read_exact_json_document(
                self.directory / f"{sequence:08d}.json",
                expected,
                drift_code="event_journal_identity_drift",
                drift_message="notarization event journal changed",
            )
            previous_sha256 = event_sha256
            previous_recorded_at = recorded_at
        if previous_sha256 is None or previous_sha256 != self.previous_event_sha256:
            raise TransactionError(
                "event_journal_identity_drift",
                "notarization event journal head changed",
            )
        return previous_sha256


def _validate_context(
    context: TransactionContext,
    *,
    recovery: bool = False,
) -> None:
    repository = context.repository
    if (
        not repository.is_absolute()
        or repository.is_symlink()
        or repository.resolve(strict=True) != repository
    ):
        raise TransactionError("unsafe_repository", "repository must be an absolute real path")
    _require_real_directory(repository, trusted=True)
    if context.build_kind not in ("validation", "release"):
        raise TransactionError("invalid_build_kind", "build kind is unsupported")
    canonical_build_version(context.build_number, "build number")
    if not COMMIT_RE.fullmatch(context.repository_commit):
        raise TransactionError("invalid_source_identity", "repository commit is malformed")
    if not SHA256_RE.fullmatch(context.release_source_sha256):
        raise TransactionError("invalid_source_identity", "release source digest is malformed")
    if context.deployment_target != EXPECTED_DEPLOYMENT_TARGET:
        raise TransactionError(
            "invalid_deployment_target",
            "deployment target differs from the v0.4.0 release contract",
        )
    if set(context.toolchain_metadata) != TOOLCHAIN_METADATA_KEYS or any(
        not SHA256_RE.fullmatch(value) for value in context.toolchain_metadata.values()
    ):
        raise TransactionError("invalid_toolchain_identity", "toolchain identity is incomplete")
    if (
        not context.notary_profile
        or len(context.notary_profile) > 256
        or "\0" in context.notary_profile
    ):
        raise TransactionError("invalid_notary_profile", "notary profile name is malformed")
    _require_real_directory(context.repository / "target", trusted=True)
    _require_real_directory(context.repository / "target/candidates", trusted=True)
    _require_real_directory(context.candidate_base, trusted=True)
    _require_real_directory(context.build_root.parent, trusted=True)
    _require_real_directory(context.build_root, trusted=True)
    _require_real_directory(context.native_products, trusted=True)
    expected_native = context.build_root / "native-products"
    if context.native_products != expected_native:
        raise TransactionError("unsafe_native_products", "native products path is not canonical")
    if recovery:
        if context.staged_app is not None:
            raise TransactionError(
                "unsafe_recovery_context",
                "recovery must not accept a new staged application",
            )
        _require_real_directory(context.attempt_root, private=True)
        _require_real_directory(context.attempt_root / "events", private=True)
        direct_sealed_state = (
            (context.attempt_root / "publish-ready").is_dir()
            or (
                context.final_root.is_dir()
                and (
                    (context.attempt_root / "receipt.json").is_file()
                    or (
                        context.attempt_root
                        / PUBLISH_READY_RECEIPT_PENDING_FILENAME
                    ).exists()
                )
            )
        )
        if not (
            (context.attempt_root / "work").is_dir()
            or (context.attempt_root / "recovery-source").is_dir()
            or (context.attempt_root / "publish-ready").is_dir()
            or direct_sealed_state
        ):
            raise TransactionError(
                "recovery_state_missing",
                "recovery attempt has neither work nor publish-ready state",
            )
    else:
        if os.path.lexists(context.attempt_root):
            raise TransactionError(
                "attempt_exists",
                "this lane/build already has a notarization attempt and must not be resubmitted",
            )
        if context.staged_app is None or context.staged_app.name != "Clash for Mac.app":
            raise TransactionError("unsafe_staged_app", "staged app name is not canonical")
        staging = context.staged_app.parent
        if staging.parent != context.candidate_base or not staging.name.startswith(
            ".signed-stage."
        ):
            raise TransactionError("unsafe_staged_app", "staged app parent is not canonical")
        _require_real_directory(staging, trusted=True)
        _require_real_directory(context.staged_app)
    if not recovery and os.path.lexists(context.final_root):
        raise TransactionError("publish_destination_exists", "signed output already exists")


def _claim_attempt(context: TransactionContext) -> tuple[Path, Path]:
    attempts = context.candidate_base / "notary-attempts"
    lane = attempts / context.build_kind
    _mkdir_private(attempts, exclusive=False)
    _mkdir_private(lane, exclusive=False)
    _mkdir_private(context.attempt_root, exclusive=True)
    events = context.attempt_root / "events"
    work = context.attempt_root / "work"
    _mkdir_private(events, exclusive=True)
    _mkdir_private(work, exclusive=True)
    return events, work


def _load_recovery_intent_document(
    context: TransactionContext,
) -> tuple[dict[str, Any], Path, str]:
    path = context.attempt_root / "intent.json"
    data = _read_regular_bytes(path)
    value = _decode_json_bytes(data, path)
    if not isinstance(value, dict) or set(value) != INTENT_FIELDS:
        raise TransactionError(
            "notarization_intent_identity_drift",
            "notarization intent has an unexpected field set",
        )
    if data != _canonical_json(value).encode("utf-8"):
        raise TransactionError(
            "notarization_intent_identity_drift",
            "notarization intent is not canonical JSON",
        )
    attempt_id = _canonical_uuid(value["attempt_id"], "local attempt id")
    archive_size = value["archive_size"]
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["document"] != ATTEMPT_DOCUMENT
        or value["lane"] != context.build_kind
        or value["build_number"] != context.build_number
        or value["version"] != VERSION
        or value["repository_commit"] != context.repository_commit
        or value["release_source_sha256"] != context.release_source_sha256
        or value["team_id"] != EXPECTED_TEAM_ID
        or value["archive_name"] != context.archive_name
        or not isinstance(value["archive_sha256"], str)
        or not SHA256_RE.fullmatch(value["archive_sha256"])
        or not isinstance(archive_size, int)
        or isinstance(archive_size, bool)
        or archive_size <= 0
        or not isinstance(value["pre_staple_app_tree_sha256"], str)
        or not SHA256_RE.fullmatch(value["pre_staple_app_tree_sha256"])
    ):
        raise TransactionError(
            "notarization_intent_identity_drift",
            "notarization intent differs from the recovery context",
        )
    _parse_utc_timestamp(value["prepared_at"], "intent prepared_at")
    value["attempt_id"] = attempt_id
    return value, path, hashlib.sha256(data).hexdigest()


def _is_direct_source_preparation_failure_event(
    event: dict[str, Any],
    *,
    submission_id: str,
) -> bool:
    return (
        event["state"] == "outcome_unknown"
        and event["submission_id"] == submission_id
        and event["failure_code"] == "direct_source_preparation_failed"
        and event["exit_code"] is None
    )


def _is_recoverable_wait_outcome_event(
    event: dict[str, Any],
    *,
    submission_id: str,
) -> bool:
    if (
        event["state"] != "outcome_unknown"
        or event["submission_id"] != submission_id
        or event["failure_code"] not in RECOVERABLE_WAIT_FAILURE_CODES
    ):
        return False
    if event["failure_code"] == "wait_failed":
        return event["exit_code"] is not None and event["exit_code"] != 0
    return event["exit_code"] is None


def _decode_recoverable_event_prefix(
    journal: EventJournal,
) -> AttemptEventReduction:
    if len(journal.documents) < 3:
        raise TransactionError(
            "recovery_state_unsupported",
            "notarization journal is too short for submission recovery",
        )
    first, readiness, submitting = journal.documents[:3]
    if (
        first["state"] != "prepared"
        or readiness["state"]
        not in {"notary_ready", "pre_submission_policy_compatibility_applied"}
        or submitting["state"] != "submitting"
    ):
        raise TransactionError(
            "recovery_state_unsupported",
            "notarization journal is not an unbound submit outcome",
        )
    for event in (first, readiness, submitting):
        if (
            event["submission_id"] is not None
            or event["failure_code"] is not None
            or event["exit_code"] is not None
        ):
            raise TransactionError(
                "recovery_state_unsupported",
                "pre-submit notarization events contain terminal fields",
            )
    submitted_receipt_expected = False
    direct_evidence_required = False
    direct_finalization_ready = False
    direct_source_preparation_incomplete = False
    outcome: dict[str, Any] | None = None
    fourth = journal.documents[3] if len(journal.documents) >= 4 else None
    if fourth is None or fourth["state"] in {
        "reconciliation_started",
        "reconciliation_deferred",
        "submission_reconciled",
    }:
        recovery_event_start = 3
        direct_evidence_required = True
        outcome_submission_id = None
    elif fourth["state"] == "outcome_unknown":
        outcome = fourth
        recovery_event_start = 4
        failure_codes = RECOVERABLE_SUBMIT_FAILURE_CODES
        allowed_exit_code_failure = "submit_failed"
    elif fourth["state"] == "submitted":
        submitted_receipt_expected = True
        if (
            fourth["submission_id"] is None
            or fourth["failure_code"] is not None
            or fourth["exit_code"] is not None
        ):
            raise TransactionError(
                "recovery_state_unsupported",
                "submitted notarization event is inconsistent",
            )
        fifth = journal.documents[4] if len(journal.documents) >= 5 else None
        direct_boundary: dict[str, Any] | None = None
        if fifth is not None and fifth["state"] == "direct_finalization_preparing":
            if (
                fifth["submission_id"] != fourth["submission_id"]
                or fifth["failure_code"] is not None
                or fifth["exit_code"] is not None
                or not isinstance(fifth.get("evidence_sha256"), str)
                or not SHA256_RE.fullmatch(fifth["evidence_sha256"])
            ):
                raise TransactionError(
                    "recovery_state_unsupported",
                    "direct finalization preparation marker is malformed",
                )
            sixth = journal.documents[5] if len(journal.documents) >= 6 else None
            if sixth is None:
                recovery_event_start = fifth["sequence"]
                direct_source_preparation_incomplete = True
            elif _is_direct_source_preparation_failure_event(
                sixth,
                submission_id=fourth["submission_id"],
            ):
                seventh = (
                    journal.documents[6]
                    if len(journal.documents) >= 7
                    else None
                )
                if seventh is None:
                    recovery_event_start = sixth["sequence"]
                    direct_source_preparation_incomplete = True
                elif seventh["state"] == "direct_finalization_ready":
                    direct_boundary = seventh
                else:
                    raise TransactionError(
                        "recovery_state_unsupported",
                        "direct source preparation failure has an unsupported suffix",
                    )
            elif sixth["state"] == "direct_finalization_ready":
                direct_boundary = sixth
            else:
                raise TransactionError(
                    "recovery_state_unsupported",
                    "direct finalization preparation has an unsupported suffix",
                )
            direct_evidence_required = True
            outcome_submission_id = fourth["submission_id"]
        elif fifth is not None and _is_direct_source_preparation_failure_event(
            fifth,
            submission_id=fourth["submission_id"],
        ):
            sixth = journal.documents[5] if len(journal.documents) >= 6 else None
            if sixth is None:
                recovery_event_start = fifth["sequence"]
                direct_evidence_required = True
                direct_source_preparation_incomplete = True
                outcome_submission_id = fourth["submission_id"]
            elif sixth["state"] == "direct_finalization_ready":
                direct_boundary = sixth
            else:
                raise TransactionError(
                    "recovery_state_unsupported",
                    "direct source preparation failure has an unsupported suffix",
                )
        elif (
            fifth is not None
            and _is_recoverable_wait_outcome_event(
                fifth,
                submission_id=fourth["submission_id"],
            )
            and len(journal.documents) >= 6
            and journal.documents[5]["state"]
            == "direct_finalization_ready"
        ):
            direct_boundary = journal.documents[5]
        elif fifth is not None and fifth["state"] == "direct_finalization_ready":
            direct_boundary = fifth
        if (
            direct_boundary is not None
            and direct_boundary["state"] == "direct_finalization_ready"
        ):
            if (
                direct_boundary["submission_id"] != fourth["submission_id"]
                or direct_boundary["failure_code"] is not None
                or direct_boundary["exit_code"] is not None
                or not isinstance(
                    direct_boundary.get("evidence_sha256"), str
                )
                or not SHA256_RE.fullmatch(
                    direct_boundary["evidence_sha256"]
                )
            ):
                raise TransactionError(
                    "recovery_state_unsupported",
                    "direct finalization boundary is malformed",
                )
            recovery_event_start = direct_boundary["sequence"]
            direct_evidence_required = True
            direct_finalization_ready = True
            outcome_submission_id = fourth["submission_id"]
        elif direct_source_preparation_incomplete:
            pass
        elif fifth is None or fifth["state"] in {
            "reconciliation_started",
            "reconciliation_deferred",
            "submission_reconciled",
        }:
            recovery_event_start = 4
            direct_evidence_required = True
            outcome_submission_id = fourth["submission_id"]
        else:
            outcome = fifth
            recovery_event_start = 5
            failure_codes = RECOVERABLE_WAIT_FAILURE_CODES
            allowed_exit_code_failure = "wait_failed"
            if outcome["submission_id"] != fourth["submission_id"]:
                raise TransactionError(
                    "recovery_state_unsupported",
                    "wait outcome differs from the submitted notarization id",
                )
    else:
        raise TransactionError(
            "recovery_state_unsupported",
            "notarization journal is not at a recoverable submit or wait boundary",
        )
    if outcome is not None:
        if (
            outcome["state"] != "outcome_unknown"
            or outcome["failure_code"] not in failure_codes
        ):
            raise TransactionError(
                "recovery_state_unsupported",
                "notarization journal outcome is not recoverable",
            )
        exit_code = outcome["exit_code"]
        if (
            outcome["failure_code"] == allowed_exit_code_failure
            and (exit_code is None or exit_code == 0)
        ) or (
            outcome["failure_code"] != allowed_exit_code_failure
            and exit_code is not None
        ):
            raise TransactionError(
                "recovery_state_unsupported",
                "the unknown submit outcome has an unexpected exit status",
            )
        outcome_submission_id = outcome["submission_id"]
    timestamps = [
        _parse_utc_timestamp(event["recorded_at"], "event recorded_at")[1]
        for event in journal.documents[:recovery_event_start]
    ]
    if timestamps != sorted(timestamps):
        raise TransactionError(
            "recovery_state_unsupported",
            "notarization event timestamps are not monotonic",
        )
    base_event_path = journal.directory / f"{recovery_event_start:08d}.json"
    phase = AttemptPhase.SUBMISSION_RECOVERABLE
    if direct_source_preparation_incomplete:
        phase = AttemptPhase.DIRECT_SOURCE_PREPARING
    elif direct_finalization_ready:
        phase = AttemptPhase.DIRECT_FINALIZATION_READY
    return AttemptEventReduction(
        phase=phase,
        submit_window_start=timestamps[2],
        submit_window_end=timestamps[-1],
        prior_event_sha256=_sha256_file(base_event_path),
        recovery_event_start=recovery_event_start,
        submission_id=outcome_submission_id,
        boundary_submission_id=outcome_submission_id,
        submitted_receipt_expected=submitted_receipt_expected,
        direct_evidence_required=direct_evidence_required,
        direct_finalization_ready=direct_finalization_ready,
        direct_source_preparation_incomplete=(
            direct_source_preparation_incomplete
        ),
    )


def _decode_attempt_inventory(
    context: TransactionContext,
    *,
    allowed_entries: set[str],
    require_source: bool,
) -> AttemptInventory:
    entries = frozenset(
        _strict_directory_inventory(
            context.attempt_root,
            failure_code="recovery_inventory_unavailable",
            failure_message="notarization attempt cannot be enumerated",
        )
    )
    if not entries <= allowed_entries:
        raise TransactionError(
            "recovery_inventory_mismatch",
            "notarization attempt contains unsupported entries",
        )
    source_names = entries & {"work", "recovery-source"}
    if len(source_names) > 1 or (require_source and len(source_names) != 1):
        raise TransactionError(
            "recovery_inventory_mismatch",
            "notarization attempt source inventory is ambiguous",
        )
    source = (
        context.attempt_root / next(iter(source_names))
        if source_names
        else None
    )
    if source is not None:
        _require_real_directory(source, private=True)
    finalization_root = context.attempt_root / "finalization-runs"
    run_entries: tuple[Path, ...] = ()
    finalization_logical_bytes = 0
    if "finalization-runs" in entries:
        try:
            run_entries, finalization_logical_bytes = (
                _bounded_finalization_run_inventory(finalization_root)
            )
        except TransactionError as error:
            if error.code in {
                "finalization_run_quota_exceeded",
                "finalization_byte_quota_exceeded",
                "finalization_entry_quota_exceeded",
                "finalization_quota_unavailable",
            }:
                raise
            raise TransactionError(
                "recovery_inventory_mismatch",
                "recovery finalization workspace inventory is malformed",
            ) from error
    direct_publish_ready = (
        context.attempt_root / "publish-ready"
        if "publish-ready" in entries
        else None
    )
    if direct_publish_ready is not None:
        _require_real_directory(direct_publish_ready, private=True)
    return AttemptInventory(
        entries=entries,
        source=source,
        finalization_runs=run_entries,
        finalization_logical_bytes=finalization_logical_bytes,
        direct_publish_ready=direct_publish_ready,
        final_exists=os.path.lexists(context.final_root),
        receipt_exists="receipt.json" in entries,
        receipt_pending_exists=(
            PUBLISH_READY_RECEIPT_PENDING_FILENAME in entries
        ),
    )


def _load_recoverable_attempt(
    context: TransactionContext,
    *,
    archive_validator: ArchiveValidator,
    manifest_verifier: ManifestVerifier,
    source_identity_reader: SourceIdentityReader,
    toolchain_metadata_reader: ToolchainMetadataReader,
    clock: Clock,
) -> RecoverableAttempt:
    _validate_context(context, recovery=True)
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)
    allowed_attempt_entries = {
        "events",
        "finalization-runs",
        "intent.json",
        "recovery-continuation.json",
        RECOVERY_CONTINUATION_PENDING_FILENAME,
        "recovery-intent.json",
        "recovery-source",
        "submission-observation.json",
        "submission-receipt.json",
        "work",
    }
    inventory = _decode_attempt_inventory(
        context,
        allowed_entries=allowed_attempt_entries,
        require_source=True,
    )
    if not {"events", "intent.json"}.issubset(inventory.entries):
        raise TransactionError(
            "recovery_inventory_mismatch",
            "notarization attempt inventory is not recoverable",
        )
    work = inventory.source
    if work is None:
        raise TransactionError(
            "recovery_inventory_mismatch",
            "notarization attempt has no recovery source",
        )
    work_app = work / "Clash for Mac.app"
    archive = work / context.archive_name
    archive_manifest = work / f"{context.archive_name}.manifest.json"
    expected_work_entries = {
        work_app.name,
        archive.name,
        archive_manifest.name,
    }
    if {path.name for path in work.iterdir()} != expected_work_entries:
        raise TransactionError(
            "recovery_inventory_mismatch",
            "notarization work inventory is not recoverable",
        )
    _require_real_directory(work_app)
    intent, intent_path, intent_sha256 = _load_recovery_intent_document(context)
    archive_sha256, archive_size = _archive_identity(archive)
    if (
        archive_sha256 != intent["archive_sha256"]
        or archive_size != intent["archive_size"]
    ):
        raise TransactionError(
            "archive_identity_drift",
            "retained notarization archive differs from its intent",
        )
    try:
        archive_validator(archive, work_app)
    except TransactionError:
        raise
    except Exception as error:
        raise TransactionError(
            "archive_validation_failed",
            "retained notarization archive validation did not complete",
        ) from error
    _require_archive_identity(archive, archive_sha256, archive_size)
    pre_staple_app_sha256 = _app_tree_sha256(
        work_app,
        failure_code="app_identity_failed",
        failure_message="retained pre-staple app digest cannot be derived",
    )
    if pre_staple_app_sha256 != intent["pre_staple_app_tree_sha256"]:
        raise TransactionError(
            "app_identity_drift",
            "retained pre-staple app differs from its intent",
        )
    archive_metadata = _archive_metadata(context)
    _run_manifest_verification_barrier(
        manifest_verifier,
        ((archive, archive_manifest, archive_metadata),),
    )
    journal = EventJournal.load_existing(
        context.attempt_root / "events",
        intent_sha256,
        clock,
    )
    continuation_pending = (
        context.attempt_root / RECOVERY_CONTINUATION_PENDING_FILENAME
    )
    continuation_path = context.attempt_root / "recovery-continuation.json"
    if os.path.lexists(continuation_pending):
        continuation_markers = [
            (sequence, event)
            for sequence, event in enumerate(journal.documents, start=1)
            if event["state"] == "recovery_tool_continued"
        ]
        if (
            os.path.lexists(continuation_path)
            or len(continuation_markers) != 1
            or continuation_markers[0][0] != journal.sequence
        ):
            raise TransactionError(
                "recovery_inventory_mismatch",
                "continuation pending evidence is outside its marker-only crash state",
            )
        _read_private_pending_bytes(continuation_pending)
    event_reduction = _reduce_attempt_events(journal)
    submit_window_start = event_reduction.submit_window_start
    submit_window_end = event_reduction.submit_window_end
    prior_event_sha256 = event_reduction.prior_event_sha256
    recovery_event_start = event_reduction.recovery_event_start
    outcome_submission_id = event_reduction.boundary_submission_id
    submitted_receipt_expected = (
        event_reduction.submitted_receipt_expected
    )
    direct_evidence_required = event_reduction.direct_evidence_required
    direct_finalization_ready = event_reduction.direct_finalization_ready
    direct_source_preparation_incomplete = (
        event_reduction.direct_source_preparation_incomplete
    )
    if direct_finalization_ready and work.name != "recovery-source":
        raise TransactionError(
            "recovery_state_unsupported",
            "direct finalization boundary lacks its immutable recovery source",
        )
    submit_window_end_rendered = journal.documents[
        recovery_event_start - 1
    ]["recorded_at"]
    recovery_observed_at: datetime | None = None
    if recovery_event_start == 3:
        recovery_observed_rendered, recovery_observed_at = _parse_utc_timestamp(
            clock(),
            "recovery observed_at",
        )
        if recovery_observed_at < submit_window_start:
            raise TransactionError(
                "recovery_state_unsupported",
                "recovery time precedes the submit attempt",
            )
        submit_window_end = recovery_observed_at
        submit_window_end_rendered = recovery_observed_rendered
    submission_observation_path = (
        context.attempt_root / "submission-observation.json"
    )
    observed_submission_id: str | None = None
    submission_observation_sha256: str | None = None
    if os.path.lexists(submission_observation_path):
        observation_data = _read_regular_bytes(submission_observation_path)
        observation = _decode_json_bytes(
            observation_data,
            submission_observation_path,
        )
        if (
            not isinstance(observation, dict)
            or set(observation) != SUBMISSION_OBSERVATION_FIELDS
            or observation_data != _canonical_json(observation).encode("utf-8")
            or type(observation["schema_version"]) is not int
            or observation["schema_version"] != 1
            or observation["document"] != SUBMISSION_OBSERVATION_DOCUMENT
            or observation["attempt_id"] != intent["attempt_id"]
            or observation["intent_sha256"] != intent_sha256
            or observation["archive_name"] != context.archive_name
            or observation["archive_sha256"] != archive_sha256
            or observation["path_binding"] != "exact"
        ):
            raise TransactionError(
                "submission_observation_identity_drift",
                "submission observation differs from the retained attempt",
            )
        observed_submission_id = _canonical_uuid(
            observation["submission_id"],
            "observed submission id",
        )
        observed_at = _parse_utc_timestamp(
            observation["observed_at"],
            "submission observation observed_at",
        )[1]
        if not _timestamp_within_recorded_window(
            observed_at,
            window_start=submit_window_start,
            window_end=submit_window_end,
            window_end_rendered=submit_window_end_rendered,
        ):
            raise TransactionError(
                "submission_observation_identity_drift",
                "submission observation falls outside the submit outcome window",
            )
        if recovery_event_start == 3:
            submit_window_end = observed_at
            submit_window_end_rendered = observation["observed_at"]
        if (
            outcome_submission_id is not None
            and outcome_submission_id != observed_submission_id
        ):
            raise TransactionError(
                "submission_observation_identity_drift",
                "submission observation differs from the outcome event",
            )
        submission_observation_sha256 = hashlib.sha256(
            observation_data
        ).hexdigest()
    elif outcome_submission_id is not None:
        _canonical_uuid(outcome_submission_id, "journal submission id")
        boundary_event = journal.documents[recovery_event_start - 1]
        if boundary_event["failure_code"] != "submission_observation_failed":
            raise TransactionError(
                "submission_observation_missing",
                "durable submit observation is missing from an id-bearing outcome",
            )
    if direct_evidence_required and observed_submission_id is None:
        raise TransactionError(
            "submission_observation_missing",
            "crash-boundary recovery requires a durable submit observation",
        )
    submission_receipt_path = context.attempt_root / "submission-receipt.json"
    existing_submission_receipt: dict[str, Any] | None = None
    existing_submission_receipt_path: Path | None = None
    submission_receipt_sha256: str | None = None
    if os.path.lexists(submission_receipt_path):
        receipt_data = _read_regular_bytes(submission_receipt_path)
        receipt = _decode_json_bytes(receipt_data, submission_receipt_path)
        if (
            not isinstance(receipt, dict)
            or set(receipt) != SUBMISSION_RECEIPT_FIELDS
            or receipt_data != _canonical_json(receipt).encode("utf-8")
            or type(receipt["schema_version"]) is not int
            or receipt["schema_version"] != 2
            or receipt["document"] != SUBMISSION_DOCUMENT
            or receipt["attempt_id"] != intent["attempt_id"]
            or receipt["archive_name"] != context.archive_name
            or receipt["archive_sha256"] != archive_sha256
        ):
            raise TransactionError(
                "submission_receipt_identity_drift",
                "persisted submission receipt differs from the retained attempt",
            )
        receipt_submission_id = _canonical_uuid(
            receipt["submission_id"],
            "submission receipt id",
        )
        if (
            (
                observed_submission_id is not None
                and receipt_submission_id != observed_submission_id
            )
            or (
                outcome_submission_id is not None
                and receipt_submission_id != outcome_submission_id
            )
        ):
            raise TransactionError(
                "submission_receipt_identity_drift",
                "persisted submission receipt id differs from the submit evidence",
            )
        receipt_observed_at = _parse_utc_timestamp(
            receipt["observed_at"],
            "submission receipt observed_at",
        )[1]
        acquisition = receipt["acquisition"]
        if acquisition == "submit-no-wait":
            if recovery_event_start == 3:
                if recovery_observed_at is None:
                    raise TransactionError(
                        "recovery_state_unsupported",
                        "direct receipt recovery lacks its observed time ceiling",
                    )
                if (
                    receipt_observed_at < submit_window_end
                    or receipt_observed_at > recovery_observed_at
                ):
                    raise TransactionError(
                        "submission_receipt_identity_drift",
                        "direct receipt time is inconsistent with its observation",
                )
                submit_window_end = receipt_observed_at
                submit_window_end_rendered = receipt["observed_at"]
            if (
                receipt["recovery_intent_sha256"] is not None
                or receipt["notary_created_at"] is not None
                or receipt["causal_binding"] != "direct-submit-observation"
                or submission_observation_sha256 is None
                or receipt["submission_observation_sha256"]
                != submission_observation_sha256
                or not _timestamp_within_recorded_window(
                    receipt_observed_at,
                    window_start=submit_window_start,
                    window_end=submit_window_end,
                    window_end_rendered=submit_window_end_rendered,
                )
            ):
                raise TransactionError(
                    "submission_receipt_identity_drift",
                    "direct submission receipt differs from the retained submit evidence",
                )
        elif acquisition == "explicit-recovery":
            recovery_sha256 = receipt["recovery_intent_sha256"]
            recovery_intent_path = context.attempt_root / "recovery-intent.json"
            expected_causal_binding = (
                "direct-submit-observation-and-log"
                if submission_observation_sha256 is not None
                else "unique-history-window-and-log"
            )
            notary_created_at = _parse_utc_timestamp(
                receipt["notary_created_at"],
                "submission receipt notary_created_at",
            )[1]
            if (
                not isinstance(recovery_sha256, str)
                or not SHA256_RE.fullmatch(recovery_sha256)
                or not os.path.lexists(recovery_intent_path)
                or _sha256_file(recovery_intent_path) != recovery_sha256
                or receipt["submission_observation_sha256"]
                != submission_observation_sha256
                or receipt["causal_binding"] != expected_causal_binding
                or not _timestamp_within_recorded_window(
                    notary_created_at,
                    window_start=submit_window_start,
                    window_end=submit_window_end,
                    window_end_rendered=submit_window_end_rendered,
                )
            ):
                raise TransactionError(
                    "submission_receipt_identity_drift",
                    "recovery receipt differs from the retained reconciliation evidence",
                )
        else:
            raise TransactionError(
                "submission_receipt_identity_drift",
                "persisted submission receipt acquisition is unsupported",
            )
        if submitted_receipt_expected and acquisition != "submit-no-wait":
            raise TransactionError(
                "submission_receipt_identity_drift",
                "submitted event is not bound to its direct submission receipt",
            )
        existing_submission_receipt = receipt
        existing_submission_receipt_path = submission_receipt_path
        submission_receipt_sha256 = hashlib.sha256(receipt_data).hexdigest()
    elif submitted_receipt_expected:
        raise TransactionError(
            "submission_receipt_missing",
            "submitted event lacks its immutable submission receipt",
        )
    if direct_finalization_ready or direct_source_preparation_incomplete:
        direct_markers = [
            event
            for event in journal.documents[4:recovery_event_start]
            if event["state"]
            in {"direct_finalization_preparing", "direct_finalization_ready"}
        ]
        if (
            existing_submission_receipt is None
            or existing_submission_receipt["acquisition"] != "submit-no-wait"
            or submission_receipt_sha256 is None
            or not direct_markers
            or any(
                marker.get("evidence_sha256") != submission_receipt_sha256
                for marker in direct_markers
            )
        ):
            raise TransactionError(
                "direct_finalization_boundary_mismatch",
                "direct finalization boundary differs from its submission receipt",
            )
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)
    _require_archive_identity(archive, archive_sha256, archive_size)
    if _app_tree_sha256(
        work_app,
        failure_code="app_identity_drift",
        failure_message="retained pre-staple app digest cannot be revalidated",
    ) != pre_staple_app_sha256:
        raise TransactionError(
            "app_identity_drift",
            "retained pre-staple app changed during recovery validation",
        )
    return RecoverableAttempt(
        context=context,
        work=work,
        work_app=work_app,
        archive=archive,
        archive_manifest=archive_manifest,
        archive_metadata=archive_metadata,
        archive_sha256=archive_sha256,
        archive_size=archive_size,
        pre_staple_app_sha256=pre_staple_app_sha256,
        attempt_id=intent["attempt_id"],
        intent=intent,
        intent_path=intent_path,
        intent_sha256=intent_sha256,
        journal=journal,
        submit_window_start=submit_window_start,
        submit_window_end=submit_window_end,
        submit_window_end_rendered=submit_window_end_rendered,
        prior_event_sha256=prior_event_sha256,
        recovery_event_start=recovery_event_start,
        journal_submission_id=outcome_submission_id,
        observed_submission_id=observed_submission_id,
        submission_observation_sha256=submission_observation_sha256,
        existing_submission_receipt=existing_submission_receipt,
        existing_submission_receipt_path=existing_submission_receipt_path,
        direct_finalization_ready=direct_finalization_ready,
        direct_source_preparation_incomplete=(
            direct_source_preparation_incomplete
        ),
    )


def _require_source_identity(
    context: TransactionContext,
    reader: SourceIdentityReader,
) -> None:
    try:
        observed = reader(context.repository)
    except Exception as error:
        raise TransactionError(
            "source_identity_unavailable", "cannot derive the clean repository identity"
        ) from error
    if observed != context.source_identity:
        raise TransactionError(
            "source_identity_drift", "release source identity changed during notarization"
        )


def _require_toolchain_identity(
    context: TransactionContext,
    reader: ToolchainMetadataReader,
) -> None:
    try:
        observed = reader(context.repository)
    except Exception as error:
        raise TransactionError(
            "toolchain_identity_unavailable",
            "cannot derive the canonical release toolchain identity",
        ) from error
    if observed != context.toolchain_metadata:
        raise TransactionError(
            "toolchain_identity_drift",
            "release toolchain identity changed during notarization",
        )


def _archive_identity(path: Path) -> tuple[str, int]:
    digest, size = _hash_regular_file(path)
    if size <= 0:
        raise TransactionError("empty_archive", "notarization archive is empty")
    return digest, size


def _require_archive_identity(path: Path, digest: str, size: int) -> None:
    observed_digest, observed_size = _archive_identity(path)
    if (observed_digest, observed_size) != (digest, size):
        raise TransactionError(
            "archive_identity_drift", "notarization archive changed during the transaction"
        )


def _app_metadata(context: TransactionContext) -> dict[str, str]:
    return {
        "artifactKind": context.artifact_kind,
        "architecture": "arm64",
        "buildNumber": context.build_number,
        "deploymentTarget": context.deployment_target,
        "releaseSourceSha256": context.release_source_sha256,
        "repositoryCommit": context.repository_commit,
        "teamID": EXPECTED_TEAM_ID,
        "version": VERSION,
        **context.toolchain_metadata,
    }


def _archive_metadata(context: TransactionContext) -> dict[str, str]:
    return {
        "artifactKind": "notarization-submission-v1",
        "architecture": "arm64",
        "buildNumber": context.build_number,
        "releaseSourceSha256": context.release_source_sha256,
        "repositoryCommit": context.repository_commit,
        "teamID": EXPECTED_TEAM_ID,
        "version": VERSION,
        **context.toolchain_metadata,
    }


def _capture_command_result(
    runner: CommandRunner,
    role: CommandRole,
    command: list[str],
    timeout: float,
) -> CommandResult:
    try:
        return runner(role, command, timeout)
    except Exception as error:
        raise TransactionError(
            f"{role.value}_execution_failed",
            f"{role.value} command did not complete",
        ) from error


def _result_or_error(
    runner: CommandRunner,
    role: CommandRole,
    command: list[str],
    timeout: float,
    *,
    uncertain: bool = False,
) -> CommandResult:
    try:
        result = _capture_command_result(runner, role, command, timeout)
    except TransactionError as error:
        if uncertain:
            raise TransactionError(
                error.code,
                str(error),
                terminal_state="outcome_unknown",
            ) from error
        raise
    if result.returncode != 0:
        raise TransactionError(
            f"{role.value}_failed",
            f"{role.value} command failed",
            terminal_state="outcome_unknown" if uncertain else "failed",
            exit_code=result.returncode,
        )
    return result


def _require_syspolicy_success(
    result: CommandResult,
    role: CommandRole,
    app: Path,
) -> None:
    value = _parse_command_json(result.stdout)
    if not isinstance(value, dict) or set(value) != {"output"}:
        raise TransactionError(
            f"{role.value}_invalid_output",
            f"{role.value} returned an unexpected JSON document",
        )
    if value["output"] != []:
        raise TransactionError(
            f"{role.value}_finding",
            f"{role.value} reported a release-blocking finding",
        )
    _require_syspolicy_diagnostic(result, role, app)


def _require_syspolicy_diagnostic(
    result: CommandResult,
    role: CommandRole,
    app: Path,
) -> None:
    expected = (
        f"{_SINGLE_SIGNATURE_DIAGNOSTIC_PREFIX}{app.resolve().as_uri()}"
        f"{_SINGLE_SIGNATURE_DIAGNOSTIC_SUFFIX}"
    )
    if result.stderr not in {"", expected}:
        raise TransactionError(
            f"{role.value}_stderr",
            f"{role.value} emitted unexpected diagnostic output",
        )


def _require_exact_syspolicy_finding(
    result: CommandResult,
    role: CommandRole,
    app: Path,
    expected_finding: dict[str, str],
    *,
    expected_returncode: int,
) -> None:
    if result.returncode != expected_returncode:
        raise TransactionError(
            f"{role.value}_unexpected_status",
            f"{role.value} returned an unsupported status",
            exit_code=result.returncode,
        )
    value = _parse_command_json(result.stdout)
    if (
        not isinstance(value, dict)
        or set(value) != {"output"}
        or not isinstance(value["output"], list)
        or value["output"] != [expected_finding]
    ):
        raise TransactionError(
            f"{role.value}_finding_mismatch",
            f"{role.value} did not return the exact expected finding",
            exit_code=result.returncode,
        )
    _require_syspolicy_diagnostic(result, role, app)


def _require_exact_macos_27_notary_false_positive(
    result: CommandResult,
    app: Path,
    identity: HostSystemIdentity,
) -> None:
    role = CommandRole.NOTARY_READINESS
    if identity != KNOWN_MACOS_27_COMPATIBILITY_IDENTITY:
        raise TransactionError(
            "notary-readiness_compatibility_unsupported_host",
            "notary readiness failed outside the single known host compatibility build",
            exit_code=result.returncode,
        )
    executable = app.resolve() / "Contents/MacOS/clash-for-mac"
    _require_exact_syspolicy_finding(
        result,
        role,
        app,
        {
            "SyspolicyCheckAdditionalInformation": "",
            "SyspolicyCheckAdvice": "",
            "SyspolicyCheckDocumentationLink": (
                "https://developer.apple.com/forums/thread/706442"
            ),
            "SyspolicyCheckErrorFile": str(executable),
            "SyspolicyCheckErrorLevel": "Fatal",
            "SyspolicyCheckLongError": _KNOWN_NOTARY_FALSE_POSITIVE_LONG_ERROR,
            "SyspolicyCheckShortError": "Codesign Error",
        },
        expected_returncode=70,
    )


def _require_exact_pre_notary_missing_ticket(
    result: CommandResult,
    app: Path,
) -> None:
    role = CommandRole.NOTARY_READINESS_CORROBORATION
    _require_exact_syspolicy_finding(
        result,
        role,
        app,
        {
            "SyspolicyCheckAdditionalInformation": "",
            "SyspolicyCheckAdvice": _MISSING_TICKET_ADVICE,
            "SyspolicyCheckDocumentationLink": (
                "https://developer.apple.com/documentation/security/"
                "notarizing_macos_software_before_distribution."
            ),
            "SyspolicyCheckErrorFile": str(app.resolve()),
            "SyspolicyCheckErrorLevel": "Fatal",
            "SyspolicyCheckLongError": _MISSING_TICKET_LONG_ERROR,
            "SyspolicyCheckShortError": "Notary Ticket Missing",
        },
        expected_returncode=70,
    )


def _establish_pre_submission_policy(
    runner: CommandRunner,
    app: Path,
    identity_reader: HostSystemIdentityReader,
) -> PreSubmissionPolicyMode:
    readiness = _capture_command_result(
        runner,
        CommandRole.NOTARY_READINESS,
        [
            "/usr/bin/syspolicy_check",
            "notary-submission",
            str(app),
            "--json",
        ],
        600,
    )
    if readiness.returncode == 0:
        _require_syspolicy_success(
            readiness,
            CommandRole.NOTARY_READINESS,
            app,
        )
        return PreSubmissionPolicyMode.NATIVE
    if readiness.returncode != 70:
        raise TransactionError(
            "notary-readiness_failed",
            "notary-readiness command failed",
            exit_code=readiness.returncode,
        )
    try:
        identity = identity_reader()
    except TransactionError:
        raise
    except Exception as error:
        raise TransactionError(
            "host_system_identity_unavailable",
            "cannot derive the release host identity",
        ) from error
    _require_exact_macos_27_notary_false_positive(readiness, app, identity)
    corroboration = _capture_command_result(
        runner,
        CommandRole.NOTARY_READINESS_CORROBORATION,
        [
            "/usr/bin/syspolicy_check",
            "distribution",
            str(app),
            "--json",
        ],
        600,
    )
    _require_exact_pre_notary_missing_ticket(corroboration, app)
    return PreSubmissionPolicyMode.MACOS_27_26A5388G_COMPATIBILITY


def _require_empty_notary_stderr(
    result: CommandResult,
    role: CommandRole,
) -> None:
    if result.stderr:
        raise TransactionError(
            f"{role.value}_stderr",
            f"{role.value} emitted unexpected diagnostic output",
            terminal_state=(
                "outcome_unknown"
                if role in (CommandRole.SUBMIT, CommandRole.WAIT)
                else "failed"
            ),
        )


def _require_exact_persisted_evidence(
    directory: Path,
    *,
    expected_notarization: dict[str, str],
    expected_log: dict[str, Any],
    expected_gatekeeper: dict[str, Any],
    archive_filename: str,
    archive_sha256: str,
    failure_code: str,
    failure_message: str,
) -> PersistedEvidenceSnapshot:
    persisted_notarization, notarization_sha256 = _read_exact_json_document(
        directory / "notarization.json",
        expected_notarization,
        drift_code="notarization_result_identity_drift",
        drift_message=(
            "persisted notarization result differs from this transaction"
        ),
    )
    persisted_log, notary_log_sha256 = _read_exact_json_document(
        directory / "notarization-log.json",
        expected_log,
        drift_code="accepted_notary_log_identity_drift",
        drift_message=(
            "persisted Accepted notarization log differs from this transaction"
        ),
    )
    persisted_gatekeeper, gatekeeper_sha256 = _read_exact_json_document(
        directory / "gatekeeper.json",
        expected_gatekeeper,
        drift_code="gatekeeper_evidence_identity_drift",
        drift_message=(
            "persisted Gatekeeper evidence differs from this transaction"
        ),
    )
    try:
        validated_log = validate_normalized_documents(
            persisted_notarization,
            persisted_log,
            archive_filename=archive_filename,
            archive_sha256=archive_sha256,
        )
        validated_gatekeeper = validate_gatekeeper_evidence(
            persisted_gatekeeper,
            expected_assessment_type="execute",
            expected_primary_signature_context=False,
        )
    except (NotaryLogError, ValueError) as error:
        raise TransactionError(failure_code, failure_message) from error
    if validated_log != expected_log or validated_gatekeeper != expected_gatekeeper:
        raise TransactionError(failure_code, failure_message)
    return PersistedEvidenceSnapshot(
        gatekeeper=validated_gatekeeper,
        notarization_sha256=notarization_sha256,
        notary_log_sha256=notary_log_sha256,
        gatekeeper_sha256=gatekeeper_sha256,
    )


def _require_submission_acquisition_evidence(
    prepared: PreparedAttempt,
) -> None:
    receipt, _ = _read_exact_json_document(
        prepared.submission_receipt_path,
        prepared.submission_receipt,
        drift_code="submission_receipt_identity_drift",
        drift_message="Apple submission receipt differs from this transaction",
    )
    if (
        set(receipt) != SUBMISSION_RECEIPT_FIELDS
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 2
        or receipt["document"] != SUBMISSION_DOCUMENT
        or receipt["attempt_id"] != prepared.attempt_id
        or receipt["submission_id"] != prepared.submission_id
        or receipt["archive_name"] != prepared.context.archive_name
        or receipt["archive_sha256"] != prepared.archive_sha256
    ):
        raise TransactionError(
            "submission_receipt_identity_drift",
            "Apple submission receipt has an invalid v2 identity",
        )
    _parse_utc_timestamp(receipt["observed_at"], "submission receipt observed_at")
    observation_sha256 = receipt["submission_observation_sha256"]
    if observation_sha256 is not None:
        if (
            not isinstance(observation_sha256, str)
            or not SHA256_RE.fullmatch(observation_sha256)
            or _sha256_file(
                prepared.context.attempt_root / "submission-observation.json"
            )
            != observation_sha256
        ):
            raise TransactionError(
                "submission_observation_identity_drift",
                "submission observation differs from its receipt",
            )
    recovery_components = (
        prepared.recovery_intent,
        prepared.recovery_intent_path,
        prepared.recovery_tool_repository,
        prepared.recovery_tool_identity,
        prepared.recovery_tool_identity_reader,
    )
    recovery_present = all(component is not None for component in recovery_components)
    if any(component is not None for component in recovery_components) and not recovery_present:
        raise TransactionError(
            "recovery_intent_identity_drift",
            "recovery provenance is incomplete",
        )
    continuation_present = (
        prepared.recovery_continuation is not None
        and prepared.recovery_continuation_path is not None
    )
    if (
        prepared.recovery_continuation is None
    ) != (
        prepared.recovery_continuation_path is None
    ):
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "recovery continuation provenance is incomplete",
        )
    if continuation_present and not recovery_present:
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "recovery continuation exists without its recovery intent",
        )
    if receipt["acquisition"] == "submit-no-wait":
        if (
            observation_sha256 is None
            or receipt["recovery_intent_sha256"] is not None
            or receipt["notary_created_at"] is not None
            or receipt["causal_binding"] != "direct-submit-observation"
        ):
            raise TransactionError(
                "submission_receipt_identity_drift",
                "direct submission receipt has inconsistent acquisition evidence",
            )
        if not recovery_present:
            return
        expected_recovery_sha256 = None
    elif receipt["acquisition"] == "explicit-recovery":
        expected_recovery_sha256 = receipt["recovery_intent_sha256"]
        if not recovery_present:
            raise TransactionError(
                "recovery_intent_identity_drift",
                "recovery receipt lacks its complete recovery tool binding",
            )
    else:
        raise TransactionError(
            "submission_receipt_identity_drift",
            "submission receipt acquisition is unsupported",
        )
    if (
        prepared.recovery_intent is None
        or prepared.recovery_intent_path is None
        or prepared.recovery_tool_repository is None
        or prepared.recovery_tool_identity is None
        or prepared.recovery_tool_identity_reader is None
    ):
        raise TransactionError(
            "recovery_intent_identity_drift",
            "recovery receipt lacks its complete recovery tool binding",
        )
    _, persisted_recovery_sha256 = _read_exact_json_document(
        prepared.recovery_intent_path,
        prepared.recovery_intent,
        drift_code="recovery_intent_identity_drift",
        drift_message="recovery intent differs from the accepted transaction",
    )
    if (
        expected_recovery_sha256 is not None
        and (
            not isinstance(expected_recovery_sha256, str)
            or not SHA256_RE.fullmatch(expected_recovery_sha256)
            or persisted_recovery_sha256 != expected_recovery_sha256
        )
    ):
        raise TransactionError(
            "recovery_intent_identity_drift",
            "recovery intent hash differs from the submission receipt",
        )
    expected_tool_identity = _recovery_intent_tool_identity(
        prepared.recovery_intent
    )
    if continuation_present:
        if (
            prepared.recovery_continuation is None
            or prepared.recovery_continuation_path is None
        ):
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation provenance is incomplete",
            )
        continuation, _ = _read_exact_json_document(
            prepared.recovery_continuation_path,
            prepared.recovery_continuation,
            drift_code="recovery_continuation_identity_drift",
            drift_message="recovery continuation differs from this transaction",
        )
        if (
            continuation.get("recovery_intent_sha256")
            != persisted_recovery_sha256
            or continuation.get("prior_recovery_tool_repository_commit")
            != expected_tool_identity["repositoryCommit"]
            or continuation.get("prior_recovery_tool_release_source_sha256")
            != expected_tool_identity["releaseSourceSha256"]
        ):
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation is not bound to its prior recovery intent",
            )
        expected_tool_identity = {
            "repositoryCommit": continuation[
                "continuation_tool_repository_commit"
            ],
            "releaseSourceSha256": continuation[
                "continuation_tool_release_source_sha256"
            ],
        }
    if prepared.recovery_tool_identity != expected_tool_identity:
        raise TransactionError(
            "recovery_tool_identity_drift",
            "recovery tool identity differs from its immutable provenance chain",
        )
    try:
        recovery_tool_identity = prepared.recovery_tool_identity_reader(
            prepared.recovery_tool_repository
        )
    except Exception as error:
        raise TransactionError(
            "recovery_tool_identity_unavailable",
            "cannot revalidate the recovery tool source identity",
        ) from error
    if recovery_tool_identity != prepared.recovery_tool_identity:
        raise TransactionError(
            "recovery_tool_identity_drift",
            "recovery tool source changed while finalizing the accepted submission",
        )
    if receipt["acquisition"] == "explicit-recovery":
        _parse_utc_timestamp(
            receipt["notary_created_at"],
            "submission receipt notary_created_at",
        )
        expected_causal_binding = (
            "direct-submit-observation-and-log"
            if observation_sha256 is not None
            else "unique-history-window-and-log"
        )
        if receipt["causal_binding"] != expected_causal_binding:
            raise TransactionError(
                "submission_receipt_identity_drift",
                "recovery receipt has inconsistent causal binding",
            )


def _is_receipt_durability_unknown_event(
    event: dict[str, Any],
    *,
    submission_id: str,
) -> bool:
    return (
        event["state"] == "outcome_unknown"
        and event["submission_id"] == submission_id
        and event["failure_code"] == "atomic_evidence_durability_unknown"
        and event["exit_code"] is None
    )


def _build_publish_ready_receipt(
    prepared: PreparedAttempt,
    *,
    journal: EventJournal,
    publication_root: Path,
    sealed_at: str,
    expected_notarization: dict[str, str] | None = None,
    expected_log: dict[str, Any] | None = None,
    expected_gatekeeper: dict[str, Any] | None = None,
    expected_post_staple_app_sha256: str | None = None,
) -> dict[str, Any]:
    sealed_timestamp = _parse_utc_timestamp(
        sealed_at,
        "publish-ready receipt sealed_at",
    )[1]
    if not journal.documents:
        raise TransactionError(
            "receipt_preseal_lineage_mismatch",
            "publish-ready receipt requires a distribution-verified journal head",
        )
    preseal_sequence = journal.sequence
    preseal_event = journal.documents[-1]
    if _is_receipt_durability_unknown_event(
        preseal_event,
        submission_id=prepared.submission_id,
    ):
        if journal.sequence < 2:
            raise TransactionError(
                "receipt_preseal_lineage_mismatch",
                "receipt durability outcome has no distribution event",
            )
        outcome_event = preseal_event
        preseal_sequence -= 1
        preseal_event = journal.documents[-2]
        preseal_sha256 = _sha256_file(
            journal.directory / f"{preseal_sequence:08d}.json"
        )
        if (
            outcome_event["previous_event_sha256"] != preseal_sha256
            or sealed_timestamp
            > _parse_utc_timestamp(
                outcome_event["recorded_at"],
                "receipt durability outcome recorded_at",
            )[1]
        ):
            raise TransactionError(
                "receipt_preseal_lineage_mismatch",
                "receipt durability outcome is not causally bound to preseal",
            )
    else:
        preseal_sha256 = journal.verify()
    if (
        preseal_event["state"] != "distribution_verified"
        or preseal_event["submission_id"] != prepared.submission_id
        or preseal_event["failure_code"] is not None
        or preseal_event["exit_code"] is not None
    ):
        raise TransactionError(
            "receipt_preseal_lineage_mismatch",
            "publish-ready receipt requires a distribution-verified preseal event",
        )
    distribution_timestamp = _parse_utc_timestamp(
        preseal_event["recorded_at"],
        "distribution verified event recorded_at",
    )[1]
    if sealed_timestamp < distribution_timestamp:
        raise TransactionError(
            "receipt_preseal_lineage_mismatch",
            "publish-ready receipt predates distribution verification",
        )
    context = prepared.context
    expected_components = (
        expected_notarization,
        expected_log,
        expected_gatekeeper,
        expected_post_staple_app_sha256,
    )
    if any(component is None for component in expected_components) and any(
        component is not None for component in expected_components
    ):
        raise TransactionError(
            "receipt_builder_input_mismatch",
            "receipt builder expected evidence is incomplete",
        )
    notarization = (
        {"id": prepared.submission_id, "status": "Accepted"}
        if expected_notarization is None
        else expected_notarization
    )
    log_path = publication_root / "notarization-log.json"
    gatekeeper_path = publication_root / "gatekeeper.json"
    normalized_log = (
        _decode_json_bytes(_read_regular_bytes(log_path), log_path)
        if expected_log is None
        else expected_log
    )
    gatekeeper = (
        _decode_json_bytes(_read_regular_bytes(gatekeeper_path), gatekeeper_path)
        if expected_gatekeeper is None
        else expected_gatekeeper
    )
    if not isinstance(normalized_log, dict) or not isinstance(gatekeeper, dict):
        raise TransactionError(
            "sealed_evidence_verification_failed",
            "publish-ready evidence is not a JSON object",
        )
    evidence = _require_exact_persisted_evidence(
        publication_root,
        expected_notarization=notarization,
        expected_log=normalized_log,
        expected_gatekeeper=gatekeeper,
        archive_filename=context.archive_name,
        archive_sha256=prepared.archive_sha256,
        failure_code="sealed_evidence_verification_failed",
        failure_message="publish-ready evidence failed strict validation",
    )
    final_app = publication_root / "Clash for Mac.app"
    post_staple_app_sha256 = _app_tree_sha256(
        final_app,
        failure_code="sealed_app_identity_drift",
        failure_message="publish-ready app identity cannot be derived",
    )
    if (
        expected_post_staple_app_sha256 is not None
        and post_staple_app_sha256 != expected_post_staple_app_sha256
    ) or (
        evidence.gatekeeper["target_signed_app_tree_sha256"]
        != post_staple_app_sha256
    ):
        raise TransactionError(
            "sealed_gatekeeper_target_mismatch",
            "publish-ready Gatekeeper evidence is not bound to the app",
        )
    _require_submission_acquisition_evidence(prepared)
    _, intent_sha256 = _read_exact_json_document(
        prepared.intent_path,
        prepared.intent,
        drift_code="notarization_intent_identity_drift",
        drift_message="notarization intent differs while building its receipt",
    )
    _, submission_receipt_sha256 = _read_exact_json_document(
        prepared.submission_receipt_path,
        prepared.submission_receipt,
        drift_code="submission_receipt_identity_drift",
        drift_message="submission receipt differs while building final receipt",
    )
    recovery_intent_sha256: str | None = None
    if prepared.recovery_intent is not None:
        if prepared.recovery_intent_path is None:
            raise TransactionError(
                "recovery_intent_identity_drift",
                "recovery intent path is missing",
            )
        _, recovery_intent_sha256 = _read_exact_json_document(
            prepared.recovery_intent_path,
            prepared.recovery_intent,
            drift_code="recovery_intent_identity_drift",
            drift_message="recovery intent differs while building final receipt",
        )
    recovery_continuation_sha256: str | None = None
    if prepared.recovery_continuation is not None:
        if prepared.recovery_continuation_path is None:
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation path is missing",
            )
        _, recovery_continuation_sha256 = _read_exact_json_document(
            prepared.recovery_continuation_path,
            prepared.recovery_continuation,
            drift_code="recovery_continuation_identity_drift",
            drift_message="recovery continuation differs while building final receipt",
        )
    archive = publication_root / context.archive_name
    _require_archive_identity(
        archive,
        prepared.archive_sha256,
        prepared.archive_size,
    )
    return {
        "schema_version": 3,
        "document": RECEIPT_DOCUMENT,
        "attempt_id": prepared.attempt_id,
        "submission_id": prepared.submission_id,
        "intent_sha256": intent_sha256,
        "preseal_event_sha256": preseal_sha256,
        "submission_receipt_sha256": submission_receipt_sha256,
        "recovery_intent_sha256": recovery_intent_sha256,
        "recovery_continuation_sha256": recovery_continuation_sha256,
        "accepted_notary_log_sha256": evidence.notary_log_sha256,
        "notarization_result_sha256": evidence.notarization_sha256,
        "archive_sha256": prepared.archive_sha256,
        "pre_staple_app_tree_sha256": prepared.pre_staple_app_sha256,
        "post_staple_app_tree_sha256": post_staple_app_sha256,
        "gatekeeper_evidence_sha256": evidence.gatekeeper_sha256,
        "app_manifest_sha256": _sha256_file(
            publication_root / "Clash for Mac.app.manifest.json"
        ),
        "archive_manifest_sha256": _sha256_file(
            publication_root / f"{context.archive_name}.manifest.json"
        ),
        "state": "publish-ready",
        "sealed_at": sealed_at,
    }


def _require_sealed_journal_lineage(
    journal: EventJournal,
    *,
    receipt: dict[str, Any],
    submission_id: str,
    allow_direct_publish_failure: bool = False,
    allow_missing_sealed: bool = False,
    allow_receipt_durability_unknown: bool = False,
) -> None:
    matching_preseal_sequences = [
        sequence
        for sequence in range(1, journal.sequence + 1)
        if _sha256_file(journal.directory / f"{sequence:08d}.json")
        == receipt["preseal_event_sha256"]
    ]
    if len(matching_preseal_sequences) != 1:
        raise TransactionError(
            "sealed_journal_lineage_mismatch",
            "sealed receipt does not identify one retained preseal journal event",
        )
    preseal_sequence = matching_preseal_sequences[0]
    preseal = journal.documents[preseal_sequence - 1]
    if (
        preseal["state"] != "distribution_verified"
        or preseal["submission_id"] != submission_id
        or preseal["failure_code"] is not None
        or preseal["exit_code"] is not None
    ):
        raise TransactionError(
            "sealed_journal_lineage_mismatch",
            "sealed receipt preseal event is not distribution verification",
        )
    sealed_sequence = preseal_sequence + 1
    receipt_unknown: dict[str, Any] | None = None
    if sealed_sequence <= journal.sequence:
        candidate = journal.documents[sealed_sequence - 1]
        if _is_receipt_durability_unknown_event(
            candidate,
            submission_id=submission_id,
        ):
            if not allow_receipt_durability_unknown:
                raise TransactionError(
                    "sealed_journal_lineage_mismatch",
                    "receipt durability outcome is unsupported in this lane",
                )
            if (
                candidate["previous_event_sha256"]
                != receipt["preseal_event_sha256"]
                or not (
                    _parse_utc_timestamp(
                        preseal["recorded_at"],
                        "distribution verified event recorded_at",
                    )[1]
                    <= _parse_utc_timestamp(
                        receipt["sealed_at"],
                        "publish-ready receipt sealed_at",
                    )[1]
                    <= _parse_utc_timestamp(
                        candidate["recorded_at"],
                        "receipt durability outcome recorded_at",
                    )[1]
                )
            ):
                raise TransactionError(
                    "sealed_journal_lineage_mismatch",
                    "receipt durability outcome is not causally bound",
                )
            receipt_unknown = candidate
            sealed_sequence += 1
    if sealed_sequence > journal.sequence:
        if (
            allow_missing_sealed
            and (
                preseal_sequence == journal.sequence
                or (
                    receipt_unknown is not None
                    and preseal_sequence + 1 == journal.sequence
                )
            )
            and _parse_utc_timestamp(
                receipt["sealed_at"],
                "publish-ready receipt sealed_at",
            )[1]
            >= _parse_utc_timestamp(
                preseal["recorded_at"],
                "distribution verified event recorded_at",
            )[1]
        ):
            return
        raise TransactionError(
            "sealed_journal_lineage_mismatch",
            "sealed receipt has no retained sealed journal event",
        )
    sealed = journal.documents[sealed_sequence - 1]
    expected_previous_sha256 = _sha256_file(
        journal.directory / f"{sealed_sequence - 1:08d}.json"
    )
    sealed_recorded_at = _parse_utc_timestamp(
        sealed["recorded_at"],
        "sealed event recorded_at",
    )[1]
    receipt_sealed_at = _parse_utc_timestamp(
        receipt["sealed_at"],
        "publish-ready receipt sealed_at",
    )[1]
    timestamp_matches = (
        sealed_recorded_at == receipt_sealed_at
        if receipt_unknown is None
        else _parse_utc_timestamp(
            receipt_unknown["recorded_at"],
            "receipt durability outcome recorded_at",
        )[1]
        <= sealed_recorded_at
    )
    if (
        sealed["state"] != "sealed"
        or sealed["previous_event_sha256"] != expected_previous_sha256
        or sealed["submission_id"] != submission_id
        or not timestamp_matches
        or sealed["failure_code"] is not None
        or sealed["exit_code"] is not None
    ):
        raise TransactionError(
            "sealed_journal_lineage_mismatch",
            "sealed journal event differs from its receipt",
        )
    suffix = journal.documents[sealed_sequence:]
    if not suffix:
        return
    if len(suffix) != 1:
        raise TransactionError(
            "sealed_journal_lineage_mismatch",
            "sealed publication has unsupported later journal events",
        )
    outcome = suffix[0]
    sealed_sha256 = _sha256_file(
        journal.directory / f"{sealed_sequence:08d}.json"
    )
    accepted_terminal = (
        outcome["state"] == "outcome_unknown"
        and outcome["failure_code"] == "publish_durability_unknown"
    ) or (
        allow_direct_publish_failure
        and outcome["state"] == "failed"
        and outcome["failure_code"] == "atomic_publish_failed"
    )
    if (
        not accepted_terminal
        or outcome["previous_event_sha256"] != sealed_sha256
        or outcome["submission_id"] != submission_id
        or outcome["exit_code"] is not None
    ):
        raise TransactionError(
            "sealed_journal_lineage_mismatch",
            "sealed publication has an unsupported terminal journal outcome",
        )


def _strict_directory_inventory(
    directory: Path,
    *,
    failure_code: str,
    failure_message: str,
) -> set[str]:
    try:
        return {path.name for path in directory.iterdir()}
    except OSError as error:
        raise TransactionError(failure_code, failure_message) from error


def _strict_path_identity(
    path: Path,
    *,
    failure_code: str,
    failure_message: str,
) -> tuple[int, ...]:
    try:
        return _transaction_file_identity(os.lstat(path))
    except OSError as error:
        raise TransactionError(failure_code, failure_message) from error


def _validate_sealed_publication(
    prepared: PreparedAttempt,
    *,
    journal: EventJournal,
    publication_root: Path,
    receipt_path: Path,
    manifest_verifier: ManifestVerifier,
    source_identity_reader: SourceIdentityReader,
    toolchain_metadata_reader: ToolchainMetadataReader,
    allow_direct_publish_failure: bool = False,
    allow_missing_sealed: bool = False,
    expected_receipt: dict[str, Any] | None = None,
    allow_receipt_durability_unknown: bool = False,
) -> dict[str, Any]:
    context = prepared.context
    _require_real_directory(publication_root, private=True)
    publication_identity = _strict_path_identity(
        publication_root,
        failure_code="sealed_publication_identity_unavailable",
        failure_message="sealed publication identity cannot be captured",
    )
    run_root = receipt_path.parent
    recovery_run = run_root.parent == context.attempt_root / "finalization-runs"
    direct_run = run_root == context.attempt_root
    if receipt_path.name != "receipt.json" or not (recovery_run or direct_run):
        raise TransactionError(
            "sealed_receipt_location_invalid",
            "sealed receipt is outside a canonical finalization run",
        )
    if recovery_run:
        _canonical_uuid(run_root.name, "finalization run id")
        _require_real_directory(run_root, private=True)
        expected_run_inventory = {"receipt.json"}
        if publication_root.parent == run_root:
            expected_run_inventory.add(publication_root.name)
        if _strict_directory_inventory(
            run_root,
            failure_code="sealed_finalization_inventory_unavailable",
            failure_message="matching finalization run cannot be enumerated",
        ) != expected_run_inventory:
            raise TransactionError(
                "sealed_finalization_inventory_mismatch",
                "matching finalization run has unexpected entries",
            )
    elif (
        publication_root.parent != context.attempt_root
        and publication_root != context.final_root
    ):
        raise TransactionError(
            "sealed_receipt_location_invalid",
            "direct publication is outside its notarization attempt",
        )

    if expected_receipt is None:
        receipt_data = _read_regular_bytes(receipt_path)
        receipt = _decode_json_bytes(receipt_data, receipt_path)
    else:
        receipt = expected_receipt
        receipt_data = _canonical_json(receipt).encode("utf-8")
    if (
        not isinstance(receipt, dict)
        or set(receipt) != PUBLISH_READY_RECEIPT_FIELDS
        or receipt_data != _canonical_json(receipt).encode("utf-8")
        or type(receipt.get("schema_version")) is not int
        or receipt.get("schema_version") != 3
        or receipt.get("document") != RECEIPT_DOCUMENT
        or receipt.get("attempt_id") != prepared.attempt_id
        or receipt.get("submission_id") != prepared.submission_id
        or receipt.get("intent_sha256") != prepared.intent_sha256
        or receipt.get("archive_sha256") != prepared.archive_sha256
        or receipt.get("pre_staple_app_tree_sha256")
        != prepared.pre_staple_app_sha256
        or receipt.get("state") != "publish-ready"
    ):
        raise TransactionError(
            "sealed_receipt_identity_drift",
            "publish-ready receipt differs from this notarization transaction",
        )
    for key in PUBLISH_READY_RECEIPT_FIELDS - {
        "schema_version",
        "document",
        "attempt_id",
        "submission_id",
        "recovery_intent_sha256",
        "recovery_continuation_sha256",
        "state",
        "sealed_at",
    }:
        if not isinstance(receipt[key], str) or not SHA256_RE.fullmatch(
            receipt[key]
        ):
            raise TransactionError(
                "sealed_receipt_identity_drift",
                "publish-ready receipt contains a malformed digest",
            )
    for optional_key in (
        "recovery_intent_sha256",
        "recovery_continuation_sha256",
    ):
        if receipt[optional_key] is not None and (
            not isinstance(receipt[optional_key], str)
            or not SHA256_RE.fullmatch(receipt[optional_key])
        ):
            raise TransactionError(
                "sealed_receipt_identity_drift",
                "publish-ready receipt contains a malformed optional digest",
            )
    _parse_utc_timestamp(receipt["sealed_at"], "publish-ready receipt sealed_at")
    _require_sealed_journal_lineage(
        journal,
        receipt=receipt,
        submission_id=prepared.submission_id,
        allow_direct_publish_failure=allow_direct_publish_failure,
        allow_missing_sealed=allow_missing_sealed,
        allow_receipt_durability_unknown=allow_receipt_durability_unknown,
    )

    expected_inventory = set(FINAL_INVENTORY_TEMPLATE)
    expected_inventory.update(
        {
            context.archive_name,
            f"{context.archive_name}.manifest.json",
        }
    )
    if _strict_directory_inventory(
        publication_root,
        failure_code="sealed_publication_inventory_unavailable",
        failure_message="sealed publication directory cannot be enumerated",
    ) != expected_inventory:
        raise TransactionError(
            "sealed_publication_inventory_mismatch",
            "sealed publication directory has unexpected entries",
        )
    final_app = publication_root / "Clash for Mac.app"
    app_manifest = publication_root / "Clash for Mac.app.manifest.json"
    final_archive = publication_root / context.archive_name
    archive_manifest = publication_root / f"{context.archive_name}.manifest.json"
    notarization = {"id": prepared.submission_id, "status": "Accepted"}
    normalized_log = _decode_json_bytes(
        _read_regular_bytes(publication_root / "notarization-log.json"),
        publication_root / "notarization-log.json",
    )
    gatekeeper = _decode_json_bytes(
        _read_regular_bytes(publication_root / "gatekeeper.json"),
        publication_root / "gatekeeper.json",
    )
    if not isinstance(normalized_log, dict) or not isinstance(gatekeeper, dict):
        raise TransactionError(
            "sealed_evidence_verification_failed",
            "sealed notarization evidence is not a JSON object",
        )
    evidence = _require_exact_persisted_evidence(
        publication_root,
        expected_notarization=notarization,
        expected_log=normalized_log,
        expected_gatekeeper=gatekeeper,
        archive_filename=context.archive_name,
        archive_sha256=prepared.archive_sha256,
        failure_code="sealed_evidence_verification_failed",
        failure_message="sealed notarization evidence failed strict validation",
    )
    final_verifications = (
        (final_app, app_manifest, _app_metadata(context)),
        (final_archive, archive_manifest, prepared.archive_metadata),
    )
    try:
        _run_configured_manifest_verification_hooks(
            manifest_verifier,
            final_verifications,
        )
        _run_production_manifest_verifications(final_verifications)
    except TransactionError:
        raise
    except Exception as error:
        raise TransactionError(
            "sealed_manifest_verification_failed",
            "sealed publication manifest verification did not complete",
        ) from error
    _require_archive_identity(
        final_archive,
        prepared.archive_sha256,
        prepared.archive_size,
    )
    final_app_tree_sha256 = _app_tree_sha256(
        final_app,
        failure_code="sealed_app_identity_drift",
        failure_message="sealed application identity cannot be derived",
    )
    if (
        final_app_tree_sha256 != receipt["post_staple_app_tree_sha256"]
        or evidence.gatekeeper["target_signed_app_tree_sha256"]
        != final_app_tree_sha256
    ):
        raise TransactionError(
            "sealed_gatekeeper_target_mismatch",
            "sealed Gatekeeper evidence is not bound to the published app",
        )

    _require_submission_acquisition_evidence(prepared)
    _, intent_sha256 = _read_exact_json_document(
        prepared.intent_path,
        prepared.intent,
        drift_code="notarization_intent_identity_drift",
        drift_message="notarization intent differs from the sealed publication",
    )
    _, submission_receipt_sha256 = _read_exact_json_document(
        prepared.submission_receipt_path,
        prepared.submission_receipt,
        drift_code="submission_receipt_identity_drift",
        drift_message="submission receipt differs from the sealed publication",
    )
    recovery_intent_sha256: str | None = None
    if prepared.recovery_intent is not None:
        if prepared.recovery_intent_path is None:
            raise TransactionError(
                "recovery_intent_identity_drift",
                "recovery intent path is missing",
            )
        _, recovery_intent_sha256 = _read_exact_json_document(
            prepared.recovery_intent_path,
            prepared.recovery_intent,
            drift_code="recovery_intent_identity_drift",
            drift_message="recovery intent differs from the sealed publication",
        )
    recovery_continuation_sha256: str | None = None
    if prepared.recovery_continuation is not None:
        if prepared.recovery_continuation_path is None:
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation path is missing",
            )
        _, recovery_continuation_sha256 = _read_exact_json_document(
            prepared.recovery_continuation_path,
            prepared.recovery_continuation,
            drift_code="recovery_continuation_identity_drift",
            drift_message="recovery continuation differs from the sealed publication",
        )
    bindings = {
        "intent_sha256": intent_sha256,
        "submission_receipt_sha256": submission_receipt_sha256,
        "recovery_intent_sha256": recovery_intent_sha256,
        "recovery_continuation_sha256": recovery_continuation_sha256,
        "accepted_notary_log_sha256": evidence.notary_log_sha256,
        "notarization_result_sha256": evidence.notarization_sha256,
        "gatekeeper_evidence_sha256": evidence.gatekeeper_sha256,
        "app_manifest_sha256": _sha256_file(app_manifest),
        "archive_manifest_sha256": _sha256_file(archive_manifest),
    }
    if any(receipt[key] != value for key, value in bindings.items()):
        raise TransactionError(
            "sealed_receipt_binding_mismatch",
            "sealed publication differs from its publish-ready receipt",
        )
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)
    journal.verify()
    _require_archive_identity(
        final_archive,
        prepared.archive_sha256,
        prepared.archive_size,
    )
    final_file_bindings = {
        "accepted_notary_log_sha256": _sha256_file(
            publication_root / "notarization-log.json"
        ),
        "notarization_result_sha256": _sha256_file(
            publication_root / "notarization.json"
        ),
        "gatekeeper_evidence_sha256": _sha256_file(
            publication_root / "gatekeeper.json"
        ),
        "app_manifest_sha256": _sha256_file(app_manifest),
        "archive_manifest_sha256": _sha256_file(archive_manifest),
    }
    if (
        _strict_path_identity(
            publication_root,
            failure_code="sealed_publication_identity_unavailable",
            failure_message="sealed publication identity cannot be recaptured",
        )
        != publication_identity
        or _strict_directory_inventory(
            publication_root,
            failure_code="sealed_publication_inventory_unavailable",
            failure_message="sealed publication directory cannot be re-enumerated",
        ) != expected_inventory
        or _app_tree_sha256(
            final_app,
            failure_code="sealed_app_identity_drift",
            failure_message="sealed application changed during validation",
        )
        != final_app_tree_sha256
        or (
            expected_receipt is None
            and _sha256_file(receipt_path)
            != hashlib.sha256(receipt_data).hexdigest()
        )
        or any(
            receipt[key] != value
            for key, value in final_file_bindings.items()
        )
    ):
        raise TransactionError(
            "sealed_publication_changed",
            "sealed publication changed during validation",
        )
    return receipt


def _validate_direct_sealed_event_grammar(
    journal: EventJournal,
    *,
    submission_id: str,
    allow_distribution_head: bool = False,
) -> None:
    expected_states = [
        "prepared",
        "notary_ready",
        "submitting",
        "submitted",
        "accepted",
        "log_verified",
        "stapling",
        "stapled",
        "gatekeeper_verified",
        "app_verified",
        "distribution_verified",
        "sealed",
    ]
    observed_states = [event["state"] for event in journal.documents]
    if len(observed_states) < len(expected_states) - 1:
        raise TransactionError(
            "direct_sealed_journal_mismatch",
            "direct notarization journal is shorter than distribution verification",
        )
    if observed_states[1] == "pre_submission_policy_compatibility_applied":
        expected_states[1] = "pre_submission_policy_compatibility_applied"
    preseal_states = expected_states[:-1]
    if observed_states[: len(preseal_states)] != preseal_states:
        raise TransactionError(
            "direct_sealed_journal_mismatch",
            "direct notarization journal states are out of order",
        )
    for index, event in enumerate(journal.documents[: len(preseal_states)]):
        expected_submission_id = None if index < 3 else submission_id
        if (
            event["submission_id"] != expected_submission_id
            or event["failure_code"] is not None
            or event["exit_code"] is not None
        ):
            raise TransactionError(
                "direct_sealed_journal_mismatch",
                "direct notarization journal event fields are inconsistent",
            )
    index = len(preseal_states)
    if index == len(journal.documents):
        if allow_distribution_head:
            return
        raise TransactionError(
            "direct_sealed_journal_mismatch",
            "direct notarization journal has no sealed event",
        )
    candidate = journal.documents[index]
    if _is_receipt_durability_unknown_event(
        candidate,
        submission_id=submission_id,
    ):
        preseal_sha256 = _sha256_file(
            journal.directory / f"{index:08d}.json"
        )
        if candidate["previous_event_sha256"] != preseal_sha256:
            raise TransactionError(
                "direct_sealed_journal_mismatch",
                "receipt durability outcome differs from the distribution head",
            )
        index += 1
        if index == len(journal.documents):
            if allow_distribution_head:
                return
            raise TransactionError(
                "direct_sealed_journal_mismatch",
                "receipt durability outcome has no repaired sealed event",
            )
        candidate = journal.documents[index]
    if (
        candidate["state"] != "sealed"
        or candidate["submission_id"] != submission_id
        or candidate["failure_code"] is not None
        or candidate["exit_code"] is not None
    ):
        raise TransactionError(
            "direct_sealed_journal_mismatch",
            "direct notarization sealed event is malformed or missing",
        )
    index += 1
    if index == len(journal.documents):
        return
    if index + 1 != len(journal.documents):
        raise TransactionError(
            "direct_sealed_journal_mismatch",
            "direct notarization journal has multiple terminal events",
        )
    terminal = journal.documents[index]
    if (
        terminal["submission_id"] != submission_id
        or terminal["exit_code"] is not None
        or not (
            (
                terminal["state"] == "outcome_unknown"
                and terminal["failure_code"] == "publish_durability_unknown"
            )
            or (
                terminal["state"] == "failed"
                and terminal["failure_code"] == "atomic_publish_failed"
            )
        )
    ):
        raise TransactionError(
            "direct_sealed_journal_mismatch",
            "direct notarization terminal publication event is unsupported",
        )


def _resume_direct_sealed_transaction(
    context: TransactionContext,
    *,
    submission_id: str,
    manifest_verifier: ManifestVerifier,
    source_identity_reader: SourceIdentityReader,
    toolchain_metadata_reader: ToolchainMetadataReader,
    publisher: Publisher,
    clock: Clock,
) -> Path:
    _validate_context(context, recovery=True)
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)
    direct_allowed_entries = {
        "events",
        "intent.json",
        "submission-observation.json",
        "submission-receipt.json",
        "receipt.json",
        PUBLISH_READY_RECEIPT_PENDING_FILENAME,
        "publish-ready",
    }
    inventory = _decode_attempt_inventory(
        context,
        allowed_entries=direct_allowed_entries,
        require_source=False,
    )
    publish_ready = context.attempt_root / "publish-ready"
    final_exists = inventory.final_exists
    publish_ready_exists = inventory.direct_publish_ready is not None
    if final_exists == publish_ready_exists:
        raise TransactionError(
            "direct_sealed_inventory_mismatch",
            "direct sealed transaction must have exactly one publication location",
        )
    receipt_path = context.attempt_root / "receipt.json"
    receipt_pending_path = (
        context.attempt_root / PUBLISH_READY_RECEIPT_PENDING_FILENAME
    )
    receipt_exists = inventory.receipt_exists
    receipt_pending_exists = inventory.receipt_pending_exists
    if receipt_exists and receipt_pending_exists:
        raise TransactionError(
            "direct_sealed_inventory_mismatch",
            "direct sealed transaction has conflicting receipt states",
        )
    expected_attempt_inventory = {
        "events",
        "intent.json",
        "submission-observation.json",
        "submission-receipt.json",
    }
    if receipt_exists:
        expected_attempt_inventory.add("receipt.json")
    if receipt_pending_exists:
        expected_attempt_inventory.add(PUBLISH_READY_RECEIPT_PENDING_FILENAME)
    if publish_ready_exists:
        expected_attempt_inventory.add("publish-ready")
    if inventory.entries != expected_attempt_inventory:
        raise TransactionError(
            "direct_sealed_inventory_mismatch",
            "direct sealed attempt has unexpected entries",
        )
    intent, intent_path, intent_sha256 = _load_recovery_intent_document(context)
    journal = EventJournal.load_existing(
        context.attempt_root / "events",
        intent_sha256,
        clock,
    )
    submission_receipt_path = context.attempt_root / "submission-receipt.json"
    submission_receipt_data = _read_regular_bytes(submission_receipt_path)
    submission_receipt = _decode_json_bytes(
        submission_receipt_data,
        submission_receipt_path,
    )
    if (
        not isinstance(submission_receipt, dict)
        or set(submission_receipt) != SUBMISSION_RECEIPT_FIELDS
        or submission_receipt_data
        != _canonical_json(submission_receipt).encode("utf-8")
        or type(submission_receipt.get("schema_version")) is not int
        or submission_receipt.get("schema_version") != 2
        or submission_receipt.get("document") != SUBMISSION_DOCUMENT
        or submission_receipt.get("attempt_id") != intent["attempt_id"]
        or submission_receipt.get("submission_id") != submission_id
        or submission_receipt.get("acquisition") != "submit-no-wait"
        or submission_receipt.get("archive_name") != context.archive_name
        or submission_receipt.get("archive_sha256") != intent["archive_sha256"]
    ):
        raise TransactionError(
            "direct_submission_receipt_mismatch",
            "direct sealed submission receipt differs from its intent",
        )
    observation_path = context.attempt_root / "submission-observation.json"
    observation_data = _read_regular_bytes(observation_path)
    observation = _decode_json_bytes(observation_data, observation_path)
    observation_sha256 = hashlib.sha256(observation_data).hexdigest()
    if (
        not isinstance(observation, dict)
        or set(observation) != SUBMISSION_OBSERVATION_FIELDS
        or observation_data != _canonical_json(observation).encode("utf-8")
        or type(observation.get("schema_version")) is not int
        or observation.get("schema_version") != 1
        or observation.get("document") != SUBMISSION_OBSERVATION_DOCUMENT
        or observation.get("attempt_id") != intent["attempt_id"]
        or observation.get("submission_id") != submission_id
        or observation.get("intent_sha256") != intent_sha256
        or observation.get("archive_name") != context.archive_name
        or observation.get("archive_sha256") != intent["archive_sha256"]
        or observation.get("path_binding") != "exact"
        or submission_receipt.get("submission_observation_sha256")
        != observation_sha256
    ):
        raise TransactionError(
            "direct_submission_observation_mismatch",
            "direct sealed submission observation differs from its receipt",
        )
    observation_at = _parse_utc_timestamp(
        observation["observed_at"],
        "direct submission observation observed_at",
    )[1]
    receipt_observed_at = _parse_utc_timestamp(
        submission_receipt["observed_at"],
        "direct submission receipt observed_at",
    )[1]
    _reduce_attempt_events(
        journal,
        submission_id=submission_id,
        direct_sealed=True,
        allow_distribution_head=publish_ready_exists,
    )
    submitting_at = _parse_utc_timestamp(
        journal.documents[2]["recorded_at"],
        "direct submitting event recorded_at",
    )[1]
    submitted_at = _parse_utc_timestamp(
        journal.documents[3]["recorded_at"],
        "direct submitted event recorded_at",
    )[1]
    if not (
        submitting_at <= observation_at <= receipt_observed_at <= submitted_at
    ):
        raise TransactionError(
            "direct_submission_observation_mismatch",
            "direct submission observation timestamps are not causally ordered",
        )
    publication_root = context.final_root if final_exists else publish_ready
    archive_metadata = _archive_metadata(context)
    prepared = PreparedAttempt(
        context=context,
        work=publication_root,
        work_app=publication_root / "Clash for Mac.app",
        archive=publication_root / context.archive_name,
        archive_manifest=(
            publication_root / f"{context.archive_name}.manifest.json"
        ),
        archive_metadata=archive_metadata,
        archive_sha256=intent["archive_sha256"],
        archive_size=intent["archive_size"],
        pre_staple_app_sha256=intent["pre_staple_app_tree_sha256"],
        attempt_id=intent["attempt_id"],
        intent=intent,
        intent_path=intent_path,
        intent_sha256=intent_sha256,
        submission_id=submission_id,
        submission_receipt=submission_receipt,
        submission_receipt_path=submission_receipt_path,
        recovery_intent=None,
        recovery_intent_path=None,
        recovery_continuation=None,
        recovery_continuation_path=None,
        recovery_tool_repository=None,
        recovery_tool_identity=None,
        recovery_tool_identity_reader=None,
    )

    receipt_durability_unknown = _is_receipt_durability_unknown_event(
        journal.documents[-1],
        submission_id=submission_id,
    )
    if (
        journal.documents[-1]["state"] == "distribution_verified"
        or receipt_durability_unknown
    ):
        if not publish_ready_exists or final_exists:
            raise TransactionError(
                "direct_preseal_recovery_unavailable",
                "missing sealed event is recoverable only before direct publication",
            )
        if receipt_durability_unknown and (
            not receipt_exists or receipt_pending_exists
        ):
            raise TransactionError(
                "sealed_receipt_identity_drift",
                "receipt durability outcome lacks its complete final receipt",
            )
        receipt: dict[str, Any]
        receipt_needs_publish = False
        if receipt_exists:
            receipt_data = _read_regular_bytes(receipt_path)
            receipt_value = _decode_json_bytes(receipt_data, receipt_path)
            if not isinstance(receipt_value, dict):
                raise TransactionError(
                    "sealed_receipt_identity_drift",
                    "direct publish-ready receipt is not a JSON object",
                )
            receipt = _build_publish_ready_receipt(
                prepared,
                journal=journal,
                publication_root=publish_ready,
                sealed_at=receipt_value.get("sealed_at"),
            )
            if receipt_data != _canonical_json(receipt).encode("utf-8"):
                raise TransactionError(
                    "sealed_receipt_identity_drift",
                    "direct publish-ready receipt differs from rebuilt bindings",
                )
        elif receipt_pending_exists:
            pending_data = _read_private_pending_bytes(receipt_pending_path)
            try:
                pending_value = _decode_json_bytes(
                    pending_data,
                    receipt_pending_path,
                )
            except TransactionError:
                _discard_partial_pending(receipt_pending_path)
                receipt_pending_exists = False
            else:
                if not isinstance(pending_value, dict):
                    raise TransactionError(
                        "pending_evidence_identity_drift",
                        "complete receipt pending JSON is not an object",
                    )
                receipt = _build_publish_ready_receipt(
                    prepared,
                    journal=journal,
                    publication_root=publish_ready,
                    sealed_at=pending_value.get("sealed_at"),
                )
                expected_receipt_data = _canonical_json(receipt).encode("utf-8")
                if pending_data != expected_receipt_data:
                    raise TransactionError(
                        "pending_evidence_identity_drift",
                        "complete receipt pending JSON differs from rebuilt bindings",
                    )
                receipt_needs_publish = True
        if not receipt_exists:
            if not receipt_needs_publish:
                receipt = _build_publish_ready_receipt(
                    prepared,
                    journal=journal,
                    publication_root=publish_ready,
                    sealed_at=clock(),
                )
                receipt_needs_publish = True
        preseal_sequence = (
            journal.sequence - 1
            if receipt_durability_unknown
            else journal.sequence
        )
        preseal_sha256 = _sha256_file(
            journal.directory / f"{preseal_sequence:08d}.json"
        )
        if preseal_sha256 != receipt["preseal_event_sha256"]:
            raise TransactionError(
                "receipt_preseal_lineage_mismatch",
                "direct receipt is not bound to the current journal head",
            )
        _validate_sealed_publication(
            prepared,
            journal=journal,
            publication_root=publish_ready,
            receipt_path=receipt_path,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            allow_direct_publish_failure=True,
            allow_missing_sealed=True,
            allow_receipt_durability_unknown=True,
            expected_receipt=(receipt if receipt_needs_publish else None),
        )
        if receipt_needs_publish:
            _publish_pending_evidence(
                pending_path=receipt_pending_path,
                destination_path=receipt_path,
                data=_canonical_json(receipt).encode("utf-8"),
                allow_partial_rebuild=False,
            )
            receipt_exists = True
            receipt_pending_exists = False
        _validate_sealed_publication(
            prepared,
            journal=journal,
            publication_root=publish_ready,
            receipt_path=receipt_path,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            allow_direct_publish_failure=True,
            allow_missing_sealed=True,
            allow_receipt_durability_unknown=True,
        )
        sealed_recorded_at = (
            clock() if receipt_durability_unknown else receipt["sealed_at"]
        )
        if receipt_durability_unknown and _parse_utc_timestamp(
            sealed_recorded_at,
            "repaired sealed event recorded_at",
        )[1] < _parse_utc_timestamp(
            journal.documents[-1]["recorded_at"],
            "receipt durability outcome recorded_at",
        )[1]:
            raise TransactionError(
                "receipt_preseal_lineage_mismatch",
                "repaired sealed event predates receipt durability outcome",
            )
        journal.append(
            "sealed",
            submission_id=submission_id,
            recorded_at=sealed_recorded_at,
        )
        expected_attempt_inventory.discard(
            PUBLISH_READY_RECEIPT_PENDING_FILENAME
        )
        expected_attempt_inventory.add("receipt.json")
        repaired_inventory = _decode_attempt_inventory(
            context,
            allowed_entries=direct_allowed_entries,
            require_source=False,
        )
        if repaired_inventory.entries != expected_attempt_inventory:
            raise TransactionError(
                "direct_sealed_inventory_mismatch",
                "direct sealed attempt changed while repairing its receipt",
            )
    elif not receipt_exists or receipt_pending_exists:
        raise TransactionError(
            "sealed_receipt_identity_drift",
            "sealed direct journal lacks one complete final receipt",
        )

    def validate(root: Path) -> None:
        _validate_sealed_publication(
            prepared,
            journal=journal,
            publication_root=root,
            receipt_path=context.attempt_root / "receipt.json",
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            allow_direct_publish_failure=True,
            allow_receipt_durability_unknown=True,
        )

    validate(publication_root)
    if publish_ready_exists:
        try:
            publisher(publish_ready, context.final_root)
        except TransactionError:
            raise
        except Exception as error:
            raise TransactionError(
                "atomic_publish_failed",
                "direct sealed publication retry failed",
            ) from error
        if (
            os.path.lexists(publish_ready)
            or not os.path.lexists(context.final_root)
        ):
            raise TransactionError(
                "direct_publish_result_ambiguous",
                "direct publisher returned without one exclusive final location",
            )
        publication_root = context.final_root
    try:
        _fsync_tree(publication_root)
        _fsync_directory(publication_root.parent)
        _fsync_directory(context.attempt_root)
    except OSError as error:
        raise TransactionError(
            "publish_durability_unknown",
            "direct sealed publication durability remains unconfirmed",
            terminal_state="outcome_unknown",
        ) from error
    validate(publication_root)
    return publication_root / "Clash for Mac.app"


def _finalize_accepted_submission(
    prepared: PreparedAttempt,
    *,
    journal: EventJournal,
    command_runner: CommandRunner,
    gatekeeper_capture: GatekeeperCapture,
    manifest_writer: ManifestWriter,
    manifest_verifier: ManifestVerifier,
    source_identity_reader: SourceIdentityReader,
    toolchain_metadata_reader: ToolchainMetadataReader,
    publisher: Publisher,
    clock: Clock,
    accepted_raw_log: Any | None = None,
) -> Path:
    context = prepared.context
    work = prepared.work
    work_app = prepared.work_app
    archive = prepared.archive
    archive_manifest = prepared.archive_manifest
    archive_metadata = prepared.archive_metadata
    archive_sha256 = prepared.archive_sha256
    archive_size = prepared.archive_size
    pre_staple_app_sha256 = prepared.pre_staple_app_sha256
    attempt_id = prepared.attempt_id
    intent = prepared.intent
    intent_path = prepared.intent_path
    intent_sha256 = prepared.intent_sha256
    submission_id = prepared.submission_id
    submission_receipt = prepared.submission_receipt
    submission_receipt_path = prepared.submission_receipt_path
    _require_submission_acquisition_evidence(prepared)
    notarization = {"id": submission_id, "status": "Accepted"}
    notarization_path = work / "notarization.json"
    _write_json_exclusive(notarization_path, notarization)
    journal.append("accepted", submission_id=submission_id)

    if accepted_raw_log is None:
        log_command = [
            "/usr/bin/xcrun",
            "notarytool",
            "log",
            submission_id,
            "--keychain-profile",
            context.notary_profile,
        ]
        fetched_log = _result_or_error(
            command_runner,
            CommandRole.FETCH_LOG,
            log_command,
            300,
        )
        _require_empty_notary_stderr(fetched_log, CommandRole.FETCH_LOG)
        raw_log = _parse_command_json(fetched_log.stdout)
    else:
        raw_log = accepted_raw_log
    _require_archive_identity(archive, archive_sha256, archive_size)
    try:
        normalized_log = validate_documents(
            notarization,
            raw_log,
            archive_filename=context.archive_name,
            archive_sha256=archive_sha256,
        )
    except NotaryLogError as error:
        raise TransactionError(
            "notary_log_verification_failed",
            "Apple notarization log failed strict binding validation",
        ) from error
    notarization_log_path = work / "notarization-log.json"
    _write_json_exclusive(notarization_log_path, normalized_log)
    journal.append("log_verified", submission_id=submission_id)

    journal.append("stapling", submission_id=submission_id)
    _result_or_error(
        command_runner,
        CommandRole.STAPLE,
        ["/usr/bin/xcrun", "stapler", "staple", str(work_app)],
        600,
    )
    _result_or_error(
        command_runner,
        CommandRole.STAPLE_VALIDATE,
        ["/usr/bin/xcrun", "stapler", "validate", str(work_app)],
        300,
    )
    post_staple_app_sha256 = _app_tree_sha256(
        work_app,
        failure_code="app_identity_failed",
        failure_message="post-staple app digest cannot be derived",
    )
    journal.append("stapled", submission_id=submission_id)

    try:
        captured_gatekeeper = gatekeeper_capture(
            work_app,
            post_staple_app_sha256,
        )
    except TransactionError as error:
        if error.code == "gatekeeper_target_mismatch":
            raise
        raise TransactionError(
            "gatekeeper_verification_failed",
            "Gatekeeper did not accept the stapled app",
        ) from error
    except Exception as error:
        raise TransactionError(
            "gatekeeper_verification_failed",
            "Gatekeeper did not accept the stapled app",
        ) from error
    if (
        not isinstance(captured_gatekeeper, dict)
        or captured_gatekeeper.get("target_signed_app_tree_sha256")
        != post_staple_app_sha256
    ):
        raise TransactionError(
            "gatekeeper_target_mismatch",
            "Gatekeeper evidence is not bound to the exact stapled app tree",
        )
    try:
        gatekeeper = validate_gatekeeper_evidence(
            captured_gatekeeper,
            expected_assessment_type="execute",
            expected_primary_signature_context=False,
            expected_target=work_app,
        )
    except Exception as error:
        raise TransactionError(
            "gatekeeper_verification_failed", "Gatekeeper did not accept the stapled app"
        ) from error
    gatekeeper_path = work / "gatekeeper.json"
    _write_json_exclusive(gatekeeper_path, gatekeeper)
    journal.append("gatekeeper_verified", submission_id=submission_id)
    _result_or_error(
        command_runner,
        CommandRole.FINAL_VERIFY,
        [
            str(context.repository / "scripts/verify_release_app.sh"),
            str(work_app),
            str(context.native_products),
        ],
        600,
    )
    journal.append("app_verified", submission_id=submission_id)
    _require_source_identity(context, source_identity_reader)

    finalization_root = work.parent
    publish_ready = finalization_root / "publish-ready"
    _mkdir_private(publish_ready, exclusive=True)
    for item in (
        work_app,
        archive,
        archive_manifest,
        notarization_path,
        notarization_log_path,
        gatekeeper_path,
    ):
        os.rename(item, publish_ready / item.name)
    os.rmdir(work)
    _fsync_directory(publish_ready)

    final_app = publish_ready / "Clash for Mac.app"
    app_manifest = publish_ready / "Clash for Mac.app.manifest.json"
    app_metadata = _app_metadata(context)
    manifest_writer(final_app, app_manifest, app_metadata)
    _run_manifest_verification_barrier(
        manifest_verifier,
        ((final_app, app_manifest, app_metadata),),
    )
    final_archive = publish_ready / context.archive_name
    final_archive_manifest = publish_ready / f"{context.archive_name}.manifest.json"
    _run_manifest_verification_barrier(
        manifest_verifier,
        ((final_archive, final_archive_manifest, archive_metadata),),
    )
    persisted_evidence = _require_exact_persisted_evidence(
        publish_ready,
        expected_notarization=notarization,
        expected_log=normalized_log,
        expected_gatekeeper=gatekeeper,
        archive_filename=context.archive_name,
        archive_sha256=archive_sha256,
        failure_code="sealed_evidence_verification_failed",
        failure_message=(
            "sealed notarization or Gatekeeper evidence differs from the "
            "validated transaction result"
        ),
    )
    persisted_app_tree_sha256 = _app_tree_sha256(
        final_app,
        failure_code="gatekeeper_target_mismatch",
        failure_message="sealed app identity cannot be derived",
    )
    if (
        persisted_evidence.gatekeeper["target_signed_app_tree_sha256"]
        != persisted_app_tree_sha256
    ):
        raise TransactionError(
            "gatekeeper_target_mismatch",
            "sealed Gatekeeper evidence differs from the final app tree",
        )
    _result_or_error(
        command_runner,
        CommandRole.FINAL_VERIFY,
        [
            str(context.repository / "scripts/verify_release_app.sh"),
            str(final_app),
            str(context.native_products),
        ],
        600,
    )
    distribution = _result_or_error(
        command_runner,
        CommandRole.DISTRIBUTION_CHECK,
        [
            "/usr/bin/syspolicy_check",
            "distribution",
            str(final_app),
            "--json",
        ],
        600,
    )
    _require_syspolicy_success(
        distribution,
        CommandRole.DISTRIBUTION_CHECK,
        final_app,
    )
    journal.append("distribution_verified", submission_id=submission_id)
    expected_inventory = set(FINAL_INVENTORY_TEMPLATE)
    expected_inventory.update({context.archive_name, final_archive_manifest.name})
    if {path.name for path in publish_ready.iterdir()} != expected_inventory:
        raise TransactionError(
            "publish_inventory_mismatch", "publish-ready directory has unexpected entries"
        )
    sealed_at = clock()
    _require_source_identity(context, source_identity_reader)
    _result_or_error(
        command_runner,
        CommandRole.FINAL_VERIFY,
        [
            str(context.repository / "scripts/verify_release_app.sh"),
            str(final_app),
            str(context.native_products),
        ],
        600,
    )
    final_verifications = (
        (final_app, app_manifest, app_metadata),
        (final_archive, final_archive_manifest, archive_metadata),
    )
    _run_configured_manifest_verification_hooks(
        manifest_verifier,
        final_verifications,
    )
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)
    _run_production_manifest_verifications(final_verifications)
    _require_archive_identity(final_archive, archive_sha256, archive_size)
    preseal_app_tree_sha256 = _app_tree_sha256(
        final_app,
        failure_code="preseal_app_identity_drift",
        failure_message="publish-ready app identity changed before sealing",
    )
    if (
        preseal_app_tree_sha256 != post_staple_app_sha256
        or gatekeeper["target_signed_app_tree_sha256"]
        != preseal_app_tree_sha256
    ):
        raise TransactionError(
            "preseal_app_identity_drift",
            "publish-ready app differs from the stapled Gatekeeper-assessed app",
        )
    if {path.name for path in publish_ready.iterdir()} != expected_inventory:
        raise TransactionError(
            "preseal_publish_inventory_mismatch",
            "publish-ready inventory changed before sealing",
        )
    receipt = _build_publish_ready_receipt(
        prepared,
        journal=journal,
        publication_root=publish_ready,
        sealed_at=sealed_at,
        expected_notarization=notarization,
        expected_log=normalized_log,
        expected_gatekeeper=gatekeeper,
        expected_post_staple_app_sha256=post_staple_app_sha256,
    )
    receipt_path = finalization_root / "receipt.json"
    _publish_pending_evidence(
        pending_path=(
            finalization_root / PUBLISH_READY_RECEIPT_PENDING_FILENAME
        ),
        destination_path=receipt_path,
        data=_canonical_json(receipt).encode("utf-8"),
        allow_partial_rebuild=False,
    )
    journal.append(
        "sealed",
        submission_id=submission_id,
        recorded_at=sealed_at,
    )
    _fsync_tree(publish_ready)
    _run_configured_manifest_verification_hooks(
        manifest_verifier,
        final_verifications,
    )
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)
    _run_production_manifest_verifications(final_verifications)
    final_app_tree_sha256 = _app_tree_sha256(
        final_app,
        failure_code="final_app_identity_drift",
        failure_message="publish-ready app identity changed before publication",
    )
    _, final_intent_sha256 = _read_exact_json_document(
        intent_path,
        intent,
        drift_code="notarization_intent_identity_drift",
        drift_message="notarization intent differs from this transaction",
    )
    _, final_submission_receipt_sha256 = _read_exact_json_document(
        submission_receipt_path,
        submission_receipt,
        drift_code="submission_receipt_identity_drift",
        drift_message="Apple submission receipt differs from this transaction",
    )
    final_recovery_intent_sha256: str | None = None
    if prepared.recovery_intent is not None:
        if prepared.recovery_intent_path is None:
            raise TransactionError(
                "recovery_intent_identity_drift",
                "recovery intent path is missing",
            )
        _, final_recovery_intent_sha256 = _read_exact_json_document(
            prepared.recovery_intent_path,
            prepared.recovery_intent,
            drift_code="recovery_intent_identity_drift",
            drift_message="recovery intent differs from this transaction",
        )
    final_recovery_continuation_sha256: str | None = None
    if prepared.recovery_continuation is not None:
        if prepared.recovery_continuation_path is None:
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation path is missing",
            )
        _, final_recovery_continuation_sha256 = _read_exact_json_document(
            prepared.recovery_continuation_path,
            prepared.recovery_continuation,
            drift_code="recovery_continuation_identity_drift",
            drift_message="recovery continuation differs from this transaction",
        )
    final_static_bindings = {
        "submission_receipt_sha256": final_submission_receipt_sha256,
        "recovery_intent_sha256": final_recovery_intent_sha256,
        "recovery_continuation_sha256": (
            final_recovery_continuation_sha256
        ),
        "app_manifest_sha256": _sha256_file(app_manifest),
        "archive_manifest_sha256": _sha256_file(final_archive_manifest),
    }
    final_receipt, _ = _read_exact_json_document(
        receipt_path,
        receipt,
        drift_code="final_receipt_changed",
        drift_message="notarization receipt changed before publication",
    )
    if final_receipt != receipt or final_intent_sha256 != receipt["intent_sha256"]:
        raise TransactionError(
            "final_receipt_changed", "notarization receipt changed before publication"
        )
    _require_archive_identity(final_archive, archive_sha256, archive_size)
    if {path.name for path in publish_ready.iterdir()} != expected_inventory:
        raise TransactionError(
            "final_publish_inventory_mismatch",
            "publish-ready inventory changed before publication",
        )
    final_evidence = _require_exact_persisted_evidence(
        publish_ready,
        expected_notarization=notarization,
        expected_log=normalized_log,
        expected_gatekeeper=gatekeeper,
        archive_filename=context.archive_name,
        archive_sha256=archive_sha256,
        failure_code="final_evidence_verification_failed",
        failure_message=(
            "final notarization or Gatekeeper evidence changed before publication"
        ),
    )
    if (
        final_evidence.gatekeeper["target_signed_app_tree_sha256"]
        != final_app_tree_sha256
        or final_app_tree_sha256 != post_staple_app_sha256
    ):
        raise TransactionError(
            "final_gatekeeper_target_mismatch",
            "final Gatekeeper evidence is not bound to the publish-ready app",
        )
    final_bindings = {
        **final_static_bindings,
        "accepted_notary_log_sha256": final_evidence.notary_log_sha256,
        "notarization_result_sha256": final_evidence.notarization_sha256,
        "gatekeeper_evidence_sha256": final_evidence.gatekeeper_sha256,
    }
    if any(receipt[key] != value for key, value in final_bindings.items()):
        raise TransactionError(
            "final_receipt_binding_mismatch",
            "publish-ready evidence differs from its sealed receipt",
        )
    _require_submission_acquisition_evidence(prepared)
    journal.verify()
    _validate_sealed_publication(
        prepared,
        journal=journal,
        publication_root=publish_ready,
        receipt_path=receipt_path,
        manifest_verifier=manifest_verifier,
        source_identity_reader=source_identity_reader,
        toolchain_metadata_reader=toolchain_metadata_reader,
    )
    _require_current_finalization_run_within_bounds(
        context,
        finalization_root,
    )
    try:
        publisher(publish_ready, context.final_root)
    except TransactionError:
        raise
    except Exception as error:
        raise TransactionError(
            "atomic_publish_failed", "exclusive atomic publication failed"
        ) from error
    if os.path.lexists(publish_ready) or not os.path.lexists(context.final_root):
        raise TransactionError(
            "publish_result_ambiguous",
            "publisher returned without one exclusive final location",
        )
    try:
        _require_current_finalization_run_within_bounds(
            context,
            finalization_root,
        )
    except TransactionError as error:
        raise TransactionError(
            "publish_durability_unknown",
            "published finalization run quota cannot be confirmed",
            terminal_state="outcome_unknown",
        ) from error
    return context.final_root / "Clash for Mac.app"



def _recovery_intent_static_fields(
    attempt: RecoverableAttempt,
    submission_id: str,
    recovery_tool_identity: dict[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "document": RECOVERY_DOCUMENT,
        "attempt_id": attempt.attempt_id,
        "submission_id": submission_id,
        "intent_sha256": attempt.intent_sha256,
        "prior_event_sha256": attempt.prior_event_sha256,
        "archive_sha256": attempt.archive_sha256,
        "submission_observation_sha256": (
            attempt.submission_observation_sha256
        ),
        "artifact_repository_commit": attempt.context.repository_commit,
        "artifact_release_source_sha256": attempt.context.release_source_sha256,
        "recovery_tool_repository_commit": recovery_tool_identity[
            "repositoryCommit"
        ],
        "recovery_tool_release_source_sha256": recovery_tool_identity[
            "releaseSourceSha256"
        ],
    }


def _load_existing_recovery_intent(
    attempt: RecoverableAttempt,
    submission_id: str,
    recovery_tool_identity: dict[str, str],
) -> tuple[dict[str, Any], Path, str]:
    """Load immutable recovery provenance without any create-capable path."""
    path = attempt.context.attempt_root / "recovery-intent.json"
    static = _recovery_intent_static_fields(
        attempt,
        submission_id,
        recovery_tool_identity,
    )
    data = _read_regular_bytes(path)
    value = _decode_json_bytes(data, path)
    invariant_fields = set(static) - {
        "recovery_tool_repository_commit",
        "recovery_tool_release_source_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != RECOVERY_FIELDS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("document") != RECOVERY_DOCUMENT
        or any(value.get(key) != static[key] for key in invariant_fields)
        or not isinstance(value.get("recovery_tool_repository_commit"), str)
        or not COMMIT_RE.fullmatch(value["recovery_tool_repository_commit"])
        or not isinstance(
            value.get("recovery_tool_release_source_sha256"), str
        )
        or not SHA256_RE.fullmatch(
            value["recovery_tool_release_source_sha256"]
        )
        or data != _canonical_json(value).encode("utf-8")
    ):
        raise TransactionError(
            "recovery_intent_identity_drift",
            "recovery intent differs from the requested reconciliation",
        )
    _parse_utc_timestamp(value["requested_at"], "recovery requested_at")
    return value, path, hashlib.sha256(data).hexdigest()


def _load_or_create_recovery_intent(
    attempt: RecoverableAttempt,
    submission_id: str,
    recovery_tool_identity: dict[str, str],
    clock: Clock,
) -> tuple[dict[str, Any], Path, str]:
    path = attempt.context.attempt_root / "recovery-intent.json"
    static = _recovery_intent_static_fields(
        attempt,
        submission_id,
        recovery_tool_identity,
    )
    if os.path.lexists(path):
        return _load_existing_recovery_intent(
            attempt,
            submission_id,
            recovery_tool_identity,
        )
    if (
        len(attempt.journal.documents) != attempt.recovery_event_start
        and not attempt.direct_finalization_ready
    ):
        raise TransactionError(
            "recovery_intent_missing",
            "recovery events exist without their immutable recovery intent",
        )
    value = {**static, "requested_at": clock()}
    _parse_utc_timestamp(value["requested_at"], "recovery requested_at")
    _write_json_exclusive(path, value)
    return value, path, _sha256_file(path)


def _recovery_intent_tool_identity(
    recovery_intent: dict[str, Any],
) -> dict[str, str]:
    return {
        "repositoryCommit": recovery_intent[
            "recovery_tool_repository_commit"
        ],
        "releaseSourceSha256": recovery_intent[
            "recovery_tool_release_source_sha256"
        ],
    }


def _require_recovery_intent_anchor(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    recovery_intent_sha256: str,
    append_missing: bool,
) -> bool:
    markers = [
        (sequence, event)
        for sequence, event in enumerate(attempt.journal.documents, start=1)
        if event["state"] == "recovery_intent_anchored"
    ]
    receipt_anchor_sha256: str | None = None
    if (
        attempt.existing_submission_receipt is not None
        and attempt.existing_submission_receipt["acquisition"]
        == "explicit-recovery"
    ):
        receipt_anchor_sha256 = attempt.existing_submission_receipt[
            "recovery_intent_sha256"
        ]
        if receipt_anchor_sha256 != recovery_intent_sha256:
            raise TransactionError(
                "recovery_intent_identity_drift",
                "recovery intent differs from its immutable submission receipt",
            )

    if markers:
        if len(markers) != 1:
            raise TransactionError(
                "recovery_intent_identity_drift",
                "recovery journal contains multiple intent anchors",
            )
        marker_sequence, marker = markers[0]
        if attempt.direct_finalization_ready:
            marker_predecessor_sha256 = _sha256_file(
                attempt.journal.directory
                / f"{marker_sequence - 1:08d}.json"
            )
            sequence_matches = marker_sequence > attempt.recovery_event_start
            previous_matches = (
                marker["previous_event_sha256"]
                == marker_predecessor_sha256
            )
        else:
            sequence_matches = (
                marker_sequence == attempt.recovery_event_start + 1
            )
            previous_matches = (
                marker["previous_event_sha256"]
                == attempt.prior_event_sha256
            )
        if (
            not sequence_matches
            or not previous_matches
            or marker["submission_id"] != submission_id
            or marker.get("evidence_sha256") != recovery_intent_sha256
            or marker["failure_code"] is not None
            or marker["exit_code"] is not None
        ):
            raise TransactionError(
                "recovery_intent_identity_drift",
                "recovery intent anchor differs from the immutable intent",
            )
        return False

    if receipt_anchor_sha256 is not None:
        # Compatibility for accepted legacy recovery attempts whose explicit
        # recovery receipt already sealed the exact recovery intent digest.
        return False

    if (
        len(attempt.journal.documents) != attempt.recovery_event_start
        and not attempt.direct_finalization_ready
    ):
        raise TransactionError(
            "recovery_intent_anchor_missing",
            "recovery events exist without an immutable recovery intent anchor",
        )
    if not append_missing:
        return True
    attempt.journal.append(
        "recovery_intent_anchored",
        submission_id=submission_id,
        evidence_sha256=recovery_intent_sha256,
    )
    return True


def _recovery_continuation_append_required(
    attempt: RecoverableAttempt,
    *,
    recovery_intent: dict[str, Any],
    recovery_tool_identity: dict[str, str],
    already_reconciled: bool,
) -> bool:
    prior_tool_identity = _recovery_intent_tool_identity(recovery_intent)
    if prior_tool_identity == recovery_tool_identity:
        return False
    path = attempt.context.attempt_root / "recovery-continuation.json"
    marker_present = any(
        event["state"] == "recovery_tool_continued"
        for event in attempt.journal.documents
    )
    if os.path.lexists(path) or marker_present:
        return False
    if not already_reconciled:
        raise TransactionError(
            "recovery_tool_transition_unavailable",
            "recovery tool identity changed before a failed finalization",
        )
    return True


def _require_continuation_prior_event(
    attempt: RecoverableAttempt,
    continuation: dict[str, Any],
) -> int:
    matches: list[tuple[int, dict[str, Any]]] = []
    for sequence, event in enumerate(attempt.journal.documents, start=1):
        event_path = attempt.journal.directory / f"{sequence:08d}.json"
        if _sha256_file(event_path) == continuation["prior_event_sha256"]:
            matches.append((sequence, event))
    if len(matches) != 1:
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "recovery continuation prior event is not uniquely retained",
        )
    prior_sequence, prior_event = matches[0]
    if (
        prior_event["state"] != "failed"
        or prior_event["submission_id"] != continuation["submission_id"]
        or prior_event["failure_code"] != continuation["prior_failure_code"]
        or prior_event["failure_code"] is None
    ):
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "recovery continuation is not bound to a failed finalization event",
        )
    return prior_sequence


def _require_recovery_continuation_marker(
    attempt: RecoverableAttempt,
    *,
    continuation: dict[str, Any],
    continuation_sha256: str,
    prior_sequence: int,
) -> None:
    markers = [
        (sequence, event)
        for sequence, event in enumerate(attempt.journal.documents, start=1)
        if event["state"] == "recovery_tool_continued"
    ]
    if not markers:
        raise TransactionError(
            "recovery_continuation_marker_missing",
            "recovery continuation document lacks its append-only journal marker",
        )
    if len(markers) != 1:
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "recovery journal contains multiple tool continuation markers",
        )
    marker_sequence, marker = markers[0]
    if (
        marker_sequence != prior_sequence + 1
        or marker["previous_event_sha256"]
        != continuation["prior_event_sha256"]
        or marker["submission_id"] != continuation["submission_id"]
        or marker.get("evidence_sha256") != continuation_sha256
        or marker["recorded_at"] != continuation["requested_at"]
        or marker["failure_code"] is not None
        or marker["exit_code"] is not None
    ):
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "recovery continuation marker differs from its immutable document",
        )


def _recovery_continuation_value(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    recovery_intent_sha256: str,
    prior_tool_identity: dict[str, str],
    recovery_tool_identity: dict[str, str],
    prior_event_sha256: str,
    prior_failure_code: str,
    requested_at: str,
) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "document": RECOVERY_CONTINUATION_DOCUMENT,
        "attempt_id": attempt.attempt_id,
        "submission_id": submission_id,
        "recovery_intent_sha256": recovery_intent_sha256,
        "prior_recovery_tool_repository_commit": prior_tool_identity[
            "repositoryCommit"
        ],
        "prior_recovery_tool_release_source_sha256": prior_tool_identity[
            "releaseSourceSha256"
        ],
        "continuation_tool_repository_commit": recovery_tool_identity[
            "repositoryCommit"
        ],
        "continuation_tool_release_source_sha256": recovery_tool_identity[
            "releaseSourceSha256"
        ],
        "prior_event_sha256": prior_event_sha256,
        "prior_failure_code": prior_failure_code,
        "requested_at": requested_at,
    }
    _parse_utc_timestamp(
        value["requested_at"],
        "recovery continuation requested_at",
    )
    return value


def _require_recovery_continuation_chronology(
    attempt: RecoverableAttempt,
    continuation: dict[str, Any],
    prior_sequence: int,
) -> None:
    requested_at = _parse_utc_timestamp(
        continuation["requested_at"],
        "recovery continuation requested_at",
    )[1]
    prior_recorded_at = _parse_utc_timestamp(
        attempt.journal.documents[prior_sequence - 1]["recorded_at"],
        "recovery continuation prior event recorded_at",
    )[1]
    if requested_at < prior_recorded_at:
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "recovery continuation predates its failed finalization event",
        )


def _validate_recovery_continuation_document(
    attempt: RecoverableAttempt,
    *,
    value: Any,
    data: bytes,
    submission_id: str,
    recovery_intent_sha256: str,
    prior_tool_identity: dict[str, str],
    recovery_tool_identity: dict[str, str],
) -> tuple[dict[str, Any], str, int]:
    if (
        not isinstance(value, dict)
        or set(value) != RECOVERY_CONTINUATION_FIELDS
        or data != _canonical_json(value).encode("utf-8")
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("document") != RECOVERY_CONTINUATION_DOCUMENT
        or value.get("attempt_id") != attempt.attempt_id
        or value.get("submission_id") != submission_id
        or value.get("recovery_intent_sha256") != recovery_intent_sha256
        or value.get("prior_recovery_tool_repository_commit")
        != prior_tool_identity["repositoryCommit"]
        or value.get("prior_recovery_tool_release_source_sha256")
        != prior_tool_identity["releaseSourceSha256"]
        or value.get("continuation_tool_repository_commit")
        != recovery_tool_identity["repositoryCommit"]
        or value.get("continuation_tool_release_source_sha256")
        != recovery_tool_identity["releaseSourceSha256"]
        or not isinstance(value.get("prior_event_sha256"), str)
        or not SHA256_RE.fullmatch(value["prior_event_sha256"])
        or not isinstance(value.get("prior_failure_code"), str)
        or not value["prior_failure_code"]
    ):
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "recovery continuation differs from the requested tool transition",
        )
    _parse_utc_timestamp(
        value["requested_at"],
        "recovery continuation requested_at",
    )
    continuation_sha256 = hashlib.sha256(data).hexdigest()
    prior_sequence = _require_continuation_prior_event(attempt, value)
    _require_recovery_continuation_chronology(
        attempt,
        value,
        prior_sequence,
    )
    _require_recovery_continuation_marker(
        attempt,
        continuation=value,
        continuation_sha256=continuation_sha256,
        prior_sequence=prior_sequence,
    )
    return value, continuation_sha256, prior_sequence


def _load_or_create_recovery_continuation(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    recovery_intent: dict[str, Any],
    recovery_intent_sha256: str,
    recovery_tool_identity: dict[str, str],
    already_reconciled: bool,
    clock: Clock,
) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    prior_tool_identity = _recovery_intent_tool_identity(recovery_intent)
    path = attempt.context.attempt_root / "recovery-continuation.json"
    markers = [
        (sequence, event)
        for sequence, event in enumerate(attempt.journal.documents, start=1)
        if event["state"] == "recovery_tool_continued"
    ]
    if prior_tool_identity == recovery_tool_identity:
        if os.path.lexists(path) or markers:
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation exists without a tool identity transition",
            )
        return None, None, None

    if os.path.lexists(path):
        data = _read_regular_bytes(path)
        value = _decode_json_bytes(data, path)
        value, continuation_sha256, _prior_sequence = (
            _validate_recovery_continuation_document(
                attempt,
                value=value,
                data=data,
                submission_id=submission_id,
                recovery_intent_sha256=recovery_intent_sha256,
                prior_tool_identity=prior_tool_identity,
                recovery_tool_identity=recovery_tool_identity,
            )
        )
        return value, path, continuation_sha256

    if markers:
        if len(markers) != 1:
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery journal contains multiple tool continuation markers",
            )
        marker_sequence, marker = markers[0]
        if marker_sequence <= 1:
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation marker has no prior failed event",
            )
        prior_event = attempt.journal.documents[marker_sequence - 2]
        prior_event_path = (
            attempt.journal.directory / f"{marker_sequence - 1:08d}.json"
        )
        prior_event_sha256 = _sha256_file(prior_event_path)
        if (
            marker["previous_event_sha256"] != prior_event_sha256
            or prior_event["state"] != "failed"
            or prior_event["submission_id"] != submission_id
            or prior_event["failure_code"] is None
        ):
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation marker is not adjacent to its failed event",
            )
        value = _recovery_continuation_value(
            attempt,
            submission_id=submission_id,
            recovery_intent_sha256=recovery_intent_sha256,
            prior_tool_identity=prior_tool_identity,
            recovery_tool_identity=recovery_tool_identity,
            prior_event_sha256=prior_event_sha256,
            prior_failure_code=prior_event["failure_code"],
            requested_at=marker["recorded_at"],
        )
        data = _canonical_json(value).encode("utf-8")
        if hashlib.sha256(data).hexdigest() != marker.get("evidence_sha256"):
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation marker cannot reconstruct its document",
            )
        _require_recovery_continuation_chronology(
            attempt,
            value,
            marker_sequence - 1,
        )
        _publish_pending_evidence(
            pending_path=(
                attempt.context.attempt_root
                / RECOVERY_CONTINUATION_PENDING_FILENAME
            ),
            destination_path=path,
            data=data,
            allow_partial_rebuild=True,
        )
        value, continuation_sha256, _prior_sequence = (
            _validate_recovery_continuation_document(
                attempt,
                value=value,
                data=_read_regular_bytes(path),
                submission_id=submission_id,
                recovery_intent_sha256=recovery_intent_sha256,
                prior_tool_identity=prior_tool_identity,
                recovery_tool_identity=recovery_tool_identity,
            )
        )
        return value, path, continuation_sha256

    if not already_reconciled or not attempt.journal.documents:
        raise TransactionError(
            "recovery_tool_transition_unavailable",
            "recovery tool identity changed before a failed finalization",
        )
    prior_event = attempt.journal.documents[-1]
    prior_event_sha256 = attempt.journal.previous_event_sha256
    if (
        prior_event_sha256 is None
        or prior_event["state"] != "failed"
        or prior_event["submission_id"] != submission_id
        or prior_event["failure_code"] is None
    ):
        raise TransactionError(
            "recovery_tool_transition_unavailable",
            "recovery tool transition requires the latest failed finalization event",
        )
    requested_at = clock()
    value = _recovery_continuation_value(
        attempt,
        submission_id=submission_id,
        recovery_intent_sha256=recovery_intent_sha256,
        prior_tool_identity=prior_tool_identity,
        recovery_tool_identity=recovery_tool_identity,
        prior_event_sha256=prior_event_sha256,
        prior_failure_code=prior_event["failure_code"],
        requested_at=requested_at,
    )
    continuation_sha256 = hashlib.sha256(
        _canonical_json(value).encode("utf-8")
    ).hexdigest()
    prior_sequence = _require_continuation_prior_event(attempt, value)
    _require_recovery_continuation_chronology(
        attempt,
        value,
        prior_sequence,
    )
    if attempt.journal.sequence != prior_sequence:
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "recovery journal advanced before its tool continuation marker",
        )
    attempt.journal.append(
        "recovery_tool_continued",
        submission_id=submission_id,
        evidence_sha256=continuation_sha256,
        recorded_at=requested_at,
    )
    _require_recovery_continuation_marker(
        attempt,
        continuation=value,
        continuation_sha256=continuation_sha256,
        prior_sequence=prior_sequence,
    )
    _publish_pending_evidence(
        pending_path=(
            attempt.context.attempt_root
            / RECOVERY_CONTINUATION_PENDING_FILENAME
        ),
        destination_path=path,
        data=_canonical_json(value).encode("utf-8"),
        allow_partial_rebuild=True,
    )
    if _sha256_file(path) != continuation_sha256:
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "persisted recovery continuation differs from its journal marker",
        )
    return value, path, continuation_sha256


def _require_finalization_attempt_history(
    events: list[dict[str, Any]],
    *,
    submission_id: str,
    allow_continuation: bool,
    maximum_attempts: int | None,
) -> tuple[AttemptPhase | None, int]:
    finalization_active = False
    next_finalization_state = 0
    continuation_seen = False
    attempt_count = 0
    for event in events:
        if event["submission_id"] != submission_id:
            raise TransactionError(
                "recovery_state_unsupported",
                "finalization journal contains a different submission id",
            )
        state = event["state"]
        if state == "recovery_tool_continued":
            if (
                not allow_continuation
                or finalization_active
                or continuation_seen
                or event["failure_code"] is not None
                or event["exit_code"] is not None
                or not isinstance(event.get("evidence_sha256"), str)
                or not SHA256_RE.fullmatch(event["evidence_sha256"])
            ):
                raise TransactionError(
                    "recovery_state_unsupported",
                    "recovery tool continuation event is malformed or misplaced",
                )
            continuation_seen = True
        elif state == "finalization_started":
            if (
                finalization_active
                or event["failure_code"] is not None
                or event["exit_code"] is not None
            ):
                raise TransactionError(
                    "recovery_state_unsupported",
                    "finalization_started contains terminal fields",
                )
            attempt_count += 1
            if maximum_attempts is not None and attempt_count > maximum_attempts:
                raise TransactionError(
                    "recovery_state_unsupported",
                    "direct finalization journal contains multiple attempts",
                )
            finalization_active = True
            next_finalization_state = 0
        elif state in FINALIZATION_EVENT_STATES:
            if (
                not finalization_active
                or next_finalization_state >= len(FINALIZATION_EVENT_STATES)
                or state != FINALIZATION_EVENT_STATES[next_finalization_state]
                or event["failure_code"] is not None
                or event["exit_code"] is not None
            ):
                raise TransactionError(
                    "recovery_state_unsupported",
                    "recovery finalization journal is out of order",
                )
            next_finalization_state += 1
        elif state in FINALIZATION_TERMINAL_STATES:
            if not finalization_active or event["failure_code"] is None:
                raise TransactionError(
                    "recovery_state_unsupported",
                    "recovery finalization terminal event is malformed",
                )
            finalization_active = False
            next_finalization_state = 0
        else:
            raise TransactionError(
                "recovery_state_unsupported",
                "recovery journal contains an unsupported finalization state",
            )
    if attempt_count == 0:
        return None, 0
    if finalization_active:
        phase = (
            AttemptPhase.SEALED
            if next_finalization_state == len(FINALIZATION_EVENT_STATES)
            else AttemptPhase.FINALIZATION_INCOMPLETE
        )
    else:
        phase = AttemptPhase.FINALIZATION_FAILED
    return phase, attempt_count


def _reduce_recovery_event_suffix(
    journal: EventJournal,
    prefix: AttemptEventReduction,
    submission_id: str,
) -> AttemptEventReduction:
    suffix = journal.documents[prefix.recovery_event_start:]
    if prefix.direct_finalization_ready:
        anchor_indexes = [
            index
            for index, event in enumerate(suffix)
            if event["state"] == "recovery_intent_anchored"
        ]
        if len(anchor_indexes) > 1:
            raise TransactionError(
                "recovery_state_unsupported",
                "direct finalization journal contains multiple recovery anchors",
            )
        anchor_index = anchor_indexes[0] if anchor_indexes else len(suffix)
        direct_phase, direct_attempts = _require_finalization_attempt_history(
            suffix[:anchor_index],
            submission_id=submission_id,
            allow_continuation=False,
            maximum_attempts=1,
        )
        if not anchor_indexes:
            return replace(
                prefix,
                phase=direct_phase or prefix.phase,
                submission_id=submission_id,
                reconciled=True,
                finalization_attempt_count=direct_attempts,
            )
        anchor = suffix[anchor_index]
        if (
            anchor["submission_id"] != submission_id
            or anchor["failure_code"] is not None
            or anchor["exit_code"] is not None
            or not isinstance(anchor.get("evidence_sha256"), str)
            or not SHA256_RE.fullmatch(anchor["evidence_sha256"])
        ):
            raise TransactionError(
                "recovery_state_unsupported",
                "direct finalization recovery anchor is malformed",
            )
        recovery_phase, recovery_attempts = _require_finalization_attempt_history(
            suffix[anchor_index + 1 :],
            submission_id=submission_id,
            allow_continuation=True,
            maximum_attempts=None,
        )
        return replace(
            prefix,
            phase=recovery_phase or direct_phase or AttemptPhase.RECONCILED,
            submission_id=submission_id,
            reconciled=True,
            recovery_anchor_present=True,
            finalization_attempt_count=direct_attempts + recovery_attempts,
        )
    index = 0

    def require_submission(event: dict[str, Any]) -> None:
        if event["submission_id"] != submission_id:
            raise TransactionError(
                "recovery_state_unsupported",
                "recovery journal contains a different submission id",
            )

    if suffix and suffix[0]["state"] == "recovery_intent_anchored":
        anchor = suffix[0]
        require_submission(anchor)
        if (
            anchor["failure_code"] is not None
            or anchor["exit_code"] is not None
            or not isinstance(anchor.get("evidence_sha256"), str)
            or not SHA256_RE.fullmatch(anchor["evidence_sha256"])
        ):
            raise TransactionError(
                "recovery_state_unsupported",
                "recovery intent anchor event is malformed",
            )
        index = 1

    while index < len(suffix):
        event = suffix[index]
        require_submission(event)
        if event["state"] != "reconciliation_started":
            break
        if event["failure_code"] is not None or event["exit_code"] is not None:
            raise TransactionError(
                "recovery_state_unsupported",
                "reconciliation_started contains terminal fields",
            )
        index += 1
        if index == len(suffix):
            return replace(
                prefix,
                phase=AttemptPhase.RECONCILIATION_INCOMPLETE,
                submission_id=submission_id,
            )
        outcome = suffix[index]
        require_submission(outcome)
        if outcome["state"] == "reconciliation_started":
            continue
        if outcome["state"] == "reconciliation_deferred":
            if outcome["failure_code"] is None:
                raise TransactionError(
                    "recovery_state_unsupported",
                    "reconciliation_deferred lacks a failure code",
                )
            index += 1
            continue
        if outcome["state"] == "submission_reconciled":
            if (
                outcome["failure_code"] is not None
                or outcome["exit_code"] is not None
            ):
                raise TransactionError(
                    "recovery_state_unsupported",
                    "submission_reconciled contains terminal fields",
                )
            index += 1
            break
        raise TransactionError(
            "recovery_state_unsupported",
            "reconciliation attempt has an unsupported outcome",
        )
    else:
        return replace(
            prefix,
            phase=AttemptPhase.RECONCILIATION_INCOMPLETE,
            submission_id=submission_id,
        )

    if index == 0 or suffix[index - 1]["state"] != "submission_reconciled":
        raise TransactionError(
            "recovery_state_unsupported",
            "notarization journal has not reached a reconciled submission",
        )

    finalization_phase, attempt_count = _require_finalization_attempt_history(
        suffix[index:],
        submission_id=submission_id,
        allow_continuation=True,
        maximum_attempts=None,
    )
    return replace(
        prefix,
        phase=finalization_phase or AttemptPhase.RECONCILED,
        submission_id=submission_id,
        reconciled=True,
        recovery_anchor_present=(
            bool(suffix) and suffix[0]["state"] == "recovery_intent_anchored"
        ),
        finalization_attempt_count=attempt_count,
    )


def _reduce_attempt_events(
    journal: EventJournal,
    *,
    submission_id: str | None = None,
    direct_sealed: bool = False,
    allow_distribution_head: bool = False,
) -> AttemptEventReduction:
    if direct_sealed:
        if submission_id is None:
            raise TransactionError(
                "direct_sealed_journal_mismatch",
                "direct sealed reduction requires a submission id",
            )
        canonical_submission_id = _canonical_uuid(
            submission_id,
            "direct sealed submission id",
        )
        _validate_direct_sealed_event_grammar(
            journal,
            submission_id=canonical_submission_id,
            allow_distribution_head=allow_distribution_head,
        )
        submitting_at = _parse_utc_timestamp(
            journal.documents[2]["recorded_at"],
            "direct submitting event recorded_at",
        )[1]
        submitted_at = _parse_utc_timestamp(
            journal.documents[3]["recorded_at"],
            "direct submitted event recorded_at",
        )[1]
        return AttemptEventReduction(
            phase=(
                AttemptPhase.DIRECT_SEALED
                if any(
                    event["state"] == "sealed"
                    for event in journal.documents
                )
                else AttemptPhase.FINALIZATION_INCOMPLETE
            ),
            submit_window_start=submitting_at,
            submit_window_end=submitted_at,
            prior_event_sha256=journal.verify(),
            recovery_event_start=4,
            submission_id=canonical_submission_id,
            boundary_submission_id=canonical_submission_id,
            submitted_receipt_expected=True,
            direct_evidence_required=True,
            direct_finalization_ready=False,
            direct_source_preparation_incomplete=False,
            reconciled=True,
            finalization_attempt_count=1,
        )
    prefix = _decode_recoverable_event_prefix(journal)
    suffix = journal.documents[prefix.recovery_event_start:]
    suffix_submission_ids = {
        event["submission_id"]
        for event in suffix
        if event["submission_id"] is not None
    }
    if prefix.submission_id is not None:
        suffix_submission_ids.add(prefix.submission_id)
    if submission_id is not None:
        suffix_submission_ids.add(submission_id)
    if len(suffix_submission_ids) > 1:
        raise TransactionError(
            "recovery_state_unsupported",
            "notarization journal contains multiple submission identities",
        )
    reduced_submission_id = next(iter(suffix_submission_ids), None)
    if reduced_submission_id is None:
        return prefix
    return _reduce_recovery_event_suffix(
        journal,
        prefix,
        _canonical_uuid(reduced_submission_id, "journal submission id"),
    )


def _load_existing_recovery_continuation(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    recovery_intent: dict[str, Any],
    recovery_intent_sha256: str,
    recovery_tool_identity: dict[str, str],
) -> tuple[dict[str, Any] | None, Path | None]:
    prior_tool_identity = _recovery_intent_tool_identity(recovery_intent)
    path = attempt.context.attempt_root / "recovery-continuation.json"
    markers = [
        event
        for event in attempt.journal.documents
        if event["state"] == "recovery_tool_continued"
    ]
    if prior_tool_identity == recovery_tool_identity:
        if os.path.lexists(path) or markers:
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "sealed publication has an unexpected continuation",
            )
        return None, None
    if not os.path.lexists(path) or len(markers) != 1:
        raise TransactionError(
            "recovery_continuation_identity_drift",
            "sealed publication lacks its complete continuation provenance",
        )
    data = _read_regular_bytes(path)
    value = _decode_json_bytes(data, path)
    value, _continuation_sha256, _prior_sequence = (
        _validate_recovery_continuation_document(
            attempt,
            value=value,
            data=data,
            submission_id=submission_id,
            recovery_intent_sha256=recovery_intent_sha256,
            prior_tool_identity=prior_tool_identity,
            recovery_tool_identity=recovery_tool_identity,
        )
    )
    return value, path


def _unique_matching_published_receipt(
    prepared: PreparedAttempt,
    *,
    journal: EventJournal,
    publication_root: Path,
    manifest_verifier: ManifestVerifier,
    source_identity_reader: SourceIdentityReader,
    toolchain_metadata_reader: ToolchainMetadataReader,
) -> Path:
    finalization_runs = prepared.context.attempt_root / "finalization-runs"
    _require_real_directory(finalization_runs, private=True)
    try:
        run_entries = sorted(
            finalization_runs.iterdir(),
            key=lambda path: path.name,
        )
    except OSError as error:
        raise TransactionError(
            "published_receipt_inventory_unavailable",
            "finalization receipt inventory cannot be enumerated",
        ) from error
    receipt_paths: list[Path] = []
    for run_entry in run_entries:
        candidate = run_entry / "receipt.json"
        try:
            os.lstat(candidate)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise TransactionError(
                "published_receipt_inventory_unavailable",
                "finalization receipt candidate cannot be inspected",
            ) from error
        receipt_paths.append(candidate)
    matches: list[Path] = []
    for candidate in receipt_paths:
        try:
            _validate_sealed_publication(
                prepared,
                journal=journal,
                publication_root=publication_root,
                receipt_path=candidate,
                manifest_verifier=manifest_verifier,
                source_identity_reader=source_identity_reader,
                toolchain_metadata_reader=toolchain_metadata_reader,
            )
        except TransactionError as error:
            if error.code in {
                "source_identity_unavailable",
                "source_identity_drift",
                "toolchain_identity_unavailable",
                "toolchain_identity_drift",
                "recovery_tool_identity_unavailable",
                "recovery_tool_identity_drift",
                "sealed_manifest_verification_failed",
            }:
                raise
            continue
        matches.append(candidate)
    if len(matches) != 1:
        raise TransactionError(
            (
                "published_candidate_unrecognized"
                if not matches
                else "published_candidate_ambiguous"
            ),
            "published destination does not have one exact sealed receipt",
        )
    return matches[0]


def _recover_direct_published_transaction(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    manifest_verifier: ManifestVerifier,
    source_identity_reader: SourceIdentityReader,
    toolchain_metadata_reader: ToolchainMetadataReader,
) -> Path:
    context = attempt.context
    if (
        not attempt.direct_finalization_ready
        or attempt.existing_submission_receipt is None
        or attempt.existing_submission_receipt_path is None
        or attempt.existing_submission_receipt["acquisition"]
        != "submit-no-wait"
        or os.path.lexists(context.attempt_root / "recovery-intent.json")
        or os.path.lexists(context.attempt_root / "recovery-continuation.json")
        or any(
            event["state"]
            in {"recovery_intent_anchored", "recovery_tool_continued"}
            for event in attempt.journal.documents
        )
        or not _reduce_attempt_events(
            attempt.journal,
            submission_id=submission_id,
        ).reconciled
    ):
        raise TransactionError(
            "published_candidate_unrecognized",
            "published direct candidate lacks its exact local lineage",
        )
    publication_root = context.final_root
    prepared = PreparedAttempt(
        context=context,
        work=publication_root,
        work_app=publication_root / "Clash for Mac.app",
        archive=publication_root / context.archive_name,
        archive_manifest=(
            publication_root / f"{context.archive_name}.manifest.json"
        ),
        archive_metadata=attempt.archive_metadata,
        archive_sha256=attempt.archive_sha256,
        archive_size=attempt.archive_size,
        pre_staple_app_sha256=attempt.pre_staple_app_sha256,
        attempt_id=attempt.attempt_id,
        intent=attempt.intent,
        intent_path=attempt.intent_path,
        intent_sha256=attempt.intent_sha256,
        submission_id=submission_id,
        submission_receipt=attempt.existing_submission_receipt,
        submission_receipt_path=attempt.existing_submission_receipt_path,
        recovery_intent=None,
        recovery_intent_path=None,
        recovery_continuation=None,
        recovery_continuation_path=None,
        recovery_tool_repository=None,
        recovery_tool_identity=None,
        recovery_tool_identity_reader=None,
    )
    _require_submission_acquisition_evidence(prepared)
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)

    def unique_matching_receipt() -> Path:
        return _unique_matching_published_receipt(
            prepared,
            journal=attempt.journal,
            publication_root=publication_root,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
        )

    matching_receipt = unique_matching_receipt()
    try:
        _fsync_tree(publication_root)
        _fsync_directory(publication_root.parent)
        _fsync_directory(matching_receipt.parent)
        _fsync_directory(context.attempt_root / "finalization-runs")
    except OSError as error:
        raise TransactionError(
            "publish_durability_unknown",
            "published direct candidate durability remains unconfirmed",
            terminal_state="outcome_unknown",
        ) from error
    if unique_matching_receipt() != matching_receipt:
        raise TransactionError(
            "published_candidate_changed",
            "published direct candidate changed during durability recovery",
        )
    return publication_root / "Clash for Mac.app"


def _recover_published_transaction(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    recovery_tool_repository: Path,
    recovery_tool_identity: dict[str, str],
    recovery_tool_identity_reader: SourceIdentityReader,
    manifest_verifier: ManifestVerifier,
    source_identity_reader: SourceIdentityReader,
    toolchain_metadata_reader: ToolchainMetadataReader,
    clock: Clock,
) -> Path:
    context = attempt.context
    expected_recovery_intent_path = (
        context.attempt_root / "recovery-intent.json"
    )
    if not os.path.lexists(expected_recovery_intent_path):
        raise TransactionError(
            "recovery_intent_missing",
            "published destination has no immutable recovery intent",
        )
    recovery_intent, recovery_intent_path, recovery_intent_sha256 = (
        _load_or_create_recovery_intent(
            attempt,
            submission_id,
            recovery_tool_identity,
            clock,
        )
    )
    with _exclusive_recovery_lock(recovery_intent_path):
        _read_exact_json_document(
            recovery_intent_path,
            recovery_intent,
            drift_code="recovery_intent_identity_drift",
            drift_message="recovery intent changed while validating publication",
        )
        anchor_missing = _require_recovery_intent_anchor(
            attempt,
            submission_id=submission_id,
            recovery_intent_sha256=recovery_intent_sha256,
            append_missing=False,
        )
        if anchor_missing:
            raise TransactionError(
                "recovery_intent_anchor_missing",
                "published destination has no immutable recovery intent anchor",
            )
        if not _reduce_attempt_events(
            attempt.journal,
            submission_id=submission_id,
        ).reconciled:
            raise TransactionError(
                "published_candidate_unrecognized",
                "published destination has no reconciled recovery lineage",
            )
        recovery_continuation, recovery_continuation_path = (
            _load_existing_recovery_continuation(
                attempt,
                submission_id=submission_id,
                recovery_intent=recovery_intent,
                recovery_intent_sha256=recovery_intent_sha256,
                recovery_tool_identity=recovery_tool_identity,
            )
        )
        if (
            attempt.existing_submission_receipt is None
            or attempt.existing_submission_receipt_path is None
        ):
            raise TransactionError(
                "submission_receipt_missing",
                "published recovery lacks its immutable submission receipt",
            )
        publication_root = context.final_root
        prepared = PreparedAttempt(
            context=context,
            work=publication_root,
            work_app=publication_root / "Clash for Mac.app",
            archive=publication_root / context.archive_name,
            archive_manifest=(
                publication_root / f"{context.archive_name}.manifest.json"
            ),
            archive_metadata=attempt.archive_metadata,
            archive_sha256=attempt.archive_sha256,
            archive_size=attempt.archive_size,
            pre_staple_app_sha256=attempt.pre_staple_app_sha256,
            attempt_id=attempt.attempt_id,
            intent=attempt.intent,
            intent_path=attempt.intent_path,
            intent_sha256=attempt.intent_sha256,
            submission_id=submission_id,
            submission_receipt=attempt.existing_submission_receipt,
            submission_receipt_path=attempt.existing_submission_receipt_path,
            recovery_intent=recovery_intent,
            recovery_intent_path=recovery_intent_path,
            recovery_continuation=recovery_continuation,
            recovery_continuation_path=recovery_continuation_path,
            recovery_tool_repository=recovery_tool_repository,
            recovery_tool_identity=recovery_tool_identity,
            recovery_tool_identity_reader=recovery_tool_identity_reader,
        )
        finalization_runs = context.attempt_root / "finalization-runs"
        _require_real_directory(finalization_runs, private=True)
        _require_submission_acquisition_evidence(prepared)
        _require_source_identity(context, source_identity_reader)
        _require_toolchain_identity(context, toolchain_metadata_reader)

        def unique_matching_receipt() -> Path:
            return _unique_matching_published_receipt(
                prepared,
                journal=attempt.journal,
                publication_root=publication_root,
                manifest_verifier=manifest_verifier,
                source_identity_reader=source_identity_reader,
                toolchain_metadata_reader=toolchain_metadata_reader,
            )

        matching_receipt = unique_matching_receipt()
        try:
            _fsync_tree(publication_root)
            _fsync_directory(publication_root.parent)
            _fsync_directory(matching_receipt.parent)
            _fsync_directory(finalization_runs)
        except OSError as error:
            raise TransactionError(
                "publish_durability_unknown",
                "published candidate is valid but durability remains unconfirmed",
                terminal_state="outcome_unknown",
            ) from error
        if unique_matching_receipt() != matching_receipt:
            raise TransactionError(
                "published_candidate_changed",
                "published candidate receipt changed during durability recovery",
            )
        return publication_root / "Clash for Mac.app"


def _append_reconciliation_failure(
    journal: EventJournal,
    submission_id: str,
    error: Exception,
) -> None:
    if isinstance(error, TransactionError):
        failure_code = error.code
        exit_code = error.exit_code
        if error.terminal_state == "rejected":
            state = "rejected"
        elif (
            error.terminal_state == "outcome_unknown"
            or error.code in RECOVERY_RETRYABLE_READ_FAILURE_CODES
        ):
            state = "reconciliation_deferred"
        else:
            state = "failed"
    else:
        failure_code = "internal_error"
        exit_code = None
        state = "failed"
    journal.append(
        state,
        submission_id=submission_id,
        failure_code=failure_code,
        exit_code=exit_code,
    )


def _recovery_read_result(
    runner: CommandRunner,
    role: CommandRole,
    command: list[str],
    timeout: float,
) -> CommandResult:
    try:
        result = _result_or_error(runner, role, command, timeout)
        _require_empty_notary_stderr(result, role)
        return result
    except TransactionError as error:
        raise TransactionError(
            error.code,
            str(error),
            terminal_state="outcome_unknown",
            exit_code=error.exit_code,
        ) from error


def _read_accepted_recovery_evidence(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    command_runner: CommandRunner,
) -> tuple[Any, str]:
    context = attempt.context
    info = _recovery_read_result(
        command_runner,
        CommandRole.INFO,
        [
            "/usr/bin/xcrun",
            "notarytool",
            "info",
            submission_id,
            "--keychain-profile",
            context.notary_profile,
            "--output-format",
            "json",
        ],
        300,
    )
    info_status, info_created_at = _parse_notary_info_response(
        info.stdout,
        submission_id=submission_id,
        archive_name=context.archive_name,
        allowed_statuses={"Accepted", "In Progress", "Invalid", "Rejected"},
    )
    if info_status in {"Invalid", "Rejected"}:
        raise TransactionError(
            "notary_submission_rejected",
            "Apple rejected the recovered notarization submission",
            terminal_state="rejected",
        )
    if info_status != "Accepted":
        raise TransactionError(
            "notary_recovery_incomplete",
            "recovered Apple submission is not yet Accepted",
            terminal_state="outcome_unknown",
        )
    info_created = _parse_utc_timestamp(
        info_created_at,
        "info createdDate",
    )[1]
    if not _timestamp_within_recorded_window(
        info_created,
        window_start=attempt.submit_window_start,
        window_end=attempt.submit_window_end,
        window_end_rendered=attempt.submit_window_end_rendered,
    ):
        raise TransactionError(
            "submission_causal_binding_unproven",
            "notarytool info createdDate falls outside the submit window",
        )
    if (
        attempt.existing_submission_receipt is not None
        and attempt.existing_submission_receipt["acquisition"]
        == "explicit-recovery"
        and _parse_utc_timestamp(
            attempt.existing_submission_receipt["notary_created_at"],
            "submission receipt notary_created_at",
        )[1]
        != info_created
    ):
        raise TransactionError(
            "submission_receipt_identity_drift",
            "persisted recovery receipt differs from current Apple submission info",
        )
    if attempt.observed_submission_id is None:
        history = _recovery_read_result(
            command_runner,
            CommandRole.HISTORY,
            [
                "/usr/bin/xcrun",
                "notarytool",
                "history",
                "--keychain-profile",
                context.notary_profile,
                "--output-format",
                "json",
            ],
            300,
        )
        _require_unique_history_binding(
            history.stdout,
            submission_id=submission_id,
            archive_name=context.archive_name,
            window_start=attempt.submit_window_start,
            window_end=attempt.submit_window_end,
            window_end_rendered=attempt.submit_window_end_rendered,
            info_created_at=info_created_at,
        )
    fetched_log = _recovery_read_result(
        command_runner,
        CommandRole.FETCH_LOG,
        [
            "/usr/bin/xcrun",
            "notarytool",
            "log",
            submission_id,
            "--keychain-profile",
            context.notary_profile,
        ],
        300,
    )
    raw_log = _parse_command_json(fetched_log.stdout)
    notarization = {"id": submission_id, "status": "Accepted"}
    try:
        normalized_recovery_log = validate_documents(
            notarization,
            raw_log,
            archive_filename=context.archive_name,
            archive_sha256=attempt.archive_sha256,
        )
    except NotaryLogError as error:
        raise TransactionError(
            "notary_log_verification_failed",
            "recovered Apple notarization log failed strict binding validation",
        ) from error
    log_upload_at = _parse_utc_timestamp(
        normalized_recovery_log["uploadDate"],
        "log uploadDate",
    )[1]
    if (
        log_upload_at < info_created
        or not _timestamp_within_recorded_window(
            log_upload_at,
            window_start=attempt.submit_window_start,
            window_end=attempt.submit_window_end,
            window_end_rendered=attempt.submit_window_end_rendered,
        )
    ):
        raise TransactionError(
            "submission_causal_binding_unproven",
            "notarytool log uploadDate is inconsistent with the submit window",
        )
    return raw_log, info_created_at


def _validate_immutable_recovery_source(
    attempt: RecoverableAttempt,
    source: Path,
    *,
    manifest_verifier: ManifestVerifier,
) -> tuple[Path, Path, Path]:
    _require_real_directory(source, private=True)
    source_app = source / "Clash for Mac.app"
    source_archive = source / attempt.context.archive_name
    source_manifest = source / f"{attempt.context.archive_name}.manifest.json"
    if {path.name for path in source.iterdir()} != {
        source_app.name,
        source_archive.name,
        source_manifest.name,
    }:
        raise TransactionError(
            "recovery_source_inventory_mismatch",
            "immutable recovery source has unexpected entries",
        )
    if _app_tree_sha256(
        source_app,
        failure_code="app_identity_drift",
        failure_message="immutable recovery app identity cannot be derived",
    ) != attempt.pre_staple_app_sha256:
        raise TransactionError(
            "app_identity_drift",
            "immutable recovery app differs from the notarization intent",
        )
    _require_archive_identity(
        source_archive,
        attempt.archive_sha256,
        attempt.archive_size,
    )
    _run_manifest_verification_barrier(
        manifest_verifier,
        ((source_archive, source_manifest, attempt.archive_metadata),),
    )
    return source_app, source_archive, source_manifest


def _ensure_immutable_recovery_source(
    attempt: RecoverableAttempt,
    *,
    manifest_verifier: ManifestVerifier,
) -> RecoverableAttempt:
    source = attempt.context.attempt_root / "recovery-source"
    if attempt.work.name == "work":
        if os.path.lexists(source):
            raise TransactionError(
                "recovery_source_collision",
                "immutable recovery source already exists beside the original work",
            )
        _validate_immutable_recovery_source(
            attempt,
            attempt.work,
            manifest_verifier=manifest_verifier,
        )
        _fsync_tree(attempt.work)
        _validate_immutable_recovery_source(
            attempt,
            attempt.work,
            manifest_verifier=manifest_verifier,
        )
        try:
            os.rename(attempt.work, source)
            _fsync_directory(attempt.context.attempt_root)
        except OSError as error:
            raise TransactionError(
                "recovery_source_preservation_failed",
                "cannot atomically preserve the immutable notarization source",
            ) from error
    elif attempt.work != source:
        raise TransactionError(
            "unsafe_recovery_source",
            "recovery source path is not canonical",
        )
    _validate_immutable_recovery_source(
        attempt,
        source,
        manifest_verifier=manifest_verifier,
    )
    _fsync_tree(source)
    source_app, source_archive, source_manifest = (
        _validate_immutable_recovery_source(
            attempt,
            source,
            manifest_verifier=manifest_verifier,
        )
    )
    return replace(
        attempt,
        work=source,
        work_app=source_app,
        archive=source_archive,
        archive_manifest=source_manifest,
    )


def _finalization_tree_logical_bytes(
    root: Path,
    *,
    ceiling: int | None,
) -> int:
    _require_real_directory(root, private=True)
    total = 0
    entry_count = 0

    def walk_error(error: OSError) -> None:
        raise TransactionError(
            "finalization_quota_unavailable",
            "finalization workspace cannot be enumerated for quota",
        ) from error

    for current, directories, files in os.walk(
        root,
        topdown=True,
        onerror=walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        for name in [*directories, *files]:
            entry_count += 1
            if entry_count > MAX_FINALIZATION_TREE_ENTRIES:
                raise TransactionError(
                    "finalization_entry_quota_exceeded",
                    "finalization workspace has too many filesystem entries",
                )
            path = current_path / name
            try:
                metadata = os.lstat(path)
            except OSError as error:
                raise TransactionError(
                    "finalization_quota_unavailable",
                    "finalization workspace changed during quota scan",
                ) from error
            if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                total += metadata.st_size
            elif not stat.S_ISDIR(metadata.st_mode):
                raise TransactionError(
                    "unsafe_finalization_workspace",
                    "finalization workspace contains a special filesystem node",
                )
            if ceiling is not None and total > ceiling:
                raise TransactionError(
                    "finalization_byte_quota_exceeded",
                    "finalization workspace bytes exceed their release bound",
                )
    return total


def _bounded_finalization_run_inventory(
    finalization_runs: Path,
) -> tuple[tuple[Path, ...], int]:
    _require_real_directory(finalization_runs, private=True)
    root_identity = _strict_path_identity(
        finalization_runs,
        failure_code="finalization_quota_unavailable",
        failure_message="finalization run root identity is unavailable",
    )
    try:
        retained_runs = tuple(
            sorted(
                finalization_runs.iterdir(),
                key=lambda path: path.name,
            )
        )
    except OSError as error:
        raise TransactionError(
            "finalization_quota_unavailable",
            "retained finalization runs cannot be enumerated",
        ) from error
    if len(retained_runs) > MAX_FINALIZATION_RUNS:
        raise TransactionError(
            "finalization_run_quota_exceeded",
            "retained finalization run count exceeds its release bound",
        )

    total = 0
    run_identities: list[tuple[str, tuple[int, ...]]] = []
    for retained in retained_runs:
        _canonical_uuid(retained.name, "finalization run id")
        _require_real_directory(retained, private=True)
        identity = _strict_path_identity(
            retained,
            failure_code="finalization_quota_unavailable",
            failure_message="finalization run identity is unavailable",
        )
        total += _finalization_tree_logical_bytes(
            retained,
            ceiling=MAX_FINALIZATION_RUNS_BYTES - total,
        )
        if identity != _strict_path_identity(
            retained,
            failure_code="finalization_quota_unavailable",
            failure_message="finalization run changed during quota scan",
        ):
            raise TransactionError(
                "finalization_quota_unavailable",
                "finalization run changed during quota scan",
            )
        run_identities.append((retained.name, identity))

    try:
        rebound_runs = tuple(
            sorted(
                finalization_runs.iterdir(),
                key=lambda path: path.name,
            )
        )
    except OSError as error:
        raise TransactionError(
            "finalization_quota_unavailable",
            "finalization run inventory changed during quota scan",
        ) from error
    rebound_identities = tuple(
        (
            retained.name,
            _strict_path_identity(
                retained,
                failure_code="finalization_quota_unavailable",
                failure_message=(
                    "finalization run identity changed during quota scan"
                ),
            ),
        )
        for retained in rebound_runs
    )
    if (
        root_identity
        != _strict_path_identity(
            finalization_runs,
            failure_code="finalization_quota_unavailable",
            failure_message="finalization run root changed during quota scan",
        )
        or rebound_identities != tuple(run_identities)
    ):
        raise TransactionError(
            "finalization_quota_unavailable",
            "finalization run inventory changed during quota scan",
        )
    return retained_runs, total


def _require_current_finalization_run_within_bounds(
    context: TransactionContext,
    run_root: Path,
) -> int:
    finalization_runs = context.attempt_root / "finalization-runs"
    if run_root.parent != finalization_runs:
        raise TransactionError(
            "recovery_workspace_inventory_mismatch",
            "current finalization run is outside its canonical root",
        )
    _canonical_uuid(run_root.name, "current finalization run id")
    retained_runs, logical_bytes = _bounded_finalization_run_inventory(
        finalization_runs
    )
    if run_root not in retained_runs:
        raise TransactionError(
            "recovery_workspace_inventory_mismatch",
            "current finalization run is absent from its bounded inventory",
        )
    return logical_bytes


def _require_finalization_run_capacity(
    attempt: RecoverableAttempt,
    finalization_runs: Path,
) -> None:
    retained_runs, total = _bounded_finalization_run_inventory(
        finalization_runs
    )
    if len(retained_runs) >= MAX_FINALIZATION_RUNS:
        raise TransactionError(
            "finalization_run_quota_exceeded",
            "no bounded finalization run slot remains",
        )
    source_bytes = _finalization_tree_logical_bytes(
        attempt.work,
        ceiling=MAX_FINALIZATION_RUNS_BYTES - total,
    )
    if total + source_bytes > MAX_FINALIZATION_RUNS_BYTES:
        raise TransactionError(
            "finalization_byte_quota_exceeded",
            "copying the immutable source would exceed finalization quota",
        )


def _failed_cleanup_inventory_snapshot(
    context: TransactionContext,
    finalization_runs: Path,
) -> tuple[tuple[int, ...], tuple[tuple[str, tuple[int, ...]], ...]] | None:
    if os.path.lexists(context.final_root):
        return None
    root_identity = _strict_path_identity(
        finalization_runs,
        failure_code="failed_workspace_cleanup_unavailable",
        failure_message="finalization run root identity is unavailable",
    )
    try:
        retained_runs = tuple(
            sorted(
                finalization_runs.iterdir(),
                key=lambda path: path.name,
            )
        )
    except OSError as error:
        raise TransactionError(
            "failed_workspace_cleanup_unavailable",
            "cannot inspect publication ambiguity before cleanup",
        ) from error
    run_identities: list[tuple[str, tuple[int, ...]]] = []
    publication_markers = [
        context.attempt_root / "publish-ready",
        context.attempt_root / "receipt.json",
        context.attempt_root / PUBLISH_READY_RECEIPT_PENDING_FILENAME,
    ]
    for retained in retained_runs:
        _canonical_uuid(retained.name, "retained finalization run id")
        _require_real_directory(retained, private=True)
        run_identities.append(
            (
                retained.name,
                _strict_path_identity(
                    retained,
                    failure_code="failed_workspace_cleanup_unavailable",
                    failure_message=(
                        "retained finalization run identity is unavailable"
                    ),
                ),
            )
        )
        publication_markers.extend(
            [
                retained / "publish-ready",
                retained / "receipt.json",
                retained / PUBLISH_READY_RECEIPT_PENDING_FILENAME,
            ]
        )
    if any(os.path.lexists(path) for path in publication_markers):
        return None
    try:
        rebound_runs = tuple(
            sorted(
                finalization_runs.iterdir(),
                key=lambda path: path.name,
            )
        )
    except OSError as error:
        raise TransactionError(
            "failed_workspace_cleanup_unavailable",
            "finalization run inventory changed during cleanup scan",
        ) from error
    rebound_identities = tuple(
        (
            retained.name,
            _strict_path_identity(
                retained,
                failure_code="failed_workspace_cleanup_unavailable",
                failure_message=(
                    "retained finalization run changed during cleanup scan"
                ),
            ),
        )
        for retained in rebound_runs
    )
    if (
        root_identity
        != _strict_path_identity(
            finalization_runs,
            failure_code="failed_workspace_cleanup_unavailable",
            failure_message="finalization run root changed during cleanup scan",
        )
        or rebound_identities != tuple(run_identities)
    ):
        return None
    return root_identity, tuple(run_identities)


def _cleanup_failed_finalization_workspace(
    context: TransactionContext,
    run_root: Path,
    *,
    minimum_bytes: int | None = None,
) -> bool:
    finalization_runs = context.attempt_root / "finalization-runs"
    _require_real_directory(finalization_runs, private=True)
    if run_root.parent != finalization_runs:
        return False
    _canonical_uuid(run_root.name, "failed finalization run id")
    _require_real_directory(run_root, private=True)
    try:
        before = os.lstat(run_root)
    except OSError as error:
        raise TransactionError(
            "failed_workspace_cleanup_unavailable",
            "failed finalization workspace identity is unavailable",
        ) from error
    if _strict_directory_inventory(
        run_root,
        failure_code="failed_workspace_cleanup_unavailable",
        failure_message="failed finalization run cannot be enumerated",
    ) != {"work"}:
        return False
    inventory_before = _failed_cleanup_inventory_snapshot(
        context,
        finalization_runs,
    )
    if inventory_before is None:
        return False
    work = run_root / "work"
    workspace_bytes = _finalization_tree_logical_bytes(
        work,
        ceiling=None,
    )
    cleanup_minimum = (
        FAILED_FINALIZATION_CLEANUP_MIN_BYTES
        if minimum_bytes is None
        else minimum_bytes
    )
    if cleanup_minimum < 0:
        raise TransactionError(
            "failed_workspace_cleanup_unavailable",
            "failed finalization cleanup minimum is invalid",
        )
    if workspace_bytes < cleanup_minimum:
        return False
    if _strict_directory_inventory(
        run_root,
        failure_code="failed_workspace_cleanup_unavailable",
        failure_message="failed finalization run changed before cleanup",
    ) != {"work"}:
        return False
    try:
        rebound = os.lstat(run_root)
    except OSError as error:
        raise TransactionError(
            "failed_workspace_cleanup_unavailable",
            "failed finalization workspace changed before cleanup",
        ) from error
    if _transaction_file_identity(before) != _transaction_file_identity(
        rebound
    ):
        raise TransactionError(
            "failed_workspace_cleanup_race",
            "failed finalization workspace changed before cleanup",
        )
    inventory_after = _failed_cleanup_inventory_snapshot(
        context,
        finalization_runs,
    )
    if inventory_after is None or inventory_after != inventory_before:
        return False
    try:
        shutil.rmtree(run_root)
        _fsync_directory(finalization_runs)
    except OSError as error:
        raise TransactionError(
            "failed_workspace_cleanup_failed",
            "large failed finalization workspace could not be removed safely",
        ) from error
    return True


def _allocate_recovery_finalization_run(
    attempt: RecoverableAttempt,
    *,
    manifest_verifier: ManifestVerifier,
    run_root: Path,
) -> RecoverableAttempt:
    attempt = _ensure_immutable_recovery_source(
        attempt,
        manifest_verifier=manifest_verifier,
    )
    finalization_runs = attempt.context.attempt_root / "finalization-runs"
    _mkdir_private(finalization_runs, exclusive=False)
    _require_finalization_run_capacity(attempt, finalization_runs)
    if run_root.parent != finalization_runs:
        raise TransactionError(
            "recovery_workspace_inventory_mismatch",
            "allocated finalization run is outside its canonical root",
        )
    _canonical_uuid(run_root.name, "allocated finalization run id")
    _mkdir_private(run_root, exclusive=True)
    return attempt


def _prepare_recovery_finalization_work(
    attempt: RecoverableAttempt,
    *,
    manifest_verifier: ManifestVerifier,
    run_root: Path,
) -> tuple[Path, Path, Path, Path]:
    source = attempt.work
    source_app = attempt.work_app
    source_archive = attempt.archive
    if (
        run_root.parent
        != attempt.context.attempt_root / "finalization-runs"
    ):
        raise TransactionError(
            "recovery_workspace_inventory_mismatch",
            "finalization run is outside its canonical root",
        )
    _canonical_uuid(run_root.name, "finalization run id")
    _require_real_directory(run_root, private=True)
    if _strict_directory_inventory(
        run_root,
        failure_code="recovery_workspace_inventory_mismatch",
        failure_message="new finalization run cannot be enumerated",
    ):
        raise TransactionError(
            "recovery_workspace_inventory_mismatch",
            "new finalization run is not empty before copy",
        )
    run_work = run_root / "work"
    try:
        _mkdir_private(run_work, exclusive=True)
        shutil.copytree(
            source,
            run_work,
            symlinks=True,
            copy_function=shutil.copy2,
            dirs_exist_ok=True,
        )
    except (OSError, shutil.Error, TransactionError) as error:
        raise TransactionError(
            "recovery_workspace_copy_failed",
            "cannot create an isolated recovery finalization workspace",
        ) from error
    _require_current_finalization_run_within_bounds(
        attempt.context,
        run_root,
    )
    _require_real_directory(run_work, private=True)
    _fsync_tree(run_work)
    run_app = run_work / "Clash for Mac.app"
    run_archive = run_work / attempt.context.archive_name
    run_manifest = run_work / f"{attempt.context.archive_name}.manifest.json"
    if {path.name for path in run_work.iterdir()} != {
        run_app.name,
        run_archive.name,
        run_manifest.name,
    }:
        raise TransactionError(
            "recovery_workspace_inventory_mismatch",
            "isolated recovery workspace has unexpected entries",
        )
    if _app_tree_sha256(
        run_app,
        failure_code="app_identity_drift",
        failure_message="isolated recovery app identity cannot be derived",
    ) != attempt.pre_staple_app_sha256:
        raise TransactionError(
            "app_identity_drift",
            "isolated recovery app differs from the immutable source",
        )
    _require_archive_identity(
        run_archive,
        attempt.archive_sha256,
        attempt.archive_size,
    )
    _run_manifest_verification_barrier(
        manifest_verifier,
        ((run_archive, run_manifest, attempt.archive_metadata),),
    )
    if _app_tree_sha256(
        source_app,
        failure_code="app_identity_drift",
        failure_message="immutable recovery app cannot be revalidated",
    ) != attempt.pre_staple_app_sha256:
        raise TransactionError(
            "app_identity_drift",
            "immutable recovery app changed while copying its workspace",
        )
    _require_archive_identity(
        source_archive,
        attempt.archive_sha256,
        attempt.archive_size,
    )
    return run_work, run_app, run_archive, run_manifest


def _append_direct_finalization_preparing(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    manifest_verifier: ManifestVerifier,
) -> RecoverableAttempt:
    if (
        attempt.journal.sequence != 4
        or attempt.journal.documents[-1]["state"] != "submitted"
        or attempt.journal.documents[-1]["submission_id"] != submission_id
        or attempt.existing_submission_receipt is None
        or attempt.existing_submission_receipt_path is None
        or attempt.existing_submission_receipt["acquisition"] != "submit-no-wait"
        or attempt.work.name != "work"
    ):
        raise TransactionError(
            "direct_finalization_boundary_mismatch",
            "direct finalization preparation prerequisites are incomplete",
        )
    _, receipt_sha256 = _read_exact_json_document(
        attempt.existing_submission_receipt_path,
        attempt.existing_submission_receipt,
        drift_code="submission_receipt_identity_drift",
        drift_message="direct submission receipt changed before preparation",
    )
    _validate_immutable_recovery_source(
        attempt,
        attempt.work,
        manifest_verifier=manifest_verifier,
    )
    attempt.journal.append(
        "direct_finalization_preparing",
        submission_id=submission_id,
        evidence_sha256=receipt_sha256,
    )
    marker = attempt.journal.documents[-1]
    marker_recorded_at = _parse_utc_timestamp(
        marker["recorded_at"],
        "direct finalization preparation recorded_at",
    )[1]
    receipt_recorded_at = _parse_utc_timestamp(
        attempt.existing_submission_receipt["observed_at"],
        "direct submission receipt observed_at",
    )[1]
    if marker_recorded_at < receipt_recorded_at:
        raise TransactionError(
            "direct_finalization_boundary_mismatch",
            "direct finalization preparation predates its submission receipt",
        )
    if attempt.journal.previous_event_sha256 is None:
        raise TransactionError(
            "direct_finalization_boundary_mismatch",
            "direct finalization preparation lacks its journal digest",
        )
    return replace(
        attempt,
        submit_window_end=marker_recorded_at,
        submit_window_end_rendered=marker["recorded_at"],
        prior_event_sha256=attempt.journal.previous_event_sha256,
        recovery_event_start=attempt.journal.sequence,
        direct_source_preparation_incomplete=True,
    )


def _append_direct_finalization_ready(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    manifest_verifier: ManifestVerifier,
) -> RecoverableAttempt:
    if attempt.direct_finalization_ready:
        return attempt
    direct_prefix = attempt.journal.documents[4:]
    wait_outcome_supported = False
    if len(direct_prefix) == 1:
        wait_outcome_supported = _is_recoverable_wait_outcome_event(
            direct_prefix[0],
            submission_id=submission_id,
        )
    preparing_supported = (
        len(direct_prefix) == 1
        and direct_prefix[0]["state"] == "direct_finalization_preparing"
        and direct_prefix[0]["submission_id"] == submission_id
        and direct_prefix[0]["failure_code"] is None
        and direct_prefix[0]["exit_code"] is None
        and isinstance(direct_prefix[0].get("evidence_sha256"), str)
    )
    preparing_failure_supported = (
        len(direct_prefix) == 2
        and direct_prefix[0]["state"] == "direct_finalization_preparing"
        and direct_prefix[0]["submission_id"] == submission_id
        and _is_direct_source_preparation_failure_event(
            direct_prefix[1],
            submission_id=submission_id,
        )
    )
    prefix_supported = (
        not direct_prefix
        or wait_outcome_supported
        or preparing_supported
        or preparing_failure_supported
        or (
            len(direct_prefix) == 1
            and _is_direct_source_preparation_failure_event(
                direct_prefix[0],
                submission_id=submission_id,
            )
        )
    )
    if (
        len(attempt.journal.documents) < 4
        or attempt.journal.documents[3]["state"] != "submitted"
        or attempt.journal.documents[3]["submission_id"] != submission_id
        or not prefix_supported
        or attempt.existing_submission_receipt is None
        or attempt.existing_submission_receipt_path is None
        or attempt.existing_submission_receipt["acquisition"] != "submit-no-wait"
        or attempt.work.name != "recovery-source"
    ):
        raise TransactionError(
            "direct_finalization_boundary_mismatch",
            "direct finalization boundary prerequisites are incomplete",
        )
    _, receipt_sha256 = _read_exact_json_document(
        attempt.existing_submission_receipt_path,
        attempt.existing_submission_receipt,
        drift_code="submission_receipt_identity_drift",
        drift_message="direct submission receipt changed before finalization",
    )
    if any(
        event.get("evidence_sha256") != receipt_sha256
        for event in direct_prefix
        if event["state"] == "direct_finalization_preparing"
    ):
        raise TransactionError(
            "direct_finalization_boundary_mismatch",
            "direct finalization preparation differs from its receipt",
        )
    _validate_immutable_recovery_source(
        attempt,
        attempt.work,
        manifest_verifier=manifest_verifier,
    )
    attempt.journal.append(
        "direct_finalization_ready",
        submission_id=submission_id,
        evidence_sha256=receipt_sha256,
    )
    boundary = attempt.journal.documents[-1]
    boundary_recorded_at = _parse_utc_timestamp(
        boundary["recorded_at"],
        "direct finalization boundary recorded_at",
    )[1]
    receipt_recorded_at = _parse_utc_timestamp(
        attempt.existing_submission_receipt["observed_at"],
        "direct submission receipt observed_at",
    )[1]
    if boundary_recorded_at < receipt_recorded_at:
        raise TransactionError(
            "direct_finalization_boundary_mismatch",
            "direct finalization boundary predates its submission receipt",
        )
    if attempt.journal.previous_event_sha256 is None:
        raise TransactionError(
            "direct_finalization_boundary_mismatch",
            "direct finalization boundary lacks its journal digest",
        )
    return replace(
        attempt,
        submit_window_end=boundary_recorded_at,
        submit_window_end_rendered=boundary["recorded_at"],
        prior_event_sha256=attempt.journal.previous_event_sha256,
        recovery_event_start=attempt.journal.sequence,
        direct_finalization_ready=True,
        direct_source_preparation_incomplete=False,
    )


def _terminal_event_fields(
    error: Exception,
) -> tuple[str, str, int | None]:
    if isinstance(error, TransactionError):
        return error.terminal_state, error.code, error.exit_code
    return "failed", "internal_error", None


def _journal_ends_with_terminal(
    journal: EventJournal,
    *,
    submission_id: str | None,
    error: Exception,
) -> bool:
    if not journal.documents:
        return False
    state, failure_code, exit_code = _terminal_event_fields(error)
    last = journal.documents[-1]
    return (
        last["state"] == state
        and last["submission_id"] == submission_id
        and last["failure_code"] == failure_code
        and last["exit_code"] == exit_code
    )


def _run_accepted_finalization_locked(
    attempt: RecoverableAttempt,
    *,
    submission_id: str,
    submission_receipt: dict[str, Any],
    submission_receipt_path: Path,
    recovery_intent: dict[str, Any] | None,
    recovery_intent_path: Path | None,
    recovery_continuation: dict[str, Any] | None,
    recovery_continuation_path: Path | None,
    recovery_tool_repository: Path | None,
    recovery_tool_identity: dict[str, str] | None,
    recovery_tool_identity_reader: SourceIdentityReader | None,
    command_runner: CommandRunner,
    gatekeeper_capture: GatekeeperCapture,
    manifest_writer: ManifestWriter,
    manifest_verifier: ManifestVerifier,
    source_identity_reader: SourceIdentityReader,
    toolchain_metadata_reader: ToolchainMetadataReader,
    publisher: Publisher,
    clock: Clock,
    accepted_raw_log: Any | None,
) -> Path:
    finalization_run_root: Path | None = None
    try:
        attempt.journal.append(
            "finalization_started",
            submission_id=submission_id,
        )
        finalization_run_root = (
            attempt.context.attempt_root
            / "finalization-runs"
            / str(uuid.uuid4())
        )
        attempt = _allocate_recovery_finalization_run(
            attempt,
            manifest_verifier=manifest_verifier,
            run_root=finalization_run_root,
        )
        (
            finalization_work,
            finalization_app,
            finalization_archive,
            finalization_archive_manifest,
        ) = _prepare_recovery_finalization_work(
            attempt,
            manifest_verifier=manifest_verifier,
            run_root=finalization_run_root,
        )
        prepared = PreparedAttempt(
            context=attempt.context,
            work=finalization_work,
            work_app=finalization_app,
            archive=finalization_archive,
            archive_manifest=finalization_archive_manifest,
            archive_metadata=attempt.archive_metadata,
            archive_sha256=attempt.archive_sha256,
            archive_size=attempt.archive_size,
            pre_staple_app_sha256=attempt.pre_staple_app_sha256,
            attempt_id=attempt.attempt_id,
            intent=attempt.intent,
            intent_path=attempt.intent_path,
            intent_sha256=attempt.intent_sha256,
            submission_id=submission_id,
            submission_receipt=submission_receipt,
            submission_receipt_path=submission_receipt_path,
            recovery_intent=recovery_intent,
            recovery_intent_path=recovery_intent_path,
            recovery_continuation=recovery_continuation,
            recovery_continuation_path=recovery_continuation_path,
            recovery_tool_repository=recovery_tool_repository,
            recovery_tool_identity=recovery_tool_identity,
            recovery_tool_identity_reader=recovery_tool_identity_reader,
        )
        return _finalize_accepted_submission(
            prepared,
            journal=attempt.journal,
            command_runner=command_runner,
            gatekeeper_capture=gatekeeper_capture,
            manifest_writer=manifest_writer,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            publisher=publisher,
            clock=clock,
            accepted_raw_log=accepted_raw_log,
        )
    except Exception as error:
        if (
            isinstance(error, TransactionError)
            and error.code == "recovery_workspace_copy_failed"
            and finalization_run_root is not None
            and os.path.lexists(finalization_run_root)
        ):
            try:
                _cleanup_failed_finalization_workspace(
                    attempt.context,
                    finalization_run_root,
                    minimum_bytes=0,
                )
            except TransactionError as cleanup_error:
                raise cleanup_error from error
        state, failure_code, exit_code = _terminal_event_fields(error)
        attempt.journal.append(
            state,
            submission_id=submission_id,
            failure_code=failure_code,
            exit_code=exit_code,
        )
        if (
            finalization_run_root is not None
            and os.path.lexists(finalization_run_root)
        ):
            try:
                _cleanup_failed_finalization_workspace(
                    attempt.context,
                    finalization_run_root,
                )
            except TransactionError as cleanup_error:
                raise cleanup_error from error
        raise


@_serialize_recovery
def recover_transaction(
    context: TransactionContext,
    submission_id: str,
    recovery_tool_repository: Path,
    *,
    command_runner: CommandRunner = production_command_runner,
    archive_validator: ArchiveValidator = production_archive_validator,
    gatekeeper_capture: GatekeeperCapture = production_gatekeeper_capture,
    manifest_writer: ManifestWriter = production_manifest_writer,
    manifest_verifier: ManifestVerifier = production_manifest_verifier,
    source_identity_reader: SourceIdentityReader = production_source_identity_reader,
    toolchain_metadata_reader: ToolchainMetadataReader = (
        production_toolchain_metadata_reader
    ),
    recovery_tool_identity_reader: SourceIdentityReader = (
        production_source_identity_reader
    ),
    publisher: Publisher = publish_exclusive,
    clock: Clock = _utc_now,
) -> Path:
    submission_id = _canonical_uuid(submission_id, "recovery submission id")
    if (
        not recovery_tool_repository.is_absolute()
        or recovery_tool_repository.is_symlink()
        or recovery_tool_repository.resolve(strict=True) != recovery_tool_repository
    ):
        raise TransactionError(
            "unsafe_recovery_tool_repository",
            "recovery tool repository must be an absolute real path",
        )
    _require_real_directory(recovery_tool_repository, trusted=True)
    try:
        recovery_tool_identity = recovery_tool_identity_reader(
            recovery_tool_repository
        )
    except Exception as error:
        raise TransactionError(
            "recovery_tool_identity_unavailable",
            "cannot derive the clean recovery tool source identity",
        ) from error
    if (
        set(recovery_tool_identity) != {"repositoryCommit", "releaseSourceSha256"}
        or not COMMIT_RE.fullmatch(recovery_tool_identity["repositoryCommit"])
        or not SHA256_RE.fullmatch(recovery_tool_identity["releaseSourceSha256"])
    ):
        raise TransactionError(
            "recovery_tool_identity_invalid",
            "recovery tool source identity is malformed",
        )
    direct_receipt_path = context.attempt_root / "receipt.json"
    direct_receipt_pending_path = (
        context.attempt_root / PUBLISH_READY_RECEIPT_PENDING_FILENAME
    )
    if os.path.lexists(context.attempt_root / "publish-ready") or (
        os.path.lexists(context.final_root)
        and (
            os.path.lexists(direct_receipt_path)
            or os.path.lexists(direct_receipt_pending_path)
        )
    ):
        return _resume_direct_sealed_transaction(
            context,
            submission_id=submission_id,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            publisher=publisher,
            clock=clock,
        )
    attempt = _load_recoverable_attempt(
        context,
        archive_validator=archive_validator,
        manifest_verifier=manifest_verifier,
        source_identity_reader=source_identity_reader,
        toolchain_metadata_reader=toolchain_metadata_reader,
        clock=clock,
    )
    if (
        attempt.journal_submission_id is not None
        and attempt.journal_submission_id != submission_id
    ):
        raise TransactionError(
            "submission_id_mismatch",
            "recovery id differs from the persisted submit outcome",
        )
    if (
        attempt.observed_submission_id is not None
        and attempt.observed_submission_id != submission_id
    ):
        raise TransactionError(
            "submission_id_mismatch",
            "recovery id differs from the durable submit observation",
        )
    direct_receipt = attempt.existing_submission_receipt
    complete_interrupted_direct_boundary = (
        not attempt.direct_finalization_ready
        and direct_receipt is not None
        and direct_receipt["acquisition"] == "submit-no-wait"
        and not os.path.lexists(
            context.attempt_root / "recovery-intent.json"
        )
        and (
            attempt.direct_source_preparation_incomplete
            or (
                attempt.work.name == "recovery-source"
                and attempt.journal.sequence == attempt.recovery_event_start
            )
        )
    )
    if complete_interrupted_direct_boundary:
        if (
            attempt.journal.sequence + DIRECT_BOUNDARY_RECOVERY_EVENT_RESERVE
            > MAX_EVENT_DOCUMENTS
        ):
            raise TransactionError(
                "event_journal_capacity_exceeded",
                "journal lacks capacity to complete direct finalization recovery",
            )
        attempt = _ensure_immutable_recovery_source(
            attempt,
            manifest_verifier=manifest_verifier,
        )
        attempt = _append_direct_finalization_ready(
            attempt,
            submission_id=submission_id,
            manifest_verifier=manifest_verifier,
        )
    if os.path.lexists(context.final_root):
        if (
            attempt.direct_finalization_ready
            and not os.path.lexists(
                context.attempt_root / "recovery-intent.json"
            )
        ):
            return _recover_direct_published_transaction(
                attempt,
                submission_id=submission_id,
                manifest_verifier=manifest_verifier,
                source_identity_reader=source_identity_reader,
                toolchain_metadata_reader=toolchain_metadata_reader,
            )
        return _recover_published_transaction(
            attempt,
            submission_id=submission_id,
            recovery_tool_repository=recovery_tool_repository,
            recovery_tool_identity=recovery_tool_identity,
            recovery_tool_identity_reader=recovery_tool_identity_reader,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            clock=clock,
        )
    _result_or_error(
        command_runner,
        CommandRole.FINAL_VERIFY,
        [
            str(context.repository / "scripts/verify_release_app.sh"),
            "--pre-notary",
            str(attempt.work_app),
            str(context.native_products),
        ],
        600,
    )
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)
    _require_archive_identity(
        attempt.archive,
        attempt.archive_sha256,
        attempt.archive_size,
    )
    recovery_intent, recovery_intent_path, recovery_intent_sha256 = (
        _load_or_create_recovery_intent(
            attempt,
            submission_id,
            recovery_tool_identity,
            clock,
        )
    )
    with _exclusive_recovery_lock(recovery_intent_path):
        _read_exact_json_document(
            recovery_intent_path,
            recovery_intent,
            drift_code="recovery_intent_identity_drift",
            drift_message="recovery intent changed after locking",
        )
        already_reconciled = _reduce_attempt_events(
            attempt.journal,
            submission_id=submission_id,
        ).reconciled
        if already_reconciled and attempt.existing_submission_receipt is None:
            raise TransactionError(
                "submission_receipt_missing",
                "reconciled recovery event lacks its immutable submission receipt",
            )
        anchor_append_required = _require_recovery_intent_anchor(
            attempt,
            submission_id=submission_id,
            recovery_intent_sha256=recovery_intent_sha256,
            append_missing=False,
        )
        continuation_append_required = _recovery_continuation_append_required(
            attempt,
            recovery_intent=recovery_intent,
            recovery_tool_identity=recovery_tool_identity,
            already_reconciled=already_reconciled,
        )
        required_events = (
            (10 if already_reconciled else RECOVERY_SUCCESS_EVENT_RESERVE)
            + int(anchor_append_required)
            + int(continuation_append_required)
        )
        if attempt.journal.sequence + required_events > MAX_EVENT_DOCUMENTS:
            raise TransactionError(
                "event_journal_capacity_exceeded",
                "notarization journal lacks capacity for atomic recovery finalization",
            )
        if anchor_append_required:
            _require_recovery_intent_anchor(
                attempt,
                submission_id=submission_id,
                recovery_intent_sha256=recovery_intent_sha256,
                append_missing=True,
            )
        (
            recovery_continuation,
            recovery_continuation_path,
            _recovery_continuation_sha256,
        ) = _load_or_create_recovery_continuation(
            attempt,
            submission_id=submission_id,
            recovery_intent=recovery_intent,
            recovery_intent_sha256=recovery_intent_sha256,
            recovery_tool_identity=recovery_tool_identity,
            already_reconciled=already_reconciled,
            clock=clock,
        )
        if not already_reconciled:
            attempt.journal.append(
                "reconciliation_started",
                submission_id=submission_id,
            )
        try:
            raw_log, info_created_at = _read_accepted_recovery_evidence(
                attempt,
                submission_id=submission_id,
                command_runner=command_runner,
            )
            _require_source_identity(context, source_identity_reader)
            _require_toolchain_identity(context, toolchain_metadata_reader)
            _require_archive_identity(
                attempt.archive,
                attempt.archive_sha256,
                attempt.archive_size,
            )
            if _app_tree_sha256(
                attempt.work_app,
                failure_code="app_identity_drift",
                failure_message="recovery app identity cannot be revalidated",
            ) != attempt.pre_staple_app_sha256:
                raise TransactionError(
                    "app_identity_drift",
                    "recovery app changed during Apple evidence reconciliation",
                )
            if attempt.existing_submission_receipt is None:
                submission_receipt = {
                    "schema_version": 2,
                    "document": SUBMISSION_DOCUMENT,
                    "attempt_id": attempt.attempt_id,
                    "submission_id": submission_id,
                    "acquisition": "explicit-recovery",
                    "archive_name": context.archive_name,
                    "submission_observation_sha256": (
                        attempt.submission_observation_sha256
                    ),
                    "recovery_intent_sha256": recovery_intent_sha256,
                    "notary_created_at": info_created_at,
                    "causal_binding": (
                        "direct-submit-observation-and-log"
                        if attempt.observed_submission_id is not None
                        else "unique-history-window-and-log"
                    ),
                    "archive_sha256": attempt.archive_sha256,
                    "observed_at": clock(),
                }
                submission_receipt_path = (
                    context.attempt_root / "submission-receipt.json"
                )
                _write_json_exclusive(
                    submission_receipt_path,
                    submission_receipt,
                )
            else:
                if attempt.existing_submission_receipt_path is None:
                    raise TransactionError(
                        "submission_receipt_identity_drift",
                        "persisted submission receipt path is missing",
                    )
                submission_receipt = attempt.existing_submission_receipt
                submission_receipt_path = (
                    attempt.existing_submission_receipt_path
                )
            if not already_reconciled:
                attempt.journal.append(
                    "submission_reconciled",
                    submission_id=submission_id,
                )
        except Exception as error:
            _append_reconciliation_failure(
                attempt.journal,
                submission_id,
                error,
            )
            raise

        return _run_accepted_finalization_locked(
            attempt,
            submission_id=submission_id,
            submission_receipt=submission_receipt,
            submission_receipt_path=submission_receipt_path,
            recovery_intent=recovery_intent,
            recovery_intent_path=recovery_intent_path,
            recovery_continuation=recovery_continuation,
            recovery_continuation_path=recovery_continuation_path,
            recovery_tool_repository=recovery_tool_repository,
            recovery_tool_identity=recovery_tool_identity,
            recovery_tool_identity_reader=recovery_tool_identity_reader,
            command_runner=command_runner,
            gatekeeper_capture=gatekeeper_capture,
            manifest_writer=manifest_writer,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            publisher=publisher,
            clock=clock,
            accepted_raw_log=raw_log,
        )


def execute_transaction(
    context: TransactionContext,
    *,
    command_runner: CommandRunner = production_command_runner,
    archive_builder: ArchiveBuilder = production_archive_builder,
    archive_validator: ArchiveValidator = production_archive_validator,
    gatekeeper_capture: GatekeeperCapture = production_gatekeeper_capture,
    manifest_writer: ManifestWriter = production_manifest_writer,
    manifest_verifier: ManifestVerifier = production_manifest_verifier,
    source_identity_reader: SourceIdentityReader = production_source_identity_reader,
    toolchain_metadata_reader: ToolchainMetadataReader = (
        production_toolchain_metadata_reader
    ),
    publisher: Publisher = publish_exclusive,
    clock: Clock = _utc_now,
    attempt_id_factory: AttemptIdFactory = lambda: str(uuid.uuid4()),
    host_system_identity_reader: HostSystemIdentityReader = (
        production_host_system_identity_reader
    ),
) -> Path:
    _validate_context(context)
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)
    events, work = _claim_attempt(context)
    journal: EventJournal | None = None
    submission_id: str | None = None
    attempt_lock_scope = ExitStack()
    attempt_lock_held = False
    attempt_lock_required = False
    direct_boundary_event_incomplete = False
    try:
        staged_app = context.staged_app
        if staged_app is None:
            raise TransactionError(
                "unsafe_staged_app", "new transaction requires a staged application"
            )
        work_app = work / "Clash for Mac.app"
        try:
            os.rename(staged_app, work_app)
            os.rmdir(staged_app.parent)
        except OSError as error:
            raise TransactionError(
                "staged_app_transfer_failed", "cannot transfer the signed app into the attempt"
            ) from error
        _fsync_directory(work)
        pre_staple_app_sha256 = _app_tree_sha256(
            work_app,
            failure_code="app_identity_failed",
            failure_message="pre-staple app digest cannot be derived",
        )

        archive = work / context.archive_name
        archive_builder(work_app, archive)
        _fsync_regular_file(archive)
        archive_sha256, archive_size = _archive_identity(archive)
        try:
            archive_validator(archive, work_app)
        except TransactionError:
            raise
        except Exception as error:
            raise TransactionError(
                "archive_validation_failed",
                "notarization archive validation did not complete",
            ) from error
        _require_archive_identity(archive, archive_sha256, archive_size)
        validated_app_sha256 = _app_tree_sha256(
            work_app,
            failure_code="archive_source_identity_drift",
            failure_message="signed app changed while validating its archive",
        )
        if validated_app_sha256 != pre_staple_app_sha256:
            raise TransactionError(
                "archive_source_identity_drift",
                "signed app changed while validating its archive",
            )
        archive_manifest = work / f"{context.archive_name}.manifest.json"
        archive_metadata = _archive_metadata(context)
        manifest_writer(archive, archive_manifest, archive_metadata)
        _run_manifest_verification_barrier(
            manifest_verifier,
            ((archive, archive_manifest, archive_metadata),),
        )

        attempt_id = _canonical_uuid(attempt_id_factory(), "local attempt id")
        intent = {
            "schema_version": 1,
            "document": ATTEMPT_DOCUMENT,
            "attempt_id": attempt_id,
            "lane": context.build_kind,
            "build_number": context.build_number,
            "version": VERSION,
            "repository_commit": context.repository_commit,
            "release_source_sha256": context.release_source_sha256,
            "team_id": EXPECTED_TEAM_ID,
            "archive_name": context.archive_name,
            "archive_sha256": archive_sha256,
            "archive_size": archive_size,
            "pre_staple_app_tree_sha256": pre_staple_app_sha256,
            "prepared_at": clock(),
        }
        intent_path = context.attempt_root / "intent.json"
        _write_json_exclusive(intent_path, intent)
        intent_sha256 = _sha256_file(intent_path)
        journal = EventJournal(events, intent_sha256, clock)
        journal.append("prepared")
        readiness_mode = _establish_pre_submission_policy(
            command_runner,
            work_app,
            host_system_identity_reader,
        )
        if readiness_mode is PreSubmissionPolicyMode.NATIVE:
            journal.append("notary_ready")
        else:
            journal.append("pre_submission_policy_compatibility_applied")
        _require_source_identity(context, source_identity_reader)
        _require_toolchain_identity(context, toolchain_metadata_reader)
        _require_archive_identity(archive, archive_sha256, archive_size)
        submission_inventory = _decode_attempt_inventory(
            replace(context, staged_app=None),
            allowed_entries={"events", "intent.json", "work"},
            require_source=True,
        )
        if submission_inventory.entries != {
            "events",
            "intent.json",
            "work",
        }:
            raise TransactionError(
                "submission_inventory_mismatch",
                "pre-submission attempt inventory is incomplete",
            )
        attempt_lock_required = True
        attempt_lock_scope.enter_context(
            _exclusive_attempt_recovery_lock(context)
        )
        attempt_lock_held = True
        if (
            journal.sequence + 2 + DIRECT_FINALIZATION_EVENT_RESERVE
            > MAX_EVENT_DOCUMENTS
        ):
            raise TransactionError(
                "event_journal_capacity_exceeded",
                "notarization journal lacks capacity for direct finalization",
            )
        journal.append("submitting")

        submit_command = [
            "/usr/bin/xcrun",
            "notarytool",
            "submit",
            str(archive),
            "--no-wait",
            "--keychain-profile",
            context.notary_profile,
            "--output-format",
            "json",
        ]
        try:
            submit = _capture_command_result(
                command_runner,
                CommandRole.SUBMIT,
                submit_command,
                1800,
            )
        except TransactionError as error:
            raise TransactionError(
                error.code,
                str(error),
                terminal_state="outcome_unknown",
            ) from error
        try:
            submission_id = _project_notary_submit_identity(submit.stdout, archive)
        except TransactionError as error:
            if submit.returncode != 0:
                raise TransactionError(
                    "submit_failed",
                    "submit command failed without a safely projectable identity",
                    terminal_state="outcome_unknown",
                    exit_code=submit.returncode,
                ) from error
            if submit.stderr:
                raise TransactionError(
                    "submit_stderr",
                    "submit emitted unexpected diagnostic output without a safely projectable identity",
                    terminal_state="outcome_unknown",
                ) from error
            raise TransactionError(
                error.code,
                str(error),
                terminal_state="outcome_unknown",
            ) from error
        submission_observation = {
            "schema_version": 1,
            "document": SUBMISSION_OBSERVATION_DOCUMENT,
            "attempt_id": attempt_id,
            "submission_id": submission_id,
            "intent_sha256": intent_sha256,
            "archive_name": context.archive_name,
            "archive_sha256": archive_sha256,
            "path_binding": "exact",
            "observed_at": clock(),
        }
        submission_observation_path = (
            context.attempt_root / "submission-observation.json"
        )
        try:
            _write_json_exclusive(
                submission_observation_path,
                submission_observation,
            )
        except TransactionError as error:
            raise TransactionError(
                "submission_observation_failed",
                "Apple returned a submission id but its safe observation was not persisted",
                terminal_state="outcome_unknown",
            ) from error
        if submit.returncode != 0:
            raise TransactionError(
                "submit_failed",
                "submit command failed after returning a safely observed submission id",
                terminal_state="outcome_unknown",
                exit_code=submit.returncode,
            )
        _require_empty_notary_stderr(submit, CommandRole.SUBMIT)
        try:
            parsed_submission_id = _parse_notary_submit_response(
                submit.stdout,
                archive,
            )
        except TransactionError as error:
            raise TransactionError(
                error.code,
                str(error),
                terminal_state="outcome_unknown",
            ) from error
        if parsed_submission_id != submission_id:
            raise TransactionError(
                "submission_id_mismatch",
                "notarytool submit identity changed between projection and validation",
                terminal_state="outcome_unknown",
            )
        submission_receipt = {
            "schema_version": 2,
            "document": SUBMISSION_DOCUMENT,
            "attempt_id": attempt_id,
            "submission_id": submission_id,
            "acquisition": "submit-no-wait",
            "archive_name": context.archive_name,
            "submission_observation_sha256": _sha256_file(
                submission_observation_path
            ),
            "recovery_intent_sha256": None,
            "notary_created_at": None,
            "causal_binding": "direct-submit-observation",
            "archive_sha256": archive_sha256,
            "observed_at": clock(),
        }
        submission_receipt_path = context.attempt_root / "submission-receipt.json"
        try:
            _write_json_exclusive(submission_receipt_path, submission_receipt)
        except TransactionError as error:
            raise TransactionError(
                "submission_receipt_failed",
                "Apple returned a submission id but its receipt was not persisted",
                terminal_state="outcome_unknown",
            ) from error
        journal.append("submitted", submission_id=submission_id)

        wait_command = [
            "/usr/bin/xcrun",
            "notarytool",
            "wait",
            submission_id,
            "--keychain-profile",
            context.notary_profile,
            "--output-format",
            "json",
            "--timeout",
            "2h",
        ]
        waited = _result_or_error(
            command_runner,
            CommandRole.WAIT,
            wait_command,
            7500,
            uncertain=True,
        )
        _require_empty_notary_stderr(waited, CommandRole.WAIT)
        try:
            wait_id, wait_status = _parse_notary_wait_response(
                waited.stdout,
                allowed_statuses={"In Progress", "Accepted", "Invalid", "Rejected"},
            )
        except TransactionError as error:
            raise TransactionError(
                error.code,
                str(error),
                terminal_state="outcome_unknown",
            ) from error
        if wait_id != submission_id:
            raise TransactionError(
                "submission_id_mismatch",
                "notarytool wait returned a different submission id",
                terminal_state="outcome_unknown",
            )
        if wait_status in ("Invalid", "Rejected"):
            raise TransactionError(
                "notary_submission_rejected",
                "Apple rejected the notarization submission",
                terminal_state="rejected",
            )
        if wait_status != "Accepted":
            raise TransactionError(
                "notary_wait_incomplete",
                "Apple notarization did not reach a terminal result",
                terminal_state="outcome_unknown",
            )
        attempt = _load_recoverable_attempt(
            replace(context, staged_app=None),
            archive_validator=archive_validator,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            clock=clock,
        )
        journal = attempt.journal
        if (
            attempt.observed_submission_id != submission_id
            or attempt.existing_submission_receipt != submission_receipt
            or attempt.existing_submission_receipt_path
            != submission_receipt_path
        ):
            raise TransactionError(
                "direct_finalization_boundary_mismatch",
                "accepted submission differs from its durable direct evidence",
            )
        try:
            attempt = _append_direct_finalization_preparing(
                attempt,
                submission_id=submission_id,
                manifest_verifier=manifest_verifier,
            )
        except Exception:
            direct_boundary_event_incomplete = True
            raise
        try:
            attempt = _ensure_immutable_recovery_source(
                attempt,
                manifest_verifier=manifest_verifier,
            )
        except Exception as error:
            raise TransactionError(
                "direct_source_preparation_failed",
                "cannot establish the immutable direct finalization source",
                terminal_state="outcome_unknown",
            ) from error
        try:
            attempt = _append_direct_finalization_ready(
                attempt,
                submission_id=submission_id,
                manifest_verifier=manifest_verifier,
            )
        except Exception:
            direct_boundary_event_incomplete = True
            raise
        direct_reduction = _reduce_attempt_events(
            attempt.journal,
            submission_id=submission_id,
        )
        if direct_reduction.phase is not AttemptPhase.DIRECT_FINALIZATION_READY:
            raise TransactionError(
                "direct_finalization_boundary_mismatch",
                "direct finalization reducer did not reach its ready phase",
            )
        return _run_accepted_finalization_locked(
            attempt,
            submission_id=submission_id,
            submission_receipt=submission_receipt,
            submission_receipt_path=submission_receipt_path,
            recovery_intent=None,
            recovery_intent_path=None,
            recovery_continuation=None,
            recovery_continuation_path=None,
            recovery_tool_repository=None,
            recovery_tool_identity=None,
            recovery_tool_identity_reader=None,
            command_runner=command_runner,
            gatekeeper_capture=gatekeeper_capture,
            manifest_writer=manifest_writer,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            publisher=publisher,
            clock=clock,
            accepted_raw_log=None,
        )
    except Exception as error:
        if (
            journal is not None
            and (attempt_lock_held or not attempt_lock_required)
            and not direct_boundary_event_incomplete
            and not _journal_ends_with_terminal(
                journal,
                submission_id=submission_id,
                error=error,
            )
        ):
            terminal_state, failure_code, exit_code = _terminal_event_fields(
                error
            )
            try:
                journal.append(
                    terminal_state,
                    submission_id=submission_id,
                    failure_code=failure_code,
                    exit_code=exit_code,
                )
            except Exception as receipt_error:
                raise TransactionError(
                    "failure_receipt_failed",
                    "transaction failed with "
                    f"{failure_code} and its terminal receipt could not be persisted",
                    terminal_state=terminal_state,
                    exit_code=exit_code,
                ) from receipt_error
        raise
    finally:
        attempt_lock_scope.close()


def _validate_published_transaction_receipt_once(
    context: TransactionContext,
) -> PublishedTransactionEvidence:
    """Read-only validation of one canonical direct or recovered publication.

    This is the production evidence-consumer boundary. It never resumes,
    appends, repairs, fsyncs, or republishes a transaction. A legacy direct
    receipt is accepted only at ``attempt_root/receipt.json`` with its exact
    inventory. Current direct and recovered receipts are accepted only through
    the journal-bound unique-match validator under ``finalization-runs``.
    Historical recovery-tool bytes are rederived from immutable Git blobs at
    the receipt-bound commit, so no caller-selected checkout or unverifiable
    identity is trusted.
    """
    _validate_context(context, recovery=True)
    _require_source_identity(context, production_source_identity_reader)
    _require_toolchain_identity(context, production_toolchain_metadata_reader)
    publication_root = context.final_root
    _require_real_directory(publication_root, private=True)
    direct_receipt_path = context.attempt_root / "receipt.json"

    if os.path.lexists(direct_receipt_path):
        allowed = {
            "events",
            "intent.json",
            "submission-observation.json",
            "submission-receipt.json",
            "receipt.json",
        }
        inventory = _decode_attempt_inventory(
            context,
            allowed_entries=allowed,
            require_source=False,
        )
        if inventory.entries != allowed or not inventory.final_exists:
            raise TransactionError(
                "direct_sealed_inventory_mismatch",
                "published direct attempt inventory is not canonical",
            )
        intent, intent_path, intent_sha256 = _load_recovery_intent_document(context)
        receipt_data = _read_regular_bytes(direct_receipt_path)
        receipt = _decode_json_bytes(receipt_data, direct_receipt_path)
        if (
            not isinstance(receipt, dict)
            or set(receipt) != PUBLISH_READY_RECEIPT_FIELDS
            or receipt_data != _canonical_json(receipt).encode("utf-8")
        ):
            raise TransactionError(
                "sealed_receipt_identity_drift",
                "direct publish-ready receipt is not canonical",
            )
        submission_id = _canonical_uuid(
            receipt.get("submission_id"),
            "direct receipt submission id",
        )
        submission_receipt_path = context.attempt_root / "submission-receipt.json"
        submission_receipt_data = _read_regular_bytes(submission_receipt_path)
        submission_receipt = _decode_json_bytes(
            submission_receipt_data,
            submission_receipt_path,
        )
        if not isinstance(submission_receipt, dict):
            raise TransactionError(
                "submission_receipt_identity_drift",
                "direct submission receipt is not a JSON object",
            )
        journal = EventJournal.load_existing(
            context.attempt_root / "events",
            intent_sha256,
            _utc_now,
        )
        prepared = PreparedAttempt(
            context=context,
            work=publication_root,
            work_app=publication_root / "Clash for Mac.app",
            archive=publication_root / context.archive_name,
            archive_manifest=(
                publication_root / f"{context.archive_name}.manifest.json"
            ),
            archive_metadata=_archive_metadata(context),
            archive_sha256=intent["archive_sha256"],
            archive_size=intent["archive_size"],
            pre_staple_app_sha256=intent["pre_staple_app_tree_sha256"],
            attempt_id=intent["attempt_id"],
            intent=intent,
            intent_path=intent_path,
            intent_sha256=intent_sha256,
            submission_id=submission_id,
            submission_receipt=submission_receipt,
            submission_receipt_path=submission_receipt_path,
            recovery_intent=None,
            recovery_intent_path=None,
            recovery_continuation=None,
            recovery_continuation_path=None,
            recovery_tool_repository=None,
            recovery_tool_identity=None,
            recovery_tool_identity_reader=None,
        )
        validated_receipt = _validate_sealed_publication(
            prepared,
            journal=journal,
            publication_root=publication_root,
            receipt_path=direct_receipt_path,
            manifest_verifier=production_manifest_verifier,
            source_identity_reader=production_source_identity_reader,
            toolchain_metadata_reader=production_toolchain_metadata_reader,
            allow_direct_publish_failure=True,
            allow_receipt_durability_unknown=True,
        )
        return PublishedTransactionEvidence(
            receipt=validated_receipt,
            receipt_path=direct_receipt_path,
            prepared_at=intent["prepared_at"],
        )

    attempt = _load_recoverable_attempt(
        context,
        archive_validator=production_archive_validator,
        manifest_verifier=production_manifest_verifier,
        source_identity_reader=production_source_identity_reader,
        toolchain_metadata_reader=production_toolchain_metadata_reader,
        clock=_utc_now,
    )
    reduction = _reduce_attempt_events(attempt.journal)
    if (
        not attempt.existing_submission_receipt
        or attempt.existing_submission_receipt_path is None
        or not attempt.journal.documents
        or not reduction.reconciled
    ):
        raise TransactionError(
            "published_candidate_unrecognized",
            "published recovery lacks a reconciled immutable submission",
        )
    submission_id = _canonical_uuid(
        attempt.existing_submission_receipt["submission_id"],
        "recovery receipt submission id",
    )
    recovery_intent_path = context.attempt_root / "recovery-intent.json"
    if attempt.direct_finalization_ready and not os.path.lexists(recovery_intent_path):
        prepared_direct = PreparedAttempt(
            context=context,
            work=publication_root,
            work_app=publication_root / "Clash for Mac.app",
            archive=publication_root / context.archive_name,
            archive_manifest=(
                publication_root / f"{context.archive_name}.manifest.json"
            ),
            archive_metadata=attempt.archive_metadata,
            archive_sha256=attempt.archive_sha256,
            archive_size=attempt.archive_size,
            pre_staple_app_sha256=attempt.pre_staple_app_sha256,
            attempt_id=attempt.attempt_id,
            intent=attempt.intent,
            intent_path=attempt.intent_path,
            intent_sha256=attempt.intent_sha256,
            submission_id=submission_id,
            submission_receipt=attempt.existing_submission_receipt,
            submission_receipt_path=attempt.existing_submission_receipt_path,
            recovery_intent=None,
            recovery_intent_path=None,
            recovery_continuation=None,
            recovery_continuation_path=None,
            recovery_tool_repository=None,
            recovery_tool_identity=None,
            recovery_tool_identity_reader=None,
        )
        matching_direct_receipt = _unique_matching_published_receipt(
            prepared_direct,
            journal=attempt.journal,
            publication_root=publication_root,
            manifest_verifier=production_manifest_verifier,
            source_identity_reader=production_source_identity_reader,
            toolchain_metadata_reader=production_toolchain_metadata_reader,
        )
        direct_receipt = _validate_sealed_publication(
            prepared_direct,
            journal=attempt.journal,
            publication_root=publication_root,
            receipt_path=matching_direct_receipt,
            manifest_verifier=production_manifest_verifier,
            source_identity_reader=production_source_identity_reader,
            toolchain_metadata_reader=production_toolchain_metadata_reader,
        )
        return PublishedTransactionEvidence(
            receipt=direct_receipt,
            receipt_path=matching_direct_receipt,
            prepared_at=attempt.intent["prepared_at"],
        )

    preliminary_intent = _decode_json_bytes(
        _read_regular_bytes(recovery_intent_path),
        recovery_intent_path,
    )
    if not isinstance(preliminary_intent, dict):
        raise TransactionError(
            "recovery_intent_identity_drift",
            "recovery intent is not a JSON object",
        )
    initial_tool_identity = {
        "repositoryCommit": preliminary_intent.get(
            "recovery_tool_repository_commit"
        ),
        "releaseSourceSha256": preliminary_intent.get(
            "recovery_tool_release_source_sha256"
        ),
    }
    try:
        observed_initial = identity_at_commit(
            context.repository,
            initial_tool_identity["repositoryCommit"],
        )
    except (OSError, SourceIdentityError, TypeError) as error:
        raise TransactionError(
            "recovery_tool_identity_unavailable",
            "recovery tool Git object identity is unavailable",
        ) from error
    if observed_initial != initial_tool_identity:
        raise TransactionError(
            "recovery_tool_identity_drift",
            "recovery tool Git blobs differ from the immutable intent",
        )
    recovery_intent, recovery_intent_path, recovery_intent_sha256 = (
        _load_existing_recovery_intent(
            attempt,
            submission_id,
            initial_tool_identity,
        )
    )
    if _require_recovery_intent_anchor(
        attempt,
        submission_id=submission_id,
        recovery_intent_sha256=recovery_intent_sha256,
        append_missing=False,
    ):
        raise TransactionError(
            "recovery_intent_anchor_missing",
            "published recovery has no immutable recovery intent anchor",
        )

    continuation_path = context.attempt_root / "recovery-continuation.json"
    final_tool_identity = initial_tool_identity
    if os.path.lexists(continuation_path):
        preliminary_continuation = _decode_json_bytes(
            _read_regular_bytes(continuation_path),
            continuation_path,
        )
        if not isinstance(preliminary_continuation, dict):
            raise TransactionError(
                "recovery_continuation_identity_drift",
                "recovery continuation is not a JSON object",
            )
        final_tool_identity = {
            "repositoryCommit": preliminary_continuation.get(
                "continuation_tool_repository_commit"
            ),
            "releaseSourceSha256": preliminary_continuation.get(
                "continuation_tool_release_source_sha256"
            ),
        }
        try:
            observed_final = identity_at_commit(
                context.repository,
                final_tool_identity["repositoryCommit"],
            )
        except (OSError, SourceIdentityError, TypeError) as error:
            raise TransactionError(
                "recovery_tool_identity_unavailable",
                "continued recovery tool Git object identity is unavailable",
            ) from error
        if observed_final != final_tool_identity:
            raise TransactionError(
                "recovery_tool_identity_drift",
                "continued recovery tool Git blobs differ from immutable provenance",
            )
    recovery_continuation, recovery_continuation_path = (
        _load_existing_recovery_continuation(
            attempt,
            submission_id=submission_id,
            recovery_intent=recovery_intent,
            recovery_intent_sha256=recovery_intent_sha256,
            recovery_tool_identity=final_tool_identity,
        )
    )

    def historical_identity_reader(_repository: Path) -> dict[str, str]:
        return identity_at_commit(
            context.repository,
            final_tool_identity["repositoryCommit"],
        )

    prepared = PreparedAttempt(
        context=context,
        work=publication_root,
        work_app=publication_root / "Clash for Mac.app",
        archive=publication_root / context.archive_name,
        archive_manifest=(
            publication_root / f"{context.archive_name}.manifest.json"
        ),
        archive_metadata=attempt.archive_metadata,
        archive_sha256=attempt.archive_sha256,
        archive_size=attempt.archive_size,
        pre_staple_app_sha256=attempt.pre_staple_app_sha256,
        attempt_id=attempt.attempt_id,
        intent=attempt.intent,
        intent_path=attempt.intent_path,
        intent_sha256=attempt.intent_sha256,
        submission_id=submission_id,
        submission_receipt=attempt.existing_submission_receipt,
        submission_receipt_path=attempt.existing_submission_receipt_path,
        recovery_intent=recovery_intent,
        recovery_intent_path=recovery_intent_path,
        recovery_continuation=recovery_continuation,
        recovery_continuation_path=recovery_continuation_path,
        recovery_tool_repository=context.repository,
        recovery_tool_identity=final_tool_identity,
        recovery_tool_identity_reader=historical_identity_reader,
    )
    matching_receipt = _unique_matching_published_receipt(
        prepared,
        journal=attempt.journal,
        publication_root=publication_root,
        manifest_verifier=production_manifest_verifier,
        source_identity_reader=production_source_identity_reader,
        toolchain_metadata_reader=production_toolchain_metadata_reader,
    )
    receipt = _validate_sealed_publication(
        prepared,
        journal=attempt.journal,
        publication_root=publication_root,
        receipt_path=matching_receipt,
        manifest_verifier=production_manifest_verifier,
        source_identity_reader=production_source_identity_reader,
        toolchain_metadata_reader=production_toolchain_metadata_reader,
    )
    return PublishedTransactionEvidence(
        receipt=receipt,
        receipt_path=matching_receipt,
        prepared_at=attempt.intent["prepared_at"],
    )


def _published_tree_digest(path: Path, label: str) -> str:
    try:
        value = build_manifest(path, algorithm="sha256-tree-v2").get("sha256")
    except (OSError, ValueError) as error:
        raise TransactionError(
            "published_snapshot_unavailable",
            f"{label} cannot be captured for read-only validation",
        ) from error
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise TransactionError(
            "published_snapshot_unavailable",
            f"{label} produced a malformed tree identity",
        )
    return value


def validate_published_transaction_receipt(
    context: TransactionContext,
) -> PublishedTransactionEvidence:
    """Validate publication without writes and reject any concurrent tree drift."""
    _validate_context(context, recovery=True)
    before = (
        _published_tree_digest(context.attempt_root, "notarization attempt tree"),
        _published_tree_digest(context.final_root, "published candidate tree"),
    )
    evidence = _validate_published_transaction_receipt_once(context)
    after = (
        _published_tree_digest(context.attempt_root, "notarization attempt tree"),
        _published_tree_digest(context.final_root, "published candidate tree"),
    )
    if after != before:
        raise TransactionError(
            "published_candidate_changed",
            "published notarization evidence changed during read-only validation",
        )
    return evidence


def self_check() -> None:
    if TOOLCHAIN_METADATA_KEYS != set(TOOLCHAIN_METADATA_ORDER):
        raise TransactionError("self_check_failed", "toolchain metadata contract drifted")
    if MAX_FINALIZATION_RUNS != 8:
        raise TransactionError(
            "self_check_failed",
            "finalization run quota contract drifted",
        )
    if MAX_FINALIZATION_RUNS_BYTES != 4 * 1024 * 1024 * 1024:
        raise TransactionError(
            "self_check_failed",
            "finalization logical-byte quota contract drifted",
        )
    if RENAME_EXCL != 0x00000004:
        raise TransactionError("self_check_failed", "RENAME_EXCL constant drifted")
    if RENAME_NOFOLLOW_ANY != 0x00000010:
        raise TransactionError("self_check_failed", "RENAME_NOFOLLOW_ANY constant drifted")
    print("notarization transaction self-check ok")


def _metadata(arguments: argparse.Namespace) -> dict[str, str]:
    return {
        "goModuleCacheTreeSha256": arguments.go_module_cache_tree_sha256,
        "goToolchainTreeSha256": arguments.go_toolchain_tree_sha256,
        "goToolsTreeSha256": arguments.go_tools_tree_sha256,
        "nodeToolchainTreeSha256": arguments.node_toolchain_tree_sha256,
        "tauriToolchainTreeSha256": arguments.tauri_toolchain_tree_sha256,
        "toolchainSha256": arguments.toolchain_sha256,
        "uiDependenciesTreeSha256": arguments.ui_dependencies_tree_sha256,
        "xcodegenToolchainTreeSha256": arguments.xcodegen_toolchain_tree_sha256,
    }


def main() -> None:
    if sys.argv[1:] == ["--self-check"]:
        self_check()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-kind", choices=("validation", "release"), required=True)
    parser.add_argument("--build-number", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged-app", type=Path)
    mode.add_argument("--recover-submission-id")
    parser.add_argument("--artifact-repository", type=Path)
    parser.add_argument("--toolchain-root", type=Path)
    parser.add_argument("--native-products", type=Path, required=True)
    parser.add_argument("--notary-profile", required=True)
    parser.add_argument("--repository-commit", required=True)
    parser.add_argument("--release-source-sha256", required=True)
    parser.add_argument("--deployment-target", required=True)
    parser.add_argument("--go-module-cache-tree-sha256", required=True)
    parser.add_argument("--go-toolchain-tree-sha256", required=True)
    parser.add_argument("--go-tools-tree-sha256", required=True)
    parser.add_argument("--node-toolchain-tree-sha256", required=True)
    parser.add_argument("--tauri-toolchain-tree-sha256", required=True)
    parser.add_argument("--toolchain-sha256", required=True)
    parser.add_argument("--ui-dependencies-tree-sha256", required=True)
    parser.add_argument("--xcodegen-toolchain-tree-sha256", required=True)
    arguments = parser.parse_args()
    recovery_tool_repository = Path(__file__).resolve().parent.parent
    if arguments.recover_submission_id is None:
        if arguments.artifact_repository is not None:
            parser.error("--artifact-repository is only valid with recovery")
        if arguments.toolchain_root is not None:
            parser.error("--toolchain-root is only valid with recovery")
        repository = recovery_tool_repository
    else:
        if arguments.artifact_repository is None:
            parser.error("recovery requires --artifact-repository")
        if arguments.toolchain_root is None:
            parser.error("recovery requires --toolchain-root")
        try:
            toolchain_root = arguments.toolchain_root
            if (
                not toolchain_root.is_absolute()
                or toolchain_root.is_symlink()
                or toolchain_root.resolve(strict=True) != toolchain_root
            ):
                raise OSError("unsafe toolchain root")
            _require_real_directory(toolchain_root, trusted=True)
        except (OSError, TransactionError):
            parser.error("--toolchain-root must be an absolute real directory")
        os.environ["CFW_TOOLCHAIN_ROOT"] = str(toolchain_root)
        repository = arguments.artifact_repository
    context = TransactionContext(
        repository=repository,
        build_kind=arguments.build_kind,
        build_number=arguments.build_number,
        staged_app=arguments.staged_app,
        native_products=arguments.native_products,
        notary_profile=arguments.notary_profile,
        repository_commit=arguments.repository_commit,
        release_source_sha256=arguments.release_source_sha256,
        deployment_target=arguments.deployment_target,
        toolchain_metadata=_metadata(arguments),
    )
    try:
        if arguments.recover_submission_id is None:
            app = execute_transaction(context)
        else:
            app = recover_transaction(
                context,
                arguments.recover_submission_id,
                recovery_tool_repository,
            )
    except (OSError, TransactionError, ValueError) as error:
        code = error.code if isinstance(error, TransactionError) else "unexpected_error"
        raise SystemExit(f"error: notarization transaction [{code}]: {error}") from error
    print(f"notarization transaction published: {app.relative_to(repository)}")


if __name__ == "__main__":
    main()
