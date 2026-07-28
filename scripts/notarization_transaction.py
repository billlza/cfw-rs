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
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
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
    from .repository_source_identity import current_identity
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
    from repository_source_identity import current_identity
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
SUBMISSION_DOCUMENT = "cfw-notarization-submission-receipt-v2"
SUBMISSION_OBSERVATION_DOCUMENT = "cfw-notarization-submission-observation-v1"
RECEIPT_DOCUMENT = "cfw-notarization-publish-ready-receipt-v2"
RECOVERY_DOCUMENT = "cfw-notarization-recovery-intent-v1"
RENAME_EXCL = 0x00000004
RENAME_NOFOLLOW_ANY = 0x00000010
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_EVENT_DOCUMENTS = 4096
RECOVERY_SUCCESS_EVENT_RESERVE = 12
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
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
    recovery_tool_repository: Path | None
    recovery_tool_identity: dict[str, str] | None
    recovery_tool_identity_reader: SourceIdentityReader | None


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
    core = capture_gatekeeper(
        app,
        "execute",
        primary_signature_context=False,
    )
    return validate_gatekeeper_evidence(
        {
            **core,
            "target_signed_app_tree_sha256": tree_sha256,
            "captured_at": _utc_now(),
        }
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
        if not names or names != [
            f"{sequence:08d}.json" for sequence in range(1, len(names) + 1)
        ] or len(names) > MAX_EVENT_DOCUMENTS:
            raise TransactionError(
                "event_journal_identity_drift",
                "notarization event journal inventory is not contiguous",
            )
        journal = cls(directory, intent_sha256, clock)
        previous_sha256: str | None = None
        for sequence, name in enumerate(names, start=1):
            path = directory / name
            data = _read_regular_bytes(path)
            value = _decode_json_bytes(data, path)
            if not isinstance(value, dict) or set(value) != EVENT_FIELDS:
                raise TransactionError(
                    "event_journal_identity_drift",
                    "notarization event has an unexpected field set",
                )
            if data != _canonical_json(value).encode("utf-8"):
                raise TransactionError(
                    "event_journal_identity_drift",
                    "notarization event is not canonical JSON",
                )
            if (
                value["schema_version"] != 1
                or isinstance(value["schema_version"], bool)
                or value["document"] != EVENT_DOCUMENT
                or value["sequence"] != sequence
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
            previous_sha256 = hashlib.sha256(data).hexdigest()
            journal.sequence = sequence
            journal.previous_event_sha256 = previous_sha256
            journal.documents.append(value)
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
    ) -> None:
        next_sequence = self.sequence + 1
        if next_sequence > MAX_EVENT_DOCUMENTS:
            raise TransactionError(
                "event_journal_capacity_exceeded",
                "notarization event journal reached its bounded capacity",
            )
        document = {
            "schema_version": 1,
            "document": EVENT_DOCUMENT,
            "sequence": next_sequence,
            "previous_event_sha256": self.previous_event_sha256,
            "intent_sha256": self.intent_sha256,
            "state": state,
            "recorded_at": self.clock() if recorded_at is None else recorded_at,
            "submission_id": submission_id,
            "failure_code": failure_code,
            "exit_code": exit_code,
        }
        path = self.directory / f"{next_sequence:08d}.json"
        _write_json_exclusive(path, document)
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
        for sequence, expected in enumerate(self.documents, start=1):
            if (
                expected["sequence"] != sequence
                or expected["previous_event_sha256"] != previous_sha256
                or expected["intent_sha256"] != self.intent_sha256
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
        if not (
            (context.attempt_root / "work").is_dir()
            or (context.attempt_root / "recovery-source").is_dir()
            or (context.attempt_root / "publish-ready").is_dir()
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
    if os.path.lexists(context.final_root):
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
        value["schema_version"] != 1
        or isinstance(value["schema_version"], bool)
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


def _require_recoverable_event_prefix(
    journal: EventJournal,
) -> tuple[datetime, datetime, str, int, str | None, bool, bool]:
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
        if fifth is None or fifth["state"] in {
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
    return (
        timestamps[2],
        timestamps[-1],
        _sha256_file(base_event_path),
        recovery_event_start,
        outcome_submission_id,
        submitted_receipt_expected,
        direct_evidence_required,
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
        "recovery-intent.json",
        "recovery-source",
        "submission-observation.json",
        "submission-receipt.json",
        "work",
    }
    observed_attempt_entries = {
        path.name for path in context.attempt_root.iterdir()
    }
    source_names = observed_attempt_entries & {"work", "recovery-source"}
    if (
        not {"events", "intent.json"}.issubset(observed_attempt_entries)
        or len(source_names) != 1
        or not observed_attempt_entries <= allowed_attempt_entries
    ):
        raise TransactionError(
            "recovery_inventory_mismatch",
            "notarization attempt inventory is not recoverable",
        )
    work = context.attempt_root / next(iter(source_names))
    _require_real_directory(work, private=True)
    finalization_runs = context.attempt_root / "finalization-runs"
    if os.path.lexists(finalization_runs):
        _require_real_directory(finalization_runs, private=True)
        run_entries = list(finalization_runs.iterdir())
        if len(run_entries) > MAX_EVENT_DOCUMENTS:
            raise TransactionError(
                "recovery_inventory_mismatch",
                "too many retained recovery finalization workspaces",
            )
        for run_entry in run_entries:
            try:
                _canonical_uuid(run_entry.name, "finalization run id")
                _require_real_directory(run_entry, private=True)
            except TransactionError as error:
                raise TransactionError(
                    "recovery_inventory_mismatch",
                    "recovery finalization workspace inventory is malformed",
                ) from error
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
    (
        submit_window_start,
        submit_window_end,
        prior_event_sha256,
        recovery_event_start,
        outcome_submission_id,
        submitted_receipt_expected,
        direct_evidence_required,
    ) = (
        _require_recoverable_event_prefix(journal)
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
            or observation["schema_version"] != 1
            or isinstance(observation["schema_version"], bool)
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
    if os.path.lexists(submission_receipt_path):
        receipt_data = _read_regular_bytes(submission_receipt_path)
        receipt = _decode_json_bytes(receipt_data, submission_receipt_path)
        if (
            not isinstance(receipt, dict)
            or set(receipt) != SUBMISSION_RECEIPT_FIELDS
            or receipt_data != _canonical_json(receipt).encode("utf-8")
            or receipt["schema_version"] != 2
            or isinstance(receipt["schema_version"], bool)
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
    elif submitted_receipt_expected:
        raise TransactionError(
            "submission_receipt_missing",
            "submitted event lacks its immutable submission receipt",
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
        validated_gatekeeper = validate_gatekeeper_evidence(persisted_gatekeeper)
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
        or receipt["schema_version"] != 2
        or isinstance(receipt["schema_version"], bool)
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
        gatekeeper = validate_gatekeeper_evidence(
            gatekeeper_capture(work_app, post_staple_app_sha256)
        )
    except Exception as error:
        raise TransactionError(
            "gatekeeper_verification_failed", "Gatekeeper did not accept the stapled app"
        ) from error
    if gatekeeper["target_signed_app_tree_sha256"] != post_staple_app_sha256:
        raise TransactionError(
            "gatekeeper_target_mismatch",
            "Gatekeeper evidence is not bound to the exact stapled app tree",
        )
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
    _require_submission_acquisition_evidence(prepared)
    sealed_intent, sealed_intent_sha256 = _read_exact_json_document(
        intent_path,
        intent,
        drift_code="notarization_intent_identity_drift",
        drift_message="notarization intent differs from this transaction",
    )
    if sealed_intent != intent or sealed_intent_sha256 != intent_sha256:
        raise TransactionError(
            "notarization_intent_identity_drift",
            "notarization intent differs from this transaction",
        )
    _, sealed_submission_receipt_sha256 = _read_exact_json_document(
        submission_receipt_path,
        submission_receipt,
        drift_code="submission_receipt_identity_drift",
        drift_message="Apple submission receipt differs from this transaction",
    )
    sealed_recovery_intent_sha256: str | None = None
    if prepared.recovery_intent is not None:
        if prepared.recovery_intent_path is None:
            raise TransactionError(
                "recovery_intent_identity_drift",
                "recovery intent path is missing",
            )
        _, sealed_recovery_intent_sha256 = _read_exact_json_document(
            prepared.recovery_intent_path,
            prepared.recovery_intent,
            drift_code="recovery_intent_identity_drift",
            drift_message="recovery intent differs from this transaction",
        )
    sealed_evidence = _require_exact_persisted_evidence(
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
    preseal_event_sha256 = journal.verify()
    receipt = {
        "schema_version": 2,
        "document": RECEIPT_DOCUMENT,
        "attempt_id": attempt_id,
        "submission_id": submission_id,
        "intent_sha256": intent_sha256,
        "preseal_event_sha256": preseal_event_sha256,
        "submission_receipt_sha256": sealed_submission_receipt_sha256,
        "recovery_intent_sha256": sealed_recovery_intent_sha256,
        "accepted_notary_log_sha256": sealed_evidence.notary_log_sha256,
        "notarization_result_sha256": sealed_evidence.notarization_sha256,
        "archive_sha256": archive_sha256,
        "pre_staple_app_tree_sha256": pre_staple_app_sha256,
        "post_staple_app_tree_sha256": post_staple_app_sha256,
        "gatekeeper_evidence_sha256": sealed_evidence.gatekeeper_sha256,
        "app_manifest_sha256": _sha256_file(app_manifest),
        "archive_manifest_sha256": _sha256_file(final_archive_manifest),
        "state": "publish-ready",
        "sealed_at": sealed_at,
    }
    receipt_path = finalization_root / "receipt.json"
    _write_json_exclusive(receipt_path, receipt)
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
    final_static_bindings = {
        "submission_receipt_sha256": final_submission_receipt_sha256,
        "recovery_intent_sha256": final_recovery_intent_sha256,
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
    try:
        publisher(publish_ready, context.final_root)
    except TransactionError:
        raise
    except Exception as error:
        raise TransactionError(
            "atomic_publish_failed", "exclusive atomic publication failed"
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
        data = _read_regular_bytes(path)
        value = _decode_json_bytes(data, path)
        if (
            not isinstance(value, dict)
            or set(value) != RECOVERY_FIELDS
            or value.get("schema_version") != 1
            or isinstance(value.get("schema_version"), bool)
            or value.get("document") != RECOVERY_DOCUMENT
            or any(value.get(key) != expected for key, expected in static.items())
            or data != _canonical_json(value).encode("utf-8")
        ):
            raise TransactionError(
                "recovery_intent_identity_drift",
                "recovery intent differs from the requested reconciliation",
            )
        _parse_utc_timestamp(value["requested_at"], "recovery requested_at")
        return value, path, hashlib.sha256(data).hexdigest()
    if len(attempt.journal.documents) != attempt.recovery_event_start:
        raise TransactionError(
            "recovery_intent_missing",
            "recovery events exist without their immutable recovery intent",
        )
    value = {**static, "requested_at": clock()}
    _parse_utc_timestamp(value["requested_at"], "recovery requested_at")
    _write_json_exclusive(path, value)
    return value, path, _sha256_file(path)


def _require_recovery_event_suffix(
    attempt: RecoverableAttempt,
    submission_id: str,
) -> bool:
    suffix = attempt.journal.documents[attempt.recovery_event_start:]
    index = 0

    def require_submission(event: dict[str, Any]) -> None:
        if event["submission_id"] != submission_id:
            raise TransactionError(
                "recovery_state_unsupported",
                "recovery journal contains a different submission id",
            )

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
            return False
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
        return False

    if index == 0 or suffix[index - 1]["state"] != "submission_reconciled":
        raise TransactionError(
            "recovery_state_unsupported",
            "notarization journal has not reached a reconciled submission",
        )

    finalization_active = False
    next_finalization_state = 0
    while index < len(suffix):
        event = suffix[index]
        require_submission(event)
        state = event["state"]
        if state == "finalization_started":
            if (
                event["failure_code"] is not None
                or event["exit_code"] is not None
            ):
                raise TransactionError(
                    "recovery_state_unsupported",
                    "finalization_started contains terminal fields",
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
        index += 1
    return True


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


def _prepare_recovery_finalization_work(
    attempt: RecoverableAttempt,
    *,
    manifest_verifier: ManifestVerifier,
) -> tuple[Path, Path, Path, Path]:
    source = attempt.context.attempt_root / "recovery-source"
    if attempt.work.name == "work":
        if os.path.lexists(source):
            raise TransactionError(
                "recovery_source_collision",
                "immutable recovery source already exists beside the original work",
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
    _require_real_directory(source, private=True)
    source_app = source / "Clash for Mac.app"
    source_archive = source / attempt.context.archive_name
    source_manifest = source / f"{attempt.context.archive_name}.manifest.json"
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

    finalization_runs = attempt.context.attempt_root / "finalization-runs"
    _mkdir_private(finalization_runs, exclusive=False)
    run_id = str(uuid.uuid4())
    run_root = finalization_runs / run_id
    _mkdir_private(run_root, exclusive=True)
    run_work = run_root / "work"
    try:
        shutil.copytree(
            source,
            run_work,
            symlinks=True,
            copy_function=shutil.copy2,
        )
    except (OSError, shutil.Error) as error:
        raise TransactionError(
            "recovery_workspace_copy_failed",
            "cannot create an isolated recovery finalization workspace",
        ) from error
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
        already_reconciled = _require_recovery_event_suffix(
            attempt,
            submission_id,
        )
        if already_reconciled and attempt.existing_submission_receipt is None:
            raise TransactionError(
                "submission_receipt_missing",
                "reconciled recovery event lacks its immutable submission receipt",
            )
        required_events = 10 if already_reconciled else RECOVERY_SUCCESS_EVENT_RESERVE
        if attempt.journal.sequence + required_events > MAX_EVENT_DOCUMENTS:
            raise TransactionError(
                "event_journal_capacity_exceeded",
                "notarization journal lacks capacity for atomic recovery finalization",
            )
        if not already_reconciled:
            attempt.journal.append(
                "reconciliation_started",
                submission_id=submission_id,
            )
        try:
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

        try:
            attempt.journal.append(
                "finalization_started",
                submission_id=submission_id,
            )
            (
                finalization_work,
                finalization_app,
                finalization_archive,
                finalization_archive_manifest,
            ) = _prepare_recovery_finalization_work(
                attempt,
                manifest_verifier=manifest_verifier,
            )
            prepared = PreparedAttempt(
                context=context,
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
                accepted_raw_log=raw_log,
            )
        except Exception as error:
            if isinstance(error, TransactionError):
                terminal_state = error.terminal_state
                failure_code = error.code
                exit_code = error.exit_code
            else:
                terminal_state = "failed"
                failure_code = "internal_error"
                exit_code = None
            attempt.journal.append(
                terminal_state,
                submission_id=submission_id,
                failure_code=failure_code,
                exit_code=exit_code,
            )
            raise


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
        prepared = PreparedAttempt(
            context=context,
            work=work,
            work_app=work_app,
            archive=archive,
            archive_manifest=archive_manifest,
            archive_metadata=archive_metadata,
            archive_sha256=archive_sha256,
            archive_size=archive_size,
            pre_staple_app_sha256=pre_staple_app_sha256,
            attempt_id=attempt_id,
            intent=intent,
            intent_path=intent_path,
            intent_sha256=intent_sha256,
            submission_id=submission_id,
            submission_receipt=submission_receipt,
            submission_receipt_path=submission_receipt_path,
            recovery_intent=None,
            recovery_intent_path=None,
            recovery_tool_repository=None,
            recovery_tool_identity=None,
            recovery_tool_identity_reader=None,
        )
        return _finalize_accepted_submission(
            prepared,
            journal=journal,
            command_runner=command_runner,
            gatekeeper_capture=gatekeeper_capture,
            manifest_writer=manifest_writer,
            manifest_verifier=manifest_verifier,
            source_identity_reader=source_identity_reader,
            toolchain_metadata_reader=toolchain_metadata_reader,
            publisher=publisher,
            clock=clock,
        )
    except Exception as error:
        if journal is not None:
            if isinstance(error, TransactionError):
                terminal_state = error.terminal_state
                failure_code = error.code
                exit_code = error.exit_code
            else:
                terminal_state = "failed"
                failure_code = "internal_error"
                exit_code = None
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


def self_check() -> None:
    if TOOLCHAIN_METADATA_KEYS != set(TOOLCHAIN_METADATA_ORDER):
        raise TransactionError("self_check_failed", "toolchain metadata contract drifted")
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
