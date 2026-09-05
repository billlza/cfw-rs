#!/usr/bin/env python3
"""Notarize one exact DMG with durable, same-submission recovery.

This is a deliberately small adapter over the canonical notarization protocol,
event journal, private-file, bounded-runner, and exclusive-publication
primitives in ``notarization_transaction``.  It does not implement another app
build transaction.  It only owns the DMG identity and the irreversible Apple
submission boundary that the packaging shell cannot recover safely.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any, Callable
import uuid

if not __package__:
    # Isolated mode deliberately removes the script directory from sys.path.
    # Re-add only this file's resolved repository and sibling directory. The
    # shared freeze callback must use the same scripts.* module identity as
    # the stage contract; sibling imports retain the existing direct entrypoint.
    _SCRIPT_DIRECTORY = Path(__file__).resolve().parent
    if _SCRIPT_DIRECTORY.name != "scripts":
        raise RuntimeError("DMG transaction is not located in the reviewed scripts directory")
    sys.path.insert(0, str(_SCRIPT_DIRECTORY))
    sys.path.insert(0, str(_SCRIPT_DIRECTORY.parent))

if __package__:
    from .candidate_freeze import (
        CandidateFreezeError,
        frozen_candidate_verification_session,
    )
    from .gatekeeper_assessment import (
        GatekeeperEvidenceError,
        capture as capture_gatekeeper,
        validate_evidence as validate_gatekeeper_evidence,
    )
    from .notarization_transaction import (
        CommandResult,
        CommandRole,
        EventJournal,
        NOTARY_PROFILE,
        TransactionError,
        _canonical_json,
        _capture_command_result,
        confirm_published_tree_durable,
        _decode_json_bytes,
        _exclusive_attempt_recovery_lock,
        _fsync_directory,
        _fsync_tree,
        _hash_regular_file,
        _mkdir_private,
        _parse_notary_info_response,
        _parse_notary_submit_response,
        _parse_notary_wait_response,
        _parse_utc_timestamp,
        _project_notary_submit_identity,
        _read_exact_json_document,
        _read_regular_bytes,
        _require_empty_notary_stderr,
        _require_real_directory,
        _require_unique_history_binding,
        _result_or_error,
        _timestamp_within_recorded_window,
        _write_json_exclusive,
        production_command_runner,
        publish_exclusive,
    )
    from .publication.common import PublicationError, copy_regular_new
    from .publication.ga_release_contract import verify_prepackage_authorization
    from .release_artifact_set import (
        ArtifactSetError,
        DMG_SUBMISSION_DOCUMENT,
        MAX_DMG_BYTES,
        MAX_PUBLICATION_DOCUMENT_BYTES,
        PackagedAppManifestReader,
        PrepackageStageVerifier,
        read_dmg_app_manifest,
        seal_dmg_set,
        verify_dmg_set,
    )
    from .repository_source_identity import SourceIdentityError, current_identity
    from .release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
    from .verify_notary_log import NotaryLogError, validate_documents
else:
    from scripts.candidate_freeze import (
        CandidateFreezeError,
        frozen_candidate_verification_session,
    )
    from gatekeeper_assessment import (
        GatekeeperEvidenceError,
        capture as capture_gatekeeper,
        validate_evidence as validate_gatekeeper_evidence,
    )
    from notarization_transaction import (
        CommandResult,
        CommandRole,
        EventJournal,
        NOTARY_PROFILE,
        TransactionError,
        _canonical_json,
        _capture_command_result,
        confirm_published_tree_durable,
        _decode_json_bytes,
        _exclusive_attempt_recovery_lock,
        _fsync_directory,
        _fsync_tree,
        _hash_regular_file,
        _mkdir_private,
        _parse_notary_info_response,
        _parse_notary_submit_response,
        _parse_notary_wait_response,
        _parse_utc_timestamp,
        _project_notary_submit_identity,
        _read_exact_json_document,
        _read_regular_bytes,
        _require_empty_notary_stderr,
        _require_real_directory,
        _require_unique_history_binding,
        _result_or_error,
        _timestamp_within_recorded_window,
        _write_json_exclusive,
        production_command_runner,
        publish_exclusive,
    )
    from publication.common import PublicationError, copy_regular_new
    from publication.ga_release_contract import verify_prepackage_authorization
    from release_artifact_set import (
        ArtifactSetError,
        DMG_SUBMISSION_DOCUMENT,
        MAX_DMG_BYTES,
        MAX_PUBLICATION_DOCUMENT_BYTES,
        PackagedAppManifestReader,
        PrepackageStageVerifier,
        read_dmg_app_manifest,
        seal_dmg_set,
        verify_dmg_set,
    )
    from repository_source_identity import SourceIdentityError, current_identity
    from release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
    from verify_notary_log import NotaryLogError, validate_documents


EXPECTED_TEAM_ID = "YKUPL7Z869"
_XCRUN = "/usr/bin/xcrun"
INTENT_DOCUMENT = "cfw-dmg-notarization-intent-v3"
OBSERVATION_DOCUMENT = "cfw-dmg-notarization-submission-observation-v1"
MAX_DMG_EVENTS = 64
MAX_RECOVERY_RUNS = 8
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
STAPLE_PENDING_DIRECTORY = "staple-pending"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
INTENT_FIELDS = {
    "attempt_id",
    "build_number",
    "dmg_name",
    "dmg_sha256",
    "dmg_size",
    "document",
    "notary_profile",
    "prepared_at",
    "prepackage",
    "release_source_sha256",
    "repository_commit",
    "schema_version",
    "submit_not_after",
    "submit_not_before",
    "team_id",
    "version",
}
OBSERVATION_FIELDS = {
    "attempt_id",
    "document",
    "dmg_name",
    "dmg_sha256",
    "intent_sha256",
    "observed_at",
    "schema_version",
    "submission_id",
}
SUBMISSION_FIELDS = {
    "acquisition",
    "attempt_id",
    "build_number",
    "document",
    "intent_sha256",
    "notary_created_at",
    "notary_profile",
    "observed_at",
    "pre_staple_dmg_sha256",
    "schema_version",
    "submission_id",
    "submitted_filename",
    "version",
}
ALLOWED_STATES = {
    "accepted",
    "artifact_verified",
    "finalization_deferred",
    "gatekeeper_verified",
    "log_verified",
    "outcome_unknown",
    "prepared",
    "publication_deferred",
    "published",
    "recovering",
    "recovery_deferred",
    "rejected",
    "sealed",
    "stapled",
    "stapling",
    "submission_observed",
    "submitting",
    "waiting",
}
TRANSITIONS = {
    None: {"prepared"},
    "prepared": {"submitting"},
    "submitting": {"outcome_unknown", "recovering", "submission_observed"},
    "submission_observed": {"outcome_unknown", "recovering", "waiting"},
    "waiting": {"accepted", "outcome_unknown", "recovering", "rejected"},
    "outcome_unknown": {"recovering"},
    "recovery_deferred": {"recovering"},
    "finalization_deferred": {"recovering"},
    "publication_deferred": {"published", "recovering"},
    "recovering": {"accepted", "recovery_deferred", "rejected"},
    "accepted": {"finalization_deferred", "log_verified", "recovering"},
    "log_verified": {"finalization_deferred", "recovering", "stapling"},
    "stapling": {"finalization_deferred", "recovering", "stapled"},
    "stapled": {"finalization_deferred", "gatekeeper_verified", "recovering"},
    "gatekeeper_verified": {
        "artifact_verified",
        "finalization_deferred",
        "recovering",
    },
    "artifact_verified": {"finalization_deferred", "recovering", "sealed"},
    "sealed": {
        "finalization_deferred",
        "publication_deferred",
        "published",
        "recovering",
    },
    "published": set(),
    "rejected": set(),
}


class DmgCommandRole(Enum):
    DMG_VERIFY = "dmg-verify"


Runner = Callable[[Enum, list[str], float], CommandResult]
Clock = Callable[[], str]
GatekeeperCapture = Callable[[Path, str], dict[str, Any]]
Publisher = Callable[[Path, Path], None]
SourceIdentityReader = Callable[[Path], dict[str, str]]


@dataclass(frozen=True)
class DmgContext:
    repository: Path
    version: str
    build_number: str
    notary_profile: str
    source_identity: dict[str, str]
    staged_dmg: Path | None = None

    @property
    def dmg_name(self) -> str:
        return f"Clash.for.Mac_{self.version}_arm64.dmg"

    @property
    def ga_candidate_root(self) -> Path:
        return ga_root(self.repository)

    @property
    def package_root(self) -> Path:
        return self.ga_candidate_root / "packages"

    @property
    def transaction_root(self) -> Path:
        return self.ga_candidate_root / "transactions/dmg-notary"

    @property
    def attempt_root(self) -> Path:
        return self.transaction_root / f"v{ACTIVE_RELEASE_IDENTITY.product_version}"

    @property
    def final_root(self) -> Path:
        return self.package_root / "dmg" / f"v{ACTIVE_RELEASE_IDENTITY.product_version}"


@dataclass
class DmgAttempt:
    context: DmgContext
    intent: dict[str, Any]
    intent_sha256: str
    journal: EventJournal
    submission_id: str | None
    observation: dict[str, Any] | None
    submission_receipt: dict[str, Any] | None

    @property
    def dmg_path(self) -> Path:
        # This path is the immutable, exact pre-staple object submitted to
        # Apple. Stapling always operates on a disposable private copy.
        return self.context.attempt_root / self.context.dmg_name

    @property
    def staple_pending_root(self) -> Path:
        return self.context.attempt_root / STAPLE_PENDING_DIRECTORY

    @property
    def staple_pending_dmg(self) -> Path:
        return self.staple_pending_root / self.context.dmg_name


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


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


def _dmg_identity(path: Path) -> tuple[str, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise TransactionError("unsafe_dmg", "cannot inspect the transaction DMG") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise TransactionError(
            "unsafe_dmg", "transaction DMG must be a single-link regular file"
        )
    if metadata.st_size <= 0 or metadata.st_size > MAX_DMG_BYTES:
        raise TransactionError(
            "invalid_dmg_size", f"DMG size must be within 1..={MAX_DMG_BYTES} bytes"
        )
    digest, size = _hash_regular_file(path)
    if size != metadata.st_size:
        raise TransactionError("dmg_identity_drift", "DMG changed while hashing")
    return digest, size


def _make_submitted_dmg_read_only(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
            ):
                raise TransactionError(
                    "unsafe_dmg", "submitted DMG is not a private regular file"
                )
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise TransactionError(
            "submitted_dmg_protection_failed",
            "cannot protect the immutable pre-staple DMG",
        ) from error
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        raise TransactionError(
            "submitted_dmg_protection_failed",
            "immutable pre-staple DMG mode or ownership differs",
        )


def _submitted_dmg_identity(path: Path) -> tuple[str, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise TransactionError(
            "submitted_dmg_missing", "immutable pre-staple DMG is unavailable"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        raise TransactionError(
            "submitted_dmg_identity_drift",
            "immutable pre-staple DMG mode or ownership changed",
        )
    return _dmg_identity(path)


def _validate_context(context: DmgContext, *, initial: bool) -> None:
    if not context.repository.is_absolute():
        raise TransactionError("unsafe_repository", "repository path must be absolute")
    for path, label in (
        (context.repository, "repository"),
        (context.ga_candidate_root, "GA candidate root"),
        (context.package_root, "GA package root"),
        (context.transaction_root, "transaction root"),
    ):
        if path.resolve(strict=False) != path:
            raise TransactionError(
                "unsafe_canonical_path", f"{label} path is not canonical"
            )
    if context.version != ACTIVE_RELEASE_IDENTITY.product_version:
        raise TransactionError(
            "invalid_version",
            "DMG transaction is fixed to the active GA product version",
        )
    if context.build_number != ACTIVE_RELEASE_IDENTITY.ga_build:
        raise TransactionError(
            "invalid_build_number",
            "DMG transaction is fixed to the active GA build number",
        )
    if context.notary_profile != NOTARY_PROFILE:
        raise TransactionError(
            "invalid_notary_profile",
            f"notary profile must be exactly {NOTARY_PROFILE}",
        )
    if set(context.source_identity) != {"repositoryCommit", "releaseSourceSha256"}:
        raise TransactionError("source_identity_invalid", "release source identity is incomplete")
    if not COMMIT_RE.fullmatch(context.source_identity["repositoryCommit"]):
        raise TransactionError("source_identity_invalid", "repository commit is malformed")
    if not SHA256_RE.fullmatch(context.source_identity["releaseSourceSha256"]):
        raise TransactionError("source_identity_invalid", "release source digest is malformed")
    _require_real_directory(context.repository, trusted=True)
    _require_real_directory(context.ga_candidate_root, trusted=True)
    _require_real_directory(context.package_root, trusted=True)
    _require_real_directory(context.final_root.parent, trusted=True)
    if initial:
        if context.staged_dmg is None or not context.staged_dmg.is_absolute():
            raise TransactionError("unsafe_dmg_path", "staged DMG path must be absolute")
        if context.staged_dmg.resolve(strict=False) != context.staged_dmg:
            raise TransactionError("unsafe_dmg_path", "staged DMG path is not canonical")
        if context.staged_dmg.name != context.dmg_name:
            raise TransactionError("dmg_name_mismatch", "staged DMG has the wrong release filename")
        if (
            context.staged_dmg.parent.parent != context.final_root.parent
            or not context.staged_dmg.parent.name.startswith("dmg-stage.")
            or context.staged_dmg.parent.name == "dmg-stage."
        ):
            raise TransactionError(
                "unsafe_dmg_path",
                "staged DMG must be inside the fixed GA DMG staging root",
            )
        _dmg_identity(context.staged_dmg)


def _require_source_identity(
    context: DmgContext, reader: SourceIdentityReader
) -> None:
    try:
        observed = reader(context.repository)
    except Exception as error:
        raise TransactionError(
            "source_identity_unavailable",
            "cannot derive the release source identity",
        ) from error
    if observed != context.source_identity:
        raise TransactionError(
            "source_identity_drift", "release source identity changed during DMG notarization"
        )


def _validate_prepackage_reference(
    context: DmgContext, value: object
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"manifest", "manifest_path"}:
        raise TransactionError(
            "prepackage_identity_drift",
            "DMG prepackage binding has an unexpected field set",
        )
    expected_path = context.ga_candidate_root / "prepackage/manifest.json"
    if value["manifest_path"] != str(expected_path.relative_to(context.repository)):
        raise TransactionError(
            "prepackage_identity_drift",
            "DMG prepackage binding uses a noncanonical path",
        )
    manifest = value["manifest"]
    if not isinstance(manifest, dict) or set(manifest) != {
        "filename",
        "sha256",
        "size",
    }:
        raise TransactionError(
            "prepackage_identity_drift",
            "DMG prepackage manifest binding has an unexpected field set",
        )
    if (
        manifest["filename"] != "manifest.json"
        or not isinstance(manifest["sha256"], str)
        or not SHA256_RE.fullmatch(manifest["sha256"])
        or not isinstance(manifest["size"], int)
        or isinstance(manifest["size"], bool)
        or manifest["size"] <= 0
        or manifest["size"] > MAX_PUBLICATION_DOCUMENT_BYTES
    ):
        raise TransactionError(
            "prepackage_identity_drift",
            "DMG prepackage manifest identity is malformed",
        )
    return value


def _require_prepackage_stage(
    context: DmgContext,
    verifier: PrepackageStageVerifier,
    *,
    expected: object | None = None,
) -> dict[str, Any]:
    try:
        observed = _validate_prepackage_reference(
            context, verifier(context.repository)
        )
    except TransactionError:
        raise
    except (ArtifactSetError, OSError, PublicationError, ValueError) as error:
        raise TransactionError(
            "prepackage_authorization_invalid",
            "fixed GA prepackage stage authorization is invalid",
        ) from error
    if expected is not None and observed != _validate_prepackage_reference(
        context, expected
    ):
        raise TransactionError(
            "prepackage_identity_drift",
            "current GA prepackage stage differs from the DMG transaction intent",
        )
    return observed


def production_source_identity_reader(repository: Path) -> dict[str, str]:
    return current_identity(repository, require_clean=True)


def production_gatekeeper_capture(dmg: Path, digest: str) -> dict[str, Any]:
    try:
        core = capture_gatekeeper(
            dmg,
            "open",
            primary_signature_context=True,
            expected_team_id=EXPECTED_TEAM_ID,
        )
        evidence = validate_gatekeeper_evidence(
            {**core, "captured_at": _utc_now()},
            expected_assessment_type="open",
            expected_primary_signature_context=True,
            expected_target=dmg,
        )
    except (GatekeeperEvidenceError, OSError, ValueError) as error:
        raise TransactionError(
            "gatekeeper_verification_failed",
            "Gatekeeper did not accept the exact stapled DMG",
        ) from error
    if evidence["target_signed_app_tree_sha256"] != digest:
        raise TransactionError(
            "gatekeeper_target_mismatch",
            "Gatekeeper evidence targets different DMG bytes",
        )
    return evidence


def _ensure_private_roots(context: DmgContext) -> None:
    transaction_parent = context.transaction_root.parent
    if os.path.lexists(transaction_parent):
        _require_real_directory(transaction_parent, private=True)
    else:
        _mkdir_private(transaction_parent, exclusive=True)
    if os.path.lexists(context.transaction_root):
        _require_real_directory(context.transaction_root, private=True)
    else:
        _mkdir_private(context.transaction_root, exclusive=True)


def preflight_new(
    context: DmgContext,
    prepackage_stage_verifier: PrepackageStageVerifier = verify_prepackage_authorization,
) -> dict[str, Any]:
    _validate_context(context, initial=False)
    prepackage = _require_prepackage_stage(context, prepackage_stage_verifier)
    if os.path.lexists(context.final_root):
        raise TransactionError(
            "release_set_exists", "refusing to replace an existing DMG release set"
        )
    if os.path.lexists(context.attempt_root):
        raise TransactionError(
            "attempt_exists",
            "this version already has a DMG notarization attempt and must not be resubmitted",
        )
    if os.path.lexists(context.transaction_root):
        _require_real_directory(context.transaction_root, private=True)
    return prepackage


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _safe_restore_unsubmitted(
    pending: Path, original: Path, moved: Path, *, published: bool
) -> None:
    if published:
        return
    try:
        if os.path.lexists(moved) and not os.path.lexists(original):
            os.chmod(moved, 0o600, follow_symlinks=False)
            os.rename(moved, original)
            _fsync_directory(original.parent)
        if os.path.lexists(pending):
            shutil.rmtree(pending)
            _fsync_directory(pending.parent)
    except OSError as error:
        raise TransactionError(
            "pre_submission_cleanup_failed",
            "could not restore the confirmed-unsubmitted DMG",
        ) from error


def _prepare_attempt(
    context: DmgContext,
    *,
    clock: Clock,
    attempt_id_factory: Callable[[], str],
    publisher: Publisher,
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> DmgAttempt:
    if context.staged_dmg is None:
        raise TransactionError("missing_dmg", "initial transaction has no staged DMG")
    prepackage = preflight_new(context, prepackage_stage_verifier)
    _ensure_private_roots(context)
    pending = context.transaction_root / (
        f".v{context.version}.pending-{_canonical_uuid(attempt_id_factory(), 'attempt id')}"
    )
    _mkdir_private(pending, exclusive=True)
    events = pending / "events"
    _mkdir_private(events, exclusive=True)
    moved = pending / context.dmg_name
    published = False
    try:
        before_digest, before_size = _dmg_identity(context.staged_dmg)
        os.rename(context.staged_dmg, moved)
        _fsync_directory(context.staged_dmg.parent)
        _fsync_directory(pending)
        _make_submitted_dmg_read_only(moved)
        after_digest, after_size = _submitted_dmg_identity(moved)
        if (after_digest, after_size) != (before_digest, before_size):
            raise TransactionError("dmg_identity_drift", "DMG changed while entering the transaction")
        prepared_at = clock()
        _, prepared = _parse_utc_timestamp(prepared_at, "DMG prepared_at")
        submit_not_after = _format_timestamp(prepared + timedelta(minutes=30))
        # The pending name includes UUID hyphens; derive the exact final 36 bytes.
        attempt_id = pending.name[-36:]
        _canonical_uuid(attempt_id, "attempt id")
        intent = {
            "attempt_id": attempt_id,
            "build_number": context.build_number,
            "dmg_name": context.dmg_name,
            "dmg_sha256": after_digest,
            "dmg_size": after_size,
            "document": INTENT_DOCUMENT,
            "notary_profile": context.notary_profile,
            "prepared_at": prepared_at,
            "prepackage": prepackage,
            "release_source_sha256": context.source_identity["releaseSourceSha256"],
            "repository_commit": context.source_identity["repositoryCommit"],
            "schema_version": 3,
            "submit_not_after": submit_not_after,
            "submit_not_before": prepared_at,
            "team_id": EXPECTED_TEAM_ID,
            "version": context.version,
        }
        intent_path = pending / "intent.json"
        _write_json_exclusive(intent_path, intent)
        intent_sha256 = _hash_regular_file(intent_path)[0]
        journal = EventJournal(events, intent_sha256, clock)
        journal.append("prepared")
        _fsync_tree(pending)
        publisher(pending, context.attempt_root)
        published = True
    except BaseException:
        _safe_restore_unsubmitted(
            pending, context.staged_dmg, moved, published=published
        )
        raise
    return _load_attempt(context, clock=clock)


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], str]:
    data = _read_regular_bytes(path, MAX_EVIDENCE_BYTES)
    value = _decode_json_bytes(data, path)
    if not isinstance(value, dict):
        raise TransactionError("evidence_identity_drift", f"{label} is not a JSON object")
    if data != _canonical_json(value).encode("utf-8"):
        raise TransactionError("evidence_identity_drift", f"{label} is not canonical JSON")
    return value, hashlib.sha256(data).hexdigest()


def _validate_intent(context: DmgContext, value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != INTENT_FIELDS:
        raise TransactionError("intent_identity_drift", "DMG notarization intent has unexpected fields")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 3
        or value["document"] != INTENT_DOCUMENT
        or value["version"] != context.version
        or value["build_number"] != context.build_number
        or value["dmg_name"] != context.dmg_name
        or value["team_id"] != EXPECTED_TEAM_ID
        or value["notary_profile"] != NOTARY_PROFILE
        or value["notary_profile"] != context.notary_profile
        or value["repository_commit"] != context.source_identity["repositoryCommit"]
        or value["release_source_sha256"]
        != context.source_identity["releaseSourceSha256"]
    ):
        raise TransactionError("intent_identity_drift", "DMG notarization intent identity differs")
    _validate_prepackage_reference(context, value["prepackage"])
    _canonical_uuid(value["attempt_id"], "attempt id")
    if not SHA256_RE.fullmatch(value.get("dmg_sha256", "")):
        raise TransactionError("intent_identity_drift", "DMG intent digest is malformed")
    if (
        not isinstance(value["dmg_size"], int)
        or isinstance(value["dmg_size"], bool)
        or value["dmg_size"] <= 0
        or value["dmg_size"] > MAX_DMG_BYTES
    ):
        raise TransactionError("intent_identity_drift", "DMG intent size is outside its bound")
    prepared_text, prepared = _parse_utc_timestamp(value["prepared_at"], "prepared_at")
    before_text, before = _parse_utc_timestamp(
        value["submit_not_before"], "submit_not_before"
    )
    after_text, after = _parse_utc_timestamp(value["submit_not_after"], "submit_not_after")
    if prepared_text != before_text or prepared != before or after != before + timedelta(minutes=30):
        raise TransactionError("intent_identity_drift", "DMG submit window is inconsistent")
    return value


def _validate_observation(
    value: object, *, intent: dict[str, Any], intent_sha256: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != OBSERVATION_FIELDS:
        raise TransactionError(
            "submission_observation_identity_drift",
            "DMG submission observation has unexpected fields",
        )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["document"] != OBSERVATION_DOCUMENT
        or value["attempt_id"] != intent["attempt_id"]
        or value["intent_sha256"] != intent_sha256
        or value["dmg_name"] != intent["dmg_name"]
        or value["dmg_sha256"] != intent["dmg_sha256"]
    ):
        raise TransactionError(
            "submission_observation_identity_drift",
            "DMG submission observation identity differs",
        )
    _canonical_uuid(value["submission_id"], "observed submission id")
    _parse_utc_timestamp(value["observed_at"], "submission observed_at")
    return value


def _validate_submission_receipt(
    value: object, *, intent: dict[str, Any], intent_sha256: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != SUBMISSION_FIELDS:
        raise TransactionError(
            "submission_receipt_identity_drift",
            "DMG submission receipt has unexpected fields",
        )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["document"] != DMG_SUBMISSION_DOCUMENT
        or value["attempt_id"] != intent["attempt_id"]
        or value["intent_sha256"] != intent_sha256
        or value["version"] != intent["version"]
        or value["build_number"] != intent["build_number"]
        or value["submitted_filename"] != intent["dmg_name"]
        or value["pre_staple_dmg_sha256"] != intent["dmg_sha256"]
        or value["notary_profile"] != NOTARY_PROFILE
        or value["notary_profile"] != intent["notary_profile"]
        or value["acquisition"] not in {"submit-no-wait", "explicit-recovery"}
    ):
        raise TransactionError(
            "submission_receipt_identity_drift", "DMG submission receipt differs"
        )
    _canonical_uuid(value["submission_id"], "receipt submission id")
    _parse_utc_timestamp(value["observed_at"], "receipt observed_at")
    if value["acquisition"] == "explicit-recovery":
        _parse_utc_timestamp(value["notary_created_at"], "receipt notary_created_at")
    elif value["notary_created_at"] is not None:
        raise TransactionError(
            "submission_receipt_identity_drift",
            "direct receipt has an unexpected Apple creation time",
        )
    return value


def _validate_journal(journal: EventJournal) -> str:
    if not journal.documents or len(journal.documents) > MAX_DMG_EVENTS:
        raise TransactionError(
            "event_journal_capacity_exceeded", "DMG event journal is empty or oversized"
        )
    previous: str | None = None
    recovery_count = 0
    known_submission_id: str | None = None
    for event in journal.documents:
        state = event["state"]
        if state not in ALLOWED_STATES or state not in TRANSITIONS.get(previous, set()):
            raise TransactionError(
                "event_journal_identity_drift",
                f"DMG event transition is invalid: {previous!r} -> {state!r}",
            )
        event_id = event["submission_id"]
        if event_id is not None:
            if known_submission_id is None:
                known_submission_id = event_id
            elif event_id != known_submission_id:
                raise TransactionError(
                    "submission_id_mismatch", "DMG event journal contains multiple submission IDs"
                )
        if state == "recovering":
            recovery_count += 1
        previous = state
    if recovery_count > MAX_RECOVERY_RUNS:
        raise TransactionError(
            "recovery_quota_exceeded", "DMG recovery run quota is exhausted"
        )
    return previous or ""


def _load_attempt(context: DmgContext, *, clock: Clock) -> DmgAttempt:
    _validate_context(context, initial=False)
    _require_real_directory(context.transaction_root, private=True)
    _require_real_directory(context.attempt_root, private=True)
    allowed_entries = {
        context.dmg_name,
        "events",
        "final-set",
        "gatekeeper.json",
        "intent.json",
        "notarization-log.json",
        "notarization.json",
        "submission-observation.json",
        "submission-receipt.json",
        STAPLE_PENDING_DIRECTORY,
    }
    try:
        entries = {path.name: path for path in context.attempt_root.iterdir()}
    except OSError as error:
        raise TransactionError(
            "attempt_inventory_unavailable", "cannot enumerate the DMG attempt"
        ) from error
    if not set(entries).issubset(allowed_entries):
        raise TransactionError(
            "attempt_inventory_mismatch", "DMG attempt contains an unexpected entry"
        )
    for name, path in entries.items():
        metadata = path.lstat()
        if name in {"events", "final-set", STAPLE_PENDING_DIRECTORY}:
            if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
                raise TransactionError(
                    "attempt_inventory_mismatch", "DMG attempt directory entry is unsafe"
                )
        elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise TransactionError(
                "attempt_inventory_mismatch", "DMG attempt file entry is unsafe"
            )
    intent, intent_sha256 = _load_json(context.attempt_root / "intent.json", "DMG intent")
    intent = _validate_intent(context, intent)
    journal = EventJournal.load_existing(
        context.attempt_root / "events", intent_sha256, clock
    )
    _validate_journal(journal)
    observation: dict[str, Any] | None = None
    observation_path = context.attempt_root / "submission-observation.json"
    if os.path.lexists(observation_path):
        observation, _ = _load_json(observation_path, "DMG submission observation")
        observation = _validate_observation(
            observation, intent=intent, intent_sha256=intent_sha256
        )
    receipt: dict[str, Any] | None = None
    receipt_path = context.attempt_root / "submission-receipt.json"
    if os.path.lexists(receipt_path):
        receipt, _ = _load_json(receipt_path, "DMG submission receipt")
        receipt = _validate_submission_receipt(
            receipt, intent=intent, intent_sha256=intent_sha256
        )
        if receipt["acquisition"] == "submit-no-wait" and observation is None:
            raise TransactionError(
                "submission_receipt_identity_drift",
                "direct DMG submission receipt lacks its durable observation",
            )
    ids = {
        value
        for value in (
            observation and observation["submission_id"],
            receipt and receipt["submission_id"],
            *(
                event["submission_id"]
                for event in journal.documents
                if event["submission_id"] is not None
            ),
        )
        if value is not None
    }
    if len(ids) > 1:
        raise TransactionError(
            "submission_id_mismatch", "DMG transaction evidence contains multiple submission IDs"
        )
    attempt = DmgAttempt(
        context=context,
        intent=intent,
        intent_sha256=intent_sha256,
        journal=journal,
        submission_id=next(iter(ids), None),
        observation=observation,
        submission_receipt=receipt,
    )
    digest, size = _submitted_dmg_identity(attempt.dmg_path)
    if (digest, size) != (
        intent["dmg_sha256"],
        intent["dmg_size"],
    ):
        raise TransactionError(
            "submitted_dmg_identity_drift",
            "immutable pre-staple submitted DMG bytes changed",
        )
    return attempt


def _append(
    attempt: DmgAttempt,
    state: str,
    *,
    submission_id: str | None = None,
    failure_code: str | None = None,
    exit_code: int | None = None,
) -> None:
    if len(attempt.journal.documents) >= MAX_DMG_EVENTS:
        raise TransactionError(
            "event_journal_capacity_exceeded", "DMG event journal reached its bound"
        )
    attempt.journal.append(
        state,
        submission_id=submission_id,
        failure_code=failure_code,
        exit_code=exit_code,
    )
    _validate_journal(attempt.journal)


def _persist_observation(
    attempt: DmgAttempt, submission_id: str, *, clock: Clock
) -> dict[str, Any]:
    observation = {
        "attempt_id": attempt.intent["attempt_id"],
        "document": OBSERVATION_DOCUMENT,
        "dmg_name": attempt.intent["dmg_name"],
        "dmg_sha256": attempt.intent["dmg_sha256"],
        "intent_sha256": attempt.intent_sha256,
        "observed_at": clock(),
        "schema_version": 1,
        "submission_id": submission_id,
    }
    path = attempt.context.attempt_root / "submission-observation.json"
    _write_json_exclusive(path, observation)
    attempt.observation = observation
    attempt.submission_id = submission_id
    return observation


def _persist_submission_receipt(
    attempt: DmgAttempt,
    submission_id: str,
    *,
    acquisition: str,
    notary_created_at: str | None,
    clock: Clock,
) -> dict[str, Any]:
    receipt = {
        "acquisition": acquisition,
        "attempt_id": attempt.intent["attempt_id"],
        "build_number": attempt.intent["build_number"],
        "document": DMG_SUBMISSION_DOCUMENT,
        "intent_sha256": attempt.intent_sha256,
        "notary_created_at": notary_created_at,
        "notary_profile": attempt.context.notary_profile,
        "observed_at": clock(),
        "pre_staple_dmg_sha256": attempt.intent["dmg_sha256"],
        "schema_version": 2,
        "submission_id": submission_id,
        "submitted_filename": attempt.intent["dmg_name"],
        "version": attempt.intent["version"],
    }
    path = attempt.context.attempt_root / "submission-receipt.json"
    _write_json_exclusive(path, receipt)
    attempt.submission_receipt = receipt
    attempt.submission_id = submission_id
    return receipt


def _require_exact_or_write(path: Path, value: dict[str, Any], label: str) -> None:
    if os.path.lexists(path):
        _read_exact_json_document(
            path,
            value,
            drift_code="evidence_identity_drift",
            drift_message=f"persisted {label} differs from the DMG transaction",
        )
    else:
        _write_json_exclusive(path, value)


def _fetch_log(
    attempt: DmgAttempt,
    submission_id: str,
    *,
    runner: Runner,
) -> tuple[dict[str, str], dict[str, Any]]:
    result = _result_or_error(
        runner,
        CommandRole.FETCH_LOG,
        [
            _XCRUN,
            "notarytool",
            "log",
            submission_id,
            "--keychain-profile",
            attempt.context.notary_profile,
        ],
        300,
    )
    _require_empty_notary_stderr(result, CommandRole.FETCH_LOG)
    try:
        raw_log = json.loads(result.stdout, object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, _DuplicateFieldError) as error:
        raise TransactionError(
            "invalid_notary_response", "notarytool log is not strict JSON"
        ) from error
    notarization = {"id": submission_id, "status": "Accepted"}
    try:
        normalized = validate_documents(
            notarization,
            raw_log,
            archive_filename=attempt.intent["dmg_name"],
            archive_sha256=attempt.intent["dmg_sha256"],
        )
    except NotaryLogError as error:
        raise TransactionError(
            "notary_log_verification_failed",
            "Apple notarization log does not bind the exact submitted DMG",
        ) from error
    _require_exact_or_write(
        attempt.context.attempt_root / "notarization.json",
        notarization,
        "notarization result",
    )
    _require_exact_or_write(
        attempt.context.attempt_root / "notarization-log.json",
        normalized,
        "notarization log",
    )
    return notarization, normalized


class _DuplicateFieldError(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateFieldError(f"duplicate field: {key}")
        value[key] = child
    return value


def _command_ok(
    runner: Runner,
    role: Enum,
    command: list[str],
    timeout: float,
) -> CommandResult:
    result = _capture_command_result(runner, role, command, timeout)
    if result.returncode != 0:
        raise TransactionError(
            f"{role.value}_failed",
            f"{role.value} command failed",
            exit_code=result.returncode,
        )
    diagnostics = "\n".join(
        stream for stream in (result.stdout, result.stderr) if stream
    )
    if re.search(r"(?im)\b(?:warning|error)\b", diagnostics):
        raise TransactionError(
            f"{role.value}_diagnostic_failed",
            f"{role.value} command emitted a warning or error diagnostic",
        )
    return result


def _staple_and_verify(
    attempt: DmgAttempt,
    submission_id: str,
    *,
    runner: Runner,
) -> tuple[Path, str]:
    submitted_digest, submitted_size = _submitted_dmg_identity(
        attempt.dmg_path
    )
    if (submitted_digest, submitted_size) != (
        attempt.intent["dmg_sha256"],
        attempt.intent["dmg_size"],
    ):
        raise TransactionError(
            "submitted_dmg_identity_drift",
            "immutable pre-staple submitted DMG differs from its intent",
        )
    if os.path.lexists(attempt.staple_pending_root):
        raise TransactionError(
            "stale_staple_pending",
            "staple pending set must be discarded before finalization",
        )
    _mkdir_private(attempt.staple_pending_root, exclusive=True)
    try:
        copied_size, copied_digest = copy_regular_new(
            attempt.dmg_path,
            attempt.staple_pending_dmg,
            MAX_DMG_BYTES,
        )
    except PublicationError as error:
        raise TransactionError(
            "staple_copy_failed",
            "cannot create a private staple copy from submitted DMG bytes",
        ) from error
    if (copied_digest, copied_size) != (submitted_digest, submitted_size):
        raise TransactionError(
            "staple_copy_identity_drift",
            "private staple copy differs from submitted DMG bytes",
        )
    dmg = attempt.staple_pending_dmg
    _append(attempt, "stapling", submission_id=submission_id)
    _command_ok(
        runner,
        CommandRole.STAPLE,
        [_XCRUN, "stapler", "staple", str(dmg)],
        600,
    )
    _command_ok(
        runner,
        CommandRole.STAPLE_VALIDATE,
        [_XCRUN, "stapler", "validate", str(dmg)],
        300,
    )
    stapled_digest, _stapled_size = _dmg_identity(dmg)
    _append(attempt, "stapled", submission_id=submission_id)
    return dmg, stapled_digest


def _load_or_capture_gatekeeper(
    attempt: DmgAttempt,
    dmg: Path,
    digest: str,
    *,
    capture: GatekeeperCapture,
) -> dict[str, Any]:
    path = attempt.context.attempt_root / "gatekeeper.json"
    if os.path.lexists(path):
        evidence, _ = _load_json(path, "DMG Gatekeeper evidence")
        try:
            evidence = validate_gatekeeper_evidence(
                evidence,
                expected_assessment_type="open",
                expected_primary_signature_context=True,
            )
        except (GatekeeperEvidenceError, ValueError) as error:
            raise TransactionError(
                "gatekeeper_verification_failed", "persisted Gatekeeper evidence is invalid"
            ) from error
    else:
        evidence = capture(dmg, digest)
        try:
            evidence = validate_gatekeeper_evidence(
                evidence,
                expected_assessment_type="open",
                expected_primary_signature_context=True,
                expected_target=dmg,
            )
        except (GatekeeperEvidenceError, ValueError) as error:
            raise TransactionError(
                "gatekeeper_verification_failed", "Gatekeeper evidence is invalid"
            ) from error
        _write_json_exclusive(path, evidence)
    if evidence["target_signed_app_tree_sha256"] != digest:
        raise TransactionError(
            "gatekeeper_target_mismatch", "Gatekeeper evidence targets different DMG bytes"
        )
    return evidence


def _safe_remove_private_regular_directory(path: Path, label: str) -> None:
    _require_real_directory(path, private=True)
    try:
        entries = list(path.iterdir())
    except OSError as error:
        raise TransactionError(
            "partial_set_cleanup_failed", f"cannot inspect {label}"
        ) from error
    for entry in entries:
        metadata = entry.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
        ):
            raise TransactionError(
                "unsafe_partial_set", f"{label} contains an unsafe entry"
            )
    shutil.rmtree(path)
    _fsync_directory(path.parent)


def _safe_remove_partial_final_set(path: Path) -> None:
    _safe_remove_private_regular_directory(path, "partial DMG set")


def _reset_unpublished_stapling(attempt: DmgAttempt) -> None:
    for path, label in (
        (attempt.staple_pending_root, "staple pending set"),
        (attempt.context.attempt_root / "final-set", "unpublished final DMG set"),
    ):
        if os.path.lexists(path):
            _safe_remove_private_regular_directory(path, label)
    gatekeeper = attempt.context.attempt_root / "gatekeeper.json"
    if os.path.lexists(gatekeeper):
        metadata = gatekeeper.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
        ):
            raise TransactionError(
                "unsafe_staple_evidence",
                "unpublished Gatekeeper evidence is not a private regular file",
            )
        gatekeeper.unlink()
        _fsync_directory(gatekeeper.parent)


def _copy_final_evidence(
    attempt: DmgAttempt,
    final_set: Path,
    *,
    stapled_dmg: Path,
    stapled_digest: str,
) -> None:
    source_names = {
        "notarization.json": MAX_EVIDENCE_BYTES,
        "notarization-log.json": MAX_EVIDENCE_BYTES,
        "gatekeeper.json": MAX_EVIDENCE_BYTES,
        "submission-receipt.json": MAX_EVIDENCE_BYTES,
    }
    destination_names = {
        "notarization.json": f"Clash.for.Mac_{attempt.context.version}_arm64.notarization.json",
        "notarization-log.json": (
            f"Clash.for.Mac_{attempt.context.version}_arm64.notarization-log.json"
        ),
        "gatekeeper.json": f"Clash.for.Mac_{attempt.context.version}_arm64.gatekeeper.json",
        "submission-receipt.json": (
            f"Clash.for.Mac_{attempt.context.version}_arm64.submission.json"
        ),
    }
    try:
        copied_size, copied_digest = copy_regular_new(
            stapled_dmg,
            final_set / attempt.context.dmg_name,
            MAX_DMG_BYTES,
        )
        if copied_digest != stapled_digest or copied_size <= 0:
            raise TransactionError(
                "final_set_copy_identity_drift",
                "final DMG copy differs from the verified stapled bytes",
            )
        for source_name, maximum in source_names.items():
            source = attempt.context.attempt_root / source_name
            destination_name = destination_names.get(source_name, source_name)
            copy_regular_new(source, final_set / destination_name, maximum)
    except PublicationError as error:
        raise TransactionError(
            "final_set_copy_failed", "cannot copy exact DMG evidence into its final set"
        ) from error


def _prepare_and_publish_set(
    attempt: DmgAttempt,
    submission_id: str,
    *,
    stapled_dmg: Path,
    stapled_digest: str,
    clock: Clock,
    publisher: Publisher,
    packaged_app_manifest_reader: PackagedAppManifestReader,
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> Path:
    context = attempt.context
    if os.path.lexists(context.final_root):
        seal = verify_dmg_set(
            context.final_root,
            repository=context.repository,
            version=context.version,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        if seal["submission_id"] != submission_id:
            raise TransactionError(
                "submission_id_mismatch", "published DMG set uses another submission ID"
            )
        confirm_published_tree_durable(
            context.attempt_root / "final-set", context.final_root
        )
        seal = verify_dmg_set(
            context.final_root,
            repository=context.repository,
            version=context.version,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        if seal["submission_id"] != submission_id:
            raise TransactionError(
                "submission_id_mismatch", "published DMG set uses another submission ID"
            )
        if _validate_journal(attempt.journal) != "published":
            _append(attempt, "published", submission_id=submission_id)
        return context.final_root
    final_set = context.attempt_root / "final-set"
    if os.path.lexists(final_set):
        try:
            seal = verify_dmg_set(
                final_set,
                repository=context.repository,
                version=context.version,
                packaged_app_manifest_reader=packaged_app_manifest_reader,
                require_version_directory=False,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
        except (ArtifactSetError, OSError, ValueError):
            _safe_remove_partial_final_set(final_set)
        else:
            if seal["submission_id"] != submission_id:
                raise TransactionError(
                    "submission_id_mismatch", "sealed DMG set uses another submission ID"
                )
    if not os.path.lexists(final_set):
        _mkdir_private(final_set, exclusive=True)
        if stapled_dmg != attempt.staple_pending_dmg:
            raise TransactionError(
                "staple_copy_path_mismatch",
                "final DMG source is not the private staple pending copy",
            )
        if _dmg_identity(stapled_dmg)[0] != stapled_digest:
            raise TransactionError(
                "staple_copy_identity_drift",
                "private staple copy changed before final-set construction",
            )
        _copy_final_evidence(
            attempt,
            final_set,
            stapled_dmg=stapled_dmg,
            stapled_digest=stapled_digest,
        )
        seal_dmg_set(
            final_set,
            repository=context.repository,
            version=context.version,
            build_number=context.build_number,
            pre_staple_sha256=attempt.intent["dmg_sha256"],
            prepackage=attempt.intent["prepackage"],
            source_identity={
                "repository_commit": context.source_identity["repositoryCommit"],
                "release_source_sha256": context.source_identity["releaseSourceSha256"],
            },
            sealed_at=clock(),
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
    if _validate_journal(attempt.journal) != "sealed":
        _append(attempt, "sealed", submission_id=submission_id)
    _fsync_tree(final_set)
    try:
        publisher(final_set, context.final_root)
    except Exception as error:
        if not os.path.lexists(final_set) and os.path.lexists(context.final_root):
            try:
                seal = verify_dmg_set(
                    context.final_root,
                    repository=context.repository,
                    version=context.version,
                    packaged_app_manifest_reader=packaged_app_manifest_reader,
                    prepackage_stage_verifier=prepackage_stage_verifier,
                )
            except (ArtifactSetError, OSError, ValueError):
                pass
            else:
                if seal["submission_id"] == submission_id:
                    confirm_published_tree_durable(
                        final_set, context.final_root
                    )
                    seal = verify_dmg_set(
                        context.final_root,
                        repository=context.repository,
                        version=context.version,
                        packaged_app_manifest_reader=packaged_app_manifest_reader,
                        prepackage_stage_verifier=prepackage_stage_verifier,
                    )
                    if seal["submission_id"] != submission_id:
                        raise TransactionError(
                            "submission_id_mismatch",
                            "published DMG set uses another submission ID",
                        )
                    _append(attempt, "published", submission_id=submission_id)
                    return context.final_root
        raise TransactionError(
            "atomic_publish_failed", "cannot atomically publish the complete DMG set"
        ) from error
    if os.path.lexists(final_set) or not os.path.lexists(context.final_root):
        raise TransactionError(
            "publish_result_ambiguous",
            "DMG publisher did not leave exactly one complete destination set",
            terminal_state="outcome_unknown",
        )
    confirm_published_tree_durable(final_set, context.final_root)
    seal = verify_dmg_set(
        context.final_root,
        repository=context.repository,
        version=context.version,
        packaged_app_manifest_reader=packaged_app_manifest_reader,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )
    if seal["submission_id"] != submission_id:
        raise TransactionError(
            "submission_id_mismatch", "published DMG set uses another submission ID"
        )
    _append(attempt, "published", submission_id=submission_id)
    return context.final_root


def _finalize_accepted(
    attempt: DmgAttempt,
    submission_id: str,
    *,
    runner: Runner,
    gatekeeper_capture: GatekeeperCapture,
    publisher: Publisher,
    clock: Clock,
    packaged_app_manifest_reader: PackagedAppManifestReader,
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> Path:
    _fetch_log(attempt, submission_id, runner=runner)
    _append(attempt, "log_verified", submission_id=submission_id)
    dmg, digest = _staple_and_verify(attempt, submission_id, runner=runner)
    _load_or_capture_gatekeeper(
        attempt, dmg, digest, capture=gatekeeper_capture
    )
    _append(attempt, "gatekeeper_verified", submission_id=submission_id)
    _command_ok(
        runner,
        DmgCommandRole.DMG_VERIFY,
        ["/usr/bin/hdiutil", "verify", str(dmg)],
        600,
    )
    _command_ok(
        runner,
        CommandRole.FINAL_VERIFY,
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=4", str(dmg)],
        300,
    )
    if _dmg_identity(dmg)[0] != digest:
        raise TransactionError("dmg_identity_drift", "DMG changed during final verification")
    _append(attempt, "artifact_verified", submission_id=submission_id)
    return _prepare_and_publish_set(
        attempt,
        submission_id,
        stapled_dmg=dmg,
        stapled_digest=digest,
        clock=clock,
        publisher=publisher,
        packaged_app_manifest_reader=packaged_app_manifest_reader,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )


def _record_deferred(
    attempt: DmgAttempt,
    error: Exception,
    *,
    submission_id: str | None,
    recovery: bool,
) -> None:
    current_state = _validate_journal(attempt.journal)
    if recovery and current_state == "recovering":
        state = "recovery_deferred"
    elif current_state == "sealed" and os.path.lexists(
        attempt.context.final_root
    ):
        state = "publication_deferred"
    elif current_state in {"submitting", "submission_observed", "waiting"}:
        state = "outcome_unknown"
    else:
        state = "finalization_deferred"
    if isinstance(error, TransactionError):
        failure_code = error.code
        exit_code = error.exit_code
        if error.terminal_state == "rejected" or error.code == "notary_submission_rejected":
            state = "rejected"
    else:
        failure_code = "internal_error"
        exit_code = None
    if current_state in {"published", "rejected"}:
        return
    _append(
        attempt,
        state,
        submission_id=submission_id,
        failure_code=failure_code,
        exit_code=exit_code,
    )


def _direct_submit(
    attempt: DmgAttempt,
    *,
    runner: Runner,
    gatekeeper_capture: GatekeeperCapture,
    publisher: Publisher,
    clock: Clock,
    packaged_app_manifest_reader: PackagedAppManifestReader,
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> Path:
    context = attempt.context
    _require_prepackage_stage(
        context,
        prepackage_stage_verifier,
        expected=attempt.intent["prepackage"],
    )
    _append(attempt, "submitting")
    command = [
        _XCRUN,
        "notarytool",
        "submit",
        str(attempt.dmg_path),
        "--no-wait",
        "--keychain-profile",
        context.notary_profile,
        "--output-format",
        "json",
    ]
    submission_id: str | None = None
    try:
        result = _capture_command_result(runner, CommandRole.SUBMIT, command, 1800)
        try:
            submission_id = _project_notary_submit_identity(
                result.stdout, attempt.dmg_path
            )
        except TransactionError as error:
            raise TransactionError(
                error.code,
                str(error),
                terminal_state="outcome_unknown",
            ) from error
        _persist_observation(attempt, submission_id, clock=clock)
        if result.returncode != 0:
            raise TransactionError(
                "submit_failed",
                "DMG submit failed after returning a submission ID",
                terminal_state="outcome_unknown",
                exit_code=result.returncode,
            )
        _require_empty_notary_stderr(result, CommandRole.SUBMIT)
        if _parse_notary_submit_response(result.stdout, attempt.dmg_path) != submission_id:
            raise TransactionError(
                "submission_id_mismatch",
                "notarytool submit identity changed during validation",
                terminal_state="outcome_unknown",
            )
        _persist_submission_receipt(
            attempt,
            submission_id,
            acquisition="submit-no-wait",
            notary_created_at=None,
            clock=clock,
        )
        _append(attempt, "submission_observed", submission_id=submission_id)
        _append(attempt, "waiting", submission_id=submission_id)
        waited = _result_or_error(
            runner,
            CommandRole.WAIT,
            [
                _XCRUN,
                "notarytool",
                "wait",
                submission_id,
                "--keychain-profile",
                context.notary_profile,
                "--output-format",
                "json",
                "--timeout",
                "2h",
            ],
            7500,
            uncertain=True,
        )
        _require_empty_notary_stderr(waited, CommandRole.WAIT)
        waited_id, status = _parse_notary_wait_response(
            waited.stdout,
            allowed_statuses={"Accepted", "In Progress", "Invalid", "Rejected"},
        )
        if waited_id != submission_id:
            raise TransactionError(
                "submission_id_mismatch",
                "notarytool wait returned a different DMG submission ID",
                terminal_state="outcome_unknown",
            )
        if status in {"Invalid", "Rejected"}:
            raise TransactionError(
                "notary_submission_rejected",
                "Apple rejected the DMG notarization submission",
                terminal_state="rejected",
            )
        if status != "Accepted":
            raise TransactionError(
                "notary_wait_incomplete",
                "DMG notarization did not reach a terminal result",
                terminal_state="outcome_unknown",
            )
        _append(attempt, "accepted", submission_id=submission_id)
        return _finalize_accepted(
            attempt,
            submission_id,
            runner=runner,
            gatekeeper_capture=gatekeeper_capture,
            publisher=publisher,
            clock=clock,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
    except Exception as error:
        _record_deferred(
            attempt, error, submission_id=submission_id, recovery=False
        )
        raise


def execute_transaction(
    context: DmgContext,
    *,
    runner: Runner = production_command_runner,
    gatekeeper_capture: GatekeeperCapture = production_gatekeeper_capture,
    source_identity_reader: SourceIdentityReader = production_source_identity_reader,
    publisher: Publisher = publish_exclusive,
    packaged_app_manifest_reader: PackagedAppManifestReader = read_dmg_app_manifest,
    clock: Clock = _utc_now,
    attempt_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
    prepackage_stage_verifier: PrepackageStageVerifier = verify_prepackage_authorization,
) -> Path:
    _validate_context(context, initial=True)
    _require_source_identity(context, source_identity_reader)
    _ensure_private_roots(context)
    with _exclusive_attempt_recovery_lock(context):
        attempt = _prepare_attempt(
            context,
            clock=clock,
            attempt_id_factory=attempt_id_factory,
            publisher=publisher,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        _require_source_identity(context, source_identity_reader)
        _require_prepackage_stage(
            context,
            prepackage_stage_verifier,
            expected=attempt.intent["prepackage"],
        )
        return _direct_submit(
            attempt,
            runner=runner,
            gatekeeper_capture=gatekeeper_capture,
            publisher=publisher,
            clock=clock,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )


def _read_recovery_acceptance(
    attempt: DmgAttempt,
    submission_id: str,
    *,
    runner: Runner,
) -> str:
    context = attempt.context
    info = _result_or_error(
        runner,
        CommandRole.INFO,
        [
            _XCRUN,
            "notarytool",
            "info",
            submission_id,
            "--keychain-profile",
            context.notary_profile,
            "--output-format",
            "json",
        ],
        300,
        uncertain=True,
    )
    _require_empty_notary_stderr(info, CommandRole.INFO)
    status, created_at = _parse_notary_info_response(
        info.stdout,
        submission_id=submission_id,
        archive_name=context.dmg_name,
        allowed_statuses={"Accepted", "In Progress", "Invalid", "Rejected"},
    )
    if status in {"Invalid", "Rejected"}:
        raise TransactionError(
            "notary_submission_rejected",
            "Apple rejected the recovered DMG submission",
            terminal_state="rejected",
        )
    if status != "Accepted":
        raise TransactionError(
            "notary_recovery_incomplete",
            "recovered DMG submission is not Accepted",
            terminal_state="outcome_unknown",
        )
    _, created = _parse_utc_timestamp(created_at, "info createdDate")
    not_before = _parse_utc_timestamp(
        attempt.intent["submit_not_before"], "submit_not_before"
    )[1]
    not_after_text, not_after = _parse_utc_timestamp(
        attempt.intent["submit_not_after"], "submit_not_after"
    )
    if not _timestamp_within_recorded_window(
        created,
        window_start=not_before,
        window_end=not_after,
        window_end_rendered=not_after_text,
    ):
        raise TransactionError(
            "submission_causal_binding_unproven",
            "Apple submission creation time falls outside the durable submit window",
        )
    if attempt.observation is None:
        history = _result_or_error(
            runner,
            CommandRole.HISTORY,
            [
                _XCRUN,
                "notarytool",
                "history",
                "--keychain-profile",
                context.notary_profile,
                "--output-format",
                "json",
            ],
            300,
            uncertain=True,
        )
        _require_empty_notary_stderr(history, CommandRole.HISTORY)
        _require_unique_history_binding(
            history.stdout,
            submission_id=submission_id,
            archive_name=context.dmg_name,
            window_start=not_before,
            window_end=not_after,
            window_end_rendered=not_after_text,
            info_created_at=created_at,
        )
    return created_at


def recover_transaction(
    context: DmgContext,
    submission_id: str,
    *,
    runner: Runner = production_command_runner,
    gatekeeper_capture: GatekeeperCapture = production_gatekeeper_capture,
    source_identity_reader: SourceIdentityReader = production_source_identity_reader,
    publisher: Publisher = publish_exclusive,
    packaged_app_manifest_reader: PackagedAppManifestReader = read_dmg_app_manifest,
    clock: Clock = _utc_now,
    prepackage_stage_verifier: PrepackageStageVerifier = verify_prepackage_authorization,
) -> Path:
    submission_id = _canonical_uuid(submission_id, "recovery submission id")
    _validate_context(context, initial=False)
    _require_source_identity(context, source_identity_reader)
    with _exclusive_attempt_recovery_lock(context):
        attempt = _load_attempt(context, clock=clock)
        _require_prepackage_stage(
            context,
            prepackage_stage_verifier,
            expected=attempt.intent["prepackage"],
        )
        state = _validate_journal(attempt.journal)
        if attempt.submission_id is not None and attempt.submission_id != submission_id:
            raise TransactionError(
                "submission_id_mismatch",
                "recovery submission ID differs from durable transaction evidence",
            )
        if state == "rejected":
            raise TransactionError(
                "notary_submission_rejected", "rejected DMG submission cannot be recovered"
            )
        if state == "published":
            seal = verify_dmg_set(
                context.final_root,
                repository=context.repository,
                version=context.version,
                packaged_app_manifest_reader=packaged_app_manifest_reader,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            if seal["submission_id"] != submission_id:
                raise TransactionError(
                    "submission_id_mismatch", "published DMG seal uses another submission ID"
                )
            confirm_published_tree_durable(
                context.attempt_root / "final-set", context.final_root
            )
            seal = verify_dmg_set(
                context.final_root,
                repository=context.repository,
                version=context.version,
                packaged_app_manifest_reader=packaged_app_manifest_reader,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            if seal["submission_id"] != submission_id:
                raise TransactionError(
                    "submission_id_mismatch", "published DMG seal uses another submission ID"
                )
            return context.final_root
        if os.path.lexists(context.final_root):
            if state not in {"publication_deferred", "sealed"}:
                raise TransactionError(
                    "published_set_without_seal_event",
                    "a public DMG set exists without the durable sealed boundary",
                )
            seal = verify_dmg_set(
                context.final_root,
                repository=context.repository,
                version=context.version,
                packaged_app_manifest_reader=packaged_app_manifest_reader,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            if seal["submission_id"] != submission_id:
                raise TransactionError(
                    "submission_id_mismatch", "published DMG seal uses another submission ID"
                )
            confirm_published_tree_durable(
                context.attempt_root / "final-set", context.final_root
            )
            seal = verify_dmg_set(
                context.final_root,
                repository=context.repository,
                version=context.version,
                packaged_app_manifest_reader=packaged_app_manifest_reader,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            if seal["submission_id"] != submission_id:
                raise TransactionError(
                    "submission_id_mismatch", "published DMG seal uses another submission ID"
                )
            _append(attempt, "published", submission_id=submission_id)
            return context.final_root
        if state not in {
            "accepted",
            "artifact_verified",
            "finalization_deferred",
            "gatekeeper_verified",
            "log_verified",
            "outcome_unknown",
            "publication_deferred",
            "recovery_deferred",
            "sealed",
            "stapled",
            "stapling",
            "submission_observed",
            "submitting",
            "waiting",
        }:
            raise TransactionError(
                "recovery_state_unsupported", "DMG transaction is not at a recoverable boundary"
            )
        _reset_unpublished_stapling(attempt)
        _append(attempt, "recovering", submission_id=submission_id)
        try:
            created_at = _read_recovery_acceptance(
                attempt, submission_id, runner=runner
            )
            if attempt.submission_receipt is None:
                _persist_submission_receipt(
                    attempt,
                    submission_id,
                    acquisition=(
                        "submit-no-wait"
                        if attempt.observation is not None
                        else "explicit-recovery"
                    ),
                    notary_created_at=(
                        None if attempt.observation is not None else created_at
                    ),
                    clock=clock,
                )
            elif (
                attempt.submission_receipt["acquisition"] == "explicit-recovery"
                and attempt.submission_receipt["notary_created_at"] != created_at
            ):
                raise TransactionError(
                    "submission_receipt_identity_drift",
                    "Apple submission creation time differs from its durable receipt",
                )
            _append(attempt, "accepted", submission_id=submission_id)
            return _finalize_accepted(
                attempt,
                submission_id,
                runner=runner,
                gatekeeper_capture=gatekeeper_capture,
                publisher=publisher,
                clock=clock,
                packaged_app_manifest_reader=packaged_app_manifest_reader,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
        except Exception as error:
            _record_deferred(
                attempt, error, submission_id=submission_id, recovery=True
            )
            raise


def self_check() -> None:
    if MAX_DMG_EVENTS != 64 or MAX_RECOVERY_RUNS != 8:
        raise TransactionError("self_check_failed", "DMG transaction quota drifted")
    if TRANSITIONS["submitting"] != {
        "outcome_unknown",
        "recovering",
        "submission_observed",
    }:
        raise TransactionError("self_check_failed", "DMG submit transition drifted")
    if INTENT_DOCUMENT != "cfw-dmg-notarization-intent-v3":
        raise TransactionError("self_check_failed", "DMG intent contract drifted")
    if NOTARY_PROFILE != "clashformac-notary":
        raise TransactionError("self_check_failed", "DMG notary profile drifted")
    if _XCRUN != "/usr/bin/xcrun":
        raise TransactionError("self_check_failed", "system-tool path drifted")
    print("DMG notarization transaction self-check ok")


def _context_from_arguments(
    arguments: argparse.Namespace, *, initial: bool
) -> DmgContext:
    repository = arguments.repository
    identity = current_identity(repository, require_clean=True)
    return DmgContext(
        repository=repository,
        version=arguments.version,
        build_number=arguments.build_number,
        notary_profile=arguments.notary_profile,
        source_identity=identity,
        staged_dmg=arguments.dmg if initial else None,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("self-check")
    for name in ("preflight", "start", "recover"):
        command = commands.add_parser(name)
        command.add_argument("--repository", type=Path, required=True)
        command.add_argument(
            "--version",
            choices=(ACTIVE_RELEASE_IDENTITY.product_version,),
            required=True,
        )
        command.add_argument(
            "--build-number",
            choices=(ACTIVE_RELEASE_IDENTITY.ga_build,),
            required=True,
        )
        command.add_argument("--notary-profile", required=True)
        if name == "start":
            command.add_argument("--dmg", type=Path, required=True)
        if name == "recover":
            command.add_argument("--submission-id", required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "self-check":
            self_check()
            return
        context = _context_from_arguments(
            arguments, initial=arguments.command == "start"
        )
        primary: BaseException | None = None
        session_error: BaseException | None = None
        operation_completed = False
        publication_existed = False
        if arguments.command in {"start", "recover"}:
            try:
                context.final_root.lstat()
            except FileNotFoundError:
                pass
            else:
                publication_existed = True
        try:
            with frozen_candidate_verification_session(context.repository) as freeze_verifier:
                stage_verifier = partial(
                    verify_prepackage_authorization,
                    freeze_verifier=freeze_verifier,
                )
                try:
                    if arguments.command == "preflight":
                        preflight_new(context, stage_verifier)
                        message = "DMG notarization transaction preflight ok"
                    elif arguments.command == "start":
                        destination = execute_transaction(
                            context, prepackage_stage_verifier=stage_verifier
                        )
                        message = f"DMG release set published: {destination}"
                    else:
                        destination = recover_transaction(
                            context,
                            arguments.submission_id,
                            prepackage_stage_verifier=stage_verifier,
                        )
                        message = f"DMG release set published: {destination}"
                except BaseException as error:
                    primary = error
                else:
                    operation_completed = True
        except BaseException as error:
            session_error = error
        if primary is not None:
            if session_error is not None:
                cleanup_note = (
                    "secondary DMG verifier session cleanup failure: "
                    f"{type(session_error).__name__}: {session_error}"
                )
                cleanup_note += "".join(
                    f"\n{note}" for note in getattr(session_error, "__notes__", ())
                )
                primary.add_note(cleanup_note)
                if arguments.command in {"start", "recover"} and not publication_existed:
                    try:
                        context.final_root.lstat()
                    except FileNotFoundError:
                        pass
                    except OSError as observation_error:
                        unknown = TransactionError(
                            "dmg_verifier_close_outcome_unknown",
                            "DMG publication and verifier session closure outcomes are unknown",
                            terminal_state="outcome_unknown",
                        )
                        unknown.add_note(cleanup_note)
                        unknown.add_note(f"publication observation failed: {observation_error}")
                        raise unknown from primary
                    else:
                        unknown = TransactionError(
                            "dmg_verifier_close_outcome_unknown",
                            "new DMG set exists but verification and session closure failed",
                            terminal_state="outcome_unknown",
                        )
                        unknown.add_note(cleanup_note)
                        raise unknown from primary
            raise primary
        if session_error is not None:
            if operation_completed and arguments.command in {"start", "recover"}:
                raise TransactionError(
                    "dmg_verifier_close_outcome_unknown",
                    "published DMG verification session did not close successfully",
                    terminal_state="outcome_unknown",
                ) from session_error
            raise session_error
    except (
        ArtifactSetError,
        CandidateFreezeError,
        OSError,
        PublicationError,
        SourceIdentityError,
        TransactionError,
        ValueError,
    ) as error:
        code = error.code if isinstance(error, TransactionError) else "artifact_set_error"
        notes = "".join(f"\n{note}" for note in getattr(error, "__notes__", ()))
        raise SystemExit(
            f"error: DMG notarization transaction [{code}]: {error}{notes}"
        ) from error
    print(message)


if __name__ == "__main__":
    main()
