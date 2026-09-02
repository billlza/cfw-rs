#!/usr/bin/env python3
"""Run and recover append-only Developer ID signing attempts for GA build 40040.

The frozen candidate is never copied into a canonical signing path until one
private attempt has passed signing, full app verification, and transformation
proof.  The complete ``signing-output`` container is then published with one
non-overwriting atomic directory rename.  A failed attempt remains immutable
evidence and a crash is reconciled explicitly by the fixed ``resume`` entry.
"""

from __future__ import annotations

import argparse
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
from typing import Any, Callable, Final, Mapping, Sequence

if __package__:
    from .candidate_freeze import (
        CandidateFreezeError,
        DOCUMENT as FREEZE_DOCUMENT,
        SCHEMA_VERSION as FREEZE_SCHEMA_VERSION,
        FrozenCandidate,
        verify_frozen_candidate,
    )
    from .publication.bounded_process import (
        BoundedProcessError,
        run_bounded_process,
    )
    from .publication.common import PublicationError
    from .publication.durable_file import (
        DurabilityOutcomeUnknown,
        confirm_private_directory_published,
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        fsync_private_tree,
        publish_private_directory_exclusive,
        publish_private_directory_locked,
        read_private_pending,
        write_private_pending_locked,
    )
    from .release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        BuildIdentityError,
        CandidateBundleContext,
        SIGNED_APP_WITHIN_OUTPUT,
        SIGNED_NATIVE_PRODUCTS_NAME,
        SIGNING_OUTPUT_RELATIVE,
        candidate_signing_output,
        ga_root,
    )
    from .release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )
    from .release_signing_plan import SigningPlanError, validate_plan
    from .release_signing_preflight import (
        SigningPreflightError,
        load_preflight_manifest,
        signing_certificate_digests,
        verify_live_profile_validity,
        verify_materialized_profiles,
    )
    from .repository_source_identity import (
        SourceIdentityError,
        current_identity,
    )
    from .updater_key_possession_proof import (
        UpdaterKeyPossessionError,
        UpdaterKeyPossessionOperationalError,
        VerifiedUpdaterKeyPossession,
        production_embedded_verifier_session,
        verify_possession_proof,
    )
    from .verify_signing_transformation import (
        RECOVERABLE_VERIFICATION_ERROR_CODES,
        RECEIPT_NAME as TRANSFORMATION_RECEIPT_NAME,
        SigningTransformationError,
        SigningTransformationOutcomeUnknown,
        create_attempt_receipt,
        load_attempt_receipt,
        verify_attempt_receipt,
        verify_receipt,
    )
else:
    from candidate_freeze import (
        CandidateFreezeError,
        DOCUMENT as FREEZE_DOCUMENT,
        SCHEMA_VERSION as FREEZE_SCHEMA_VERSION,
        FrozenCandidate,
        verify_frozen_candidate,
    )
    from publication.bounded_process import BoundedProcessError, run_bounded_process
    from publication.common import PublicationError
    from publication.durable_file import (
        DurabilityOutcomeUnknown,
        confirm_private_directory_published,
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        fsync_private_tree,
        publish_private_directory_exclusive,
        publish_private_directory_locked,
        read_private_pending,
        write_private_pending_locked,
    )
    from release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        BuildIdentityError,
        CandidateBundleContext,
        SIGNED_APP_WITHIN_OUTPUT,
        SIGNED_NATIVE_PRODUCTS_NAME,
        SIGNING_OUTPUT_RELATIVE,
        candidate_signing_output,
        ga_root,
    )
    from release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )
    from release_signing_plan import SigningPlanError, validate_plan
    from release_signing_preflight import (
        SigningPreflightError,
        load_preflight_manifest,
        signing_certificate_digests,
        verify_live_profile_validity,
        verify_materialized_profiles,
    )
    from repository_source_identity import SourceIdentityError, current_identity
    from updater_key_possession_proof import (
        UpdaterKeyPossessionError,
        UpdaterKeyPossessionOperationalError,
        VerifiedUpdaterKeyPossession,
        production_embedded_verifier_session,
        verify_possession_proof,
    )
    from verify_signing_transformation import (
        RECOVERABLE_VERIFICATION_ERROR_CODES,
        RECEIPT_NAME as TRANSFORMATION_RECEIPT_NAME,
        SigningTransformationError,
        SigningTransformationOutcomeUnknown,
        create_attempt_receipt,
        load_attempt_receipt,
        verify_attempt_receipt,
        verify_receipt,
    )


ATTEMPT_DOCUMENT: Final = "cfm-ga-signing-attempt-v1"
EVENT_DOCUMENT: Final = "cfm-ga-signing-attempt-event-v1"
SCHEMA_VERSION: Final = 1
ATTEMPTS_RELATIVE: Final = Path("transactions/signing-attempts")
INTENT_NAME: Final = "intent.json"
WORK_NAME: Final = "work"
PUBLISH_READY_NAME: Final = "publish-ready"
MAX_JSON_BYTES: Final = 4 * 1024 * 1024
MAX_HELPER_OUTPUT_BYTES: Final = 32 * 1024 * 1024
HELPER_TIMEOUT_SECONDS: Final = 3600
ATTEMPT_ID_RE: Final = re.compile(r"\A[0-9]{8}\Z")
EVENT_NAME_RE: Final = re.compile(r"\Aevent-([0-9]{8})[.]json\Z")
SHA256_RE: Final = re.compile(r"\A[0-9a-f]{64}\Z")
COMMIT_RE: Final = re.compile(r"\A[0-9a-f]{40}\Z")
CERT_SHA1_RE: Final = re.compile(r"\A[0-9A-F]{40}\Z")
CERT_SHA256_RE: Final = re.compile(r"\A[0-9A-F]{64}\Z")
FAILURE_CODE_RE: Final = re.compile(r"\A[a-z][a-z0-9_]{0,127}\Z")
ABANDONED_BEFORE_SIGNING: Final = "attempt_abandoned_before_signing"
INTERRUPTED_DURING_SIGNING: Final = "interrupted_during_signing"
SIGNING_OUTPUT_PUBLISH_REPLY_UNKNOWN: Final = (
    "signing_output_publish_reply_unknown"
)
VERIFICATION_RECOVERY_FAILED: Final = "verification_recovery_failed"
VERIFICATION_RECOVERY_INTERRUPTED: Final = "verification_recovery_interrupted"
VERIFICATION_RECOVERY_PRECONDITION_FAILED: Final = (
    "verification_recovery_precondition_failed"
)
_DOWNSTREAM_RECOVERY_GUARDS: Final = (
    Path("packages"),
    Path("prepackage"),
    Path("ga-acceptance"),
    Path("publication"),
    Path("signed"),
    Path("stage-inputs/final-candidate"),
    Path("stage-inputs/ga-acceptance"),
    Path("stage-inputs/publication"),
    Path("stage-inputs/sealed-manifest"),
    Path("transactions/app-notary"),
    Path("transactions/notarization"),
    Path("transactions/dmg-notary"),
)

INTENT_FIELDS: Final = frozenset(
    {
        "attempt_id",
        "candidate_freeze_intent_sha256",
        "created_at",
        "document",
        "product",
        "release_source_sha256",
        "repository_commit",
        "schema_version",
        "signing_certificate_sha256",
        "signing_preflight_sha256",
        "signing_plan_sha256",
        "updater_embedded_public_key_sha256",
        "updater_key_possession_proof_sha256",
        "updater_tauri_config_sha256",
    }
)
EVENT_FIELDS: Final = frozenset(
    {
        "document",
        "event_sha256",
        "exit_code",
        "failure_code",
        "intent_sha256",
        "previous_event_sha256",
        "recorded_at",
        "schema_version",
        "sequence",
        "state",
    }
)
STATES: Final = frozenset(
    {
        "prepared",
        "signing",
        "verification_blocked",
        "verification_recovering",
        "verification_committing",
        "verified",
        "publishing",
        "published",
        "failed",
        "outcome_unknown",
    }
)
TRANSITIONS: Final = {
    "prepared": frozenset({"signing", "failed"}),
    "signing": frozenset(
        {"verification_blocked", "verified", "failed", "outcome_unknown"}
    ),
    "verification_blocked": frozenset({"verification_recovering", "failed"}),
    "verification_recovering": frozenset({"verification_committing", "failed"}),
    "verification_committing": frozenset({"verified", "failed"}),
    "verified": frozenset({"publishing", "failed"}),
    "publishing": frozenset({"published", "outcome_unknown"}),
    "outcome_unknown": frozenset({"publishing", "published"}),
    "published": frozenset(),
    "failed": frozenset(),
}
FAILURE_EVIDENCE_STATES: Final = frozenset(
    {"failed", "outcome_unknown", "verification_blocked"}
)
LEGACY_OUTPUTS: Final = (
    Path("signing-input"),
    Path(SIGNED_NATIVE_PRODUCTS_NAME),
    Path(f"{SIGNED_NATIVE_PRODUCTS_NAME}.pending"),
    Path("transactions/signing-transformation.json"),
)


class SigningAttemptError(RuntimeError):
    """One signing attempt failed without claiming canonical publication."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SigningAttemptOutcomeUnknown(SigningAttemptError):
    """The signing-output rename may have completed and needs fixed recovery."""

    def __init__(self, message: str) -> None:
        super().__init__("signing_publication_outcome_unknown", message)


class SigningVerificationBlocked(SigningAttemptError):
    """A durable private receipt needs one bounded read-only verification retry."""

    def __init__(self, cause_code: str) -> None:
        if cause_code not in RECOVERABLE_VERIFICATION_ERROR_CODES:
            raise ValueError("verification-blocked cause code is not allowlisted")
        super().__init__(
            "signing_verification_blocked",
            "private signing transformation verification is blocked; use the "
            "fixed resume entry once",
        )
        self.cause_code = cause_code


@dataclass(frozen=True, slots=True)
class FrozenSigningBindings:
    frozen: FrozenCandidate
    repository_commit: str
    release_source_sha256: str
    signing_preflight_sha256: str
    signing_plan_sha256: str
    signing_certificate_sha1: str
    signing_certificate_sha256: str
    updater_key_possession_proof_sha256: str
    updater_embedded_public_key_sha256: str
    updater_tauri_config_sha256: str


@dataclass(frozen=True, slots=True)
class Attempt:
    identifier: str
    root: Path
    intent: dict[str, Any]
    intent_sha256: str
    events: tuple[dict[str, Any], ...]

    @property
    def state(self) -> str:
        return str(self.events[-1]["state"])

    @property
    def work(self) -> Path:
        return self.root / WORK_NAME

    @property
    def publish_ready(self) -> Path:
        return self.root / PUBLISH_READY_NAME


Clock = Callable[[], str]
HelperRunner = Callable[[Path, str, str], int]
VerificationRunner = Callable[[Path, CandidateBundleContext], None]
FreezeVerifier = Callable[[Path], FrozenCandidate]
LiveReadinessVerifier = Callable[[Path], None]
Publisher = Callable[[Path, Path], None]
Confirmer = Callable[[Path, Path], None]
TransformationCreator = Callable[[Path, Path], Mapping[str, Any]]
TransformationVerifier = Callable[[Path, Path], Mapping[str, Any]]
TransformationReceiptLoader = Callable[[Path, Path], Mapping[str, Any]]
CanonicalTransformationVerifier = Callable[[Path], Mapping[str, Any]]
EmbeddedVerifier = Callable[
    [Path, Path, Path],
    tuple[dict[str, Any], dict[str, Any]],
]
PossessionVerifier = Callable[[Path, Path], VerifiedUpdaterKeyPossession]
EmbeddedVerifierSessionFactory = Callable[
    [Path],
    AbstractContextManager[EmbeddedVerifier],
]


class _VerifierRetryBudget(str, Enum):
    DISARMED = "disarmed"
    ARMED = "armed"
    SPENT = "spent"


class _EmbeddedVerifierSessionOperation:
    """Own one verifier session and one post-sign operational replacement."""

    def __init__(
        self,
        repository: Path,
        session_factory: EmbeddedVerifierSessionFactory,
        *,
        allow_post_sign_retry: bool,
    ) -> None:
        self._repository = repository
        self._session_factory = session_factory
        self._allow_post_sign_retry = allow_post_sign_retry
        self._manager: AbstractContextManager[EmbeddedVerifier] | None = None
        self._embedded_verifier: EmbeddedVerifier | None = None
        self._budget = _VerifierRetryBudget.DISARMED
        self._first_operational_error: UpdaterKeyPossessionOperationalError | None = (
            None
        )
        self._active = False
        self._replay_lock = threading.Lock()

    def __enter__(self) -> "_EmbeddedVerifierSessionOperation":
        if self._active or self._manager is not None:
            raise SigningAttemptError(
                "updater_verifier_session_state_invalid",
                "operation-scoped updater verifier session is already active",
            )
        self._open_current()
        self._active = True
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object,
    ) -> bool:
        del exception_type, traceback
        self._active = False
        self._replay_lock.acquire()
        try:
            try:
                self._close_current(exception)
            except BaseException as cleanup_error:
                if exception is None:
                    raise
                exception.add_note(
                    "secondary operation-scoped updater verifier cleanup failure: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        finally:
            self._replay_lock.release()
        return False

    def _open_current(self) -> None:
        if self._manager is not None or self._embedded_verifier is not None:
            raise SigningAttemptError(
                "updater_verifier_session_state_invalid",
                "operation-scoped updater verifier session was not closed",
            )
        manager = self._session_factory(self._repository)
        embedded_verifier = manager.__enter__()
        self._manager = manager
        self._embedded_verifier = embedded_verifier

    def _close_current(self, primary: BaseException | None) -> None:
        manager = self._manager
        self._manager = None
        self._embedded_verifier = None
        if manager is None:
            return
        suppressed = manager.__exit__(
            type(primary) if primary is not None else None,
            primary,
            primary.__traceback__ if primary is not None else None,
        )
        if primary is not None and suppressed:
            raise SigningAttemptError(
                "updater_verifier_session_cleanup_failed",
                "updater verifier session unexpectedly suppressed its primary failure",
            )

    def arm_post_sign_retry(self) -> None:
        with self._replay_lock:
            if (
                not self._active
                or self._manager is None
                or not self._allow_post_sign_retry
                or self._budget is not _VerifierRetryBudget.DISARMED
            ):
                raise SigningAttemptError(
                    "updater_verifier_retry_budget_invalid",
                    "post-sign updater verifier retry budget cannot be armed",
                )
            self._budget = _VerifierRetryBudget.ARMED

    def _verify_once(
        self,
        repository: Path,
        root: Path,
    ) -> VerifiedUpdaterKeyPossession:
        embedded_verifier = self._embedded_verifier
        if embedded_verifier is None:
            raise SigningAttemptError(
                "updater_verifier_session_state_invalid",
                "operation-scoped updater verifier session is unavailable",
            )
        return verify_possession_proof(
            repository,
            root,
            embedded_verifier=embedded_verifier,
        )

    def _retry_exhausted(
        self,
        error: UpdaterKeyPossessionOperationalError,
    ) -> SigningAttemptError:
        first = self._first_operational_error
        if first is None:
            return SigningAttemptError(
                "updater_verifier_retry_state_invalid",
                "updater verifier retry state lost its first operational failure",
            )
        exhausted = SigningAttemptError(
            "updater_verifier_retry_exhausted",
            "fresh updater verifier session was operationally unavailable",
        )
        exhausted.__cause__ = ExceptionGroup(
            "updater verifier operational retry failures",
            [first, error],
        )
        return exhausted

    def verify_possession(
        self,
        repository: Path,
        root: Path,
    ) -> VerifiedUpdaterKeyPossession:
        if not self._replay_lock.acquire(blocking=False):
            raise SigningAttemptError(
                "updater_verifier_replay_concurrent",
                "updater verifier replay cannot be concurrent or reentrant",
            )
        try:
            if not self._active or self._manager is None:
                raise SigningAttemptError(
                    "updater_verifier_session_state_invalid",
                    "operation-scoped updater verifier session is not active",
                )
            try:
                return self._verify_once(repository, root)
            except UpdaterKeyPossessionOperationalError as first_error:
                if self._budget is _VerifierRetryBudget.DISARMED:
                    raise
                if self._budget is _VerifierRetryBudget.SPENT:
                    raise self._retry_exhausted(first_error)

                self._budget = _VerifierRetryBudget.SPENT
                self._first_operational_error = first_error
                try:
                    self._close_current(first_error)
                except Exception as cleanup_error:
                    raise SigningAttemptError(
                        "updater_verifier_session_cleanup_failed",
                        "failed updater verifier session could not be cleaned up",
                    ) from ExceptionGroup(
                        "updater verifier operational and cleanup failures",
                        [first_error, cleanup_error],
                    )

                try:
                    self._open_current()
                except Exception as rebuild_error:
                    raise SigningAttemptError(
                        "updater_verifier_session_rebuild_failed",
                        "fresh updater verifier session could not be established",
                    ) from ExceptionGroup(
                        "updater verifier operational and rebuild failures",
                        [first_error, rebuild_error],
                    )

                try:
                    return self._verify_once(repository, root)
                except UpdaterKeyPossessionOperationalError as retry_error:
                    raise self._retry_exhausted(retry_error)
                except (OSError, UpdaterKeyPossessionError, ValueError) as error:
                    raise SigningAttemptError(
                        "updater_verifier_fresh_replay_invalid",
                        "fresh updater verifier replay failed semantic validation",
                    ) from ExceptionGroup(
                        "updater verifier operational and semantic failures",
                        [first_error, error],
                    )
        finally:
            self._replay_lock.release()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _validate_timestamp(value: object, label: str) -> None:
    if not isinstance(value, str):
        raise SigningAttemptError("invalid_timestamp", f"{label} is not text")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise SigningAttemptError(
            "invalid_timestamp", f"{label} is not canonical UTC time"
        ) from error
    rendered = parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed) or rendered != value:
        raise SigningAttemptError(
            "invalid_timestamp", f"{label} is not canonical UTC time"
        )


def _canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        raise SigningAttemptError(
            "noncanonical_json", "signing-attempt evidence cannot be canonical JSON"
        ) from error


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise SigningAttemptError(
                "duplicate_json_key", f"signing-attempt JSON repeats {key!r}"
            )
        value[key] = child
    return value


def _reject_constant(token: str) -> Any:
    raise SigningAttemptError(
        "invalid_json", f"signing-attempt JSON contains {token}"
    )


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = read_private_pending(path, MAX_JSON_BYTES)
    except (OSError, PublicationError) as error:
        raise SigningAttemptError(
            "unsafe_evidence", f"cannot durably read {label}"
        ) from error
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except SigningAttemptError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SigningAttemptError(
            "invalid_json", f"{label} is not strict JSON"
        ) from error
    if type(value) is not dict or raw != _canonical_json(value):
        raise SigningAttemptError(
            "noncanonical_json", f"{label} is not canonical JSON"
        )
    return value, raw


def _sha256_file(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SigningAttemptError("input_missing", f"input is unavailable: {path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_size < 1
        or metadata.st_size > MAX_JSON_BYTES
    ):
        raise SigningAttemptError("unsafe_input", f"input is unsafe: {path}")
    try:
        data = path.read_bytes()
        rebound = path.lstat()
    except OSError as error:
        raise SigningAttemptError("input_unreadable", f"cannot read input: {path}") from error
    if metadata != rebound or len(data) != metadata.st_size:
        raise SigningAttemptError("input_changed", f"input changed: {path}")
    return hashlib.sha256(data).hexdigest()


def _canonical_repository(repository: Path) -> Path:
    repository = Path(repository)
    try:
        resolved = repository.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        raise SigningAttemptError(
            "repository_unavailable", "release repository is unavailable"
        ) from error
    if (
        not repository.is_absolute()
        or repository != resolved
        or resolved.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise SigningAttemptError(
            "unsafe_repository", "release repository is not one canonical owned directory"
        )
    return resolved


def _reject_legacy_outputs(root: Path) -> None:
    for relative in LEGACY_OUTPUTS:
        path = root / relative
        if os.path.lexists(path):
            raise SigningAttemptError(
                "legacy_signing_output_present",
                f"legacy non-atomic signing output is present: {relative}",
            )


def _verify_frozen_inputs(
    repository: Path,
    *,
    freeze_verifier: FreezeVerifier = verify_frozen_candidate,
    possession_verifier: PossessionVerifier = verify_possession_proof,
) -> FrozenSigningBindings:
    repository = _canonical_repository(repository)
    try:
        frozen = freeze_verifier(repository)
    except CandidateFreezeError as error:
        if error.code == "updater_verifier_unavailable":
            raise SigningAttemptError(
                "updater_possession_verifier_unavailable",
                "candidate updater verifier is operationally unavailable",
            ) from error
        raise SigningAttemptError(
            "candidate_freeze_invalid", f"frozen GA candidate is invalid: {error}"
        ) from error
    root = ga_root(repository)
    if (
        frozen.root != root
        or frozen.intent_path != root / "candidate-freeze/intent.json"
        or frozen.product_version != ACTIVE_RELEASE_IDENTITY.product_version
        or frozen.build_number != ACTIVE_RELEASE_IDENTITY.ga_build
        or SHA256_RE.fullmatch(frozen.intent_sha256) is None
    ):
        raise SigningAttemptError(
            "candidate_freeze_identity_drift",
            "frozen candidate differs from the single active GA identity",
        )
    _reject_legacy_outputs(root)
    freeze_intent, freeze_raw = _read_json(
        frozen.intent_path, "candidate-freeze intent"
    )
    if (
        hashlib.sha256(freeze_raw).hexdigest() != frozen.intent_sha256
        or freeze_intent.get("document") != FREEZE_DOCUMENT
        or freeze_intent.get("schema_version") != FREEZE_SCHEMA_VERSION
    ):
        raise SigningAttemptError(
            "candidate_freeze_intent_drift", "candidate-freeze intent changed"
        )
    try:
        identity = current_identity(repository, require_clean=True)
    except SourceIdentityError as error:
        raise SigningAttemptError(
            "source_identity_invalid", "release source identity cannot be verified"
        ) from error
    repository_commit = freeze_intent.get("repository_commit")
    release_source_sha256 = freeze_intent.get("release_source_sha256")
    if (
        not isinstance(repository_commit, str)
        or COMMIT_RE.fullmatch(repository_commit) is None
        or not isinstance(release_source_sha256, str)
        or SHA256_RE.fullmatch(release_source_sha256) is None
        or identity
        != {
            "repositoryCommit": repository_commit,
            "releaseSourceSha256": release_source_sha256,
        }
    ):
        raise SigningAttemptError(
            "source_identity_drift", "current source differs from the frozen GA source"
        )

    preflight = root / "profiles/signing-preflight.json"
    try:
        load_preflight_manifest(preflight)
        certificate_sha1, certificate_sha256 = signing_certificate_digests(preflight)
    except SigningPreflightError as error:
        raise SigningAttemptError(
            "signing_preflight_receipt_invalid",
            f"frozen signing-preflight receipt is invalid: {error}",
        ) from error
    try:
        verify_materialized_profiles(
            preflight,
            {
                "host": root / "profiles/host.provisionprofile",
                "proxy-agent": root / "profiles/proxy-agent.provisionprofile",
                "packet-tunnel": root / "profiles/packet-tunnel.provisionprofile",
            },
        )
    except SigningPreflightError as error:
        raise SigningAttemptError(
            "materialized_profile_mismatch",
            f"frozen provisioning profiles differ from the preflight receipt: {error}",
        ) from error
    try:
        validate_plan(repository, root)
    except (OSError, SigningPlanError, ValueError) as error:
        raise SigningAttemptError(
            "frozen_signing_plan_invalid",
            "frozen signing plan is invalid",
        ) from error
    try:
        updater = possession_verifier(repository, root)
    except UpdaterKeyPossessionOperationalError as error:
        raise SigningAttemptError(
            "updater_possession_verifier_unavailable",
            "operation-scoped updater verifier session is unavailable",
        ) from error
    except (OSError, UpdaterKeyPossessionError, ValueError) as error:
        raise SigningAttemptError(
            "updater_possession_receipt_invalid",
            "frozen updater possession receipt is invalid",
        ) from error

    preflight_sha256 = _sha256_file(preflight)
    signing_plan_sha256 = _sha256_file(root / "signing-plan.json")
    expected_bindings = {
        "signing_preflight_sha256": preflight_sha256,
        "signing_plan_sha256": signing_plan_sha256,
        "updater_key_possession_proof_sha256": updater.proof_sha256,
        "updater_embedded_public_key_sha256": updater.embedded_public_key_sha256,
        "updater_tauri_config_sha256": updater.tauri_config_sha256,
    }
    if any(freeze_intent.get(key) != value for key, value in expected_bindings.items()):
        raise SigningAttemptError(
            "frozen_signing_binding_drift",
            "candidate-freeze intent differs from the reopened signing inputs",
        )
    if (
        CERT_SHA1_RE.fullmatch(certificate_sha1) is None
        or CERT_SHA256_RE.fullmatch(certificate_sha256) is None
    ):
        raise SigningAttemptError(
            "signing_certificate_identity_invalid",
            "frozen signing certificate fingerprints are malformed",
        )
    return FrozenSigningBindings(
        frozen=frozen,
        repository_commit=repository_commit,
        release_source_sha256=release_source_sha256,
        signing_preflight_sha256=preflight_sha256,
        signing_plan_sha256=signing_plan_sha256,
        signing_certificate_sha1=certificate_sha1,
        signing_certificate_sha256=certificate_sha256,
        updater_key_possession_proof_sha256=updater.proof_sha256,
        updater_embedded_public_key_sha256=updater.embedded_public_key_sha256,
        updater_tauri_config_sha256=updater.tauri_config_sha256,
    )


def _intent(bindings: FrozenSigningBindings, identifier: str, now: str) -> dict[str, Any]:
    return {
        "attempt_id": identifier,
        "candidate_freeze_intent_sha256": bindings.frozen.intent_sha256,
        "created_at": now,
        "document": ATTEMPT_DOCUMENT,
        "product": {
            "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            "version": ACTIVE_RELEASE_IDENTITY.product_version,
        },
        "release_source_sha256": bindings.release_source_sha256,
        "repository_commit": bindings.repository_commit,
        "schema_version": SCHEMA_VERSION,
        "signing_certificate_sha256": bindings.signing_certificate_sha256,
        "signing_preflight_sha256": bindings.signing_preflight_sha256,
        "signing_plan_sha256": bindings.signing_plan_sha256,
        "updater_embedded_public_key_sha256": (
            bindings.updater_embedded_public_key_sha256
        ),
        "updater_key_possession_proof_sha256": (
            bindings.updater_key_possession_proof_sha256
        ),
        "updater_tauri_config_sha256": bindings.updater_tauri_config_sha256,
    }


def _event(
    *,
    sequence: int,
    previous: str | None,
    intent_sha256: str,
    state: str,
    recorded_at: str,
    failure_code: str | None = None,
    exit_code: int | None = None,
) -> dict[str, Any]:
    if state not in STATES:
        raise SigningAttemptError("invalid_state", "signing-attempt state is invalid")
    value: dict[str, Any] = {
        "document": EVENT_DOCUMENT,
        "event_sha256": None,
        "exit_code": exit_code,
        "failure_code": failure_code,
        "intent_sha256": intent_sha256,
        "previous_event_sha256": previous,
        "recorded_at": recorded_at,
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
        "state": state,
    }
    digest_input = dict(value)
    digest_input.pop("event_sha256")
    value["event_sha256"] = hashlib.sha256(_canonical_json(digest_input)).hexdigest()
    return value


def _validate_intent(value: dict[str, Any], identifier: str) -> None:
    product = value.get("product")
    digest_fields = INTENT_FIELDS - {
        "attempt_id",
        "created_at",
        "document",
        "product",
        "repository_commit",
        "schema_version",
        "signing_certificate_sha256",
    }
    if (
        set(value) != INTENT_FIELDS
        or value.get("document") != ATTEMPT_DOCUMENT
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("attempt_id") != identifier
        or product
        != {
            "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            "version": ACTIVE_RELEASE_IDENTITY.product_version,
        }
        or not isinstance(value.get("created_at"), str)
        or not isinstance(value.get("repository_commit"), str)
        or COMMIT_RE.fullmatch(value["repository_commit"]) is None
        or not isinstance(value.get("signing_certificate_sha256"), str)
        or CERT_SHA256_RE.fullmatch(value["signing_certificate_sha256"]) is None
        or any(
            not isinstance(value.get(field), str)
            or SHA256_RE.fullmatch(value[field]) is None
            for field in digest_fields
        )
    ):
        raise SigningAttemptError(
            "invalid_attempt_intent", "signing-attempt intent identity is invalid"
        )
    _validate_timestamp(value["created_at"], "signing-attempt created_at")


def _validate_event(
    value: dict[str, Any],
    *,
    sequence: int,
    previous: str | None,
    intent_sha256: str,
) -> None:
    event_sha256 = value.get("event_sha256")
    state = value.get("state")
    if (
        set(value) != EVENT_FIELDS
        or value.get("document") != EVENT_DOCUMENT
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("sequence") != sequence
        or value.get("previous_event_sha256") != previous
        or value.get("intent_sha256") != intent_sha256
        or state not in STATES
        or not isinstance(value.get("recorded_at"), str)
        or (
            value.get("failure_code") is not None
            and (
                not isinstance(value["failure_code"], str)
                or FAILURE_CODE_RE.fullmatch(value["failure_code"]) is None
            )
        )
        or (value.get("exit_code") is not None and type(value["exit_code"]) is not int)
        or not isinstance(event_sha256, str)
        or SHA256_RE.fullmatch(event_sha256) is None
    ):
        raise SigningAttemptError(
            "invalid_attempt_event", "signing-attempt event identity is invalid"
        )
    if (
        state in FAILURE_EVIDENCE_STATES
        and value["failure_code"] is None
        or state not in FAILURE_EVIDENCE_STATES
        and value["failure_code"] is not None
        or state != "failed"
        and value["exit_code"] is not None
        or state == "verification_blocked"
        and value["failure_code"] not in RECOVERABLE_VERIFICATION_ERROR_CODES
    ):
        raise SigningAttemptError(
            "invalid_attempt_event", "signing-attempt failure evidence is invalid"
        )
    _validate_timestamp(value["recorded_at"], "signing-attempt recorded_at")
    digest_input = dict(value)
    digest_input.pop("event_sha256")
    if hashlib.sha256(_canonical_json(digest_input)).hexdigest() != event_sha256:
        raise SigningAttemptError(
            "attempt_event_hash_mismatch", "signing-attempt event hash differs"
        )


def _attempt_names(attempts_root: Path) -> tuple[str, ...]:
    try:
        names = sorted(os.listdir(attempts_root))
    except OSError as error:
        raise SigningAttemptError(
            "attempt_inventory_unavailable", "cannot enumerate signing attempts"
        ) from error
    if any(ATTEMPT_ID_RE.fullmatch(name) is None for name in names):
        raise SigningAttemptError(
            "attempt_inventory_invalid", "signing-attempt root has an unexpected entry"
        )
    expected = tuple(f"{number:08d}" for number in range(1, len(names) + 1))
    if tuple(names) != expected:
        raise SigningAttemptError(
            "attempt_sequence_invalid", "signing-attempt identifiers are not contiguous"
        )
    return tuple(names)


def _load_attempt(attempts_root: Path, identifier: str) -> Attempt:
    if ATTEMPT_ID_RE.fullmatch(identifier) is None:
        raise SigningAttemptError("invalid_attempt_id", "signing-attempt id is invalid")
    root = attempts_root / identifier
    try:
        metadata = root.lstat()
        names = set(os.listdir(root))
    except OSError as error:
        raise SigningAttemptError(
            "attempt_unavailable", f"signing attempt {identifier} is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or root.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SigningAttemptError(
            "unsafe_attempt", f"signing attempt {identifier} is not private"
        )
    event_names = sorted(name for name in names if EVENT_NAME_RE.fullmatch(name))
    allowed = {INTENT_NAME, WORK_NAME, PUBLISH_READY_NAME, *event_names}
    if (
        names - allowed
        or INTENT_NAME not in names
        or not event_names
        or WORK_NAME in names and PUBLISH_READY_NAME in names
    ):
        raise SigningAttemptError(
            "attempt_inventory_invalid", f"signing attempt {identifier} inventory is invalid"
        )
    intent, raw = _read_json(root / INTENT_NAME, "signing-attempt intent")
    _validate_intent(intent, identifier)
    intent_sha256 = hashlib.sha256(raw).hexdigest()
    expected_event_names = [
        f"event-{sequence:08d}.json" for sequence in range(1, len(event_names) + 1)
    ]
    if event_names != expected_event_names:
        raise SigningAttemptError(
            "attempt_event_sequence_invalid", "signing-attempt events are not contiguous"
        )
    events: list[dict[str, Any]] = []
    previous: str | None = None
    for sequence, name in enumerate(event_names, 1):
        event, _event_raw = _read_json(root / name, "signing-attempt event")
        _validate_event(
            event,
            sequence=sequence,
            previous=previous,
            intent_sha256=intent_sha256,
        )
        if events:
            previous_event = events[-1]
            if event["state"] not in TRANSITIONS[str(previous_event["state"])]:
                raise SigningAttemptError(
                    "invalid_attempt_transition",
                    "signing-attempt state transition is invalid",
                )
            if previous_event["state"] == "outcome_unknown" and not (
                len(events) >= 2
                and events[-2]["state"] == "publishing"
                and previous_event["failure_code"]
                == SIGNING_OUTPUT_PUBLISH_REPLY_UNKNOWN
                and previous_event["exit_code"] is None
            ):
                raise SigningAttemptError(
                    "invalid_attempt_transition",
                    "only a publication-bound outcome may continue",
                )
        events.append(event)
        previous = str(event["event_sha256"])
    if events[0]["state"] != "prepared":
        raise SigningAttemptError(
            "invalid_attempt_initial_state", "signing attempt did not begin prepared"
        )
    return Attempt(identifier, root, intent, intent_sha256, tuple(events))


def _append_event(
    repository: Path,
    attempt: Attempt,
    state: str,
    *,
    clock: Clock,
    failure_code: str | None = None,
    exit_code: int | None = None,
) -> Attempt:
    if attempt.state == "outcome_unknown" and not _is_publication_outcome_unknown(
        attempt
    ):
        raise SigningAttemptError(
            "invalid_attempt_transition",
            "only a publication-bound outcome may continue",
        )
    if state not in TRANSITIONS[attempt.state]:
        raise SigningAttemptError(
            "invalid_attempt_transition",
            f"cannot transition signing attempt from {attempt.state} to {state}",
        )
    sequence = len(attempt.events) + 1
    value = _event(
        sequence=sequence,
        previous=str(attempt.events[-1]["event_sha256"]),
        intent_sha256=attempt.intent_sha256,
        state=state,
        recorded_at=clock(),
        failure_code=failure_code,
        exit_code=exit_code,
    )
    name = f"event-{sequence:08d}.json"
    try:
        with exclusive_rooted_directory_lock(
            repository, attempt.root, require_private=True
        ) as descriptor:
            write_private_pending_locked(
                descriptor,
                attempt.root,
                name,
                _canonical_json(value),
            )
    except (OSError, PublicationError) as error:
        raise SigningAttemptOutcomeUnknown(
            "signing-attempt event durability is unknown; resume is required"
        ) from error
    return _load_attempt(attempt.root.parent, attempt.identifier)


def _create_attempt(
    repository: Path,
    attempts_root: Path,
    attempts_descriptor: int,
    bindings: FrozenSigningBindings,
    *,
    clock: Clock,
) -> Attempt:
    names = _attempt_names(attempts_root)
    next_number = len(names) + 1
    if next_number > 99_999_999:
        raise SigningAttemptError(
            "attempt_limit_reached", "signing-attempt identifier space is exhausted"
        )
    identifier = f"{next_number:08d}"
    now = clock()
    intent = _intent(bindings, identifier, now)
    intent_raw = _canonical_json(intent)
    intent_sha256 = hashlib.sha256(intent_raw).hexdigest()
    first_event = _event(
        sequence=1,
        previous=None,
        intent_sha256=intent_sha256,
        state="prepared",
        recorded_at=now,
    )
    try:
        publish_private_directory_locked(
            attempts_descriptor,
            attempts_root,
            identifier,
            {
                INTENT_NAME: intent_raw,
                "event-00000001.json": _canonical_json(first_event),
            },
        )
    except (OSError, PublicationError) as error:
        if os.path.lexists(attempts_root / identifier):
            raise SigningAttemptOutcomeUnknown(
                "signing-attempt allocation outcome is unknown; resume is required"
            ) from error
        raise SigningAttemptError(
            "attempt_allocation_failed", "cannot durably allocate a signing attempt"
        ) from error
    attempt = _load_attempt(attempts_root, identifier)
    try:
        with exclusive_rooted_directory_lock(
            repository, attempt.root, require_private=True
        ) as descriptor:
            ensure_private_directory_locked(descriptor, attempt.root, WORK_NAME)
    except (OSError, PublicationError) as error:
        raise SigningAttemptOutcomeUnknown(
            "signing-attempt work allocation outcome is unknown; resume is required"
        ) from error
    return _load_attempt(attempts_root, identifier)


def _ensure_attempts_root(repository: Path) -> Path:
    root = ga_root(repository)
    transactions = root / "transactions"
    attempts = root / ATTEMPTS_RELATIVE
    try:
        with exclusive_rooted_directory_lock(repository, root) as descriptor:
            ensure_private_directory_locked(descriptor, root, "transactions")
        with exclusive_rooted_directory_lock(
            repository, transactions, require_private=True
        ) as descriptor:
            ensure_private_directory_locked(descriptor, transactions, "signing-attempts")
    except (OSError, PublicationError) as error:
        raise SigningAttemptError(
            "attempt_root_unavailable", "cannot establish the private signing-attempt root"
        ) from error
    return attempts


def production_live_readiness_verifier(root: Path) -> None:
    """Recheck time-sensitive profile authorization immediately before codesign."""

    try:
        verify_live_profile_validity(root / "profiles/signing-preflight.json")
    except SigningPreflightError as error:
        raise SigningAttemptError(
            "signing_profile_readiness_invalid",
            f"provisioning profiles are not currently signable: {error}",
        ) from error


def _require_helper_work_root(repository: Path, work: Path) -> None:
    try:
        classified = candidate_signing_output(repository, work)
    except BuildIdentityError as error:
        raise SigningAttemptError(
            "signing_helper_work_root_invalid",
            f"signing helper work root is not transaction-owned: {error}",
        ) from error
    if (
        classified.root != work
        or classified.context is not CandidateBundleContext.SIGNING_ATTEMPT_WORK
    ):
        raise SigningAttemptError(
            "signing_helper_work_root_invalid",
            "signing helper work root is not the exact private work stage",
        )


def production_helper_runner(work: Path, certificate_sha1: str, certificate_sha256: str) -> int:
    repository = Path(__file__).resolve().parent.parent
    _require_helper_work_root(repository, work)
    command = (
        str(repository / "scripts/run_ga_signing_attempt.sh"),
        "--transaction-owned",
    )
    environment = dict(os.environ)
    environment.update(
        {
            "CFW_SIGNING_ATTEMPT_WORK": str(work),
            "CFW_SIGNING_CERTIFICATE_SHA1": certificate_sha1,
            "CFW_SIGNING_CERTIFICATE_SHA256": certificate_sha256,
        }
    )
    try:
        completed = run_bounded_process(
            command,
            cwd=repository,
            environment=environment,
            timeout=HELPER_TIMEOUT_SECONDS,
            output_limit=MAX_HELPER_OUTPUT_BYTES,
        )
    except BoundedProcessError as error:
        if error.stdout:
            os.write(sys.stdout.fileno(), error.stdout)
        if error.stderr:
            os.write(sys.stderr.fileno(), error.stderr)
        raise SigningAttemptError(
            f"signing_helper_{error.reason}", "fixed signing helper did not complete"
        ) from error
    if completed.stdout:
        os.write(sys.stdout.fileno(), completed.stdout)
    if completed.stderr:
        os.write(sys.stderr.fileno(), completed.stderr)
    return completed.returncode


def production_verification_runner(
    signing_output: Path,
    context: CandidateBundleContext,
) -> None:
    if context is CandidateBundleContext.UNSIGNED_HOST:
        raise SigningAttemptError(
            "signing_verification_context_invalid",
            "signed GA verification cannot use unsigned-host context",
        )
    repository = Path(__file__).resolve().parent.parent
    app = signing_output / SIGNED_APP_WITHIN_OUTPUT
    native = signing_output / SIGNED_NATIVE_PRODUCTS_NAME
    commands = (
        (
            "codesign",
            ("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=4", str(app)),
        ),
        (
            "release_app",
            (
                str(repository / "scripts/verify_release_app.sh"),
                "--pre-notary",
                str(app),
                str(native),
                "--context",
                context.value,
            ),
        ),
    )
    environment = dict(os.environ)
    for phase, command in commands:
        try:
            completed = run_bounded_process(
                command,
                cwd=repository,
                environment=environment,
                timeout=600,
                output_limit=MAX_HELPER_OUTPUT_BYTES,
            )
        except BoundedProcessError as error:
            raise SigningAttemptError(
                f"signing_{phase}_{error.reason}",
                f"fixed {phase} signing verification did not complete",
            ) from error
        if completed.returncode != 0:
            raise SigningAttemptError(
                f"signing_{phase}_failed",
                f"signed GA {phase} verification failed",
            )


def _create_transformation(repository: Path, output: Path) -> Mapping[str, Any]:
    return create_attempt_receipt(repository, output)


def _verify_transformation(repository: Path, output: Path) -> Mapping[str, Any]:
    return verify_attempt_receipt(repository, output)


def _load_transformation_receipt(
    repository: Path,
    output: Path,
) -> Mapping[str, Any]:
    return load_attempt_receipt(repository, output)


def _verify_canonical_transformation(repository: Path) -> Mapping[str, Any]:
    return verify_receipt(repository)


def _validate_output_inventory(output: Path) -> None:
    try:
        metadata = output.lstat()
        names = set(os.listdir(output))
    except OSError as error:
        raise SigningAttemptError(
            "signing_output_unavailable", "signing-output is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or output.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or names
        != {"signing-input", SIGNED_NATIVE_PRODUCTS_NAME, TRANSFORMATION_RECEIPT_NAME}
    ):
        raise SigningAttemptError(
            "signing_output_inventory_invalid", "signing-output inventory is invalid"
        )
    signing_input = output / "signing-input"
    native = output / SIGNED_NATIVE_PRODUCTS_NAME
    for path in (signing_input, native):
        try:
            child = path.lstat()
        except OSError as error:
            raise SigningAttemptError(
                "signing_output_inventory_invalid",
                "signing-output private root is unavailable",
            ) from error
        if (
            not stat.S_ISDIR(child.st_mode)
            or path.is_symlink()
            or child.st_uid != os.geteuid()
            or stat.S_IMODE(child.st_mode) != 0o700
        ):
            raise SigningAttemptError(
                "signing_output_inventory_invalid",
                "signing-output contains an unsafe private root",
            )

    app = output / SIGNED_APP_WITHIN_OUTPUT
    for path in (app, native):
        child = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(child.st_mode):
            raise SigningAttemptError(
                "signing_output_inventory_invalid", "signing-output contains an unsafe root"
            )


def _require_no_canonical_or_notary_state(
    repository: Path,
) -> None:
    root = ga_root(repository)
    guarded = (
        root / SIGNING_OUTPUT_RELATIVE,
        *(root / relative for relative in _DOWNSTREAM_RECOVERY_GUARDS),
    )
    if any(os.path.lexists(path) for path in guarded):
        raise SigningAttemptError(
            VERIFICATION_RECOVERY_PRECONDITION_FAILED,
            "verification recovery is unavailable after downstream state exists",
        )


def _require_no_downstream_recovery_state(
    repository: Path,
    attempt: Attempt,
) -> None:
    _require_no_canonical_or_notary_state(repository)
    if os.path.lexists(attempt.publish_ready):
        raise SigningAttemptError(
            VERIFICATION_RECOVERY_PRECONDITION_FAILED,
            "verification-blocked work already has a publish-ready stage",
        )


def _can_block_transformation_verification(
    repository: Path,
    attempt: Attempt,
    error: SigningTransformationError,
    *,
    receipt_loader: TransformationReceiptLoader,
) -> bool:
    if error.code not in RECOVERABLE_VERIFICATION_ERROR_CODES:
        return False
    try:
        _require_no_downstream_recovery_state(repository, attempt)
        _validate_output_inventory(attempt.work)
        receipt_loader(repository, attempt.work)
        fsync_private_tree(attempt.work)
        _require_no_downstream_recovery_state(repository, attempt)
        _validate_output_inventory(attempt.work)
        receipt_loader(repository, attempt.work)
    except (
        OSError,
        PublicationError,
        SigningAttemptError,
        SigningTransformationError,
    ):
        return False
    return True


def _raise_transformation_failure(
    repository: Path,
    attempt: Attempt,
    error: SigningTransformationError,
    *,
    receipt_loader: TransformationReceiptLoader,
    outcome_unknown: bool = False,
) -> None:
    if not outcome_unknown and _can_block_transformation_verification(
        repository,
        attempt,
        error,
        receipt_loader=receipt_loader,
    ):
        raise SigningVerificationBlocked(error.code) from error
    if outcome_unknown:
        raise SigningAttemptError(
            "signing_transformation_outcome_unknown",
            "private signing-transformation receipt cannot be recovered",
        ) from error
    raise SigningAttemptError(
        "signing_transformation_failed",
        "private signing transformation failed",
    ) from error


def _prepare_output(
    repository: Path,
    attempt: Attempt,
    *,
    verification_runner: VerificationRunner,
    transformation_creator: TransformationCreator,
    transformation_verifier: TransformationVerifier,
    transformation_receipt_loader: TransformationReceiptLoader,
) -> None:
    if not attempt.work.is_dir() or attempt.work.is_symlink():
        raise SigningAttemptError(
            "attempt_work_unavailable", "signing-attempt work root is unavailable"
        )
    verification_runner(attempt.work, CandidateBundleContext.SIGNING_ATTEMPT_WORK)
    try:
        transformation_creator(repository, attempt.work)
    except SigningTransformationOutcomeUnknown:
        try:
            transformation_verifier(repository, attempt.work)
        except SigningTransformationError as error:
            _raise_transformation_failure(
                repository,
                attempt,
                error,
                receipt_loader=transformation_receipt_loader,
                outcome_unknown=True,
            )
    except SigningTransformationError as error:
        _raise_transformation_failure(
            repository,
            attempt,
            error,
            receipt_loader=transformation_receipt_loader,
        )
    try:
        transformation_verifier(repository, attempt.work)
    except SigningTransformationError as error:
        _raise_transformation_failure(
            repository,
            attempt,
            error,
            receipt_loader=transformation_receipt_loader,
        )
    _validate_output_inventory(attempt.work)
    try:
        publish_private_directory_exclusive(attempt.work, attempt.publish_ready)
    except (OSError, PublicationError) as error:
        raise SigningAttemptOutcomeUnknown(
            "signing-attempt prepare rename outcome is unknown; resume is required"
        ) from error
    if attempt.work.exists() or not attempt.publish_ready.exists():
        raise SigningAttemptOutcomeUnknown(
            "signing-attempt prepare rename cannot be confirmed; resume is required"
        )


def _reverify_publish_ready(
    repository: Path,
    attempt: Attempt,
    *,
    verification_runner: VerificationRunner,
    transformation_verifier: TransformationVerifier,
) -> None:
    _validate_output_inventory(attempt.publish_ready)
    verification_runner(
        attempt.publish_ready,
        CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY,
    )
    try:
        transformation_verifier(repository, attempt.publish_ready)
    except SigningTransformationError as error:
        raise SigningAttemptError(
            "signing_transformation_failed",
            f"private signing transformation failed: {error}",
        ) from error


def _reverify_private_stage(
    repository: Path,
    output: Path,
    context: CandidateBundleContext,
    *,
    verification_runner: VerificationRunner,
    transformation_verifier: TransformationVerifier,
    transformation_receipt_loader: TransformationReceiptLoader,
) -> None:
    _validate_output_inventory(output)
    transformation_receipt_loader(repository, output)
    verification_runner(output, context)
    transformation_verifier(repository, output)


def _verification_recovery_failure_code(error: BaseException) -> str:
    if (
        isinstance(error, SigningTransformationError)
        and error.code in RECOVERABLE_VERIFICATION_ERROR_CODES
    ):
        return error.code
    if (
        isinstance(error, SigningAttemptError)
        and error.code == VERIFICATION_RECOVERY_PRECONDITION_FAILED
    ):
        return error.code
    return VERIFICATION_RECOVERY_FAILED


def _fail_verification_recovery(
    repository: Path,
    attempt: Attempt,
    error: BaseException,
    *,
    clock: Clock,
) -> None:
    failure_code = _verification_recovery_failure_code(error)
    _append_event(
        repository,
        attempt,
        "failed",
        clock=clock,
        failure_code=failure_code,
    )
    raise SigningAttemptError(
        failure_code,
        "bounded private signing verification recovery failed",
    ) from error


def _resume_exact_work_verification(
    repository: Path,
    attempt: Attempt,
    canonical: Path,
    *,
    bindings: FrozenSigningBindings,
    clock: Clock,
    freeze_verifier: FreezeVerifier,
    possession_verifier: PossessionVerifier,
    publisher: Publisher,
    verification_runner: VerificationRunner,
    transformation_verifier: TransformationVerifier,
    transformation_receipt_loader: TransformationReceiptLoader,
) -> Path:
    if attempt.state == "verification_blocked":
        try:
            if (
                attempt.events[-1]["failure_code"]
                not in RECOVERABLE_VERIFICATION_ERROR_CODES
            ):
                raise SigningAttemptError(
                    VERIFICATION_RECOVERY_PRECONDITION_FAILED,
                    "verification-blocked cause is not recoverable",
                )
            _require_no_downstream_recovery_state(repository, attempt)
            _validate_output_inventory(attempt.work)
            transformation_receipt_loader(repository, attempt.work)
        except (
            OSError,
            PublicationError,
            SigningAttemptError,
            SigningTransformationError,
        ) as error:
            _fail_verification_recovery(repository, attempt, error, clock=clock)
        attempt = _append_event(
            repository,
            attempt,
            "verification_recovering",
            clock=clock,
        )
        try:
            _reverify_private_stage(
                repository,
                attempt.work,
                CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                verification_runner=verification_runner,
                transformation_verifier=transformation_verifier,
                transformation_receipt_loader=transformation_receipt_loader,
            )
        except (
            OSError,
            PublicationError,
            SigningAttemptError,
            SigningTransformationError,
        ) as error:
            _fail_verification_recovery(repository, attempt, error, clock=clock)
        attempt = _append_event(
            repository,
            attempt,
            "verification_committing",
            clock=clock,
        )
    elif attempt.state == "verification_recovering":
        attempt = _append_event(
            repository,
            attempt,
            "failed",
            clock=clock,
            failure_code=VERIFICATION_RECOVERY_INTERRUPTED,
        )
        raise SigningAttemptError(
            VERIFICATION_RECOVERY_INTERRUPTED,
            "bounded private signing verification recovery was interrupted",
        )
    elif attempt.state != "verification_committing":
        raise SigningAttemptError(
            "verification_recovery_state_invalid",
            "signing attempt is not at a verification recovery state",
        )

    try:
        _require_no_canonical_or_notary_state(repository)
        work_exists = os.path.lexists(attempt.work)
        ready_exists = os.path.lexists(attempt.publish_ready)
        if work_exists == ready_exists:
            raise SigningAttemptError(
                VERIFICATION_RECOVERY_PRECONDITION_FAILED,
                "verification commit requires exactly one private stage",
            )
        selected = attempt.work if work_exists else attempt.publish_ready
        selected_context = (
            CandidateBundleContext.SIGNING_ATTEMPT_WORK
            if work_exists
            else CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY
        )
        _reverify_private_stage(
            repository,
            selected,
            selected_context,
            verification_runner=verification_runner,
            transformation_verifier=transformation_verifier,
            transformation_receipt_loader=transformation_receipt_loader,
        )
    except (
        OSError,
        PublicationError,
        SigningAttemptError,
        SigningTransformationError,
    ) as error:
        _fail_verification_recovery(repository, attempt, error, clock=clock)

    if work_exists:
        try:
            publish_private_directory_exclusive(attempt.work, attempt.publish_ready)
        except (DurabilityOutcomeUnknown, OSError, PublicationError) as error:
            raise SigningAttemptOutcomeUnknown(
                "verification commit rename outcome is unknown; resume is required"
            ) from error
        if attempt.work.exists() or not attempt.publish_ready.exists():
            raise SigningAttemptOutcomeUnknown(
                "verification commit rename cannot be confirmed; resume is required"
            )

    try:
        _reverify_private_stage(
            repository,
            attempt.publish_ready,
            CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY,
            verification_runner=verification_runner,
            transformation_verifier=transformation_verifier,
            transformation_receipt_loader=transformation_receipt_loader,
        )
    except (
        OSError,
        PublicationError,
        SigningAttemptError,
        SigningTransformationError,
    ) as error:
        _fail_verification_recovery(repository, attempt, error, clock=clock)

    attempt = _append_event(repository, attempt, "verified", clock=clock)
    _publish_attempt(
        repository,
        attempt,
        canonical,
        bindings=bindings,
        clock=clock,
        freeze_verifier=freeze_verifier,
        possession_verifier=possession_verifier,
        publisher=publisher,
        verification_runner=verification_runner,
        transformation_verifier=transformation_verifier,
    )
    return canonical


def _reverify_canonical_transformation(
    repository: Path,
    verifier: CanonicalTransformationVerifier,
) -> None:
    try:
        verifier(repository)
    except SigningTransformationError as error:
        raise SigningAttemptError(
            "canonical_signing_transformation_failed",
            f"canonical signing transformation verification failed: {error}",
        ) from error


def _publish_attempt(
    repository: Path,
    attempt: Attempt,
    canonical: Path,
    *,
    bindings: FrozenSigningBindings,
    clock: Clock,
    freeze_verifier: FreezeVerifier,
    possession_verifier: PossessionVerifier,
    publisher: Publisher,
    verification_runner: VerificationRunner,
    transformation_verifier: TransformationVerifier,
) -> Attempt:
    if attempt.state == "outcome_unknown" and not _is_publication_outcome_unknown(
        attempt
    ):
        _candidate_retirement_required(
            attempt, "has no publication-bound recoverable output"
        )
    reopened = _verify_frozen_inputs(
        repository,
        freeze_verifier=freeze_verifier,
        possession_verifier=possession_verifier,
    )
    if reopened != bindings:
        raise SigningAttemptError(
            "frozen_input_drift", "frozen inputs changed during the signing attempt"
        )
    try:
        _reverify_publish_ready(
            repository,
            attempt,
            verification_runner=verification_runner,
            transformation_verifier=transformation_verifier,
        )
    except SigningAttemptError as error:
        if attempt.state == "verified":
            _append_event(
                repository,
                attempt,
                "failed",
                clock=clock,
                failure_code=error.code,
            )
            raise
        _candidate_retirement_required(
            attempt,
            f"failed publish-ready re-verification ({error.code})",
        )
    if attempt.state in {"verified", "outcome_unknown"}:
        attempt = _append_event(repository, attempt, "publishing", clock=clock)
    elif attempt.state != "publishing":
        raise SigningAttemptError(
            "attempt_not_publishable", "signing attempt is not at a publishable state"
        )
    try:
        publisher(attempt.publish_ready, canonical)
    except (DurabilityOutcomeUnknown, OSError, PublicationError) as error:
        try:
            attempt = _append_event(
                repository,
                attempt,
                "outcome_unknown",
                clock=clock,
                failure_code=SIGNING_OUTPUT_PUBLISH_REPLY_UNKNOWN,
            )
        except SigningAttemptError as journal_error:
            raise SigningAttemptOutcomeUnknown(
                "signing-output publication outcome is unknown and the "
                "outcome_unknown event durability could not be confirmed; run "
                "the fixed resume entry"
            ) from ExceptionGroup(
                "signing-output publication raised and outcome journal "
                "confirmation is unknown",
                [error, journal_error],
            )
        raise SigningAttemptOutcomeUnknown(
            "signing-output publication outcome is unknown; run the fixed resume entry"
        ) from error
    attempt = _append_event(repository, attempt, "published", clock=clock)
    return attempt


def _bindings_match_intent(bindings: FrozenSigningBindings, attempt: Attempt) -> bool:
    expected = _intent(bindings, attempt.identifier, str(attempt.intent["created_at"]))
    return attempt.intent == expected


def _pre_sign_output_is_pristine(repository: Path, attempt: Attempt) -> bool:
    if os.path.lexists(attempt.publish_ready):
        return False
    try:
        attempt.work.lstat()
    except FileNotFoundError:
        return not os.path.lexists(attempt.work) and not os.path.lexists(
            attempt.publish_ready
        )
    except OSError as error:
        raise SigningAttemptError(
            "attempt_work_unavailable",
            "signing-attempt work cannot be inspected before recovery",
        ) from error
    try:
        classified = candidate_signing_output(repository, attempt.work)
    except BuildIdentityError as error:
        raise SigningAttemptError(
            "attempt_work_unsafe",
            f"signing-attempt work is not the exact private work stage: {error}",
        ) from error
    if classified.context is not CandidateBundleContext.SIGNING_ATTEMPT_WORK:
        raise SigningAttemptError(
            "attempt_work_unsafe",
            "signing-attempt work has the wrong private output stage",
        )
    try:
        with exclusive_rooted_directory_lock(
            repository, attempt.work, require_private=True
        ) as descriptor:
            return os.listdir(descriptor) == [] and not os.path.lexists(
                attempt.publish_ready
            )
    except (OSError, PublicationError) as error:
        raise SigningAttemptError(
            "attempt_work_unavailable",
            "signing-attempt work cannot be inspected before recovery",
        ) from error


def _is_abandoned_before_signing(repository: Path, attempt: Attempt) -> bool:
    if len(attempt.events) < 2:
        return False
    previous = attempt.events[-2]
    terminal = attempt.events[-1]
    return (
        previous["state"] == "prepared"
        and terminal["state"] == "failed"
        and terminal["failure_code"] == ABANDONED_BEFORE_SIGNING
        and terminal["exit_code"] is None
        and _pre_sign_output_is_pristine(repository, attempt)
    )


def _is_publication_outcome_unknown(attempt: Attempt) -> bool:
    if len(attempt.events) < 2:
        return False
    previous = attempt.events[-2]
    terminal = attempt.events[-1]
    return (
        previous["state"] == "publishing"
        and terminal["state"] == "outcome_unknown"
        and terminal["failure_code"] == SIGNING_OUTPUT_PUBLISH_REPLY_UNKNOWN
        and terminal["exit_code"] is None
        and all(
            event["failure_code"] != INTERRUPTED_DURING_SIGNING
            for event in attempt.events
        )
    )


def _candidate_retirement_required(attempt: Attempt, reason: str) -> None:
    raise SigningAttemptError(
        "candidate_retirement_required",
        f"signing attempt {attempt.identifier} {reason}; preserve the frozen "
        "lineage and allocate a successor build",
    )


def _reconcile_existing(
    repository: Path,
    attempts_root: Path,
    bindings: FrozenSigningBindings,
    canonical: Path,
    *,
    clock: Clock,
    confirmer: Confirmer,
    publisher: Publisher,
    verification_runner: VerificationRunner,
    transformation_verifier: TransformationVerifier,
    transformation_receipt_loader: TransformationReceiptLoader,
    canonical_transformation_verifier: CanonicalTransformationVerifier,
    freeze_verifier: FreezeVerifier,
    possession_verifier: PossessionVerifier,
) -> Path | None:
    names = _attempt_names(attempts_root)
    if not names:
        if os.path.lexists(canonical):
            raise SigningAttemptError(
                "orphan_canonical_output",
                "canonical signing-output exists without a signing attempt",
            )
        return None
    attempts = tuple(_load_attempt(attempts_root, name) for name in names)
    if any(not _bindings_match_intent(bindings, attempt) for attempt in attempts):
        raise SigningAttemptError(
            "attempt_input_drift", "a signing attempt differs from frozen inputs"
        )
    latest = attempts[-1]

    publication_outcome_unknown = _is_publication_outcome_unknown(latest)
    if latest.state == "outcome_unknown" and not publication_outcome_unknown:
        _candidate_retirement_required(
            latest, "has no uniquely recoverable signed output"
        )

    canonical_exists = os.path.lexists(canonical)
    ready_exists = os.path.lexists(latest.publish_ready)
    if canonical_exists:
        if ready_exists:
            raise SigningAttemptError(
                "ambiguous_signing_output",
                "both private publish-ready and canonical signing-output exist",
            )
        if latest.state not in {"publishing", "published"} and not (
            publication_outcome_unknown
        ):
            raise SigningAttemptError(
                "unexpected_canonical_output",
                "canonical signing-output appeared before the publish boundary",
            )
        _validate_output_inventory(canonical)
        verification_runner(
            canonical, CandidateBundleContext.CANONICAL_NATIVE_CONTENT
        )
        _reverify_canonical_transformation(
            repository, canonical_transformation_verifier
        )
        try:
            confirmer(latest.publish_ready, canonical)
        except (OSError, PublicationError) as error:
            raise SigningAttemptOutcomeUnknown(
                "canonical signing-output durability cannot be confirmed"
            ) from error
        if latest.state != "published":
            latest = _append_event(repository, latest, "published", clock=clock)
        return canonical

    if latest.state == "published":
        raise SigningAttemptError(
            "published_output_missing", "published signing-output is missing"
        )
    if latest.state in {
        "verification_blocked",
        "verification_recovering",
        "verification_committing",
    }:
        return _resume_exact_work_verification(
            repository,
            latest,
            canonical,
            bindings=bindings,
            clock=clock,
            freeze_verifier=freeze_verifier,
            possession_verifier=possession_verifier,
            publisher=publisher,
            verification_runner=verification_runner,
            transformation_verifier=transformation_verifier,
            transformation_receipt_loader=transformation_receipt_loader,
        )
    if (
        latest.state == "publishing" or publication_outcome_unknown
    ) and ready_exists:
        _publish_attempt(
            repository,
            latest,
            canonical,
            bindings=bindings,
            clock=clock,
            freeze_verifier=freeze_verifier,
            possession_verifier=possession_verifier,
            publisher=publisher,
            verification_runner=verification_runner,
            transformation_verifier=transformation_verifier,
        )
        return canonical
    if latest.state == "verified" and ready_exists:
        _publish_attempt(
            repository,
            latest,
            canonical,
            bindings=bindings,
            clock=clock,
            freeze_verifier=freeze_verifier,
            possession_verifier=possession_verifier,
            publisher=publisher,
            verification_runner=verification_runner,
            transformation_verifier=transformation_verifier,
        )
        return canonical
    if latest.state == "prepared":
        if not _pre_sign_output_is_pristine(repository, latest):
            _candidate_retirement_required(
                latest, "has private output before its signing event"
            )
        _append_event(
            repository,
            latest,
            "failed",
            clock=clock,
            failure_code=ABANDONED_BEFORE_SIGNING,
        )
        return None
    if latest.state == "signing":
        _append_event(
            repository,
            latest,
            "outcome_unknown",
            clock=clock,
            failure_code=INTERRUPTED_DURING_SIGNING,
        )
        _candidate_retirement_required(
            latest, "was interrupted after signing may have started"
        )
    if latest.state == "failed":
        if _is_abandoned_before_signing(repository, latest):
            return None
        _candidate_retirement_required(latest, "failed after signing started")
    if latest.state in {"verified", "publishing"}:
        _candidate_retirement_required(
            latest, "lost its exact private publish-ready output"
        )
    raise SigningAttemptError(
        "attempt_recovery_unsupported", "latest signing attempt cannot be recovered"
    )


def run_signing_transaction(
    repository: Path,
    *,
    resume: bool,
    clock: Clock = _utc_now,
    helper_runner: HelperRunner = production_helper_runner,
    verification_runner: VerificationRunner = production_verification_runner,
    freeze_verifier: FreezeVerifier = verify_frozen_candidate,
    live_readiness_verifier: LiveReadinessVerifier = (
        production_live_readiness_verifier
    ),
    publisher: Publisher = publish_private_directory_exclusive,
    confirmer: Confirmer = confirm_private_directory_published,
    transformation_creator: TransformationCreator = _create_transformation,
    transformation_verifier: TransformationVerifier = _verify_transformation,
    transformation_receipt_loader: TransformationReceiptLoader = (
        _load_transformation_receipt
    ),
    canonical_transformation_verifier: CanonicalTransformationVerifier = (
        _verify_canonical_transformation
    ),
    embedded_verifier_session_factory: EmbeddedVerifierSessionFactory = (
        production_embedded_verifier_session
    ),
) -> Path:
    """Run one transaction with a single operation-scoped embedded verifier."""

    repository = _canonical_repository(repository)
    verifier_operation = _EmbeddedVerifierSessionOperation(
        repository,
        embedded_verifier_session_factory,
        allow_post_sign_retry=not resume,
    )
    try:
        with verifier_operation:
            def possession_verifier(
                selected_repository: Path,
                root: Path,
            ) -> VerifiedUpdaterKeyPossession:
                return verifier_operation.verify_possession(
                    selected_repository, root
                )

            def session_helper_runner(
                work: Path,
                certificate_sha1: str,
                certificate_sha256: str,
            ) -> int:
                exit_code = helper_runner(
                    work,
                    certificate_sha1,
                    certificate_sha256,
                )
                if not resume and type(exit_code) is int and exit_code == 0:
                    verifier_operation.arm_post_sign_retry()
                return exit_code

            selected_freeze_verifier = freeze_verifier
            if freeze_verifier is verify_frozen_candidate:
                def session_freeze_verifier(
                    selected_repository: Path,
                ) -> FrozenCandidate:
                    return verify_frozen_candidate(
                        selected_repository,
                        possession_verifier=possession_verifier,
                    )
                selected_freeze_verifier = session_freeze_verifier

            selected_transformation_creator = transformation_creator
            if transformation_creator is _create_transformation:
                def session_transformation_creator(
                    selected_repository: Path,
                    output: Path,
                ) -> Mapping[str, Any]:
                    return create_attempt_receipt(
                        selected_repository,
                        output,
                        freeze_verifier=selected_freeze_verifier,
                    )
                selected_transformation_creator = session_transformation_creator

            selected_transformation_verifier = transformation_verifier
            if transformation_verifier is _verify_transformation:
                def session_transformation_verifier(
                    selected_repository: Path,
                    output: Path,
                ) -> Mapping[str, Any]:
                    return verify_attempt_receipt(
                        selected_repository,
                        output,
                        freeze_verifier=selected_freeze_verifier,
                    )
                selected_transformation_verifier = session_transformation_verifier

            selected_canonical_verifier = canonical_transformation_verifier
            if canonical_transformation_verifier is _verify_canonical_transformation:
                def session_canonical_verifier(
                    selected_repository: Path,
                ) -> Mapping[str, Any]:
                    return verify_receipt(
                        selected_repository,
                        freeze_verifier=selected_freeze_verifier,
                    )
                selected_canonical_verifier = session_canonical_verifier

            return _run_signing_transaction_with_verifiers(
                repository,
                resume=resume,
                clock=clock,
                helper_runner=session_helper_runner,
                verification_runner=verification_runner,
                freeze_verifier=selected_freeze_verifier,
                possession_verifier=possession_verifier,
                live_readiness_verifier=live_readiness_verifier,
                publisher=publisher,
                confirmer=confirmer,
                transformation_creator=selected_transformation_creator,
                transformation_verifier=selected_transformation_verifier,
                transformation_receipt_loader=transformation_receipt_loader,
                canonical_transformation_verifier=selected_canonical_verifier,
            )
    except UpdaterKeyPossessionOperationalError as error:
        raise SigningAttemptError(
            "updater_possession_verifier_unavailable",
            "operation-scoped updater verifier session is unavailable",
        ) from error
    except UpdaterKeyPossessionError as error:
        raise SigningAttemptError(
            "updater_possession_verifier_invalid",
            "operation-scoped updater verifier session failed semantic validation",
        ) from error


def _run_signing_transaction_with_verifiers(
    repository: Path,
    *,
    resume: bool,
    clock: Clock,
    helper_runner: HelperRunner,
    verification_runner: VerificationRunner,
    freeze_verifier: FreezeVerifier,
    possession_verifier: PossessionVerifier,
    live_readiness_verifier: LiveReadinessVerifier,
    publisher: Publisher,
    confirmer: Confirmer,
    transformation_creator: TransformationCreator,
    transformation_verifier: TransformationVerifier,
    transformation_receipt_loader: TransformationReceiptLoader,
    canonical_transformation_verifier: CanonicalTransformationVerifier,
) -> Path:
    """Execute after all production verifier dependencies are explicitly bound."""

    bindings = _verify_frozen_inputs(
        repository,
        freeze_verifier=freeze_verifier,
        possession_verifier=possession_verifier,
    )
    attempts_root = _ensure_attempts_root(repository)
    canonical = ga_root(repository) / SIGNING_OUTPUT_RELATIVE
    try:
        with exclusive_rooted_directory_lock(
            repository, attempts_root, require_private=True
        ) as attempts_descriptor:
            names = _attempt_names(attempts_root)
            for name in names:
                _load_attempt(attempts_root, name)
            if names or os.path.lexists(canonical):
                if not resume:
                    raise SigningAttemptError(
                        "resume_required",
                        "signing state already exists; use the fixed resume entry",
                    )
                recovered = _reconcile_existing(
                    repository,
                    attempts_root,
                    bindings,
                    canonical,
                    clock=clock,
                    confirmer=confirmer,
                    publisher=publisher,
                    verification_runner=verification_runner,
                    transformation_verifier=transformation_verifier,
                    transformation_receipt_loader=transformation_receipt_loader,
                    canonical_transformation_verifier=(
                        canonical_transformation_verifier
                    ),
                    freeze_verifier=freeze_verifier,
                    possession_verifier=possession_verifier,
                )
                if recovered is not None:
                    return recovered

            live_readiness_verifier(ga_root(repository))
            attempt = _create_attempt(
                repository,
                attempts_root,
                attempts_descriptor,
                bindings,
                clock=clock,
            )
            attempt = _append_event(repository, attempt, "signing", clock=clock)
            try:
                exit_code = helper_runner(
                    attempt.work,
                    bindings.signing_certificate_sha1,
                    bindings.signing_certificate_sha256,
                )
            except SigningAttemptError as error:
                _append_event(
                    repository,
                    attempt,
                    "failed",
                    clock=clock,
                    failure_code=error.code,
                )
                raise
            if type(exit_code) is not int or exit_code != 0:
                _append_event(
                    repository,
                    attempt,
                    "failed",
                    clock=clock,
                    failure_code="signing_helper_failed",
                    exit_code=exit_code if type(exit_code) is int else None,
                )
                raise SigningAttemptError(
                    "signing_helper_failed", "fixed signing helper failed"
                )
            try:
                _prepare_output(
                    repository,
                    attempt,
                    verification_runner=verification_runner,
                    transformation_creator=transformation_creator,
                    transformation_verifier=transformation_verifier,
                    transformation_receipt_loader=transformation_receipt_loader,
                )
            except SigningAttemptOutcomeUnknown:
                raise
            except SigningVerificationBlocked as error:
                _append_event(
                    repository,
                    attempt,
                    "verification_blocked",
                    clock=clock,
                    failure_code=error.cause_code,
                )
                raise
            except SigningAttemptError as error:
                _append_event(
                    repository,
                    attempt,
                    "failed",
                    clock=clock,
                    failure_code=error.code,
                )
                raise
            except (OSError, PublicationError, SigningTransformationError) as error:
                _append_event(
                    repository,
                    attempt,
                    "failed",
                    clock=clock,
                    failure_code="signed_output_verification_failed",
                )
                raise SigningAttemptError(
                    "signed_output_verification_failed",
                    "private signed output did not pass complete verification",
                ) from error
            attempt = _load_attempt(attempts_root, attempt.identifier)
            attempt = _append_event(repository, attempt, "verified", clock=clock)
            _publish_attempt(
                repository,
                attempt,
                canonical,
                bindings=bindings,
                clock=clock,
                freeze_verifier=freeze_verifier,
                possession_verifier=possession_verifier,
                publisher=publisher,
                verification_runner=verification_runner,
                transformation_verifier=transformation_verifier,
            )
            _reverify_canonical_transformation(
                repository, canonical_transformation_verifier
            )
            return canonical
    except PublicationError as error:
        raise SigningAttemptError(
            "signing_attempt_lock_failed",
            "another signing transaction is active or its lock is unsafe",
        ) from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "resume"))
    arguments = parser.parse_args(argv)
    try:
        require_closed_release_runtime()
        repository = Path(__file__).resolve().parent.parent
        output = run_signing_transaction(
            repository,
            resume=arguments.command == "resume",
        )
    except (
        OSError,
        ReleasePythonRuntimeError,
        SigningAttemptError,
        SigningTransformationError,
        ValueError,
    ) as error:
        code = error.code if isinstance(error, SigningAttemptError) else "invalid"
        raise SystemExit(f"error: GA signing attempt [{code}]: {error}") from error
    print(f"GA signing output verified: {output.relative_to(repository)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
