from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import fcntl
import hashlib
import os
from pathlib import Path
import re
from typing import Final

from scripts.harness.raw_artifacts import RawArtifactError, canonical_json, load_json_bytes

from .archive import (
    PendingFile,
    PhysicalCaptureArchiveError,
    SecureArchive,
)
from .observation import (
    OBSERVATION_DIRECTORIES,
    ObservationCapture,
    ObservationManifest,
    PhysicalObservationError,
    load_observation_manifest,
    publish_observation_manifest,
)


JOURNAL_DIRECTORY: Final = "journal"
LOCK_FILE: Final = "session.lock"
EVENT_DOCUMENT: Final = "cfw-physical-capture-event-v1"
EVENT_SCHEMA_VERSION: Final = 1
MAX_JOURNAL_EVENTS: Final = 1024
MAX_EVENT_BYTES: Final = 64 * 1024
ZERO_SHA256: Final = "0" * 64
RECOVERY_DIRECTORY: Final = "recovery"
UNINITIALIZED_TOMBSTONE_RELATIVE: Final = (
    "recovery/uninitialized-session.json"
)
UNINITIALIZED_TOMBSTONE_DOCUMENT: Final = (
    "cfw-physical-uninitialized-session-quarantine-v1"
)
JOURNAL_RESOLUTION_DOCUMENT: Final = "cfw-physical-journal-resolution-v2"
JOURNAL_RESOLUTION_SCHEMA_VERSION: Final = 2
MAX_RECOVERY_BYTES: Final = 64 * 1024

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EVENT_FILE_RE = re.compile(r"^(?P<sequence>[0-9]{8})[.]json$")
_PENDING_EVENT_FILE_RE = re.compile(
    r"^[.][0-9]{8}[.]json[.]pending-[0-9a-f]{32}$"
)
_JOURNAL_RESOLUTION_FILE_RE = re.compile(
    r"^journal-(?P<sequence>[0-9]{8})[.]json$"
)
_UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_EVENT_FIELDS = {
    "schema_version",
    "document",
    "sequence",
    "event",
    "from_state",
    "to_state",
    "recorded_at",
    "previous_event_sha256",
    "binding_sha256",
}


class PhysicalCaptureSessionError(RuntimeError):
    """The collection session is locked, corrupted, or transitioned unsafely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CaptureState(str, Enum):
    INITIALIZED = "initialized"
    COLLECTING = "collecting"
    RAW_COMPLETE = "raw_complete"
    NONCE_REQUEST_PREPARED = "nonce_request_prepared"
    NONCE_ATTEMPTED = "nonce_attempted"
    NONCE_RECEIVED = "nonce_received"
    REPORTS_COMPOSED = "reports_composed"
    BINDINGS_COMPOSED = "bindings_composed"
    RECEIPT_REQUEST_PREPARED = "receipt_request_prepared"
    RECEIPT_ATTEMPTED = "receipt_attempted"
    RECEIPT_RECEIVED = "receipt_received"
    FINALIZED = "finalized"
    NONCE_OUTCOME_UNKNOWN = "nonce_outcome_unknown"
    RECEIPT_OUTCOME_UNKNOWN = "receipt_outcome_unknown"
    ABANDONED = "abandoned"


class CaptureEvent(str, Enum):
    SESSION_STARTED = "session_started"
    COLLECTION_STARTED = "collection_started"
    RAW_COMPLETED = "raw_completed"
    NONCE_REQUEST_PREPARED = "nonce_request_prepared"
    NONCE_ATTEMPT_STARTED = "nonce_attempt_started"
    NONCE_PRE_SEND_FAILED = "nonce_pre_send_failed"
    NONCE_RESPONSE_RECORDED = "nonce_response_recorded"
    REPORTS_COMPOSED = "reports_composed"
    BINDINGS_COMPOSED = "bindings_composed"
    RECEIPT_REQUEST_PREPARED = "receipt_request_prepared"
    RECEIPT_ATTEMPT_STARTED = "receipt_attempt_started"
    RECEIPT_PRE_SEND_FAILED = "receipt_pre_send_failed"
    RECEIPT_RESPONSE_RECORDED = "receipt_response_recorded"
    RUN_FINALIZED = "run_finalized"
    NONCE_OUTCOME_UNKNOWN = "nonce_outcome_unknown"
    RECEIPT_OUTCOME_UNKNOWN = "receipt_outcome_unknown"
    SESSION_ABANDONED = "session_abandoned"
    PRE_SEND_ATTEMPT_DISCARDED = "pre_send_attempt_discarded"


TERMINAL_STATES: Final = frozenset(
    {
        CaptureState.FINALIZED,
        CaptureState.NONCE_OUTCOME_UNKNOWN,
        CaptureState.RECEIPT_OUTCOME_UNKNOWN,
        CaptureState.ABANDONED,
    }
)

_LINEAR_TRANSITIONS: Final = {
    CaptureEvent.SESSION_STARTED: (None, CaptureState.INITIALIZED),
    CaptureEvent.COLLECTION_STARTED: (
        CaptureState.INITIALIZED,
        CaptureState.COLLECTING,
    ),
    CaptureEvent.RAW_COMPLETED: (CaptureState.COLLECTING, CaptureState.RAW_COMPLETE),
    CaptureEvent.NONCE_REQUEST_PREPARED: (
        CaptureState.RAW_COMPLETE,
        CaptureState.NONCE_REQUEST_PREPARED,
    ),
    CaptureEvent.NONCE_ATTEMPT_STARTED: (
        CaptureState.NONCE_REQUEST_PREPARED,
        CaptureState.NONCE_ATTEMPTED,
    ),
    CaptureEvent.NONCE_PRE_SEND_FAILED: (
        CaptureState.NONCE_ATTEMPTED,
        CaptureState.NONCE_REQUEST_PREPARED,
    ),
    CaptureEvent.NONCE_RESPONSE_RECORDED: (
        CaptureState.NONCE_ATTEMPTED,
        CaptureState.NONCE_RECEIVED,
    ),
    CaptureEvent.REPORTS_COMPOSED: (
        CaptureState.NONCE_RECEIVED,
        CaptureState.REPORTS_COMPOSED,
    ),
    CaptureEvent.BINDINGS_COMPOSED: (
        CaptureState.REPORTS_COMPOSED,
        CaptureState.BINDINGS_COMPOSED,
    ),
    CaptureEvent.RECEIPT_REQUEST_PREPARED: (
        CaptureState.BINDINGS_COMPOSED,
        CaptureState.RECEIPT_REQUEST_PREPARED,
    ),
    CaptureEvent.RECEIPT_ATTEMPT_STARTED: (
        CaptureState.RECEIPT_REQUEST_PREPARED,
        CaptureState.RECEIPT_ATTEMPTED,
    ),
    CaptureEvent.RECEIPT_PRE_SEND_FAILED: (
        CaptureState.RECEIPT_ATTEMPTED,
        CaptureState.RECEIPT_REQUEST_PREPARED,
    ),
    CaptureEvent.RECEIPT_RESPONSE_RECORDED: (
        CaptureState.RECEIPT_ATTEMPTED,
        CaptureState.RECEIPT_RECEIVED,
    ),
    CaptureEvent.RUN_FINALIZED: (
        CaptureState.RECEIPT_RECEIVED,
        CaptureState.FINALIZED,
    ),
    CaptureEvent.NONCE_OUTCOME_UNKNOWN: (
        CaptureState.NONCE_ATTEMPTED,
        CaptureState.NONCE_OUTCOME_UNKNOWN,
    ),
    CaptureEvent.RECEIPT_OUTCOME_UNKNOWN: (
        CaptureState.RECEIPT_ATTEMPTED,
        CaptureState.RECEIPT_OUTCOME_UNKNOWN,
    ),
}

_ABANDONABLE_STATES: Final = frozenset(
    {
        CaptureState.INITIALIZED,
        CaptureState.COLLECTING,
        CaptureState.RAW_COMPLETE,
        CaptureState.NONCE_REQUEST_PREPARED,
        CaptureState.NONCE_RECEIVED,
        CaptureState.REPORTS_COMPOSED,
        CaptureState.BINDINGS_COMPOSED,
        CaptureState.RECEIPT_REQUEST_PREPARED,
        CaptureState.RECEIPT_RECEIVED,
    }
)


@dataclass(frozen=True)
class SessionSnapshot:
    state: CaptureState
    sequence: int
    last_event_sha256: str
    last_binding_sha256: str
    last_recorded_at: datetime
    observation_manifest_sha256: str | None


@dataclass(frozen=True)
class SessionEventView:
    sequence: int
    event: CaptureEvent
    from_state: CaptureState | None
    to_state: CaptureState
    recorded_at: datetime
    previous_event_sha256: str
    binding_sha256: str
    event_sha256: str


def _format_timestamp(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_TIMESTAMP_RE.fullmatch(value) is None:
        raise PhysicalCaptureSessionError(
            "invalid_journal_timestamp", f"{label} must be a canonical UTC timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PhysicalCaptureSessionError(
            "invalid_journal_timestamp", f"{label} is not ISO-8601"
        ) from error
    return parsed


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise PhysicalCaptureSessionError(
            "invalid_journal_digest", f"{label} is not a canonical SHA-256"
        )
    return value


def _canonical_event_bytes(value: dict[str, object]) -> bytes:
    try:
        return canonical_json(value) + b"\n"
    except RawArtifactError as error:
        raise PhysicalCaptureSessionError(
            "journal_encoding_failed", "journal event cannot be canonically encoded"
        ) from error


def _transition_for(
    event: CaptureEvent, current: CaptureState | None
) -> CaptureState:
    if event is CaptureEvent.PRE_SEND_ATTEMPT_DISCARDED:
        if current not in {
            CaptureState.NONCE_REQUEST_PREPARED,
            CaptureState.RECEIPT_REQUEST_PREPARED,
        }:
            raise PhysicalCaptureSessionError(
                "invalid_session_transition",
                "pre-send pending recovery requires a prepared request state",
            )
        return current
    if event is CaptureEvent.SESSION_ABANDONED:
        if current not in _ABANDONABLE_STATES:
            raise PhysicalCaptureSessionError(
                "invalid_session_transition",
                f"cannot abandon physical capture session from {current!s}",
            )
        return CaptureState.ABANDONED
    transition = _LINEAR_TRANSITIONS.get(event)
    if transition is None or transition[0] != current:
        raise PhysicalCaptureSessionError(
            "invalid_session_transition",
            f"event {event.value!r} is invalid from state "
            f"{None if current is None else current.value!r}",
        )
    return transition[1]


class PhysicalCaptureSession:
    """Locked append-only state machine for one physical collection run."""

    def __init__(self, archive: SecureArchive, lock_fd: int) -> None:
        self.archive = archive
        self._lock_fd: int | None = lock_fd
        self._snapshot: SessionSnapshot | None = None

    @classmethod
    def create(
        cls,
        repository: Path,
        root_relative_to_target: str,
        *,
        intent_sha256: str,
    ) -> PhysicalCaptureSession:
        binding = _require_sha256(intent_sha256, "intent_sha256")
        archive = SecureArchive.create(repository, root_relative_to_target)
        lock_fd = -1
        session: PhysicalCaptureSession | None = None
        try:
            lock_fd = archive.create_lock_file(LOCK_FILE)
            cls._acquire_lock(lock_fd)
            session = cls(archive, lock_fd)
            lock_fd = -1
            archive.ensure_directory(JOURNAL_DIRECTORY)
            session._append_locked(CaptureEvent.SESSION_STARTED, binding)
            return session
        except BaseException:
            if session is not None:
                session.close()
            else:
                if lock_fd >= 0:
                    os.close(lock_fd)
                archive.close()
            raise

    @classmethod
    def open(
        cls, repository: Path, root_relative_to_target: str
    ) -> PhysicalCaptureSession:
        archive = SecureArchive.open(repository, root_relative_to_target)
        lock_fd = -1
        session: PhysicalCaptureSession | None = None
        try:
            lock_fd = archive.open_lock_file(LOCK_FILE)
            cls._acquire_lock(lock_fd)
            session = cls(archive, lock_fd)
            lock_fd = -1
            pending = archive.pending_files(JOURNAL_DIRECTORY)
            if pending:
                raise PhysicalCaptureSessionError(
                    "journal_recovery_required",
                    "physical capture journal contains an interrupted pending event; "
                    "explicit recovery is required",
                )
            session._snapshot = session._replay_final_events()
            session._snapshot = session._replay_resolution_intents(
                session._snapshot, complete_unresolved=False
            )
            session._activate_frozen_observations(session._snapshot)
            return session
        except BaseException:
            if session is not None:
                session.close()
            else:
                if lock_fd >= 0:
                    os.close(lock_fd)
                archive.close()
            raise

    @classmethod
    def recover(
        cls,
        repository: Path,
        root_relative_to_target: str,
        *,
        discard_incomplete: bool = False,
    ) -> PhysicalCaptureSession:
        archive = SecureArchive.open(repository, root_relative_to_target)
        lock_fd = -1
        session: PhysicalCaptureSession | None = None
        try:
            root_names = archive.list_root_names()
            if LOCK_FILE in root_names:
                lock_fd = archive.open_lock_file(LOCK_FILE)
            elif not root_names:
                lock_fd = archive.create_lock_file(LOCK_FILE)
            else:
                raise PhysicalCaptureSessionError(
                    "uninitialized_archive_invalid",
                    "pre-intent archive has no lock and contains unexpected data",
                )
            cls._acquire_lock(lock_fd)
            session = cls(archive, lock_fd)
            lock_fd = -1
            root_names = archive.list_root_names()
            if JOURNAL_DIRECTORY not in root_names:
                if set(root_names) != {LOCK_FILE}:
                    raise PhysicalCaptureSessionError(
                        "uninitialized_archive_invalid",
                        "pre-intent archive without journal contains unexpected data",
                    )
                archive.ensure_directory(JOURNAL_DIRECTORY)
            journal_names = archive.list_names(JOURNAL_DIRECTORY)
            if not journal_names:
                if set(archive.list_root_names()) in (
                    {JOURNAL_DIRECTORY, LOCK_FILE},
                    {
                        JOURNAL_DIRECTORY,
                        RECOVERY_DIRECTORY,
                        LOCK_FILE,
                    },
                ):
                    session._quarantine_uninitialized_session(None)
                    raise PhysicalCaptureSessionError(
                        "uninitialized_session_quarantined",
                        "pre-intent physical session was durably quarantined",
                    )
            pending = archive.pending_files(JOURNAL_DIRECTORY)
            if len(pending) > 1:
                raise PhysicalCaptureSessionError(
                    "ambiguous_pending_journal",
                    "physical capture journal contains multiple pending events",
                )
            snapshot = session._replay_final_events(allow_empty=bool(pending))
            if pending:
                session._recover_one_pending(
                    pending[0], snapshot, discard_incomplete=discard_incomplete
                )
                snapshot = session._replay_final_events()
            snapshot = session._replay_resolution_intents(
                snapshot, complete_unresolved=True
            )
            session._snapshot = snapshot
            session._activate_frozen_observations(snapshot)
            return session
        except BaseException:
            if session is not None:
                session.close()
            else:
                if lock_fd >= 0:
                    os.close(lock_fd)
                archive.close()
            raise

    @classmethod
    def uninitialized_quarantined(
        cls, repository: Path, root_relative_to_target: str
    ) -> bool:
        archive = SecureArchive.open(repository, root_relative_to_target)
        lock_fd = -1
        session: PhysicalCaptureSession | None = None
        try:
            lock_fd = archive.open_lock_file(LOCK_FILE)
            cls._acquire_lock(lock_fd)
            session = cls(archive, lock_fd)
            lock_fd = -1
            if archive.list_root_names() != (
                JOURNAL_DIRECTORY,
                RECOVERY_DIRECTORY,
                LOCK_FILE,
            ) or archive.list_names(JOURNAL_DIRECTORY):
                return False
            return session._has_uninitialized_tombstone()
        finally:
            if session is not None:
                session.close()
            else:
                if lock_fd >= 0:
                    os.close(lock_fd)
                archive.close()

    @staticmethod
    def _acquire_lock(descriptor: int) -> None:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise PhysicalCaptureSessionError(
                "session_locked", "physical capture session is already locked"
            ) from error
        except OSError as error:
            raise PhysicalCaptureSessionError(
                "session_lock_failed", "cannot acquire physical capture session lock"
            ) from error

    def __enter__(self) -> PhysicalCaptureSession:
        self._require_open()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        try:
            if self._lock_fd is not None:
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(self._lock_fd)
                    self._lock_fd = None
        finally:
            self.archive.close()

    def _require_open(self) -> int:
        if self._lock_fd is None:
            raise PhysicalCaptureSessionError(
                "session_closed", "physical capture session is closed"
            )
        return self._lock_fd

    @property
    def snapshot(self) -> SessionSnapshot:
        self._require_open()
        if self._snapshot is None:
            self._snapshot = self._replay_final_events()
        return self._snapshot

    @property
    def state(self) -> CaptureState:
        return self.snapshot.state

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def interrupted_attempt(self) -> bool:
        return self.state in {
            CaptureState.NONCE_ATTEMPTED,
            CaptureState.RECEIPT_ATTEMPTED,
        }

    def require_collection_open(self) -> None:
        """Fail before a producer or runner can execute outside collection."""

        self._require_open()
        if self.state is not CaptureState.COLLECTING:
            raise PhysicalCaptureSessionError(
                "observation_phase_closed",
                "physical observations may run only before RAW_COMPLETED",
            )

    def observation_capture(self) -> ObservationCapture:
        self.require_collection_open()
        return ObservationCapture(self)

    def complete_observations(
        self,
        observations: dict[str, object],
    ) -> ObservationManifest:
        """Bind and freeze the exact proof-free observation set once."""

        self.require_collection_open()
        try:
            manifest = publish_observation_manifest(self.archive, observations)
            self.archive.seal_prefixes(OBSERVATION_DIRECTORIES)
        except (PhysicalCaptureArchiveError, PhysicalObservationError) as error:
            raise PhysicalCaptureSessionError(
                "observation_manifest_invalid",
                "physical observations cannot be finalized into one immutable manifest",
            ) from error
        snapshot = self._append_locked(
            CaptureEvent.RAW_COMPLETED,
            manifest.root_sha256,
        )
        if snapshot.observation_manifest_sha256 != manifest.root_sha256:
            raise PhysicalCaptureSessionError(
                "observation_manifest_binding_mismatch",
                "RAW_COMPLETED did not retain the exact observation manifest root",
            )
        return manifest

    def load_observation_manifest(self) -> ObservationManifest:
        root = self.snapshot.observation_manifest_sha256
        if root is None:
            raise PhysicalCaptureSessionError(
                "observation_manifest_unavailable",
                "physical observations have not reached RAW_COMPLETED",
            )
        manifest = self._activate_frozen_observations(self.snapshot)
        if manifest is None:  # pragma: no cover - guarded by the root check above
            raise PhysicalCaptureSessionError(
                "observation_manifest_unavailable",
                "physical observations have not reached RAW_COMPLETED",
            )
        return manifest

    def append(self, event: CaptureEvent, *, binding_sha256: str) -> SessionSnapshot:
        self._require_open()
        if not isinstance(event, CaptureEvent):
            raise PhysicalCaptureSessionError(
                "invalid_event", "session event must be a CaptureEvent"
            )
        if event is CaptureEvent.RAW_COMPLETED:
            raise PhysicalCaptureSessionError(
                "raw_completion_requires_manifest",
                "RAW_COMPLETED requires complete_observations with an exact manifest",
            )
        return self._append_locked(
            event, _require_sha256(binding_sha256, "binding_sha256")
        )

    def abandon(self, *, binding_sha256: str) -> SessionSnapshot:
        return self.append(
            CaptureEvent.SESSION_ABANDONED, binding_sha256=binding_sha256
        )

    def event_view(self, sequence: int) -> SessionEventView:
        """Return a strict, byte-bound view of one committed journal event."""

        self._require_open()
        if type(sequence) is not int or not 1 <= sequence <= self.snapshot.sequence:
            raise PhysicalCaptureSessionError(
                "invalid_journal_sequence",
                "journal event view sequence is outside the committed range",
            )
        previous: SessionSnapshot | None = None
        selected: SessionEventView | None = None
        for current_sequence in range(1, sequence + 1):
            relative = f"{JOURNAL_DIRECTORY}/{current_sequence:08d}.json"
            try:
                data = self.archive.read_bytes(
                    relative, maximum=MAX_EVENT_BYTES
                )
                current = self._validate_event_bytes(
                    data, previous, current_sequence
                )
                value = load_json_bytes(data, "journal event view")
                if not isinstance(value, dict):  # pragma: no cover - validated above
                    raise RawArtifactError("journal event view is not an object")
                event = CaptureEvent(value["event"])
                raw_from_state = value["from_state"]
                from_state = (
                    None
                    if raw_from_state is None
                    else CaptureState(raw_from_state)
                )
                selected = SessionEventView(
                    sequence=current_sequence,
                    event=event,
                    from_state=from_state,
                    to_state=current.state,
                    recorded_at=current.last_recorded_at,
                    previous_event_sha256=_require_sha256(
                        value["previous_event_sha256"],
                        "previous_event_sha256",
                    ),
                    binding_sha256=current.last_binding_sha256,
                    event_sha256=current.last_event_sha256,
                )
            except (
                KeyError,
                PhysicalCaptureArchiveError,
                PhysicalCaptureSessionError,
                RawArtifactError,
                TypeError,
                ValueError,
            ) as error:
                if isinstance(error, PhysicalCaptureSessionError):
                    raise
                raise PhysicalCaptureSessionError(
                    "journal_event_view_invalid",
                    "committed journal event failed strict reopening",
                ) from error
            previous = current
        if selected is None:  # pragma: no cover - sequence is at least one
            raise PhysicalCaptureSessionError(
                "journal_event_view_invalid",
                "committed journal event view was not produced",
            )
        return selected

    def last_event_view(self) -> SessionEventView:
        """Return a strict, byte-bound view of the committed journal tip."""

        view = self.event_view(self.snapshot.sequence)
        snapshot = self.snapshot
        if (
            view.to_state is not snapshot.state
            or view.recorded_at != snapshot.last_recorded_at
            or view.binding_sha256 != snapshot.last_binding_sha256
            or view.event_sha256 != snapshot.last_event_sha256
        ):
            raise PhysicalCaptureSessionError(
                "journal_tip_invalid",
                "committed journal tip differs from the session snapshot",
            )
        return view

    def resolve_interrupted_attempt(self) -> SessionSnapshot:
        state = self.state
        if state is CaptureState.NONCE_ATTEMPTED:
            event = CaptureEvent.NONCE_OUTCOME_UNKNOWN
            domain = b"cfw-physical-capture-restart-recovery-v1\0nonce"
        elif state is CaptureState.RECEIPT_ATTEMPTED:
            event = CaptureEvent.RECEIPT_OUTCOME_UNKNOWN
            domain = b"cfw-physical-capture-restart-recovery-v1\0receipt"
        else:
            raise PhysicalCaptureSessionError(
                "no_interrupted_attempt",
                "session is not awaiting resolution of an interrupted network attempt",
            )
        return self.append(event, binding_sha256=hashlib.sha256(domain).hexdigest())

    def resolution_binding_for_last_event(
        self, event: CaptureEvent
    ) -> str | None:
        """Return the durable resolution intent bound to the journal tip.

        Ordinary source-driven events have no resolution intent. Recovery
        events must first pass the session-owned intent/event cross-check; a
        caller therefore never needs to parse recovery internals itself.
        """

        self._require_open()
        if not isinstance(event, CaptureEvent):
            raise PhysicalCaptureSessionError(
                "invalid_event", "resolution binding requires a CaptureEvent"
            )
        snapshot = self.snapshot
        self._replay_resolution_intents(snapshot, complete_unresolved=False)
        relative = self._resolution_intent_relative(snapshot.sequence)
        finals, pending = self._resolution_namespace()
        if pending:
            raise PhysicalCaptureSessionError(
                "journal_resolution_recovery_required",
                "journal resolution intent publication is still pending",
            )
        if Path(relative).name not in finals:
            return None
        try:
            data = self.archive.read_bytes(
                relative, maximum=MAX_RECOVERY_BYTES
            )
            value = load_json_bytes(data, "journal tip resolution intent")
        except (PhysicalCaptureArchiveError, RawArtifactError) as error:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_unreadable",
                "journal tip resolution intent cannot be reopened",
            ) from error
        sequence, _state, resolution_event = (
            self._validate_resolution_intent_value(value, data)
        )
        digest = hashlib.sha256(data).hexdigest()
        if (
            sequence != snapshot.sequence
            or resolution_event is not event
            or digest != snapshot.last_binding_sha256
        ):
            raise PhysicalCaptureSessionError(
                "journal_resolution_event_invalid",
                "journal tip is not bound to the requested resolution intent",
            )
        return digest

    def _append_locked(
        self, event: CaptureEvent, binding_sha256: str
    ) -> SessionSnapshot:
        current = self._snapshot
        if current is None:
            try:
                current = self._replay_final_events(allow_empty=True)
            except PhysicalCaptureSessionError:
                if event is not CaptureEvent.SESSION_STARTED:
                    raise
                current = None
        current_state = None if current is None else current.state
        if current is not None and current.observation_manifest_sha256 is not None:
            self._activate_frozen_observations(current)
        next_state = _transition_for(event, current_state)
        sequence = 1 if current is None else current.sequence + 1
        if sequence > MAX_JOURNAL_EVENTS:
            raise PhysicalCaptureSessionError(
                "journal_capacity_exceeded",
                f"physical capture journal exceeds {MAX_JOURNAL_EVENTS} events",
            )
        recorded_at = datetime.now(timezone.utc).replace(microsecond=0)
        if current is not None and recorded_at < current.last_recorded_at:
            raise PhysicalCaptureSessionError(
                "clock_rollback", "system UTC clock moved backwards during collection"
            )
        value: dict[str, object] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "document": EVENT_DOCUMENT,
            "sequence": sequence,
            "event": event.value,
            "from_state": None if current_state is None else current_state.value,
            "to_state": next_state.value,
            "recorded_at": _format_timestamp(recorded_at),
            "previous_event_sha256": (
                ZERO_SHA256 if current is None else current.last_event_sha256
            ),
            "binding_sha256": binding_sha256,
        }
        data = _canonical_event_bytes(value)
        relative = f"{JOURNAL_DIRECTORY}/{sequence:08d}.json"
        record = self.archive.write_bytes(relative, data, maximum=MAX_EVENT_BYTES)
        expected_digest = hashlib.sha256(data).hexdigest()
        if record.sha256 != expected_digest or record.size != len(data):
            raise PhysicalCaptureSessionError(
                "journal_publish_mismatch", "published journal event differs from memory"
            )
        snapshot = SessionSnapshot(
            state=next_state,
            sequence=sequence,
            last_event_sha256=record.sha256,
            last_binding_sha256=binding_sha256,
            last_recorded_at=recorded_at,
            observation_manifest_sha256=(
                binding_sha256
                if event is CaptureEvent.RAW_COMPLETED
                else (
                    None
                    if current is None
                    else current.observation_manifest_sha256
                )
            ),
        )
        self._snapshot = snapshot
        if snapshot.observation_manifest_sha256 is not None:
            self._activate_frozen_observations(snapshot)
        return snapshot

    def _activate_frozen_observations(
        self,
        snapshot: SessionSnapshot | None,
    ) -> ObservationManifest | None:
        if snapshot is None or snapshot.observation_manifest_sha256 is None:
            return None
        try:
            manifest = load_observation_manifest(
                self.archive,
                expected_root_sha256=snapshot.observation_manifest_sha256,
            )
            self.archive.seal_prefixes(OBSERVATION_DIRECTORIES)
            return manifest
        except (PhysicalCaptureArchiveError, PhysicalObservationError) as error:
            raise PhysicalCaptureSessionError(
                "observation_manifest_invalid",
                "RAW_COMPLETED observation manifest or bound bytes are unavailable",
            ) from error

    def _replay_final_events(self, *, allow_empty: bool = False) -> SessionSnapshot | None:
        self._require_open()
        names = self.archive.list_names(JOURNAL_DIRECTORY)
        final_names: list[tuple[int, str]] = []
        for name in names:
            match = _EVENT_FILE_RE.fullmatch(name)
            if match is not None:
                final_names.append((int(match.group("sequence")), name))
                continue
            if _PENDING_EVENT_FILE_RE.fullmatch(name) is not None:
                continue
            raise PhysicalCaptureSessionError(
                "unexpected_journal_entry",
                f"physical capture journal contains unexpected entry {name!r}",
            )
        if not final_names:
            if allow_empty:
                return None
            raise PhysicalCaptureSessionError(
                "empty_journal", "physical capture journal contains no committed event"
            )
        snapshot: SessionSnapshot | None = None
        for expected, (sequence, name) in enumerate(sorted(final_names), start=1):
            if sequence != expected:
                raise PhysicalCaptureSessionError(
                    "journal_sequence_gap", "physical capture journal sequence is not contiguous"
                )
            data = self.archive.read_bytes(
                f"{JOURNAL_DIRECTORY}/{name}", maximum=MAX_EVENT_BYTES
            )
            snapshot = self._validate_event_bytes(data, snapshot, expected)
        return snapshot

    def _validate_event_bytes(
        self,
        data: bytes,
        previous: SessionSnapshot | None,
        expected_sequence: int,
    ) -> SessionSnapshot:
        try:
            value = load_json_bytes(data, "physical capture journal event")
        except RawArtifactError as error:
            raise PhysicalCaptureSessionError(
                "invalid_journal_json", "physical capture journal event is not strict JSON"
            ) from error
        if not isinstance(value, dict) or set(value) != _EVENT_FIELDS:
            raise PhysicalCaptureSessionError(
                "invalid_journal_fields",
                "physical capture journal event has an unexpected field set",
            )
        if _canonical_event_bytes(value) != data:
            raise PhysicalCaptureSessionError(
                "noncanonical_journal_event", "journal event bytes are not canonical"
            )
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != EVENT_SCHEMA_VERSION
            or value["document"] != EVENT_DOCUMENT
            or type(value["sequence"]) is not int
            or value["sequence"] != expected_sequence
        ):
            raise PhysicalCaptureSessionError(
                "invalid_journal_header", "journal event schema or sequence is invalid"
            )
        try:
            event = CaptureEvent(value["event"])
        except (TypeError, ValueError) as error:
            raise PhysicalCaptureSessionError(
                "invalid_journal_event", "journal event name is unknown"
            ) from error
        current_state = None if previous is None else previous.state
        next_state = _transition_for(event, current_state)
        expected_from = None if current_state is None else current_state.value
        if value["from_state"] != expected_from or value["to_state"] != next_state.value:
            raise PhysicalCaptureSessionError(
                "journal_transition_mismatch",
                "journal event state fields differ from the fixed transition",
            )
        expected_previous = ZERO_SHA256 if previous is None else previous.last_event_sha256
        if (
            _require_sha256(
                value["previous_event_sha256"], "previous_event_sha256"
            )
            != expected_previous
        ):
            raise PhysicalCaptureSessionError(
                "journal_hash_chain_mismatch", "journal hash chain is broken"
            )
        _require_sha256(value["binding_sha256"], "binding_sha256")
        recorded_at = _parse_timestamp(value["recorded_at"], "recorded_at")
        if previous is not None and recorded_at < previous.last_recorded_at:
            raise PhysicalCaptureSessionError(
                "journal_time_rollback", "journal timestamps move backwards"
            )
        return SessionSnapshot(
            state=next_state,
            sequence=expected_sequence,
            last_event_sha256=hashlib.sha256(data).hexdigest(),
            last_binding_sha256=_require_sha256(
                value["binding_sha256"], "binding_sha256"
            ),
            last_recorded_at=recorded_at,
            observation_manifest_sha256=(
                _require_sha256(value["binding_sha256"], "binding_sha256")
                if event is CaptureEvent.RAW_COMPLETED
                else (
                    None
                    if previous is None
                    else previous.observation_manifest_sha256
                )
            ),
        )

    def _recover_one_pending(
        self,
        pending: PendingFile,
        snapshot: SessionSnapshot | None,
        *,
        discard_incomplete: bool,
    ) -> None:
        expected_sequence = 1 if snapshot is None else snapshot.sequence + 1
        expected_relative = f"{JOURNAL_DIRECTORY}/{expected_sequence:08d}.json"
        if pending.final_relative_path != expected_relative:
            raise PhysicalCaptureSessionError(
                "pending_sequence_mismatch",
                "pending journal event is not the next expected sequence",
            )
        try:
            data = self.archive.read_pending(pending, maximum=MAX_EVENT_BYTES)
            recovered = self._validate_event_bytes(data, snapshot, expected_sequence)
            if recovered.observation_manifest_sha256 is not None:
                self._activate_frozen_observations(recovered)
        except PhysicalCaptureArchiveError as error:
            if not discard_incomplete or error.code != "archive_file_size":
                raise PhysicalCaptureSessionError(
                    "pending_journal_unreadable", "pending journal event cannot be recovered"
                ) from error
            try:
                fragment = self.archive.read_pending_fragment(
                    pending, maximum=MAX_EVENT_BYTES
                )
            except PhysicalCaptureArchiveError as fragment_error:
                raise PhysicalCaptureSessionError(
                    "pending_journal_unreadable",
                    "oversized pending journal event cannot be recovered",
                ) from fragment_error
            self._recover_partial_pending(pending, snapshot, fragment)
            return
        except PhysicalCaptureSessionError as error:
            partial_content = error.code == "invalid_journal_json"
            if (
                error.code == "noncanonical_journal_event"
                and not data.endswith(b"\n")
            ):
                try:
                    self._validate_event_bytes(
                        data + b"\n", snapshot, expected_sequence
                    )
                except PhysicalCaptureSessionError:
                    partial_content = False
                else:
                    partial_content = True
            if not discard_incomplete or not partial_content:
                raise
            self._recover_partial_pending(pending, snapshot, data)
            return
        try:
            value = load_json_bytes(data, "recoverable pending journal event")
            if not isinstance(value, dict):
                raise RawArtifactError("pending journal event is not an object")
            event = CaptureEvent(value["event"])
        except (KeyError, RawArtifactError, TypeError, ValueError) as error:
            raise PhysicalCaptureSessionError(
                "pending_journal_unreadable",
                "validated pending journal event cannot be identified",
            ) from error
        if event in {
            CaptureEvent.NONCE_ATTEMPT_STARTED,
            CaptureEvent.RECEIPT_ATTEMPT_STARTED,
        }:
            if snapshot is None or snapshot.state not in {
                CaptureState.NONCE_REQUEST_PREPARED,
                CaptureState.RECEIPT_REQUEST_PREPARED,
            }:
                raise PhysicalCaptureSessionError(
                    "pending_attempt_state_invalid",
                    "pending pre-send attempt has no matching prepared request",
                )
            self._resolve_pending_with_intent(
                pending,
                snapshot,
                observed=data,
                event=CaptureEvent.PRE_SEND_ATTEMPT_DISCARDED,
                action="pre-send-attempt-not-published",
            )
            return
        if event is CaptureEvent.PRE_SEND_ATTEMPT_DISCARDED:
            self._require_matching_resolution_intent(snapshot, event)
        self.archive.publish_pending(pending)

    @staticmethod
    def _resolution_intent_relative(sequence: int) -> str:
        return f"{RECOVERY_DIRECTORY}/journal-{sequence:08d}.json"

    def _resolution_intent_bytes(
        self,
        pending: PendingFile,
        snapshot: SessionSnapshot,
        *,
        observed: bytes,
        event: CaptureEvent,
        action: str,
    ) -> bytes:
        value = {
            "schema_version": JOURNAL_RESOLUTION_SCHEMA_VERSION,
            "document": JOURNAL_RESOLUTION_DOCUMENT,
            "archive_root": self.archive.root_relative_to_target,
            "sequence": snapshot.sequence + 1,
            "from_state": snapshot.state.value,
            "previous_event_sha256": snapshot.last_event_sha256,
            "pending_relative_path": pending.relative_path,
            "pending_final_relative_path": pending.final_relative_path,
            "pending_size": len(observed),
            "pending_sha256": hashlib.sha256(observed).hexdigest(),
            "action": action,
            "resolution_event": event.value,
        }
        try:
            return canonical_json(value) + b"\n"
        except RawArtifactError as error:  # pragma: no cover - fixed values
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_invalid",
                "journal resolution intent cannot be encoded",
            ) from error

    def _validate_resolution_intent_value(
        self,
        value: object,
        data: bytes,
    ) -> tuple[int, CaptureState, CaptureEvent]:
        fields = {
            "schema_version",
            "document",
            "archive_root",
            "sequence",
            "from_state",
            "previous_event_sha256",
            "pending_relative_path",
            "pending_final_relative_path",
            "pending_size",
            "pending_sha256",
            "action",
            "resolution_event",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_invalid",
                "journal resolution intent has an unexpected field set",
            )
        try:
            sequence = value["sequence"]
            state = CaptureState(value["from_state"])
            event = CaptureEvent(value["resolution_event"])
            if (
                type(value["schema_version"]) is not int
                or value["schema_version"]
                != JOURNAL_RESOLUTION_SCHEMA_VERSION
                or value["document"] != JOURNAL_RESOLUTION_DOCUMENT
                or value["archive_root"]
                != self.archive.root_relative_to_target
                or type(sequence) is not int
                or not 1 <= sequence <= MAX_JOURNAL_EVENTS
                or canonical_json(value) + b"\n" != data
                or _require_sha256(
                    value["previous_event_sha256"],
                    "resolution previous_event_sha256",
                )
                != value["previous_event_sha256"]
                or value["pending_final_relative_path"]
                != f"{JOURNAL_DIRECTORY}/{sequence:08d}.json"
                or not isinstance(value["pending_relative_path"], str)
                or re.fullmatch(
                    rf"{re.escape(JOURNAL_DIRECTORY)}/[.]"
                    rf"{sequence:08d}[.]json[.]pending-[0-9a-f]{{32}}",
                    value["pending_relative_path"],
                )
                is None
                or type(value["pending_size"]) is not int
                or not 0 <= value["pending_size"] <= MAX_EVENT_BYTES
                or _require_sha256(
                    value["pending_sha256"], "resolution pending_sha256"
                )
                != value["pending_sha256"]
            ):
                raise ValueError("resolution intent identity differs")
        except (RawArtifactError, TypeError, ValueError) as error:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_invalid",
                "journal resolution intent identity is invalid",
            ) from error
        action = value["action"]
        allowed = (
            event is CaptureEvent.PRE_SEND_ATTEMPT_DISCARDED
            and action == "pre-send-attempt-not-published"
            and state
            in {
                CaptureState.NONCE_REQUEST_PREPARED,
                CaptureState.RECEIPT_REQUEST_PREPARED,
            }
        ) or (
            event is CaptureEvent.NONCE_OUTCOME_UNKNOWN
            and action == "partial-event-after-attempt"
            and state is CaptureState.NONCE_ATTEMPTED
        ) or (
            event is CaptureEvent.RECEIPT_OUTCOME_UNKNOWN
            and action == "partial-event-after-attempt"
            and state is CaptureState.RECEIPT_ATTEMPTED
        ) or (
            event is CaptureEvent.SESSION_ABANDONED
            and action == "partial-event-abandoned"
            and state in _ABANDONABLE_STATES
        )
        if not allowed or _transition_for(event, state) is None:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_invalid",
                "journal resolution action is not source-owned for its state",
            )
        return sequence, state, event

    def _resolution_namespace(self) -> tuple[tuple[str, ...], tuple[PendingFile, ...]]:
        try:
            names = self.archive.list_names(RECOVERY_DIRECTORY)
        except PhysicalCaptureArchiveError as error:
            if error.code == "directory_not_found":
                return (), ()
            raise PhysicalCaptureSessionError(
                "journal_resolution_namespace_unreadable",
                "journal resolution namespace cannot be inspected",
            ) from error
        try:
            pending = self.archive.pending_files(RECOVERY_DIRECTORY)
        except PhysicalCaptureArchiveError as error:
            raise PhysicalCaptureSessionError(
                "journal_resolution_namespace_unreadable",
                "journal resolution pending files cannot be inspected",
            ) from error
        pending_names = {Path(item.relative_path).name for item in pending}
        finals = tuple(name for name in names if name not in pending_names)
        if (
            len(pending_names) != len(pending)
            or set(names) != set(finals) | pending_names
            or any(
                name != "uninitialized-session.json"
                and _JOURNAL_RESOLUTION_FILE_RE.fullmatch(name) is None
                for name in finals
            )
            or any(
                Path(item.final_relative_path).name
                != "uninitialized-session.json"
                and _JOURNAL_RESOLUTION_FILE_RE.fullmatch(
                    Path(item.final_relative_path).name
                )
                is None
                for item in pending
            )
        ):
            raise PhysicalCaptureSessionError(
                "journal_resolution_namespace_invalid",
                "journal resolution namespace contains an unknown file",
            )
        return tuple(sorted(finals)), pending

    def _write_or_reopen_resolution_intent(
        self,
        pending_event: PendingFile,
        snapshot: SessionSnapshot,
        *,
        observed: bytes,
        event: CaptureEvent,
        action: str,
    ) -> str:
        data = self._resolution_intent_bytes(
            pending_event,
            snapshot,
            observed=observed,
            event=event,
            action=action,
        )
        relative = self._resolution_intent_relative(snapshot.sequence + 1)
        finals, recovery_pending = self._resolution_namespace()
        target_name = Path(relative).name
        target_pending = tuple(
            item
            for item in recovery_pending
            if item.final_relative_path == relative
        )
        if any(item not in target_pending for item in recovery_pending):
            raise PhysicalCaptureSessionError(
                "journal_resolution_namespace_invalid",
                "another journal resolution publication is pending",
            )
        if target_name in finals:
            if target_pending:
                raise PhysicalCaptureSessionError(
                    "journal_resolution_namespace_invalid",
                    "journal resolution has both final and pending bytes",
                )
            try:
                observed = self.archive.read_bytes(
                    relative, maximum=MAX_RECOVERY_BYTES
                )
            except PhysicalCaptureArchiveError as error:
                raise PhysicalCaptureSessionError(
                    "journal_resolution_intent_unreadable",
                    "journal resolution intent cannot be reopened",
                ) from error
            if observed != data:
                raise PhysicalCaptureSessionError(
                    "journal_resolution_intent_invalid",
                    "journal resolution intent differs after publication",
                )
        elif target_pending:
            if len(target_pending) != 1:
                raise PhysicalCaptureSessionError(
                    "journal_resolution_namespace_invalid",
                    "journal resolution has multiple pending publications",
                )
            candidate = target_pending[0]
            try:
                observed = self.archive.read_pending_fragment(
                    candidate, maximum=MAX_RECOVERY_BYTES
                )
            except PhysicalCaptureArchiveError as error:
                raise PhysicalCaptureSessionError(
                    "journal_resolution_intent_unreadable",
                    "pending journal resolution intent is unsafe",
                ) from error
            if observed == data:
                self.archive.publish_pending(candidate)
            elif data.startswith(observed):
                self.archive.discard_pending(candidate)
                self.archive.write_bytes(
                    relative, data, maximum=MAX_RECOVERY_BYTES
                )
            else:
                raise PhysicalCaptureSessionError(
                    "journal_resolution_intent_invalid",
                    "pending resolution intent is not an expected write prefix",
                )
        else:
            try:
                self.archive.write_bytes(
                    relative, data, maximum=MAX_RECOVERY_BYTES
                )
            except PhysicalCaptureArchiveError as error:
                raise PhysicalCaptureSessionError(
                    "journal_resolution_intent_failed",
                    "journal resolution intent could not be durably recorded",
                ) from error
        try:
            reopened = self.archive.read_bytes(
                relative, maximum=MAX_RECOVERY_BYTES
            )
        except PhysicalCaptureArchiveError as error:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_unreadable",
                "journal resolution intent cannot be verified",
            ) from error
        if reopened != data:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_invalid",
                "journal resolution intent changed after publication",
            )
        return hashlib.sha256(data).hexdigest()

    def _matching_resolution_intent(
        self,
        snapshot: SessionSnapshot,
    ) -> tuple[CaptureEvent, str] | None:
        relative = self._resolution_intent_relative(snapshot.sequence + 1)
        finals, pending = self._resolution_namespace()
        if pending:
            return None
        if Path(relative).name not in finals:
            return None
        try:
            data = self.archive.read_bytes(relative, maximum=MAX_RECOVERY_BYTES)
            value = load_json_bytes(data, "journal resolution intent")
        except (PhysicalCaptureArchiveError, RawArtifactError) as error:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_unreadable",
                "journal resolution intent cannot be reopened",
            ) from error
        sequence, state, event = self._validate_resolution_intent_value(value, data)
        if (
            sequence != snapshot.sequence + 1
            or state is not snapshot.state
            or value["previous_event_sha256"] != snapshot.last_event_sha256
        ):
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_invalid",
                "journal resolution intent differs from the current journal tip",
            )
        return event, hashlib.sha256(data).hexdigest()

    def _require_matching_resolution_intent(
        self,
        snapshot: SessionSnapshot | None,
        event: CaptureEvent,
    ) -> None:
        if snapshot is None:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_missing",
                "recovery event has no prior journal state",
            )
        matching = self._matching_resolution_intent(snapshot)
        if matching is None or matching[0] is not event:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_missing",
                "recovery event has no matching durable resolution intent",
            )

    def _replay_resolution_intents(
        self,
        snapshot: SessionSnapshot | None,
        *,
        complete_unresolved: bool,
    ) -> SessionSnapshot | None:
        finals, pending = self._resolution_namespace()
        if pending:
            raise PhysicalCaptureSessionError(
                "journal_resolution_recovery_required",
                "journal resolution intent publication is still pending",
            )
        records: list[tuple[int, dict[str, object], bytes, CaptureEvent]] = []
        for name in finals:
            if name == "uninitialized-session.json":
                raise PhysicalCaptureSessionError(
                    "journal_resolution_namespace_invalid",
                    "initialized journal cannot coexist with an uninitialized tombstone",
                )
            match = _JOURNAL_RESOLUTION_FILE_RE.fullmatch(name)
            if match is None:  # pragma: no cover - namespace already checked
                raise PhysicalCaptureSessionError(
                    "journal_resolution_namespace_invalid",
                    "journal resolution filename is malformed",
                )
            relative = f"{RECOVERY_DIRECTORY}/{name}"
            try:
                data = self.archive.read_bytes(
                    relative, maximum=MAX_RECOVERY_BYTES
                )
                value = load_json_bytes(data, "journal resolution intent")
            except (PhysicalCaptureArchiveError, RawArtifactError) as error:
                raise PhysicalCaptureSessionError(
                    "journal_resolution_intent_unreadable",
                    "journal resolution intent cannot be reopened",
                ) from error
            sequence, _state, event = self._validate_resolution_intent_value(
                value, data
            )
            if sequence != int(match.group("sequence")):
                raise PhysicalCaptureSessionError(
                    "journal_resolution_intent_invalid",
                    "journal resolution filename differs from its sequence",
                )
            records.append((sequence, value, data, event))
        if records and snapshot is None:
            raise PhysicalCaptureSessionError(
                "journal_resolution_intent_invalid",
                "journal resolution intent has no committed predecessor",
            )
        record_sequences = {sequence for sequence, _value, _data, _event in records}
        if snapshot is not None:
            for sequence in range(1, snapshot.sequence + 1):
                try:
                    event_data = self.archive.read_bytes(
                        f"{JOURNAL_DIRECTORY}/{sequence:08d}.json",
                        maximum=MAX_EVENT_BYTES,
                    )
                    journal_value = load_json_bytes(
                        event_data, "journal recovery binding scan"
                    )
                except (PhysicalCaptureArchiveError, RawArtifactError) as error:
                    raise PhysicalCaptureSessionError(
                        "journal_resolution_event_unreadable",
                        "journal recovery binding scan cannot reopen an event",
                    ) from error
                if (
                    isinstance(journal_value, dict)
                    and journal_value.get("event")
                    == CaptureEvent.PRE_SEND_ATTEMPT_DISCARDED.value
                    and sequence not in record_sequences
                ):
                    raise PhysicalCaptureSessionError(
                        "journal_resolution_intent_missing",
                        "pre-send recovery event lost its durable resolution intent",
                    )
        for sequence, value, data, event in sorted(records):
            assert snapshot is not None
            intent_sha256 = hashlib.sha256(data).hexdigest()
            if sequence <= snapshot.sequence:
                try:
                    event_data = self.archive.read_bytes(
                        f"{JOURNAL_DIRECTORY}/{sequence:08d}.json",
                        maximum=MAX_EVENT_BYTES,
                    )
                    journal_value = load_json_bytes(
                        event_data, "resolved recovery journal event"
                    )
                except (PhysicalCaptureArchiveError, RawArtifactError) as error:
                    raise PhysicalCaptureSessionError(
                        "journal_resolution_event_unreadable",
                        "resolved recovery journal event cannot be reopened",
                    ) from error
                if (
                    not isinstance(journal_value, dict)
                    or journal_value.get("sequence") != sequence
                    or journal_value.get("event") != event.value
                    or journal_value.get("from_state") != value["from_state"]
                    or journal_value.get("previous_event_sha256")
                    != value["previous_event_sha256"]
                    or journal_value.get("binding_sha256") != intent_sha256
                ):
                    raise PhysicalCaptureSessionError(
                        "journal_resolution_event_invalid",
                        "resolved recovery event differs from its durable intent",
                    )
                continue
            if (
                sequence != snapshot.sequence + 1
                or value["from_state"] != snapshot.state.value
                or value["previous_event_sha256"]
                != snapshot.last_event_sha256
            ):
                raise PhysicalCaptureSessionError(
                    "journal_resolution_sequence_invalid",
                    "journal resolution intent does not extend the current tip",
                )
            if not complete_unresolved:
                raise PhysicalCaptureSessionError(
                    "journal_resolution_recovery_required",
                    "unresolved journal resolution intent requires explicit recovery",
                )
            self._snapshot = snapshot
            snapshot = self.append(event, binding_sha256=intent_sha256)
        return snapshot

    def _resolve_pending_with_intent(
        self,
        pending: PendingFile,
        snapshot: SessionSnapshot,
        *,
        observed: bytes,
        event: CaptureEvent,
        action: str,
    ) -> None:
        binding = self._write_or_reopen_resolution_intent(
            pending,
            snapshot,
            observed=observed,
            event=event,
            action=action,
        )
        self.archive.discard_pending(pending)
        self._snapshot = snapshot
        self.append(event, binding_sha256=binding)

    def _recover_partial_pending(
        self,
        pending: PendingFile,
        snapshot: SessionSnapshot | None,
        observed: bytes,
    ) -> None:
        if snapshot is None:
            self._quarantine_uninitialized_session(pending)
            raise PhysicalCaptureSessionError(
                "uninitialized_session_quarantined",
                "partial first journal event was quarantined without inventing intent",
            )
        if snapshot.state in TERMINAL_STATES:
            raise PhysicalCaptureSessionError(
                "pending_after_terminal_state",
                "terminal physical session cannot contain a pending next event",
            )
        existing = self._matching_resolution_intent(snapshot)
        if existing is not None:
            event, _binding = existing
            action = {
                CaptureEvent.PRE_SEND_ATTEMPT_DISCARDED: (
                    "pre-send-attempt-not-published"
                ),
                CaptureEvent.NONCE_OUTCOME_UNKNOWN: "partial-event-after-attempt",
                CaptureEvent.RECEIPT_OUTCOME_UNKNOWN: "partial-event-after-attempt",
                CaptureEvent.SESSION_ABANDONED: "partial-event-abandoned",
            }[event]
            self._resolve_pending_with_intent(
                pending,
                snapshot,
                observed=observed,
                event=event,
                action=action,
            )
            return
        if snapshot.state in {
            CaptureState.NONCE_ATTEMPTED,
            CaptureState.RECEIPT_ATTEMPTED,
        }:
            event = (
                CaptureEvent.NONCE_OUTCOME_UNKNOWN
                if snapshot.state is CaptureState.NONCE_ATTEMPTED
                else CaptureEvent.RECEIPT_OUTCOME_UNKNOWN
            )
            self._resolve_pending_with_intent(
                pending,
                snapshot,
                observed=observed,
                event=event,
                action="partial-event-after-attempt",
            )
            return
        if snapshot.state not in _ABANDONABLE_STATES:
            raise PhysicalCaptureSessionError(
                "pending_recovery_state_invalid",
                "partial pending event cannot be resolved from the current state",
            )
        self._resolve_pending_with_intent(
            pending,
            snapshot,
            observed=observed,
            event=CaptureEvent.SESSION_ABANDONED,
            action="partial-event-abandoned",
        )

    def _uninitialized_tombstone_bytes(self) -> bytes:
        value = {
            "schema_version": 1,
            "document": UNINITIALIZED_TOMBSTONE_DOCUMENT,
            "archive_root": self.archive.root_relative_to_target,
            "pending_final_relative_path": f"{JOURNAL_DIRECTORY}/00000001.json",
            "action": "uninitialized-session-quarantined",
        }
        try:
            return canonical_json(value) + b"\n"
        except RawArtifactError as error:  # pragma: no cover - fixed literals
            raise PhysicalCaptureSessionError(
                "uninitialized_quarantine_failed",
                "uninitialized quarantine record cannot be encoded",
            ) from error

    def _validate_uninitialized_tombstone(self, data: bytes) -> None:
        expected = self._uninitialized_tombstone_bytes()
        if data != expected:
            raise PhysicalCaptureSessionError(
                "uninitialized_quarantine_invalid",
                "uninitialized quarantine record differs from its fixed archive root",
            )

    def _has_uninitialized_tombstone(self) -> bool:
        try:
            names = self.archive.list_names(RECOVERY_DIRECTORY)
        except PhysicalCaptureArchiveError as error:
            if error.code == "directory_not_found":
                return False
            raise PhysicalCaptureSessionError(
                "uninitialized_quarantine_unreadable",
                "uninitialized quarantine namespace cannot be inspected",
            ) from error
        if names != ("uninitialized-session.json",):
            if not names:
                return False
            raise PhysicalCaptureSessionError(
                "uninitialized_quarantine_invalid",
                "uninitialized quarantine namespace is not exact",
            )
        try:
            data = self.archive.read_bytes(
                UNINITIALIZED_TOMBSTONE_RELATIVE,
                maximum=MAX_RECOVERY_BYTES,
            )
        except PhysicalCaptureArchiveError as error:
            raise PhysicalCaptureSessionError(
                "uninitialized_quarantine_unreadable",
                "uninitialized quarantine record cannot be reopened",
            ) from error
        self._validate_uninitialized_tombstone(data)
        return True

    def _quarantine_uninitialized_session(
        self, pending: PendingFile | None
    ) -> None:
        if (
            pending is not None
            and pending.final_relative_path
            != f"{JOURNAL_DIRECTORY}/00000001.json"
        ):
            raise PhysicalCaptureSessionError(
                "uninitialized_quarantine_invalid",
                "uninitialized quarantine does not target the first journal event",
            )
        expected = self._uninitialized_tombstone_bytes()
        try:
            root_names = self.archive.list_root_names()
            if set(root_names) not in (
                {JOURNAL_DIRECTORY, LOCK_FILE},
                {JOURNAL_DIRECTORY, RECOVERY_DIRECTORY, LOCK_FILE},
            ):
                raise PhysicalCaptureSessionError(
                    "uninitialized_quarantine_invalid",
                    "uninitialized archive contains data beyond lock and journal",
                )
            expected_journal_names = (
                ()
                if pending is None
                else (Path(pending.relative_path).name,)
            )
            if self.archive.list_names(JOURNAL_DIRECTORY) != expected_journal_names:
                raise PhysicalCaptureSessionError(
                    "uninitialized_quarantine_invalid",
                    "uninitialized journal closure is not one pending first event",
                )
            try:
                names = self.archive.list_names(RECOVERY_DIRECTORY)
            except PhysicalCaptureArchiveError as error:
                if error.code != "directory_not_found":
                    raise
                names = ()
            if names:
                if names == ("uninitialized-session.json",):
                    self._validate_uninitialized_tombstone(
                        self.archive.read_bytes(
                            UNINITIALIZED_TOMBSTONE_RELATIVE,
                            maximum=MAX_RECOVERY_BYTES,
                        )
                    )
                else:
                    recovery_pending = self.archive.pending_files(
                        RECOVERY_DIRECTORY
                    )
                    if (
                        len(recovery_pending) != 1
                        or len(names) != 1
                        or recovery_pending[0].final_relative_path
                        != UNINITIALIZED_TOMBSTONE_RELATIVE
                    ):
                        raise PhysicalCaptureSessionError(
                            "uninitialized_quarantine_invalid",
                            "uninitialized quarantine publication is ambiguous",
                        )
                    recovery = recovery_pending[0]
                    data = self.archive.read_pending_fragment(
                        recovery, maximum=MAX_RECOVERY_BYTES
                    )
                    if data == expected:
                        self.archive.publish_pending(recovery)
                    elif expected.startswith(data):
                        self.archive.discard_pending(recovery)
                        self.archive.write_bytes(
                            UNINITIALIZED_TOMBSTONE_RELATIVE,
                            expected,
                            maximum=MAX_RECOVERY_BYTES,
                        )
                    else:
                        raise PhysicalCaptureSessionError(
                            "uninitialized_quarantine_invalid",
                            "pending quarantine bytes are not an expected write prefix",
                        )
            else:
                self.archive.write_bytes(
                    UNINITIALIZED_TOMBSTONE_RELATIVE,
                    expected,
                    maximum=MAX_RECOVERY_BYTES,
                )
            if not self._has_uninitialized_tombstone():
                raise PhysicalCaptureSessionError(
                    "uninitialized_quarantine_failed",
                    "uninitialized quarantine record was not durably published",
                )
            if pending is not None:
                self.archive.discard_pending(pending)
        except PhysicalCaptureSessionError:
            raise
        except PhysicalCaptureArchiveError as error:
            raise PhysicalCaptureSessionError(
                "uninitialized_quarantine_failed",
                "uninitialized session could not be durably quarantined",
            ) from error


__all__ = [
    "CaptureEvent",
    "CaptureState",
    "PhysicalCaptureSession",
    "PhysicalCaptureSessionError",
    "SessionEventView",
    "SessionSnapshot",
    "TERMINAL_STATES",
]
