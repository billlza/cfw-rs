from __future__ import annotations

from datetime import timezone
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from scripts.harness.raw_artifacts import canonical_json, load_json_bytes
from scripts.physical_capture.archive import (
    PRIVATE_FILE_MODE,
    PendingFile,
    SecureArchive,
)
from scripts.physical_capture.session import (
    CaptureEvent,
    CaptureState,
    EVENT_DOCUMENT,
    EVENT_SCHEMA_VERSION,
    JOURNAL_DIRECTORY,
    PhysicalCaptureSession,
    PhysicalCaptureSessionError,
    SessionSnapshot,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class PhysicalCaptureSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        (self.repository / "target").mkdir(mode=0o755)
        self.relative = "physical-capture/run-40003-macos15"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_session(self) -> PhysicalCaptureSession:
        return PhysicalCaptureSession.create(
            self.repository,
            self.relative,
            intent_sha256=_digest("intent"),
        )

    def append(self, session: PhysicalCaptureSession, event: CaptureEvent) -> None:
        if event is CaptureEvent.RAW_COMPLETED:
            capture = session.observation_capture()
            observation = capture.write_bytes(
                subject="session:observation",
                kind="lifecycle-event",
                relative="raw/lifecycle/observations/session.json",
                data=b'{"observed":true}\n',
            )
            session.complete_observations(
                {observation.subject: observation.descriptor.as_dict()}
            )
            return
        session.append(event, binding_sha256=_digest(event.value))

    def write_pending_nonce_attempt(
        self, nonce: str
    ) -> tuple[SessionSnapshot, Path]:
        session = self.create_session()
        for event in (
            CaptureEvent.COLLECTION_STARTED,
            CaptureEvent.RAW_COMPLETED,
            CaptureEvent.NONCE_REQUEST_PREPARED,
        ):
            self.append(session, event)
        snapshot = session.snapshot
        session.close()
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        event = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "document": EVENT_DOCUMENT,
            "sequence": snapshot.sequence + 1,
            "event": CaptureEvent.NONCE_ATTEMPT_STARTED.value,
            "from_state": CaptureState.NONCE_REQUEST_PREPARED.value,
            "to_state": CaptureState.NONCE_ATTEMPTED.value,
            "recorded_at": snapshot.last_recorded_at.astimezone(
                timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "previous_event_sha256": snapshot.last_event_sha256,
            "binding_sha256": _digest("nonce-request"),
        }
        pending = journal / (
            f".{snapshot.sequence + 1:08d}.json.pending-" + nonce * 32
        )
        pending.write_bytes(canonical_json(event) + b"\n")
        pending.chmod(PRIVATE_FILE_MODE)
        return snapshot, pending

    def test_complete_state_machine_is_append_only_and_final(self) -> None:
        events = (
            (CaptureEvent.COLLECTION_STARTED, CaptureState.COLLECTING),
            (CaptureEvent.RAW_COMPLETED, CaptureState.RAW_COMPLETE),
            (
                CaptureEvent.NONCE_REQUEST_PREPARED,
                CaptureState.NONCE_REQUEST_PREPARED,
            ),
            (CaptureEvent.NONCE_ATTEMPT_STARTED, CaptureState.NONCE_ATTEMPTED),
            (CaptureEvent.NONCE_RESPONSE_RECORDED, CaptureState.NONCE_RECEIVED),
            (CaptureEvent.REPORTS_COMPOSED, CaptureState.REPORTS_COMPOSED),
            (CaptureEvent.BINDINGS_COMPOSED, CaptureState.BINDINGS_COMPOSED),
            (
                CaptureEvent.RECEIPT_REQUEST_PREPARED,
                CaptureState.RECEIPT_REQUEST_PREPARED,
            ),
            (
                CaptureEvent.RECEIPT_ATTEMPT_STARTED,
                CaptureState.RECEIPT_ATTEMPTED,
            ),
            (
                CaptureEvent.RECEIPT_RESPONSE_RECORDED,
                CaptureState.RECEIPT_RECEIVED,
            ),
            (CaptureEvent.RUN_FINALIZED, CaptureState.FINALIZED),
        )
        with self.create_session() as session:
            self.assertEqual(session.state, CaptureState.INITIALIZED)
            for event, expected in events:
                self.append(session, event)
                self.assertEqual(session.state, expected)
            self.assertTrue(session.is_terminal)
            self.assertEqual(session.snapshot.sequence, len(events) + 1)
            with self.assertRaisesRegex(
                PhysicalCaptureSessionError, "cannot abandon"
            ):
                self.append(session, CaptureEvent.SESSION_ABANDONED)

        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        names = sorted(path.name for path in journal.iterdir())
        self.assertEqual(
            names,
            [f"{sequence:08d}.json" for sequence in range(1, len(events) + 2)],
        )

    def test_invalid_transition_creates_no_event(self) -> None:
        with self.create_session() as session:
            with self.assertRaisesRegex(
                PhysicalCaptureSessionError, "only before RAW_COMPLETED"
            ):
                session.complete_observations({})
            self.assertEqual(session.snapshot.sequence, 1)
            self.assertEqual(session.state, CaptureState.INITIALIZED)

    def test_nonce_unknown_is_terminal_and_cannot_be_abandoned(self) -> None:
        with self.create_session() as session:
            for event in (
                CaptureEvent.COLLECTION_STARTED,
                CaptureEvent.RAW_COMPLETED,
                CaptureEvent.NONCE_REQUEST_PREPARED,
                CaptureEvent.NONCE_ATTEMPT_STARTED,
            ):
                self.append(session, event)
            self.append(session, CaptureEvent.NONCE_OUTCOME_UNKNOWN)
            self.assertEqual(session.state, CaptureState.NONCE_OUTCOME_UNKNOWN)
            self.assertTrue(session.is_terminal)
            with self.assertRaises(PhysicalCaptureSessionError):
                session.abandon(binding_sha256=_digest("abandon"))

    def test_pre_send_failures_return_only_to_the_matching_prepared_state(self) -> None:
        with self.create_session() as session:
            for event in (
                CaptureEvent.COLLECTION_STARTED,
                CaptureEvent.RAW_COMPLETED,
                CaptureEvent.NONCE_REQUEST_PREPARED,
                CaptureEvent.NONCE_ATTEMPT_STARTED,
            ):
                self.append(session, event)
            binding = _digest("same-nonce-request")
            snapshot = session.append(
                CaptureEvent.NONCE_PRE_SEND_FAILED,
                binding_sha256=binding,
            )
            self.assertEqual(snapshot.state, CaptureState.NONCE_REQUEST_PREPARED)
            self.assertEqual(snapshot.last_binding_sha256, binding)
            with self.assertRaises(PhysicalCaptureSessionError):
                session.append(
                    CaptureEvent.RECEIPT_PRE_SEND_FAILED,
                    binding_sha256=binding,
                )

        self.relative = "physical-capture/run-40003-macos14"
        with self.create_session() as session:
            for event in (
                CaptureEvent.COLLECTION_STARTED,
                CaptureEvent.RAW_COMPLETED,
                CaptureEvent.NONCE_REQUEST_PREPARED,
                CaptureEvent.NONCE_ATTEMPT_STARTED,
                CaptureEvent.NONCE_RESPONSE_RECORDED,
                CaptureEvent.REPORTS_COMPOSED,
                CaptureEvent.BINDINGS_COMPOSED,
                CaptureEvent.RECEIPT_REQUEST_PREPARED,
                CaptureEvent.RECEIPT_ATTEMPT_STARTED,
            ):
                self.append(session, event)
            binding = _digest("same-receipt-request")
            snapshot = session.append(
                CaptureEvent.RECEIPT_PRE_SEND_FAILED,
                binding_sha256=binding,
            )
            self.assertEqual(snapshot.state, CaptureState.RECEIPT_REQUEST_PREPARED)
            self.assertEqual(snapshot.last_binding_sha256, binding)

    def test_receipt_unknown_is_terminal(self) -> None:
        with self.create_session() as session:
            for event in (
                CaptureEvent.COLLECTION_STARTED,
                CaptureEvent.RAW_COMPLETED,
                CaptureEvent.NONCE_REQUEST_PREPARED,
                CaptureEvent.NONCE_ATTEMPT_STARTED,
                CaptureEvent.NONCE_RESPONSE_RECORDED,
                CaptureEvent.REPORTS_COMPOSED,
                CaptureEvent.BINDINGS_COMPOSED,
                CaptureEvent.RECEIPT_REQUEST_PREPARED,
                CaptureEvent.RECEIPT_ATTEMPT_STARTED,
                CaptureEvent.RECEIPT_OUTCOME_UNKNOWN,
            ):
                self.append(session, event)
            self.assertEqual(session.state, CaptureState.RECEIPT_OUTCOME_UNKNOWN)
            self.assertTrue(session.is_terminal)

    def test_restart_replays_hash_chain_and_continues(self) -> None:
        session = self.create_session()
        self.append(session, CaptureEvent.COLLECTION_STARTED)
        expected = session.snapshot
        session.close()

        with PhysicalCaptureSession.open(self.repository, self.relative) as reopened:
            self.assertEqual(reopened.snapshot, expected)
            self.append(reopened, CaptureEvent.RAW_COMPLETED)
            self.assertEqual(reopened.state, CaptureState.RAW_COMPLETE)

    def test_session_lock_rejects_concurrent_writer(self) -> None:
        session = self.create_session()
        try:
            with self.assertRaisesRegex(PhysicalCaptureSessionError, "already locked"):
                PhysicalCaptureSession.open(self.repository, self.relative)
        finally:
            session.close()
        with PhysicalCaptureSession.open(self.repository, self.relative) as reopened:
            self.assertEqual(reopened.state, CaptureState.INITIALIZED)

    def test_restart_resolution_conservatively_marks_attempt_unknown(self) -> None:
        session = self.create_session()
        for event in (
            CaptureEvent.COLLECTION_STARTED,
            CaptureEvent.RAW_COMPLETED,
            CaptureEvent.NONCE_REQUEST_PREPARED,
            CaptureEvent.NONCE_ATTEMPT_STARTED,
        ):
            self.append(session, event)
        session.close()

        with PhysicalCaptureSession.open(self.repository, self.relative) as reopened:
            self.assertTrue(reopened.interrupted_attempt)
            reopened.resolve_interrupted_attempt()
            self.assertEqual(reopened.state, CaptureState.NONCE_OUTCOME_UNKNOWN)
            self.assertTrue(reopened.is_terminal)

    def test_resolve_interrupted_attempt_rejects_safe_resumable_state(self) -> None:
        with self.create_session() as session:
            with self.assertRaisesRegex(
                PhysicalCaptureSessionError, "not awaiting resolution"
            ):
                session.resolve_interrupted_attempt()

    def test_hash_chain_tampering_is_detected(self) -> None:
        session = self.create_session()
        self.append(session, CaptureEvent.COLLECTION_STARTED)
        self.append(session, CaptureEvent.RAW_COMPLETED)
        session.close()
        event = (
            self.repository
            / "target"
            / self.relative
            / JOURNAL_DIRECTORY
            / "00000002.json"
        )
        data = event.read_bytes()
        event.write_bytes(data.replace(b"collection_started", b"collection_tampered"))
        event.chmod(PRIVATE_FILE_MODE)
        with self.assertRaises(PhysicalCaptureSessionError):
            PhysicalCaptureSession.open(self.repository, self.relative)

    def test_sequence_gap_and_unexpected_entry_are_rejected(self) -> None:
        session = self.create_session()
        self.append(session, CaptureEvent.COLLECTION_STARTED)
        session.close()
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        (journal / "00000002.json").rename(journal / "00000003.json")
        with self.assertRaisesRegex(PhysicalCaptureSessionError, "not contiguous"):
            PhysicalCaptureSession.open(self.repository, self.relative)
        (journal / "00000003.json").rename(journal / "00000002.json")
        unexpected = journal / "notes.txt"
        unexpected.write_text("not evidence", encoding="utf-8")
        unexpected.chmod(PRIVATE_FILE_MODE)
        with self.assertRaisesRegex(PhysicalCaptureSessionError, "unexpected entry"):
            PhysicalCaptureSession.open(self.repository, self.relative)

    def test_malformed_pending_name_is_not_ignored(self) -> None:
        session = self.create_session()
        session.close()
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        malformed = journal / ".00000002.json.pending-not-a-nonce"
        malformed.write_bytes(b"not a recoverable journal event\n")
        malformed.chmod(PRIVATE_FILE_MODE)

        with self.assertRaisesRegex(PhysicalCaptureSessionError, "unexpected entry"):
            PhysicalCaptureSession.open(self.repository, self.relative)
        with self.assertRaisesRegex(PhysicalCaptureSessionError, "unexpected entry"):
            PhysicalCaptureSession.recover(self.repository, self.relative)

    def test_valid_pending_event_requires_explicit_recovery_then_is_promoted(self) -> None:
        session = self.create_session()
        snapshot = session.snapshot
        session.close()
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        recorded_at = snapshot.last_recorded_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        event = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "document": EVENT_DOCUMENT,
            "sequence": 2,
            "event": CaptureEvent.COLLECTION_STARTED.value,
            "from_state": CaptureState.INITIALIZED.value,
            "to_state": CaptureState.COLLECTING.value,
            "recorded_at": recorded_at,
            "previous_event_sha256": snapshot.last_event_sha256,
            "binding_sha256": _digest("pending-collection"),
        }
        pending = journal / (".00000002.json.pending-" + "a" * 32)
        pending.write_bytes(canonical_json(event) + b"\n")
        pending.chmod(PRIVATE_FILE_MODE)

        with self.assertRaisesRegex(PhysicalCaptureSessionError, "recovery"):
            PhysicalCaptureSession.open(self.repository, self.relative)
        with PhysicalCaptureSession.recover(self.repository, self.relative) as recovered:
            self.assertEqual(recovered.state, CaptureState.COLLECTING)
            self.assertEqual(recovered.snapshot.sequence, 2)
        self.assertFalse(pending.exists())
        self.assertTrue((journal / "00000002.json").is_file())

    def test_pending_attempt_is_discarded_and_audited_before_any_post(self) -> None:
        snapshot, pending = self.write_pending_nonce_attempt("d")
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY

        with PhysicalCaptureSession.recover(
            self.repository, self.relative
        ) as recovered:
            self.assertEqual(
                recovered.state, CaptureState.NONCE_REQUEST_PREPARED
            )
            self.assertEqual(recovered.snapshot.sequence, snapshot.sequence + 1)
        audit = journal / f"{snapshot.sequence + 1:08d}.json"
        self.assertFalse(pending.exists())
        self.assertIn(
            b'"event":"pre_send_attempt_discarded"', audit.read_bytes()
        )

    def test_open_rejects_deleted_pre_send_resolution_intent(self) -> None:
        snapshot, _pending = self.write_pending_nonce_attempt("8")
        with PhysicalCaptureSession.recover(
            self.repository, self.relative
        ):
            pass
        intent = (
            self.repository
            / "target"
            / self.relative
            / f"recovery/journal-{snapshot.sequence + 1:08d}.json"
        )
        self.assertTrue(intent.is_file())
        intent.unlink()

        with self.assertRaises(PhysicalCaptureSessionError) as raised:
            PhysicalCaptureSession.open(self.repository, self.relative)
        self.assertEqual(
            raised.exception.code, "journal_resolution_intent_missing"
        )

    def test_open_rejects_tampered_pre_send_resolution_intent(self) -> None:
        snapshot, _pending = self.write_pending_nonce_attempt("9")
        with PhysicalCaptureSession.recover(
            self.repository, self.relative
        ):
            pass
        intent = (
            self.repository
            / "target"
            / self.relative
            / f"recovery/journal-{snapshot.sequence + 1:08d}.json"
        )
        value = load_json_bytes(intent.read_bytes(), "test resolution intent")
        self.assertIsInstance(value, dict)
        value["pending_sha256"] = "f" * 64
        intent.write_bytes(canonical_json(value) + b"\n")
        intent.chmod(PRIVATE_FILE_MODE)

        with self.assertRaises(PhysicalCaptureSessionError) as raised:
            PhysicalCaptureSession.open(self.repository, self.relative)
        self.assertEqual(
            raised.exception.code, "journal_resolution_event_invalid"
        )

    def test_partial_event_after_post_attempt_becomes_outcome_unknown(self) -> None:
        session = self.create_session()
        for event in (
            CaptureEvent.COLLECTION_STARTED,
            CaptureEvent.RAW_COMPLETED,
            CaptureEvent.NONCE_REQUEST_PREPARED,
            CaptureEvent.NONCE_ATTEMPT_STARTED,
        ):
            self.append(session, event)
        snapshot = session.snapshot
        session.close()
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        pending = journal / (
            f".{snapshot.sequence + 1:08d}.json.pending-" + "e" * 32
        )
        pending.touch(mode=PRIVATE_FILE_MODE)
        pending.chmod(PRIVATE_FILE_MODE)

        with PhysicalCaptureSession.recover(
            self.repository, self.relative, discard_incomplete=True
        ) as recovered:
            self.assertEqual(
                recovered.state, CaptureState.NONCE_OUTCOME_UNKNOWN
            )
            self.assertTrue(recovered.is_terminal)
        self.assertFalse(pending.exists())

    def test_complete_json_without_final_newline_uses_partial_policy(self) -> None:
        session = self.create_session()
        snapshot = session.snapshot
        session.close()
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        event = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "document": EVENT_DOCUMENT,
            "sequence": 2,
            "event": CaptureEvent.COLLECTION_STARTED.value,
            "from_state": CaptureState.INITIALIZED.value,
            "to_state": CaptureState.COLLECTING.value,
            "recorded_at": snapshot.last_recorded_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "previous_event_sha256": snapshot.last_event_sha256,
            "binding_sha256": _digest("collection"),
        }
        pending = journal / (".00000002.json.pending-" + "3" * 32)
        pending.write_bytes(canonical_json(event))
        pending.chmod(PRIVATE_FILE_MODE)

        with PhysicalCaptureSession.recover(
            self.repository, self.relative, discard_incomplete=True
        ) as recovered:
            self.assertEqual(recovered.state, CaptureState.ABANDONED)
        self.assertFalse(pending.exists())
        self.assertTrue(
            (
                self.repository
                / "target"
                / self.relative
                / "recovery/journal-00000002.json"
            ).is_file()
        )

    def test_canonical_pending_event_with_wrong_hash_is_not_discarded(self) -> None:
        session = self.create_session()
        snapshot = session.snapshot
        session.close()
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        event = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "document": EVENT_DOCUMENT,
            "sequence": 2,
            "event": CaptureEvent.COLLECTION_STARTED.value,
            "from_state": CaptureState.INITIALIZED.value,
            "to_state": CaptureState.COLLECTING.value,
            "recorded_at": snapshot.last_recorded_at.astimezone(
                timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "previous_event_sha256": "f" * 64,
            "binding_sha256": _digest("collection"),
        }
        pending = journal / (".00000002.json.pending-" + "7" * 32)
        pending.write_bytes(canonical_json(event) + b"\n")
        pending.chmod(PRIVATE_FILE_MODE)

        with self.assertRaises(PhysicalCaptureSessionError) as raised:
            PhysicalCaptureSession.recover(
                self.repository, self.relative, discard_incomplete=True
            )
        self.assertEqual(raised.exception.code, "journal_hash_chain_mismatch")
        self.assertTrue(pending.is_file())

    def test_resolution_intent_replays_crash_after_pending_discard(self) -> None:
        session = self.create_session()
        snapshot = session.snapshot
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        pending_path = journal / (".00000002.json.pending-" + "4" * 32)
        pending_path.touch(mode=PRIVATE_FILE_MODE)
        pending_path.chmod(PRIVATE_FILE_MODE)
        pending = session.archive.pending_files(JOURNAL_DIRECTORY)[0]
        binding = session._write_or_reopen_resolution_intent(
            pending,
            snapshot,
            observed=b"",
            event=CaptureEvent.SESSION_ABANDONED,
            action="partial-event-abandoned",
        )
        session.archive.discard_pending(pending)
        session.close()

        with self.assertRaises(PhysicalCaptureSessionError) as raised:
            PhysicalCaptureSession.open(self.repository, self.relative)
        self.assertEqual(
            raised.exception.code, "journal_resolution_recovery_required"
        )
        with PhysicalCaptureSession.recover(
            self.repository, self.relative, discard_incomplete=True
        ) as recovered:
            self.assertEqual(recovered.state, CaptureState.ABANDONED)
            self.assertEqual(recovered.snapshot.last_binding_sha256, binding)
            self.assertEqual(
                recovered.resolution_binding_for_last_event(
                    CaptureEvent.SESSION_ABANDONED
                ),
                binding,
            )
        self.assertFalse(pending_path.exists())

    def test_resolution_intent_rejects_noncanonical_pending_path(self) -> None:
        with self.create_session() as session:
            pending = PendingFile(
                relative_path=(
                    "journal/.00000002.json.pending-" + "a" * 32
                ),
                final_relative_path="journal/00000002.json",
            )
            data = session._resolution_intent_bytes(
                pending,
                session.snapshot,
                observed=b"",
                event=CaptureEvent.SESSION_ABANDONED,
                action="partial-event-abandoned",
            )
            base = load_json_bytes(data, "test resolution intent")
            self.assertIsInstance(base, dict)
            for malformed_path in (
                pending.relative_path + "/../../forged",
                pending.relative_path + "-suffix",
            ):
                with self.subTest(pending_relative_path=malformed_path):
                    value = dict(base)
                    value["pending_relative_path"] = malformed_path
                    malformed = canonical_json(value) + b"\n"
                    with self.assertRaises(
                        PhysicalCaptureSessionError
                    ) as raised:
                        session._validate_resolution_intent_value(
                            value, malformed
                        )
                    self.assertEqual(
                        raised.exception.code,
                        "journal_resolution_intent_invalid",
                    )

    def test_resolution_intent_is_bound_to_its_archive_root(self) -> None:
        with self.create_session() as source:
            pending = PendingFile(
                relative_path=(
                    "journal/.00000002.json.pending-" + "c" * 32
                ),
                final_relative_path="journal/00000002.json",
            )
            data = source._resolution_intent_bytes(
                pending,
                source.snapshot,
                observed=b"",
                event=CaptureEvent.SESSION_ABANDONED,
                action="partial-event-abandoned",
            )
        value = load_json_bytes(data, "cross-root resolution intent")
        self.assertIsInstance(value, dict)
        with PhysicalCaptureSession.create(
            self.repository,
            "physical-capture/another-run",
            intent_sha256=_digest("another-intent"),
        ) as target:
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                target._validate_resolution_intent_value(value, data)
        self.assertEqual(
            raised.exception.code, "journal_resolution_intent_invalid"
        )

    def test_first_pending_event_can_recover_interrupted_session_creation(self) -> None:
        with SecureArchive.create(self.repository, self.relative) as archive:
            lock_fd = archive.create_lock_file("session.lock")
            os.close(lock_fd)
            archive.ensure_directory(JOURNAL_DIRECTORY)
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        event = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "document": EVENT_DOCUMENT,
            "sequence": 1,
            "event": CaptureEvent.SESSION_STARTED.value,
            "from_state": None,
            "to_state": CaptureState.INITIALIZED.value,
            "recorded_at": "2026-08-02T00:00:00Z",
            "previous_event_sha256": "0" * 64,
            "binding_sha256": _digest("intent"),
        }
        pending = journal / (".00000001.json.pending-" + "c" * 32)
        pending.write_bytes(canonical_json(event) + b"\n")
        pending.chmod(PRIVATE_FILE_MODE)

        with PhysicalCaptureSession.recover(self.repository, self.relative) as recovered:
            self.assertEqual(recovered.state, CaptureState.INITIALIZED)
            self.assertEqual(recovered.snapshot.sequence, 1)
        self.assertFalse(pending.exists())
        self.assertTrue((journal / "00000001.json").is_file())

    def test_incomplete_pending_requires_explicit_discard(self) -> None:
        session = self.create_session()
        session.close()
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        pending = journal / (".00000002.json.pending-" + "b" * 32)
        pending.touch(mode=PRIVATE_FILE_MODE)
        pending.chmod(PRIVATE_FILE_MODE)
        with self.assertRaisesRegex(PhysicalCaptureSessionError, "cannot be recovered"):
            PhysicalCaptureSession.recover(self.repository, self.relative)
        with PhysicalCaptureSession.recover(
            self.repository, self.relative, discard_incomplete=True
        ) as recovered:
            self.assertEqual(recovered.state, CaptureState.ABANDONED)
        self.assertFalse(pending.exists())

    def test_partial_first_event_cannot_invent_an_unknown_intent(self) -> None:
        with SecureArchive.create(self.repository, self.relative) as archive:
            lock_fd = archive.create_lock_file("session.lock")
            os.close(lock_fd)
            archive.ensure_directory(JOURNAL_DIRECTORY)
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        pending = journal / (".00000001.json.pending-" + "f" * 32)
        pending.touch(mode=PRIVATE_FILE_MODE)
        pending.chmod(PRIVATE_FILE_MODE)

        with self.assertRaisesRegex(
            PhysicalCaptureSessionError, "without inventing intent"
        ) as raised:
            PhysicalCaptureSession.recover(
                self.repository, self.relative, discard_incomplete=True
            )
        self.assertEqual(
            raised.exception.code, "uninitialized_session_quarantined"
        )
        self.assertFalse(pending.exists())
        self.assertTrue(
            PhysicalCaptureSession.uninitialized_quarantined(
                self.repository, self.relative
            )
        )

    def test_all_pre_intent_create_crash_points_are_quarantined(self) -> None:
        for index, shape in enumerate(
            ("root", "lock", "journal", "recovery"), start=1
        ):
            with self.subTest(shape=shape):
                relative = f"physical-capture/pre-intent-{index}"
                with SecureArchive.create(self.repository, relative) as archive:
                    if shape in {"lock", "journal", "recovery"}:
                        lock_fd = archive.create_lock_file("session.lock")
                        os.close(lock_fd)
                    if shape in {"journal", "recovery"}:
                        archive.ensure_directory(JOURNAL_DIRECTORY)
                    if shape == "recovery":
                        archive.ensure_directory("recovery")
                with self.assertRaises(PhysicalCaptureSessionError) as raised:
                    PhysicalCaptureSession.recover(
                        self.repository, relative, discard_incomplete=True
                    )
                self.assertEqual(
                    raised.exception.code,
                    "uninitialized_session_quarantined",
                )
                self.assertTrue(
                    PhysicalCaptureSession.uninitialized_quarantined(
                        self.repository, relative
                    )
                )

    def test_partial_tombstone_publication_is_safely_rewritten(self) -> None:
        with SecureArchive.create(self.repository, self.relative) as archive:
            lock_fd = archive.create_lock_file("session.lock")
            os.close(lock_fd)
            archive.ensure_directory(JOURNAL_DIRECTORY)
            archive.ensure_directory("recovery")
        root = self.repository / "target" / self.relative
        journal_pending = (
            root / JOURNAL_DIRECTORY / (".00000001.json.pending-" + "5" * 32)
        )
        journal_pending.touch(mode=PRIVATE_FILE_MODE)
        journal_pending.chmod(PRIVATE_FILE_MODE)
        tombstone_pending = (
            root
            / "recovery"
            / (".uninitialized-session.json.pending-" + "6" * 32)
        )
        expected_tombstone = canonical_json(
            {
                "schema_version": 1,
                "document": "cfw-physical-uninitialized-session-quarantine-v1",
                "archive_root": self.relative,
                "pending_final_relative_path": "journal/00000001.json",
                "action": "uninitialized-session-quarantined",
            }
        ) + b"\n"
        tombstone_pending.write_bytes(expected_tombstone[:47])
        tombstone_pending.chmod(PRIVATE_FILE_MODE)

        with self.assertRaises(PhysicalCaptureSessionError) as raised:
            PhysicalCaptureSession.recover(
                self.repository, self.relative, discard_incomplete=True
            )
        self.assertEqual(
            raised.exception.code, "uninitialized_session_quarantined"
        )
        self.assertFalse(journal_pending.exists())
        self.assertFalse(tombstone_pending.exists())
        self.assertTrue(
            PhysicalCaptureSession.uninitialized_quarantined(
                self.repository, self.relative
            )
        )

    def test_uninitialized_quarantine_rejects_any_extra_archive_data(self) -> None:
        with SecureArchive.create(self.repository, self.relative) as archive:
            lock_fd = archive.create_lock_file("session.lock")
            os.close(lock_fd)
            archive.ensure_directory(JOURNAL_DIRECTORY)
            archive.write_bytes("inputs/unexpected.json", b"{}\n")
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        pending = journal / (".00000001.json.pending-" + "1" * 32)
        pending.touch(mode=PRIVATE_FILE_MODE)
        pending.chmod(PRIVATE_FILE_MODE)

        with self.assertRaisesRegex(
            PhysicalCaptureSessionError, "beyond lock and journal"
        ):
            PhysicalCaptureSession.recover(
                self.repository, self.relative, discard_incomplete=True
            )
        self.assertTrue(pending.exists())
        self.assertFalse(
            PhysicalCaptureSession.uninitialized_quarantined(
                self.repository, self.relative
            )
        )

    def test_journal_files_are_owner_only_single_link(self) -> None:
        with self.create_session() as session:
            self.append(session, CaptureEvent.COLLECTION_STARTED)
        journal = self.repository / "target" / self.relative / JOURNAL_DIRECTORY
        for event in journal.iterdir():
            metadata = event.stat()
            self.assertEqual(metadata.st_uid, os.geteuid())
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(metadata.st_mode & 0o777, PRIVATE_FILE_MODE)


if __name__ == "__main__":
    unittest.main()
