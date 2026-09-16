from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile
from typing import cast
import unittest
from unittest.mock import patch

from scripts.harness.raw_artifacts import canonical_json
from scripts.physical_capture.archive import (
    PRIVATE_FILE_MODE,
    PhysicalCaptureArchiveError,
)
from scripts.physical_capture.cloud_run import (
    NonceResponse,
    OutcomeUnknownError,
    PreSendError,
    ReceiptResponse,
)
from scripts.physical_capture.session import (
    CaptureEvent,
    CaptureState,
    JOURNAL_DIRECTORY,
    PhysicalCaptureSession,
    PhysicalCaptureSessionError,
)
from scripts.physical_capture.transaction import (
    NONCE_REQUEST_RELATIVE_PATH,
    NONCE_RESPONSE_RELATIVE_PATH,
    RECEIPT_REQUEST_RELATIVE_PATH,
    RECEIPT_RESPONSE_RELATIVE_PATH,
    PhysicalCaptureOutcomeUnknownError,
    PhysicalCaptureTransaction,
    PhysicalCaptureTransactionError,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _nonce_request(label: str = "fixed") -> dict[str, object]:
    return {
        "schema_version": 1,
        "candidate": {"label": label},
        "run": {"host": "single-mac"},
    }


def _receipt_request(label: str = "fixed") -> dict[str, object]:
    return {
        "schema_version": 1,
        "candidate": {"label": label},
        "run": {"host": "single-mac"},
        "reports": [],
        "raw_artifacts": [],
    }


def _nonce_response() -> NonceResponse:
    return NonceResponse(
        schema_version=1,
        run_nonce="d" * 64,
        expires_at="2026-08-02T10:00:00Z",
    )


def _receipt_response() -> ReceiptResponse:
    signature = base64.urlsafe_b64encode(b"s" * 384).rstrip(b"=").decode("ascii")
    return ReceiptResponse(
        schema_version=1,
        signed_at="2026-08-02T09:00:00Z",
        receipt_sha256="e" * 64,
        signature=signature,
    )


class FatalCrash(BaseException):
    pass


class FakeCloudClient:
    def __init__(
        self,
        *,
        nonce_results: list[object] | None = None,
        receipt_results: list[object] | None = None,
    ) -> None:
        self.nonce_results = list(nonce_results or [_nonce_response()])
        self.receipt_results = list(receipt_results or [_receipt_response()])
        self.nonce_calls: list[dict[str, object]] = []
        self.receipt_calls: list[dict[str, object]] = []

    @staticmethod
    def _result(results: list[object]) -> object:
        if not results:
            raise AssertionError("unexpected second Cloud POST")
        result = results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def issue_nonce(self, request: dict[str, object]) -> NonceResponse:
        self.nonce_calls.append(request)
        return cast(NonceResponse, self._result(self.nonce_results))

    def issue_receipt(self, request: dict[str, object]) -> ReceiptResponse:
        self.receipt_calls.append(request)
        return cast(ReceiptResponse, self._result(self.receipt_results))


class PhysicalCaptureTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        (self.repository / "target").mkdir(mode=0o755)
        self.relative = "physical-capture/run-40003-macos15"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @property
    def root(self) -> Path:
        return self.repository / "target" / self.relative

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
                subject="transaction:observation",
                kind="lifecycle-event",
                relative="raw/lifecycle/observations/transaction.json",
                data=b'{"observed":true}\n',
            )
            session.complete_observations(
                {observation.subject: observation.descriptor.as_dict()}
            )
            return
        session.append(event, binding_sha256=_digest(event.value))

    def nonce_ready_session(self) -> PhysicalCaptureSession:
        session = self.create_session()
        self.append(session, CaptureEvent.COLLECTION_STARTED)
        self.append(session, CaptureEvent.RAW_COMPLETED)
        return session

    def receipt_ready_session(self) -> PhysicalCaptureSession:
        session = self.nonce_ready_session()
        for event in (
            CaptureEvent.NONCE_REQUEST_PREPARED,
            CaptureEvent.NONCE_ATTEMPT_STARTED,
            CaptureEvent.NONCE_RESPONSE_RECORDED,
            CaptureEvent.REPORTS_COMPOSED,
            CaptureEvent.BINDINGS_COMPOSED,
        ):
            self.append(session, event)
        return session

    def journal_documents(self) -> list[dict[str, object]]:
        directory = self.root / JOURNAL_DIRECTORY
        return [
            json.loads(path.read_bytes())
            for path in sorted(directory.glob("[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].json"))
        ]

    def assert_not_archived(self, sensitive: str) -> None:
        encoded = sensitive.encode("utf-8")
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(encoded, path.read_bytes(), path)

    def test_nonce_success_archives_exact_bytes_binds_digest_and_forbids_second_post(
        self,
    ) -> None:
        request = _nonce_request()
        response = _nonce_response()
        client = FakeCloudClient(nonce_results=[response])
        with self.nonce_ready_session() as session:
            transaction = PhysicalCaptureTransaction(session, client)
            self.assertEqual(transaction.issue_nonce(request), response)
            self.assertEqual(session.state, CaptureState.NONCE_RECEIVED)

            request_bytes = canonical_json(request) + b"\n"
            response_bytes = canonical_json(response.as_dict()) + b"\n"
            self.assertEqual(
                session.archive.read_bytes(NONCE_REQUEST_RELATIVE_PATH),
                request_bytes,
            )
            self.assertEqual(
                session.archive.read_bytes(NONCE_RESPONSE_RELATIVE_PATH),
                response_bytes,
            )
            self.assertEqual(
                session.snapshot.last_binding_sha256,
                hashlib.sha256(response_bytes).hexdigest(),
            )
            documents = self.journal_documents()
            self.assertEqual(
                documents[-3]["binding_sha256"],
                hashlib.sha256(request_bytes).hexdigest(),
            )
            self.assertEqual(documents[-3]["event"], "nonce_request_prepared")
            self.assertEqual(documents[-2]["event"], "nonce_attempt_started")
            self.assertEqual(documents[-1]["event"], "nonce_response_recorded")

            with self.assertRaises(PhysicalCaptureTransactionError):
                transaction.issue_nonce(request)
            self.assertEqual(len(client.nonce_calls), 1)

    def test_nonce_request_prefix_pending_is_recovered_before_post(self) -> None:
        request = _nonce_request("pending-restart")
        request_bytes = canonical_json(request) + b"\n"
        client = FakeCloudClient()
        with self.nonce_ready_session() as session:
            session.archive.ensure_directory("cloud")
            pending = self.root / "cloud" / (
                ".nonce-request.json.pending-" + "a" * 32
            )
            pending.write_bytes(request_bytes[:17])
            pending.chmod(PRIVATE_FILE_MODE)
            response = PhysicalCaptureTransaction(session, client).issue_nonce(
                request
            )
            self.assertEqual(response, _nonce_response())
            self.assertEqual(len(client.nonce_calls), 1)
            self.assertFalse(pending.exists())
            self.assertEqual(
                session.archive.read_bytes(NONCE_REQUEST_RELATIVE_PATH),
                request_bytes,
            )

    def test_receipt_uses_distinct_fixed_paths_states_and_method(self) -> None:
        request = _receipt_request()
        response = _receipt_response()
        client = FakeCloudClient(receipt_results=[response])
        with self.receipt_ready_session() as session:
            transaction = PhysicalCaptureTransaction(session, client)
            self.assertEqual(transaction.issue_receipt(request), response)
            self.assertEqual(session.state, CaptureState.RECEIPT_RECEIVED)
            self.assertEqual(len(client.receipt_calls), 1)
            self.assertEqual(client.nonce_calls, [])
            self.assertEqual(
                session.archive.read_bytes(RECEIPT_REQUEST_RELATIVE_PATH),
                canonical_json(request) + b"\n",
            )
            self.assertEqual(
                session.archive.read_bytes(RECEIPT_RESPONSE_RELATIVE_PATH),
                canonical_json(response.as_dict()) + b"\n",
            )
            with self.assertRaises(PhysicalCaptureTransactionError):
                transaction.issue_nonce(_nonce_request())
            self.assertEqual(client.nonce_calls, [])

    def test_invalid_or_unarchivable_request_never_reaches_cloud(self) -> None:
        client = FakeCloudClient()
        with self.nonce_ready_session() as session:
            transaction = PhysicalCaptureTransaction(session, client)
            with self.assertRaises(PhysicalCaptureTransactionError):
                transaction.issue_nonce({**_nonce_request(), "unknown": True})
            self.assertEqual(client.nonce_calls, [])
            self.assertEqual(session.state, CaptureState.RAW_COMPLETE)

            original = session.archive.write_bytes

            def fail_request(relative, data, *, maximum):
                if relative == NONCE_REQUEST_RELATIVE_PATH:
                    raise PhysicalCaptureArchiveError(
                        "injected_request_failure", "secret-request-error"
                    )
                return original(relative, data, maximum=maximum)

            with patch.object(session.archive, "write_bytes", side_effect=fail_request):
                with self.assertRaises(PhysicalCaptureTransactionError):
                    transaction.issue_nonce(_nonce_request())
            self.assertEqual(client.nonce_calls, [])
            self.assertEqual(session.state, CaptureState.RAW_COMPLETE)
        self.assert_not_archived("secret-request-error")

    def test_crash_after_request_archive_or_prepared_state_resumes_same_request(self) -> None:
        request = _nonce_request()
        data = canonical_json(request) + b"\n"
        client = FakeCloudClient()
        session = self.nonce_ready_session()
        session.archive.write_bytes(NONCE_REQUEST_RELATIVE_PATH, data)
        session.close()

        with PhysicalCaptureSession.open(self.repository, self.relative) as reopened:
            transaction = PhysicalCaptureTransaction(reopened, client)
            transaction.issue_nonce(request)
            self.assertEqual(reopened.state, CaptureState.NONCE_RECEIVED)
        self.assertEqual(len(client.nonce_calls), 1)

        other_relative = "physical-capture/run-40003-macos14"
        self.relative = other_relative
        session = self.nonce_ready_session()
        session.archive.write_bytes(NONCE_REQUEST_RELATIVE_PATH, data)
        session.append(
            CaptureEvent.NONCE_REQUEST_PREPARED,
            binding_sha256=hashlib.sha256(data).hexdigest(),
        )
        session.close()
        second_client = FakeCloudClient()
        with PhysicalCaptureSession.open(self.repository, other_relative) as reopened:
            transaction = PhysicalCaptureTransaction(reopened, second_client)
            transaction.issue_nonce(request)
        self.assertEqual(len(second_client.nonce_calls), 1)

    def test_pre_send_failure_is_recorded_and_only_manual_same_request_retries(self) -> None:
        secret = "bearer-secret-must-not-be-written"
        request = _nonce_request()
        client = FakeCloudClient(
            nonce_results=[PreSendError(secret), _nonce_response()]
        )
        session = self.nonce_ready_session()
        transaction = PhysicalCaptureTransaction(session, client)
        with self.assertRaises(PreSendError):
            transaction.issue_nonce(request)
        self.assertEqual(session.state, CaptureState.NONCE_REQUEST_PREPARED)
        self.assertEqual(len(client.nonce_calls), 1)
        self.assertEqual(
            self.journal_documents()[-1]["event"], "nonce_pre_send_failed"
        )
        session.close()

        with PhysicalCaptureSession.open(self.repository, self.relative) as session:
            transaction = PhysicalCaptureTransaction(session, client)
            with self.assertRaisesRegex(
                PhysicalCaptureTransactionError, "differs"
            ):
                transaction.issue_nonce(_nonce_request("changed"))
            self.assertEqual(len(client.nonce_calls), 1)

            transaction.issue_nonce(request)
            self.assertEqual(len(client.nonce_calls), 2)
            self.assertEqual(session.state, CaptureState.NONCE_RECEIVED)
        self.assert_not_archived(secret)

    def test_outcome_unknown_and_unexpected_client_error_are_terminal(self) -> None:
        for error in (
            OutcomeUnknownError("remote-secret"),
            RuntimeError("unexpected-client-secret"),
        ):
            with self.subTest(error=type(error).__name__):
                self.relative = (
                    "physical-capture/run-40003-" + type(error).__name__.lower()
                )
                client = FakeCloudClient(nonce_results=[error])
                with self.nonce_ready_session() as session:
                    transaction = PhysicalCaptureTransaction(session, client)
                    with self.assertRaises(PhysicalCaptureOutcomeUnknownError):
                        transaction.issue_nonce(_nonce_request())
                    self.assertEqual(
                        session.state, CaptureState.NONCE_OUTCOME_UNKNOWN
                    )
                    with self.assertRaises(PhysicalCaptureTransactionError):
                        transaction.issue_nonce(_nonce_request())
                    self.assertEqual(len(client.nonce_calls), 1)
                self.assert_not_archived(str(error))

    def test_response_archive_failure_or_existing_destination_is_terminal_unknown(
        self,
    ) -> None:
        for existing in (False, True):
            with self.subTest(existing=existing):
                self.relative = f"physical-capture/run-40003-existing-{existing}"
                client = FakeCloudClient()
                with self.nonce_ready_session() as session:
                    if existing:
                        session.archive.write_bytes(
                            NONCE_RESPONSE_RELATIVE_PATH,
                            b"preexisting-response\n",
                        )
                    original = session.archive.write_bytes

                    def write_bytes(relative, data, *, maximum):
                        if not existing and relative == NONCE_RESPONSE_RELATIVE_PATH:
                            raise PhysicalCaptureArchiveError(
                                "injected_response_failure", "response-secret"
                            )
                        return original(relative, data, maximum=maximum)

                    transaction = PhysicalCaptureTransaction(session, client)
                    with patch.object(
                        session.archive, "write_bytes", side_effect=write_bytes
                    ):
                        with self.assertRaises(
                            PhysicalCaptureOutcomeUnknownError
                        ):
                            transaction.issue_nonce(_nonce_request())
                    self.assertEqual(
                        session.state, CaptureState.NONCE_OUTCOME_UNKNOWN
                    )
                    self.assertEqual(len(client.nonce_calls), 1)
                self.assert_not_archived("response-secret")

    def test_attempted_crash_recovers_unknown_and_never_posts_again(self) -> None:
        client = FakeCloudClient(nonce_results=[FatalCrash()])
        session = self.nonce_ready_session()
        transaction = PhysicalCaptureTransaction(session, client)
        with self.assertRaises(FatalCrash):
            transaction.issue_nonce(_nonce_request())
        self.assertEqual(session.state, CaptureState.NONCE_ATTEMPTED)
        session.close()

        with PhysicalCaptureSession.open(self.repository, self.relative) as reopened:
            self.assertTrue(reopened.interrupted_attempt)
            reopened.resolve_interrupted_attempt()
            self.assertEqual(reopened.state, CaptureState.NONCE_OUTCOME_UNKNOWN)
            with self.assertRaises(PhysicalCaptureTransactionError):
                PhysicalCaptureTransaction(reopened, client).issue_nonce(
                    _nonce_request()
                )
        self.assertEqual(len(client.nonce_calls), 1)

    def test_pre_send_record_failure_stays_attempted_for_unknown_recovery(self) -> None:
        client = FakeCloudClient(nonce_results=[PreSendError("private-token")])
        session = self.nonce_ready_session()
        transaction = PhysicalCaptureTransaction(session, client)
        original = session.append

        def append(event, *, binding_sha256):
            if event is CaptureEvent.NONCE_PRE_SEND_FAILED:
                raise PhysicalCaptureSessionError(
                    "injected_journal_failure", "private-token"
                )
            return original(event, binding_sha256=binding_sha256)

        with patch.object(session, "append", side_effect=append):
            with self.assertRaisesRegex(
                PhysicalCaptureTransactionError, "do not retry"
            ):
                transaction.issue_nonce(_nonce_request())
        self.assertEqual(session.state, CaptureState.NONCE_ATTEMPTED)
        session.close()

        with PhysicalCaptureSession.open(self.repository, self.relative) as reopened:
            reopened.resolve_interrupted_attempt()
            self.assertEqual(reopened.state, CaptureState.NONCE_OUTCOME_UNKNOWN)
        self.assertEqual(len(client.nonce_calls), 1)
        self.assert_not_archived("private-token")

    def test_attempt_record_failure_never_posts_and_remains_manually_resumable(self) -> None:
        client = FakeCloudClient()
        with self.nonce_ready_session() as session:
            transaction = PhysicalCaptureTransaction(session, client)
            original = session.append

            def append(event, *, binding_sha256):
                if event is CaptureEvent.NONCE_ATTEMPT_STARTED:
                    raise PhysicalCaptureSessionError(
                        "injected_attempt_failure", "attempt journal failed"
                    )
                return original(event, binding_sha256=binding_sha256)

            with patch.object(session, "append", side_effect=append):
                with self.assertRaises(PhysicalCaptureTransactionError):
                    transaction.issue_nonce(_nonce_request())
            self.assertEqual(session.state, CaptureState.NONCE_REQUEST_PREPARED)
            self.assertEqual(client.nonce_calls, [])
            transaction.issue_nonce(_nonce_request())
            self.assertEqual(len(client.nonce_calls), 1)

    def test_crash_after_response_archive_before_journal_recovers_unknown(self) -> None:
        client = FakeCloudClient()
        session = self.nonce_ready_session()
        transaction = PhysicalCaptureTransaction(session, client)
        original = session.append

        def append(event, *, binding_sha256):
            if event is CaptureEvent.NONCE_RESPONSE_RECORDED:
                raise FatalCrash()
            return original(event, binding_sha256=binding_sha256)

        with patch.object(session, "append", side_effect=append):
            with self.assertRaises(FatalCrash):
                transaction.issue_nonce(_nonce_request())
        self.assertEqual(session.state, CaptureState.NONCE_ATTEMPTED)
        self.assertTrue((self.root / NONCE_RESPONSE_RELATIVE_PATH).is_file())
        session.close()

        with PhysicalCaptureSession.open(self.repository, self.relative) as reopened:
            reopened.resolve_interrupted_attempt()
            self.assertEqual(reopened.state, CaptureState.NONCE_OUTCOME_UNKNOWN)
            with self.assertRaises(PhysicalCaptureTransactionError):
                PhysicalCaptureTransaction(reopened, client).issue_nonce(
                    _nonce_request()
                )
        self.assertEqual(len(client.nonce_calls), 1)


if __name__ == "__main__":
    unittest.main()
