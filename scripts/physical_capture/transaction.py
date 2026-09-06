"""Crash-conservative local transactions around the two Cloud Run POSTs.

The request bytes and their journal binding are durable before the one allowed
POST begins.  Only a proven :class:`PreSendError` may return a transaction to a
prepared state.  Every other failure after the attempted event is durable is
terminal or requires restart recovery, which resolves the attempt as outcome
unknown rather than risking a duplicate POST.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Final, Literal, Protocol

from scripts.harness.raw_artifacts import (
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
)

from .archive import ArchivedFile, PhysicalCaptureArchiveError
from .cloud_run import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    NONCE_REQUEST_FIELDS,
    RECEIPT_REQUEST_FIELDS,
    NonceResponse,
    OutcomeUnknownError,
    PreSendError,
    ReceiptResponse,
)
from .session import (
    CaptureEvent,
    CaptureState,
    PhysicalCaptureSession,
    PhysicalCaptureSessionError,
)


CLOUD_TRANSACTION_DIRECTORY: Final = "cloud"
NONCE_REQUEST_RELATIVE_PATH: Final = "cloud/nonce-request.json"
NONCE_RESPONSE_RELATIVE_PATH: Final = "cloud/nonce-response.json"
RECEIPT_REQUEST_RELATIVE_PATH: Final = "cloud/receipt-request.json"
RECEIPT_RESPONSE_RELATIVE_PATH: Final = "cloud/receipt-response.json"

TransactionRole = Literal["nonce", "receipt"]


class PhysicalCaptureTransactionError(RuntimeError):
    """A fixed local Cloud POST transaction cannot progress safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PhysicalCaptureOutcomeUnknownError(PhysicalCaptureTransactionError):
    """The remote POST may have succeeded and must never be retried."""


class _CloudRunClient(Protocol):
    def issue_nonce(self, request: Any) -> NonceResponse: ...

    def issue_receipt(self, request: Any) -> ReceiptResponse: ...


@dataclass(frozen=True)
class _TransactionSpec:
    role: TransactionRole
    initial_state: CaptureState
    prepared_state: CaptureState
    attempted_state: CaptureState
    received_state: CaptureState
    prepared_event: CaptureEvent
    attempted_event: CaptureEvent
    pre_send_failed_event: CaptureEvent
    response_event: CaptureEvent
    outcome_unknown_event: CaptureEvent
    request_path: str
    response_path: str
    request_fields: frozenset[str]


_NONCE_SPEC: Final = _TransactionSpec(
    role="nonce",
    initial_state=CaptureState.RAW_COMPLETE,
    prepared_state=CaptureState.NONCE_REQUEST_PREPARED,
    attempted_state=CaptureState.NONCE_ATTEMPTED,
    received_state=CaptureState.NONCE_RECEIVED,
    prepared_event=CaptureEvent.NONCE_REQUEST_PREPARED,
    attempted_event=CaptureEvent.NONCE_ATTEMPT_STARTED,
    pre_send_failed_event=CaptureEvent.NONCE_PRE_SEND_FAILED,
    response_event=CaptureEvent.NONCE_RESPONSE_RECORDED,
    outcome_unknown_event=CaptureEvent.NONCE_OUTCOME_UNKNOWN,
    request_path=NONCE_REQUEST_RELATIVE_PATH,
    response_path=NONCE_RESPONSE_RELATIVE_PATH,
    request_fields=frozenset(NONCE_REQUEST_FIELDS),
)

_RECEIPT_SPEC: Final = _TransactionSpec(
    role="receipt",
    initial_state=CaptureState.BINDINGS_COMPOSED,
    prepared_state=CaptureState.RECEIPT_REQUEST_PREPARED,
    attempted_state=CaptureState.RECEIPT_ATTEMPTED,
    received_state=CaptureState.RECEIPT_RECEIVED,
    prepared_event=CaptureEvent.RECEIPT_REQUEST_PREPARED,
    attempted_event=CaptureEvent.RECEIPT_ATTEMPT_STARTED,
    pre_send_failed_event=CaptureEvent.RECEIPT_PRE_SEND_FAILED,
    response_event=CaptureEvent.RECEIPT_RESPONSE_RECORDED,
    outcome_unknown_event=CaptureEvent.RECEIPT_OUTCOME_UNKNOWN,
    request_path=RECEIPT_REQUEST_RELATIVE_PATH,
    response_path=RECEIPT_RESPONSE_RELATIVE_PATH,
    request_fields=frozenset(RECEIPT_REQUEST_FIELDS),
)


def _canonical_request(
    spec: _TransactionSpec, value: Any
) -> tuple[dict[str, Any], bytes, str]:
    try:
        request = exact_object(
            value,
            set(spec.request_fields),
            f"physical {spec.role} request",
        )
        if type(request["schema_version"]) is not int or request["schema_version"] != 1:
            raise RawArtifactError(
                f"physical {spec.role} request schema_version is unsupported"
            )
        data = canonical_json(request) + b"\n"
        if len(data) > MAX_REQUEST_BYTES:
            raise RawArtifactError(
                f"physical {spec.role} request exceeds its fixed byte bound"
            )
        normalized = load_json_bytes(data, f"physical {spec.role} request")
        if not isinstance(normalized, dict):
            raise RawArtifactError(f"physical {spec.role} request is not an object")
    except (RawArtifactError, TypeError, UnicodeEncodeError, ValueError):
        raise PhysicalCaptureTransactionError(
            "invalid_request",
            f"physical {spec.role} request failed strict local validation",
        ) from None
    return normalized, data, hashlib.sha256(data).hexdigest()


def _canonical_response(
    spec: _TransactionSpec, value: NonceResponse | ReceiptResponse
) -> tuple[bytes, str]:
    expected_type = NonceResponse if spec.role == "nonce" else ReceiptResponse
    if type(value) is not expected_type:
        raise PhysicalCaptureTransactionError(
            "invalid_response_type",
            f"physical {spec.role} client returned the wrong response type",
        )
    try:
        data = canonical_json(value.as_dict()) + b"\n"
    except (AttributeError, RawArtifactError, TypeError, UnicodeEncodeError, ValueError):
        raise PhysicalCaptureTransactionError(
            "invalid_response",
            f"physical {spec.role} response cannot be canonically archived",
        ) from None
    if not data or len(data) > MAX_RESPONSE_BYTES:
        raise PhysicalCaptureTransactionError(
            "invalid_response",
            f"physical {spec.role} response exceeds its fixed byte bound",
        )
    return data, hashlib.sha256(data).hexdigest()


def _read_exact_request(
    session: PhysicalCaptureSession,
    spec: _TransactionSpec,
    expected: bytes,
) -> ArchivedFile:
    try:
        observed = session.archive.read_bytes(
            spec.request_path, maximum=MAX_REQUEST_BYTES
        )
    except PhysicalCaptureArchiveError:
        raise PhysicalCaptureTransactionError(
            "request_archive_unavailable",
            f"archived physical {spec.role} request is unavailable",
        ) from None
    if observed != expected:
        raise PhysicalCaptureTransactionError(
            "request_archive_mismatch",
            f"archived physical {spec.role} request differs from the requested POST",
        )
    return ArchivedFile(
        relative_path=spec.request_path,
        size=len(observed),
        sha256=hashlib.sha256(observed).hexdigest(),
    )


def _archive_request_once(
    session: PhysicalCaptureSession,
    spec: _TransactionSpec,
    data: bytes,
) -> ArchivedFile:
    try:
        return session.archive.write_or_reopen_exact(
            spec.request_path, data, maximum=MAX_REQUEST_BYTES
        )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCaptureTransactionError(
            "request_archive_failed",
            f"physical {spec.role} request could not be durably archived",
        ) from error


class PhysicalCaptureTransaction:
    """Execute only the fixed nonce and receipt transactions for one session."""

    def __init__(
        self,
        session: PhysicalCaptureSession,
        client: _CloudRunClient,
    ) -> None:
        self._session = session
        self._client = client

    def issue_nonce(self, request: Any) -> NonceResponse:
        response = self._execute(_NONCE_SPEC, request)
        if type(response) is not NonceResponse:
            raise PhysicalCaptureOutcomeUnknownError(
                "nonce_outcome_unknown",
                "nonce POST outcome is unknown and must not be retried",
            )
        return response

    def issue_receipt(self, request: Any) -> ReceiptResponse:
        response = self._execute(_RECEIPT_SPEC, request)
        if type(response) is not ReceiptResponse:
            raise PhysicalCaptureOutcomeUnknownError(
                "receipt_outcome_unknown",
                "receipt POST outcome is unknown and must not be retried",
            )
        return response

    def _prepare(
        self,
        spec: _TransactionSpec,
        data: bytes,
        request_sha256: str,
    ) -> None:
        state = self._session.state
        if state is spec.initial_state:
            archived = _archive_request_once(self._session, spec, data)
            if archived.sha256 != request_sha256 or archived.size != len(data):
                raise PhysicalCaptureTransactionError(
                    "request_archive_mismatch",
                    f"archived physical {spec.role} request digest differs",
                )
            try:
                snapshot = self._session.append(
                    spec.prepared_event,
                    binding_sha256=request_sha256,
                )
            except (PhysicalCaptureArchiveError, PhysicalCaptureSessionError):
                raise PhysicalCaptureTransactionError(
                    "request_prepare_record_failed",
                    f"physical {spec.role} request preparation was not recorded",
                ) from None
            if snapshot.state is not spec.prepared_state:
                raise PhysicalCaptureTransactionError(
                    "request_prepare_state_mismatch",
                    f"physical {spec.role} request entered an unexpected state",
                )
            return

        if state is spec.prepared_state:
            archived = _read_exact_request(self._session, spec, data)
            if (
                archived.sha256 != request_sha256
                or self._session.snapshot.last_binding_sha256 != request_sha256
            ):
                raise PhysicalCaptureTransactionError(
                    "prepared_request_binding_mismatch",
                    f"prepared physical {spec.role} request binding differs",
                )
            return

        raise PhysicalCaptureTransactionError(
            "transaction_not_preparable",
            f"physical {spec.role} POST is forbidden from state {state.value!r}",
        )

    def _append_attempt(self, spec: _TransactionSpec, request_sha256: str) -> None:
        try:
            snapshot = self._session.append(
                spec.attempted_event,
                binding_sha256=request_sha256,
            )
        except (PhysicalCaptureArchiveError, PhysicalCaptureSessionError):
            raise PhysicalCaptureTransactionError(
                "attempt_record_failed",
                f"physical {spec.role} POST attempt was not durably recorded",
            ) from None
        if snapshot.state is not spec.attempted_state:
            raise PhysicalCaptureTransactionError(
                "attempt_state_mismatch",
                f"physical {spec.role} POST entered an unexpected attempted state",
            )

    def _record_pre_send_failure(
        self, spec: _TransactionSpec, request_sha256: str
    ) -> None:
        try:
            snapshot = self._session.append(
                spec.pre_send_failed_event,
                binding_sha256=request_sha256,
            )
        except (PhysicalCaptureArchiveError, PhysicalCaptureSessionError):
            raise PhysicalCaptureTransactionError(
                "pre_send_failure_record_failed",
                f"physical {spec.role} pre-send failure requires restart recovery; "
                "do not retry",
            ) from None
        if snapshot.state is not spec.prepared_state:
            raise PhysicalCaptureTransactionError(
                "pre_send_failure_state_mismatch",
                f"physical {spec.role} pre-send failure entered an unsafe state",
            )

    def _record_outcome_unknown(
        self, spec: _TransactionSpec, request_sha256: str
    ) -> None:
        try:
            snapshot = self._session.append(
                spec.outcome_unknown_event,
                binding_sha256=request_sha256,
            )
        except (PhysicalCaptureArchiveError, PhysicalCaptureSessionError):
            raise PhysicalCaptureTransactionError(
                "outcome_unknown_record_failed",
                f"physical {spec.role} outcome requires restart recovery; do not retry",
            ) from None
        expected = (
            CaptureState.NONCE_OUTCOME_UNKNOWN
            if spec.role == "nonce"
            else CaptureState.RECEIPT_OUTCOME_UNKNOWN
        )
        if snapshot.state is not expected:
            raise PhysicalCaptureTransactionError(
                "outcome_unknown_state_mismatch",
                f"physical {spec.role} outcome entered an unsafe state",
            )

    def _raise_outcome_unknown(
        self, spec: _TransactionSpec, request_sha256: str
    ) -> None:
        self._record_outcome_unknown(spec, request_sha256)
        raise PhysicalCaptureOutcomeUnknownError(
            f"{spec.role}_outcome_unknown",
            f"physical {spec.role} POST outcome is unknown and must not be retried",
        ) from None

    def _execute(
        self, spec: _TransactionSpec, request: Any
    ) -> NonceResponse | ReceiptResponse:
        normalized, request_bytes, request_sha256 = _canonical_request(spec, request)
        self._prepare(spec, request_bytes, request_sha256)
        self._append_attempt(spec, request_sha256)

        try:
            if spec.role == "nonce":
                response: NonceResponse | ReceiptResponse = self._client.issue_nonce(
                    normalized
                )
            else:
                response = self._client.issue_receipt(normalized)
        except PreSendError:
            self._record_pre_send_failure(spec, request_sha256)
            raise
        except OutcomeUnknownError:
            self._raise_outcome_unknown(spec, request_sha256)
        except Exception:
            # The client boundary was entered, so an undocumented exception
            # cannot prove that the POST remained local.
            self._raise_outcome_unknown(spec, request_sha256)

        try:
            response_bytes, response_sha256 = _canonical_response(spec, response)
            archived = self._session.archive.write_bytes(
                spec.response_path,
                response_bytes,
                maximum=MAX_RESPONSE_BYTES,
            )
            if (
                archived.sha256 != response_sha256
                or archived.size != len(response_bytes)
            ):
                raise PhysicalCaptureTransactionError(
                    "response_archive_mismatch",
                    f"archived physical {spec.role} response digest differs",
                )
        except Exception:
            # A returned response proves that the POST began.  Even a local
            # persistence failure therefore consumes this one-shot attempt.
            self._raise_outcome_unknown(spec, request_sha256)

        try:
            snapshot = self._session.append(
                spec.response_event,
                binding_sha256=response_sha256,
            )
        except (PhysicalCaptureArchiveError, PhysicalCaptureSessionError):
            raise PhysicalCaptureTransactionError(
                "response_record_failed",
                f"physical {spec.role} response requires restart recovery; do not retry",
            ) from None
        if (
            snapshot.state is not spec.received_state
            or snapshot.last_binding_sha256 != response_sha256
        ):
            raise PhysicalCaptureTransactionError(
                "response_state_mismatch",
                f"physical {spec.role} response entered an unsafe state",
            )
        return response


__all__ = [
    "CLOUD_TRANSACTION_DIRECTORY",
    "NONCE_REQUEST_RELATIVE_PATH",
    "NONCE_RESPONSE_RELATIVE_PATH",
    "PhysicalCaptureOutcomeUnknownError",
    "PhysicalCaptureTransaction",
    "PhysicalCaptureTransactionError",
    "RECEIPT_REQUEST_RELATIVE_PATH",
    "RECEIPT_RESPONSE_RELATIVE_PATH",
]
