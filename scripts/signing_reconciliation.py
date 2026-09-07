"""Append-only evidence for revalidating a failed, already verified signing output.

This journal is separate from the immutable signing attempt. It owns no signing
or verification implementation. Existing source/receipt digests bind the exact
lineage and detect accidental drift, not modification by the release account.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Callable, Final, Iterator

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
        SHA256_RE,
        validate_source_identity,
    )
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
        SHA256_RE,
        validate_source_identity,
    )


DOCUMENT: Final = "cfm-signing-output-reconciliation-v1"
RELATIVE_ROOT: Final = Path("transactions/signing-reconciliation")
MAX_VERIFICATIONS: Final = 8
MAX_RECORD_BYTES: Final = 16 * 1024
_VERIFICATION_NAME: Final = re.compile(r"(start|result)-([0-9]{8})[.]json\Z")
_FAILURE_CODE: Final = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
Clock = Callable[[], str]


class SigningReconciliationError(PublicationError):
    """Reconciliation evidence is unsafe, inconsistent, or cannot be persisted."""


@dataclass(frozen=True, slots=True)
class ReconciliationRequest:
    executor_repository: Path
    failed_event_sha256: str
    transformation_receipt_sha256: str

    def validate(self) -> None:
        for digest in (self.failed_event_sha256, self.transformation_receipt_sha256):
            if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
                raise SigningReconciliationError("explicit reconciliation digest is invalid")


@dataclass(frozen=True, slots=True)
class ReconciliationBinding:
    attempt_id: str
    attempt_intent_sha256: str
    failed_event_sha256: str
    candidate_freeze_intent_sha256: str
    transformation_receipt_sha256: str
    artifact_commit: str
    artifact_source_sha256: str

    def document(self, executor: ExecutorSource) -> dict[str, object]:
        artifact_source = {
            "repositoryCommit": self.artifact_commit,
            "releaseSourceSha256": self.artifact_source_sha256,
        }
        validate_source_identity(artifact_source, "artifact")
        validate_source_identity(executor.identity, "reconciliation executor")
        if (
            type(self.attempt_id) is not str
            or re.fullmatch(r"[0-9]{8}", self.attempt_id) is None
            or self.attempt_id == "00000000"
        ):
            raise SigningReconciliationError("original signing attempt id is invalid")
        digests = {
            "attempt_intent_sha256": self.attempt_intent_sha256,
            "failed_event_sha256": self.failed_event_sha256,
            "candidate_freeze_intent_sha256": self.candidate_freeze_intent_sha256,
            "transformation_receipt_sha256": self.transformation_receipt_sha256,
        }
        if any(type(value) is not str or SHA256_RE.fullmatch(value) is None
               for value in digests.values()):
            raise SigningReconciliationError("original signing binding is invalid")
        return {
            "document": DOCUMENT,
            "schema_version": 1,
            "product": {
                "version": ACTIVE_RELEASE_IDENTITY.product_version,
                "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            },
            "artifact_source": artifact_source,
            "executor_source": executor.identity,
            "attempt_id": self.attempt_id,
            **digests,
        }


def _require_timestamp(value: object) -> None:
    if type(value) is not str or not value.endswith("Z") or len(value) > 40:
        raise SigningReconciliationError("reconciliation timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise SigningReconciliationError("reconciliation timestamp is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise SigningReconciliationError("reconciliation timestamp is not UTC")


class ReconciliationJournal:
    """Use only inside the original signing lock and the rooted journal lock."""

    def __init__(
        self, root: Path, descriptor: int, clock: Clock, intent: dict[str, object]
    ) -> None:
        self.root = root
        self.descriptor = descriptor
        self.clock = clock
        self._intent = canonical_json(intent)

    def _read(self, name: str) -> dict[str, object]:
        raw = read_private_pending_locked(
            self.descriptor, self.root, name, MAX_RECORD_BYTES
        )
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as error:
            raise SigningReconciliationError("reconciliation record is not JSON") from error
        if type(value) is not dict or canonical_json(value) != raw:
            raise SigningReconciliationError("reconciliation record is not canonical")
        return value

    def _write(self, name: str, value: dict[str, object]) -> None:
        write_private_pending_locked(
            self.descriptor, self.root, name, canonical_json(value)
        )

    def _record(self, phase: str, sequence: int) -> dict[str, object]:
        now = self.clock()
        _require_timestamp(now)
        return {
            "document": DOCUMENT,
            "phase": phase,
            "recorded_at": now,
            "verification_sequence": sequence,
        }

    def _validate_record(
        self, value: dict[str, object], phase: str, sequence: int
    ) -> None:
        fields = {"document", "phase", "recorded_at", "verification_sequence"}
        if phase == "result":
            fields |= {"status", "failure_code"}
        if (
            set(value) != fields
            or value["document"] != DOCUMENT
            or value["phase"] != phase
            or type(value["verification_sequence"]) is not int
            or value["verification_sequence"] != sequence
        ):
            raise SigningReconciliationError("reconciliation record identity differs")
        _require_timestamp(value["recorded_at"])
        if phase == "result":
            status, code = value["status"], value["failure_code"]
            if (
                type(status) is not str
                or status not in {"passed", "failed", "interrupted"}
                or (status == "passed" and code is not None)
                or (status != "passed" and (
                    type(code) is not str or _FAILURE_CODE.fullmatch(code) is None
                ))
                or (status == "interrupted" and code != "verification_interrupted")
            ):
                raise SigningReconciliationError("verification result is inconsistent")

    def validate(self) -> tuple[int, bool]:
        if canonical_json(self._read("intent.json")) != self._intent:
            raise SigningReconciliationError("reconciliation intent changed")
        names = set(os.listdir(self.descriptor))
        starts, results = set(), set()
        for name in names - {"intent.json", "publication.json", "completed.json"}:
            matched = _VERIFICATION_NAME.fullmatch(name)
            if matched is None:
                raise SigningReconciliationError("unexpected reconciliation inventory")
            sequence = int(matched.group(2))
            (starts if matched.group(1) == "start" else results).add(sequence)
        count = len(starts)
        if (
            count > MAX_VERIFICATIONS
            or starts != set(range(1, count + 1))
            or results not in (starts, starts - {count})
        ):
            raise SigningReconciliationError("verification sequence is inconsistent")
        for sequence in sorted(starts):
            self._validate_record(self._read(f"start-{sequence:08d}.json"), "start", sequence)
        for sequence in sorted(results):
            self._validate_record(self._read(f"result-{sequence:08d}.json"), "result", sequence)
        if "publication.json" in names:
            publication = self._read("publication.json")
            sequence = publication.get("verification_sequence")
            if type(sequence) is not int or sequence not in results:
                raise SigningReconciliationError("publication lacks a verified predecessor")
            self._validate_record(publication, "publishing", sequence)
            if self._read(f"result-{sequence:08d}.json")["status"] != "passed":
                raise SigningReconciliationError("publication predecessor did not pass")
            if "completed.json" in names:
                self._validate_record(self._read("completed.json"), "published", sequence)
        elif "completed.json" in names:
            raise SigningReconciliationError("publication completion lacks its intent")
        return count, count in starts - results

    @property
    def publication_started(self) -> bool:
        self.validate()
        return "publication.json" in os.listdir(self.descriptor)

    @property
    def completed(self) -> bool:
        self.validate()
        return "completed.json" in os.listdir(self.descriptor)

    def start_verification(self) -> int:
        count, interrupted = self.validate()
        if interrupted:
            self.finish_verification(count, "verification_interrupted", interrupted=True)
        if count >= MAX_VERIFICATIONS:
            raise SigningReconciliationError("explicit verification attempt budget exhausted")
        sequence = count + 1
        self._write(f"start-{sequence:08d}.json", self._record("start", sequence))
        return sequence

    def finish_verification(
        self, sequence: int, failure_code: str | None = None, *, interrupted: bool = False
    ) -> None:
        count, pending = self.validate()
        if sequence != count or not pending:
            raise SigningReconciliationError("verification result has no pending start")
        result = self._record("result", sequence)
        result.update({
            "status": "interrupted" if interrupted else (
                "passed" if failure_code is None else "failed"
            ),
            "failure_code": failure_code,
        })
        self._validate_record(result, "result", sequence)
        self._write(f"result-{sequence:08d}.json", result)

    def begin_publication(self, sequence: int) -> None:
        self.validate()
        if type(sequence) is not int or not 1 <= sequence <= MAX_VERIFICATIONS:
            raise SigningReconciliationError("publication sequence is invalid")
        result = self._read(f"result-{sequence:08d}.json")
        if result["status"] != "passed":
            raise SigningReconciliationError("publication requires successful revalidation")
        if not self.publication_started:
            self._write("publication.json", self._record("publishing", sequence))

    def complete_publication(self) -> None:
        self.validate()
        publication = self._read("publication.json")
        sequence = publication["verification_sequence"]
        if type(sequence) is not int:
            raise SigningReconciliationError("publication sequence is invalid")
        if not self.completed:
            self._write("completed.json", self._record("published", sequence))


@contextmanager
def open_reconciliation(
    repository: Path,
    binding: ReconciliationBinding,
    executor: ExecutorSource,
    *,
    clock: Clock,
) -> Iterator[ReconciliationJournal]:
    """Bind one executor without changing any original signing-attempt record."""

    expected = binding.document(executor)
    root = ga_root(repository) / RELATIVE_ROOT
    with exclusive_rooted_directory_lock(
        repository, root.parent, require_private=True
    ) as parent:
        ensure_private_directory_locked(parent, root.parent, root.name)
    with exclusive_rooted_directory_lock(
        repository, root, require_private=True
    ) as descriptor:
        journal = ReconciliationJournal(root, descriptor, clock, expected)
        names = os.listdir(descriptor)
        if "intent.json" not in names:
            if names:
                raise SigningReconciliationError("reconciliation intent is missing")
            journal._write("intent.json", expected)
        if canonical_json(journal._read("intent.json")) != canonical_json(expected):
            raise SigningReconciliationError("existing reconciliation binding cannot be replaced")
        journal.validate()
        yield journal
