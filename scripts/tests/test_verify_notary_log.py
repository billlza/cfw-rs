from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.verify_notary_log import (
    MAX_JSON_BYTES,
    NotaryLogError,
    _file_sha256,
    _open_regular_file,
    validate_documents,
    validate_files,
    validate_normalized_documents,
)


IDENTIFIER = "11111111-2222-3333-4444-555555555555"
ARCHIVE = "Clash.for.Mac_0.4.0_40001_notary.zip"
ARCHIVE_SHA256 = hashlib.sha256(b"archive").hexdigest()


def _submission() -> dict:
    return {"status": "Accepted", "id": IDENTIFIER}


def _log() -> dict:
    return {
        "logFormatVersion": 1,
        "jobId": IDENTIFIER,
        "status": "Accepted",
        "statusSummary": "Ready for distribution",
        "statusCode": 0,
        "archiveFilename": ARCHIVE,
        "uploadDate": "2026-07-26T04:00:00.000Z",
        "sha256": ARCHIVE_SHA256,
        "ticketContents": [
            {
                "path": "Clash for Mac.app/Contents/MacOS/clash-for-mac",
                "digestAlgorithm": "SHA-256",
                "cdhash": "a" * 40,
                "arch": "arm64",
            }
        ],
        "issues": None,
    }


class NotaryLogValidationTests(unittest.TestCase):
    def validate(self, submission: object | None = None, log: object | None = None) -> dict:
        return validate_documents(
            _submission() if submission is None else submission,
            _log() if log is None else log,
            archive_filename=ARCHIVE,
            archive_sha256=ARCHIVE_SHA256,
        )

    def test_clean_accepted_log_passes(self) -> None:
        self.assertEqual(self.validate(), _log())

    def test_unaccepted_submission_is_rejected(self) -> None:
        submission = _submission()
        submission["status"] = "Rejected"
        with self.assertRaisesRegex(NotaryLogError, "status is not Accepted"):
            self.validate(submission=submission)

    def test_noncanonical_submission_id_is_rejected(self) -> None:
        submission = _submission()
        submission["id"] = "notary-1"
        with self.assertRaisesRegex(NotaryLogError, "not a UUID"):
            self.validate(submission=submission)

    def test_uppercase_submission_id_is_rejected_as_noncanonical(self) -> None:
        submission = _submission()
        uppercase_identifier = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".upper()
        submission["id"] = uppercase_identifier
        log = _log()
        log["jobId"] = uppercase_identifier
        with self.assertRaisesRegex(NotaryLogError, "canonical UUID text"):
            self.validate(submission=submission, log=log)

    def test_log_must_bind_the_accepted_job(self) -> None:
        log = _log()
        log["jobId"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        with self.assertRaisesRegex(NotaryLogError, "jobId differs"):
            self.validate(log=log)

    def test_log_must_bind_the_exact_archive_digest(self) -> None:
        log = _log()
        log["sha256"] = "f" * 64
        with self.assertRaisesRegex(NotaryLogError, "differs from the submission archive"):
            self.validate(log=log)

    def test_any_issue_is_release_blocking(self) -> None:
        log = _log()
        log["issues"] = [{"severity": "error", "message": "invalid signature"}]
        with self.assertRaisesRegex(NotaryLogError, "contains notarization issues"):
            self.validate(log=log)

    def test_any_warning_field_is_release_blocking(self) -> None:
        log = _log()
        log["warnings"] = [{"message": "deprecated envelope"}]
        with self.assertRaisesRegex(NotaryLogError, "unexpected field set"):
            self.validate(log=log)

    def test_warning_status_summary_is_release_blocking(self) -> None:
        log = _log()
        log["statusSummary"] = "Accepted with warnings"
        with self.assertRaisesRegex(NotaryLogError, "not Ready for distribution"):
            self.validate(log=log)

    def test_missing_ticket_contents_is_rejected(self) -> None:
        log = _log()
        log["ticketContents"] = []
        with self.assertRaisesRegex(NotaryLogError, "ticketContents"):
            self.validate(log=log)

    def test_malformed_upload_timestamp_is_rejected(self) -> None:
        log = _log()
        log["uploadDate"] = "yesterday"
        with self.assertRaisesRegex(NotaryLogError, "not a UTC timestamp"):
            self.validate(log=log)

    def test_missing_required_field_is_rejected(self) -> None:
        log = copy.deepcopy(_log())
        del log["issues"]
        with self.assertRaisesRegex(NotaryLogError, "unexpected field set"):
            self.validate(log=log)

    def test_submission_extra_field_is_rejected(self) -> None:
        submission = _submission()
        submission["webhook"] = "https://example.invalid/secret"
        with self.assertRaisesRegex(NotaryLogError, "unexpected field set"):
            self.validate(submission=submission)

    def test_bounded_raw_submit_message_is_accepted_in_memory(self) -> None:
        submission = _submission()
        submission["message"] = "Successfully uploaded"
        self.assertEqual(self.validate(submission=submission), _log())

    def test_normalized_persisted_documents_reject_raw_submit_message(self) -> None:
        submission = _submission()
        submission["message"] = "Successfully uploaded"
        with self.assertRaisesRegex(NotaryLogError, "normalized field set"):
            validate_normalized_documents(
                submission,
                _log(),
                archive_filename=ARCHIVE,
                archive_sha256=ARCHIVE_SHA256,
            )

    def test_ticket_extra_field_is_rejected(self) -> None:
        log = _log()
        log["ticketContents"][0]["downloadUrl"] = "https://example.invalid/secret"
        with self.assertRaisesRegex(NotaryLogError, "ticket.*unexpected field set"):
            self.validate(log=log)

    def test_non_architectural_ticket_may_omit_arch(self) -> None:
        log = _log()
        del log["ticketContents"][0]["arch"]
        log["ticketContents"][0]["path"] = "fixture.dmg"
        self.assertEqual(self.validate(log=log), log)

    def test_ticket_fields_are_strictly_validated(self) -> None:
        mutations = (
            ("digestAlgorithm", "SHA-1", "digestAlgorithm"),
            ("cdhash", "not-a-cdhash", "cdhash"),
            ("arch", "powerpc", "architecture"),
        )
        for field, value, pattern in mutations:
            with self.subTest(field=field):
                log = _log()
                log["ticketContents"][0][field] = value
                with self.assertRaisesRegex(NotaryLogError, pattern):
                    self.validate(log=log)

    def test_ticket_count_is_bounded(self) -> None:
        log = _log()
        log["ticketContents"] = [copy.deepcopy(log["ticketContents"][0])] * 10_001
        with self.assertRaisesRegex(NotaryLogError, "ticketContents"):
            self.validate(log=log)

    def test_absolute_ticket_path_is_rejected(self) -> None:
        log = _log()
        log["ticketContents"][0]["path"] = "/Users/example/Clash for Mac.app"
        with self.assertRaisesRegex(NotaryLogError, "canonical and relative"):
            self.validate(log=log)

    def test_parent_traversal_ticket_path_is_rejected(self) -> None:
        log = _log()
        log["ticketContents"][0]["path"] = "../Clash for Mac.app"
        with self.assertRaisesRegex(NotaryLogError, "canonical and relative"):
            self.validate(log=log)


class NotaryLogFileBoundaryTests(unittest.TestCase):
    def _files(self, root: Path) -> tuple[Path, Path, Path]:
        submission = root / "submission.json"
        log = root / "log.json"
        archive = root / ARCHIVE
        submission.write_text(json.dumps(_submission()), encoding="utf-8")
        log.write_text(json.dumps(_log()), encoding="utf-8")
        archive.write_bytes(b"archive")
        return submission, log, archive

    def test_duplicate_json_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            submission, log, archive = self._files(Path(temporary))
            submission.write_text(
                '{"id":"11111111-2222-3333-4444-555555555555",'
                '"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",'
                '"status":"Accepted"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(NotaryLogError, "not valid UTF-8 JSON"):
                validate_files(submission, log, archive)

    def test_open_identity_failure_closes_the_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "document.json"
            path.write_text("{}\n", encoding="utf-8")
            original_close = os.close
            closed: list[int] = []

            def closing(descriptor: int) -> None:
                closed.append(descriptor)
                original_close(descriptor)

            with (
                patch(
                    "scripts.verify_notary_log._file_identity",
                    side_effect=[(1,), (2,)],
                ),
                patch("scripts.verify_notary_log.os.close", side_effect=closing),
            ):
                with self.assertRaisesRegex(NotaryLogError, "changed while opening"):
                    _open_regular_file(
                        path,
                        "fixture document",
                        maximum=MAX_JSON_BYTES,
                        require_nonempty=True,
                    )
            self.assertEqual(len(closed), 1)

    def test_valid_files_and_cli_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            submission, log, archive = self._files(Path(temporary))
            self.assertEqual(validate_files(submission, log, archive), _log())
            script = Path(__file__).resolve().parents[1] / "verify_notary_log.py"
            completed = subprocess.run(
                [sys.executable, "-B", str(script), str(submission), str(log), str(archive)],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("notarization log verified", completed.stdout)

    def test_oversized_json_file_is_rejected_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            submission, log, archive = self._files(Path(temporary))
            log.write_bytes(b" " * (MAX_JSON_BYTES + 1))
            with self.assertRaisesRegex(NotaryLogError, "bounded single-link"):
                validate_files(submission, log, archive)

    def test_hardlinked_archive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            submission, log, archive = self._files(Path(temporary))
            os.link(archive, Path(temporary) / "archive-copy.zip")
            with self.assertRaisesRegex(NotaryLogError, "single-link regular"):
                validate_files(submission, log, archive)

    def test_empty_archive_is_rejected_before_log_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            submission, log, archive = self._files(Path(temporary))
            archive.write_bytes(b"")
            with self.assertRaisesRegex(NotaryLogError, "bounded single-link"):
                validate_files(submission, log, archive)

    def test_symlinked_json_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            submission, log, archive = self._files(root)
            outside = root / "outside.json"
            outside.write_text(submission.read_text(encoding="utf-8"), encoding="utf-8")
            submission.unlink()
            submission.symlink_to(outside)
            with self.assertRaisesRegex(NotaryLogError, "single-link regular"):
                validate_files(submission, log, archive)

    def test_hardlinked_json_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            submission, log, archive = self._files(root)
            os.link(log, root / "log-copy.json")
            with self.assertRaisesRegex(NotaryLogError, "single-link regular"):
                validate_files(submission, log, archive)

    def test_invalid_utf8_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            submission, log, archive = self._files(Path(temporary))
            submission.write_bytes(b"\xff")
            with self.assertRaisesRegex(NotaryLogError, "not valid UTF-8 JSON"):
                validate_files(submission, log, archive)

    def test_archive_change_during_hashing_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "archive.zip"
            archive.write_bytes(b"a" * (2 * 1024 * 1024))
            original_read = os.read
            changed = False

            def racing_read(descriptor: int, count: int) -> bytes:
                nonlocal changed
                chunk = original_read(descriptor, count)
                if chunk and not changed:
                    changed = True
                    with archive.open("ab") as handle:
                        handle.write(b"changed")
                return chunk

            with patch("scripts.verify_notary_log.os.read", side_effect=racing_read):
                with self.assertRaisesRegex(NotaryLogError, "changed while hashing"):
                    _file_sha256(archive)

    def test_archive_path_substitution_during_hashing_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "archive.zip"
            parked = root / "parked.zip"
            replacement = root / "replacement.zip"
            archive.write_bytes(b"archive")
            replacement.write_bytes(b"evil!!!")
            original_read = os.read
            substituted = False

            def racing_read(descriptor: int, count: int) -> bytes:
                nonlocal substituted
                chunk = original_read(descriptor, count)
                if chunk and not substituted:
                    substituted = True
                    archive.rename(parked)
                    replacement.rename(archive)
                return chunk

            with patch("scripts.verify_notary_log.os.read", side_effect=racing_read):
                with self.assertRaisesRegex(
                    NotaryLogError,
                    "changed (while|after) hashing",
                ):
                    _file_sha256(archive)

    def test_hardlink_added_during_archive_hashing_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "archive.zip"
            archive.write_bytes(b"a" * (2 * 1024 * 1024))
            original_read = os.read
            linked = False

            def racing_read(descriptor: int, count: int) -> bytes:
                nonlocal linked
                chunk = original_read(descriptor, count)
                if chunk and not linked:
                    linked = True
                    os.link(archive, root / "archive-hardlink.zip")
                return chunk

            with patch("scripts.verify_notary_log.os.read", side_effect=racing_read):
                with self.assertRaisesRegex(NotaryLogError, "changed while hashing"):
                    _file_sha256(archive)

    def test_hardlink_added_during_json_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            submission, log, archive = self._files(root)
            original_read = os.read
            linked = False

            def racing_read(descriptor: int, count: int) -> bytes:
                nonlocal linked
                chunk = original_read(descriptor, count)
                if chunk and not linked:
                    linked = True
                    os.link(submission, root / "submission-hardlink.json")
                return chunk

            with patch("scripts.verify_notary_log.os.read", side_effect=racing_read):
                with self.assertRaisesRegex(NotaryLogError, "changed while reading"):
                    validate_files(submission, log, archive)

    def test_json_path_substitution_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            submission, log, archive = self._files(root)
            parked = root / "parked.json"
            replacement = root / "replacement.json"
            replacement.write_text(
                submission.read_text(encoding="utf-8").replace(
                    "Accepted",
                    "Rejected",
                ),
                encoding="utf-8",
            )
            original_read = os.read
            substituted = False

            def racing_read(descriptor: int, count: int) -> bytes:
                nonlocal substituted
                chunk = original_read(descriptor, count)
                if chunk and not substituted:
                    substituted = True
                    submission.rename(parked)
                    replacement.rename(submission)
                return chunk

            with patch("scripts.verify_notary_log.os.read", side_effect=racing_read):
                with self.assertRaisesRegex(
                    NotaryLogError,
                    "changed (while|after) reading",
                ):
                    validate_files(submission, log, archive)

    def test_later_log_read_cannot_replace_the_submission_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            submission, log, archive = self._files(root)
            parked = root / "parked-submission.json"
            replacement = root / "replacement-submission.json"
            replacement.write_text(
                submission.read_text(encoding="utf-8").replace(
                    "Accepted",
                    "Rejected",
                ),
                encoding="utf-8",
            )
            log_inode = os.lstat(log).st_ino
            original_read = os.read
            substituted = False

            def racing_read(descriptor: int, count: int) -> bytes:
                nonlocal substituted
                chunk = original_read(descriptor, count)
                if (
                    chunk
                    and not substituted
                    and os.fstat(descriptor).st_ino == log_inode
                ):
                    substituted = True
                    submission.rename(parked)
                    replacement.rename(submission)
                return chunk

            with patch("scripts.verify_notary_log.os.read", side_effect=racing_read):
                with self.assertRaisesRegex(
                    NotaryLogError,
                    "submission result changed after processing",
                ):
                    validate_files(submission, log, archive)

    def test_archive_hash_cannot_replace_the_log_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            submission, log, archive = self._files(root)
            parked = root / "parked-log.json"
            replacement = root / "replacement-log.json"
            replacement.write_text(
                log.read_text(encoding="utf-8").replace(
                    "Accepted",
                    "Rejected",
                ),
                encoding="utf-8",
            )
            archive_inode = os.lstat(archive).st_ino
            original_read = os.read
            substituted = False

            def racing_read(descriptor: int, count: int) -> bytes:
                nonlocal substituted
                chunk = original_read(descriptor, count)
                if (
                    chunk
                    and not substituted
                    and os.fstat(descriptor).st_ino == archive_inode
                ):
                    substituted = True
                    log.rename(parked)
                    replacement.rename(log)
                return chunk

            with patch("scripts.verify_notary_log.os.read", side_effect=racing_read):
                with self.assertRaisesRegex(
                    NotaryLogError,
                    "notarytool log changed after processing",
                ):
                    validate_files(submission, log, archive)


if __name__ == "__main__":
    unittest.main()
