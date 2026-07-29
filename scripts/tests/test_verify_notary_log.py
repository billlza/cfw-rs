from __future__ import annotations

import copy
import hashlib
import unittest

from scripts.verify_notary_log import NotaryLogError, validate_documents


IDENTIFIER = "11111111-2222-3333-4444-555555555555"
ARCHIVE = "Clash.for.Mac_0.4.0_40001_notary.zip"
ARCHIVE_SHA256 = hashlib.sha256(b"archive").hexdigest()


def _submission() -> dict:
    return {"status": "Accepted", "id": IDENTIFIER, "message": "Successfully uploaded"}


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
        with self.assertRaisesRegex(NotaryLogError, "contains warnings"):
            self.validate(log=log)

    def test_warning_status_summary_is_release_blocking(self) -> None:
        log = _log()
        log["statusSummary"] = "Accepted with warnings"
        with self.assertRaisesRegex(NotaryLogError, "statusSummary reports warnings"):
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
        with self.assertRaisesRegex(NotaryLogError, "missing required fields"):
            self.validate(log=log)


if __name__ == "__main__":
    unittest.main()
