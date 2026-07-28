"""Deterministic notarization command fixtures for transaction tests."""

from __future__ import annotations

import hashlib
import json


SUBMISSION_ID = "11111111-2222-3333-4444-555555555555"
ARCHIVE_BYTES = b"archive"
ARCHIVE_SHA256 = hashlib.sha256(ARCHIVE_BYTES).hexdigest()


def submit_response(path: str, message: str = "Successfully uploaded file") -> str:
    return json.dumps(
        {"id": SUBMISSION_ID, "message": message, "path": path},
        sort_keys=True,
    )


def response(status: str, message: str = "Processing complete") -> str:
    return json.dumps(
        {"id": SUBMISSION_ID, "message": message, "status": status},
        sort_keys=True,
    )


def accepted_log(archive_name: str) -> dict:
    return {
        "logFormatVersion": 1,
        "jobId": SUBMISSION_ID,
        "status": "Accepted",
        "statusSummary": "Ready for distribution",
        "statusCode": 0,
        "archiveFilename": archive_name,
        "uploadDate": "2026-07-28T04:02:00.000Z",
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
