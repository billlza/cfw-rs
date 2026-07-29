#!/usr/bin/env python3
"""Verify that an Accepted notarytool submission has a clean bound log."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any
import uuid


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class NotaryLogError(ValueError):
    """Notarization output is missing, inconsistent, or contains issues."""


def _load(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file():
        raise NotaryLogError(f"{label} is absent or is a symlink")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise NotaryLogError(f"{label} is not valid UTF-8 JSON") from error


def _bounded_string(value: object, label: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise NotaryLogError(f"{label} is not a bounded non-empty string")
    return value


def _utc_timestamp(value: object, label: str) -> str:
    timestamp = _bounded_string(value, label, 64)
    if not timestamp.endswith("Z"):
        raise NotaryLogError(f"{label} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError as error:
        raise NotaryLogError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise NotaryLogError(f"{label} is not UTC")
    return timestamp


def _submission(value: object) -> str:
    if not isinstance(value, dict):
        raise NotaryLogError("notarytool submission result is not a JSON object")
    if value.get("status") != "Accepted":
        raise NotaryLogError("notarytool submission status is not Accepted")
    identifier = _bounded_string(value.get("id"), "notarytool submission id", 64)
    try:
        parsed = uuid.UUID(identifier)
    except ValueError as error:
        raise NotaryLogError("notarytool submission id is not a UUID") from error
    if str(parsed) != identifier.lower():
        raise NotaryLogError("notarytool submission id is not canonical UUID text")
    return identifier


def _file_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise NotaryLogError("notarization submission archive is absent or is a symlink")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise NotaryLogError("cannot hash the notarization submission archive") from error
    return digest.hexdigest()


def _has_warning_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in {"warning", "warnings"} and child not in (
                None,
                False,
                "",
                [],
                {},
            ):
                return True
            if _has_warning_field(child):
                return True
    elif isinstance(value, list):
        return any(_has_warning_field(child) for child in value)
    return False


def validate_documents(
    submission: object,
    log: object,
    *,
    archive_filename: str,
    archive_sha256: str,
) -> dict[str, Any]:
    identifier = _submission(submission)
    if not isinstance(log, dict):
        raise NotaryLogError("notarytool log is not a JSON object")
    required = {
        "logFormatVersion",
        "jobId",
        "status",
        "statusSummary",
        "statusCode",
        "archiveFilename",
        "uploadDate",
        "sha256",
        "ticketContents",
        "issues",
    }
    missing = sorted(required - set(log))
    if missing:
        raise NotaryLogError(f"notarytool log is missing required fields: {missing}")
    if (
        not isinstance(log["logFormatVersion"], int)
        or isinstance(log["logFormatVersion"], bool)
        or log["logFormatVersion"] != 1
    ):
        raise NotaryLogError("notarytool logFormatVersion is not 1")
    if log["jobId"] != identifier:
        raise NotaryLogError("notarytool log jobId differs from the Accepted submission")
    if (
        log["status"] != "Accepted"
        or not isinstance(log["statusCode"], int)
        or isinstance(log["statusCode"], bool)
        or log["statusCode"] != 0
    ):
        raise NotaryLogError("notarytool log is not an Accepted statusCode=0 result")
    status_summary = _bounded_string(log["statusSummary"], "notarytool statusSummary")
    if re.search(r"\bwarnings?\b", status_summary, re.IGNORECASE):
        raise NotaryLogError("notarytool statusSummary reports warnings")
    _utc_timestamp(log["uploadDate"], "notarytool uploadDate")
    if log["archiveFilename"] != archive_filename:
        raise NotaryLogError("notarytool log archiveFilename differs from the submission")
    log_sha256 = log["sha256"]
    if not isinstance(log_sha256, str) or not SHA256_RE.fullmatch(log_sha256):
        raise NotaryLogError("notarytool log sha256 is not a lowercase SHA-256")
    if log_sha256 != archive_sha256:
        raise NotaryLogError("notarytool log sha256 differs from the submission archive")
    if log["issues"] not in (None, []):
        raise NotaryLogError("notarytool log contains notarization issues")
    tickets = log["ticketContents"]
    if not isinstance(tickets, list) or not tickets or not all(
        isinstance(ticket, dict) and ticket for ticket in tickets
    ):
        raise NotaryLogError("notarytool log has no structured ticketContents")
    if _has_warning_field(log):
        raise NotaryLogError("notarytool log contains warnings")
    return log


def validate_files(submission_path: Path, log_path: Path, archive_path: Path) -> dict[str, Any]:
    return validate_documents(
        _load(submission_path, "notarytool submission result"),
        _load(log_path, "notarytool log"),
        archive_filename=archive_path.name,
        archive_sha256=_file_sha256(archive_path),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("submission", type=Path)
    parser.add_argument("log", type=Path)
    parser.add_argument("archive", type=Path)
    arguments = parser.parse_args()
    try:
        result = validate_files(arguments.submission, arguments.log, arguments.archive)
    except NotaryLogError as error:
        raise SystemExit(f"error: notarization log: {error}") from error
    print(
        "notarization log verified: "
        f"job={result['jobId']} status=Accepted issues=0 warnings=0"
    )


if __name__ == "__main__":
    main()
