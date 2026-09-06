#!/usr/bin/env python3
"""Verify that an Accepted notarytool submission has a clean bound log."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
from typing import Any
import uuid


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CDHASH_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_TICKETS = 10_000
SUBMISSION_FIELDS = {"id", "status"}
RAW_SUBMISSION_FIELDS = SUBMISSION_FIELDS | {"message"}
LOG_FIELDS = {
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
TICKET_REQUIRED_FIELDS = {"path", "digestAlgorithm", "cdhash"}
TICKET_FIELDS = TICKET_REQUIRED_FIELDS | {"arch"}


class NotaryLogError(ValueError):
    """Notarization output is missing, inconsistent, or contains issues."""


class DuplicateKeyError(ValueError):
    """A notarization document repeats a JSON field."""


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON field: {key}")
        value[key] = child
    return value


def _open_regular_file(
    path: Path,
    label: str,
    *,
    maximum: int | None = None,
    require_nonempty: bool = False,
) -> tuple[int, os.stat_result]:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise NotaryLogError(f"{label} is absent") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or (require_nonempty and before.st_size <= 0)
        or (maximum is not None and before.st_size > maximum)
    ):
        raise NotaryLogError(
            f"{label} must be a bounded single-link regular non-symlink file"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(opened):
            raise NotaryLogError(f"{label} changed while opening")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise NotaryLogError(f"opened {label} is not a single-link regular file")
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise NotaryLogError(f"cannot open {label}") from error
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    return descriptor, opened


def _read_exact_bytes(
    descriptor: int,
    opened: os.stat_result,
    label: str,
) -> bytes:
    data = bytearray()
    remaining = opened.st_size
    try:
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise NotaryLogError(f"{label} changed while reading")
            data.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NotaryLogError(f"{label} changed while reading")
        after = os.fstat(descriptor)
    except OSError as error:
        raise NotaryLogError(f"cannot read {label}") from error
    if _file_identity(opened) != _file_identity(after) or after.st_nlink != 1:
        raise NotaryLogError(f"{label} changed while reading")
    return bytes(data)


def _hash_exact_file(
    descriptor: int,
    opened: os.stat_result,
    label: str,
) -> str:
    digest = hashlib.sha256()
    remaining = opened.st_size
    try:
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise NotaryLogError(f"{label} changed while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NotaryLogError(f"{label} changed while hashing")
        after = os.fstat(descriptor)
    except OSError as error:
        raise NotaryLogError(f"cannot hash {label}") from error
    if _file_identity(opened) != _file_identity(after) or after.st_nlink != 1:
        raise NotaryLogError(f"{label} changed while hashing")
    return digest.hexdigest()


def _require_path_binding(
    path: Path,
    descriptor: int,
    opened: os.stat_result,
    label: str,
) -> None:
    try:
        current = os.fstat(descriptor)
        rebound = os.lstat(path)
    except OSError as error:
        raise NotaryLogError(f"{label} changed after processing") from error
    if (
        _file_identity(opened) != _file_identity(current)
        or _file_identity(opened) != _file_identity(rebound)
        or current.st_nlink != 1
    ):
        raise NotaryLogError(f"{label} changed after processing")


def _decode_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, DuplicateKeyError) as error:
        raise NotaryLogError(f"{label} is not valid UTF-8 JSON") from error


def _bounded_string(value: object, label: str, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
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
    if not isinstance(value, dict) or set(value) not in (
        SUBMISSION_FIELDS,
        RAW_SUBMISSION_FIELDS,
    ):
        raise NotaryLogError(
            "notarytool submission result has an unexpected field set"
        )
    if "message" in value:
        _bounded_string(value["message"], "notarytool submission message", 4096)
    if value.get("status") != "Accepted":
        raise NotaryLogError("notarytool submission status is not Accepted")
    identifier = _bounded_string(value.get("id"), "notarytool submission id", 64)
    try:
        parsed = uuid.UUID(identifier)
    except ValueError as error:
        raise NotaryLogError("notarytool submission id is not a UUID") from error
    if str(parsed) != identifier:
        raise NotaryLogError("notarytool submission id is not canonical UUID text")
    return identifier


def _file_sha256(path: Path) -> str:
    label = "notarization submission archive"
    descriptor, opened = _open_regular_file(path, label, require_nonempty=True)
    try:
        digest = _hash_exact_file(descriptor, opened, label)
        _require_path_binding(path, descriptor, opened, label)
    finally:
        os.close(descriptor)
    return digest


def _ticket(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or not TICKET_REQUIRED_FIELDS.issubset(value)
        or not set(value).issubset(TICKET_FIELDS)
    ):
        raise NotaryLogError("notarytool ticket has an unexpected field set")
    path = _bounded_string(value["path"], "notarytool ticket path", 4096)
    relative = PurePosixPath(path)
    if (
        relative.is_absolute()
        or relative.as_posix() != path
        or any(part in ("", ".", "..") for part in relative.parts)
    ):
        raise NotaryLogError("notarytool ticket path is not canonical and relative")
    if value["digestAlgorithm"] != "SHA-256":
        raise NotaryLogError("notarytool ticket digestAlgorithm is not SHA-256")
    cdhash = value["cdhash"]
    if not isinstance(cdhash, str) or not CDHASH_RE.fullmatch(cdhash):
        raise NotaryLogError("notarytool ticket cdhash is malformed")
    normalized = {
        "path": path,
        "digestAlgorithm": "SHA-256",
        "cdhash": cdhash,
    }
    if "arch" in value:
        arch = value["arch"]
        if arch not in ("arm64", "x86_64"):
            raise NotaryLogError("notarytool ticket architecture is unsupported")
        normalized["arch"] = arch
    return normalized


def validate_documents(
    submission: object,
    log: object,
    *,
    archive_filename: str,
    archive_sha256: str,
) -> dict[str, Any]:
    identifier = _submission(submission)
    if not isinstance(log, dict) or set(log) != LOG_FIELDS:
        raise NotaryLogError("notarytool log has an unexpected field set")
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
    if status_summary != "Ready for distribution":
        raise NotaryLogError("notarytool statusSummary is not Ready for distribution")
    upload_date = _utc_timestamp(log["uploadDate"], "notarytool uploadDate")
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
    if not isinstance(tickets, list) or not tickets or len(tickets) > MAX_TICKETS:
        raise NotaryLogError("notarytool log has no structured ticketContents")
    normalized_tickets = [_ticket(ticket) for ticket in tickets]
    return {
        "logFormatVersion": 1,
        "jobId": identifier,
        "status": "Accepted",
        "statusSummary": status_summary,
        "statusCode": 0,
        "archiveFilename": archive_filename,
        "uploadDate": upload_date,
        "sha256": log_sha256,
        "ticketContents": normalized_tickets,
        "issues": log["issues"],
    }


def validate_normalized_documents(
    submission: object,
    log: object,
    *,
    archive_filename: str,
    archive_sha256: str,
) -> dict[str, Any]:
    if not isinstance(submission, dict) or set(submission) != SUBMISSION_FIELDS:
        raise NotaryLogError(
            "persisted notarization result is not the normalized field set"
        )
    normalized = validate_documents(
        submission,
        log,
        archive_filename=archive_filename,
        archive_sha256=archive_sha256,
    )
    if log != normalized:
        raise NotaryLogError("persisted notarization log is not canonical")
    return normalized


def validate_files(submission_path: Path, log_path: Path, archive_path: Path) -> dict[str, Any]:
    opened_files: list[tuple[Path, int, os.stat_result, str]] = []
    try:
        for path, label, maximum, require_nonempty in (
            (
                submission_path,
                "notarytool submission result",
                MAX_JSON_BYTES,
                True,
            ),
            (log_path, "notarytool log", MAX_JSON_BYTES, True),
            (archive_path, "notarization submission archive", None, True),
        ):
            descriptor, opened = _open_regular_file(
                path,
                label,
                maximum=maximum,
                require_nonempty=require_nonempty,
            )
            opened_files.append((path, descriptor, opened, label))

        submission_data = _read_exact_bytes(
            opened_files[0][1],
            opened_files[0][2],
            opened_files[0][3],
        )
        log_data = _read_exact_bytes(
            opened_files[1][1],
            opened_files[1][2],
            opened_files[1][3],
        )
        archive_sha256 = _hash_exact_file(
            opened_files[2][1],
            opened_files[2][2],
            opened_files[2][3],
        )
        result = validate_documents(
            _decode_json(submission_data, opened_files[0][3]),
            _decode_json(log_data, opened_files[1][3]),
            archive_filename=archive_path.name,
            archive_sha256=archive_sha256,
        )
        for path, descriptor, opened, label in opened_files:
            _require_path_binding(path, descriptor, opened, label)
        return result
    finally:
        for _path, descriptor, _opened, _label in reversed(opened_files):
            os.close(descriptor)


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
