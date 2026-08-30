#!/usr/bin/env python3
"""Capture and live-verify the exact hosted GitHub Actions receipt for GA 40039.

This module is intentionally separate from the deterministic local CI-lane
collector.  A local command result can corroborate a hosted run, but it can
never satisfy this receipt.  Production access is read-only, unauthenticated,
fixed to one public repository/workflow, and revalidates one run and its fixed
Check Suite around the attempt-specific jobs and zero-annotation responses so
a rerun, workflow-file source drift, or successful job carrying diagnostics
cannot be mistaken for the retained attempt.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import ssl
import sys
from typing import Any, Final
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

if __package__:
    from .candidate_freeze import CandidateFreezeError, verify_frozen_candidate
    from .publication.common import (
        PublicationError,
        read_regular,
        sha256_bytes,
        sha256_file,
    )
    from .publication.durable_file import (
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from .repository_source_identity import SourceIdentityError, current_identity
else:
    from candidate_freeze import CandidateFreezeError, verify_frozen_candidate
    from publication.common import (
        PublicationError,
        read_regular,
        sha256_bytes,
        sha256_file,
    )
    from publication.durable_file import (
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from repository_source_identity import SourceIdentityError, current_identity


class HostedCIReceiptError(PublicationError):
    """The hosted-CI receipt is unavailable, ambiguous, or not successful."""


SCHEMA_VERSION: Final = 3
DOCUMENT: Final = "cfw-github-hosted-ci-receipt-v3"
PRODUCT_VERSION: Final = "0.4.0"
GA_BUILD: Final = "40039"

API_ORIGIN: Final = "https://api.github.com"
API_ACCEPT: Final = "application/vnd.github+json"
API_VERSION: Final = "2022-11-28"
API_USER_AGENT: Final = "cfw-rs-release-evidence/0.4.0"
API_TIMEOUT_SECONDS: Final = 30
MAX_API_RESPONSE_BYTES: Final = 8 * 1024 * 1024
MAX_RECEIPT_BYTES: Final = 4 * 1024 * 1024
MAX_WORKFLOW_BYTES: Final = 512 * 1024

REPOSITORY_FULL_NAME: Final = "billlza/cfw-rs"
REPOSITORY_ID: Final = 1_306_403_473
WORKFLOW_ID: Final = 316_580_234
WORKFLOW_NAME: Final = "CI"
WORKFLOW_PATH: Final = ".github/workflows/ci.yml"
EVENT: Final = "pull_request"
WORKFLOW_SOURCE_STEP_PREFIX: Final = "Assert exact CI source and workflow identity "
WORKFLOW_SOURCE_STEP_RE: Final = re.compile(
    rf"^{re.escape(WORKFLOW_SOURCE_STEP_PREFIX)}(?P<sha>[0-9a-f]{{40}})$"
)
EXPECTED_JOB_NAMES: Final = frozenset(
    {
        "Rust, UI, and script quality gates",
        "macOS Rust supply-chain policy",
        "libbox, Network Extension, and app skeleton gates",
    }
)
REQUIRED_JOB_STEP_NAMES: Final = {
    "Rust, UI, and script quality gates": frozenset(
        {
            "Normalize pinned Xcode ownership",
            "Verify build-script boundary",
            "Test release tooling",
            "Validate shell scripts",
            "Lint shell scripts with pinned ShellCheck",
        }
    ),
    "macOS Rust supply-chain policy": frozenset(
        {
            "Audit exact shipped Rust target graph",
            "Enforce dependency, source, and license policy",
        }
    ),
    "libbox, Network Extension, and app skeleton gates": frozenset(
        {
            "Build and verify pinned packet LAN peer",
            "Build source-bound libbox",
            "Build and verify unsigned application skeleton",
        }
    ),
}

RECEIPT_RELATIVE: Final = Path(
    "target/candidates/0.4.0/ga/40039/stage-inputs/hosted-ci.json"
)
COMMIT_RE: Final = re.compile(r"^[0-9a-f]{40}$")
BRANCH_RE: Final = re.compile(r"^[^\x00-\x20\x7f~^:?*\\\[\]]{1,255}$")
TIMESTAMP_RE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DECIMAL_RE: Final = re.compile(r"^[1-9][0-9]{0,19}$")
API_PATH_RE: Final = re.compile(
    rf"^/repos/{re.escape(REPOSITORY_FULL_NAME)}/(?:"
    r"actions/runs/[1-9][0-9]{0,19}"
    r"(?:/attempts/[1-9][0-9]{0,19}/jobs\?per_page=100&page=1)?"
    r"|check-suites/[1-9][0-9]{0,19}/check-runs"
    r"\?filter=latest&per_page=100&page=1"
    r"|check-runs/[1-9][0-9]{0,19}/annotations"
    r"\?per_page=100&page=1"
    r"|contents/\.github/workflows/ci\.yml\?ref=[0-9a-f]{40}"
    r")$"
)


def _error(message: str) -> HostedCIReceiptError:
    return HostedCIReceiptError(message)


def _canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise _error("hosted CI receipt cannot be represented as canonical JSON") from error
    return (encoded + "\n").encode("ascii")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _error(f"GitHub JSON repeats field {key!r}")
        value[key] = child
    return value


def _reject_constant(token: str) -> Any:
    raise _error(f"GitHub JSON contains non-finite constant {token}")


def _strict_json(data: bytes, label: str) -> Any:
    if not data or len(data) > MAX_API_RESPONSE_BYTES:
        raise _error(f"{label} size is outside the fixed bound")
    try:
        text = data.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except HostedCIReceiptError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise _error(f"{label} is not strict UTF-8 JSON") from error


def _exact_object(value: object, fields: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise _error(f"{label} has missing or unknown fields")
    return value


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise _error(f"{label} must be a positive integer")
    return value


def _bounded_string(value: object, label: str, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise _error(f"{label} is not a bounded printable string")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise _error(f"{label} is not a canonical GitHub UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise _error(f"{label} is not a real UTC timestamp") from error
    if parsed.year < 2020:
        raise _error(f"{label} predates the supported GitHub Actions service")
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fixed_repository(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _error(f"{label} is missing")
    identifier = _positive_int(value.get("id"), f"{label}.id")
    full_name = _bounded_string(value.get("full_name"), f"{label}.full_name")
    if identifier != REPOSITORY_ID or full_name != REPOSITORY_FULL_NAME:
        raise _error(f"{label} is not the fixed public release repository")
    return {"full_name": full_name, "id": identifier}


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        del request, file_pointer, code, message, headers, new_url
        raise _error("GitHub API redirect is forbidden")


def _api_opener():
    context = ssl.create_default_context()
    return build_opener(
        ProxyHandler({}),
        _RejectRedirects(),
        HTTPSHandler(context=context),
    )


def _api_url(path: str) -> str:
    if not isinstance(path, str) or not API_PATH_RE.fullmatch(path):
        raise _error("GitHub API path escaped the fixed release repository")
    return API_ORIGIN + path


def _fetch_api_json(path: str) -> Any:
    url = _api_url(path)
    request = Request(
        url,
        headers={
            "Accept": API_ACCEPT,
            "User-Agent": API_USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        },
        method="GET",
    )
    try:
        with _api_opener().open(request, timeout=API_TIMEOUT_SECONDS) as response:
            if response.status != 200 or response.geturl() != url:
                raise _error("GitHub API did not return an exact fixed-origin HTTP 200")
            content_encoding = response.headers.get("Content-Encoding")
            if content_encoding:
                raise _error("GitHub API response used an unexpected content encoding")
            content_type = response.headers.get("Content-Type", "")
            media_type = content_type.partition(";")[0].strip().lower()
            if media_type not in {"application/json", API_ACCEPT}:
                raise _error("GitHub API response is not JSON")
            declared_length = response.headers.get("Content-Length")
            if declared_length is not None:
                try:
                    length = int(declared_length, 10)
                except ValueError as error:
                    raise _error("GitHub API Content-Length is malformed") from error
                if length <= 0 or length > MAX_API_RESPONSE_BYTES:
                    raise _error("GitHub API Content-Length is outside the fixed bound")
            data = response.read(MAX_API_RESPONSE_BYTES + 1)
            if len(data) > MAX_API_RESPONSE_BYTES:
                raise _error("GitHub API response exceeds the fixed size bound")
            if declared_length is not None and len(data) != length:
                raise _error("GitHub API response length differs from Content-Length")
    except HostedCIReceiptError:
        raise
    except HTTPError as error:
        raise _error(f"GitHub API returned HTTP {error.code}; hosted CI is unavailable") from error
    except (URLError, TimeoutError, OSError, ssl.SSLError) as error:
        raise _error("GitHub API request failed; hosted CI is unavailable") from error
    return _strict_json(data, "GitHub API response")


def _run_api_path(run_id: int) -> str:
    return f"/repos/{REPOSITORY_FULL_NAME}/actions/runs/{run_id}"


def _jobs_api_path(run_id: int, attempt: int) -> str:
    return (
        f"{_run_api_path(run_id)}/attempts/{attempt}/jobs"
        "?per_page=100&page=1"
    )


def _check_runs_api_path(check_suite_id: int) -> str:
    return (
        f"/repos/{REPOSITORY_FULL_NAME}/check-suites/{check_suite_id}/check-runs"
        "?filter=latest&per_page=100&page=1"
    )


def _annotations_api_path(check_run_id: int) -> str:
    return (
        f"/repos/{REPOSITORY_FULL_NAME}/check-runs/{check_run_id}/annotations"
        "?per_page=100&page=1"
    )


def _workflow_contents_api_path(workflow_sha: str) -> str:
    if not COMMIT_RE.fullmatch(workflow_sha):
        raise _error("workflow-file source SHA is malformed")
    return (
        f"/repos/{REPOSITORY_FULL_NAME}/contents/{WORKFLOW_PATH}"
        f"?ref={workflow_sha}"
    )


def _workflow_source_identity(workflow_sha: str, data: bytes) -> dict[str, object]:
    if (
        not COMMIT_RE.fullmatch(workflow_sha)
        or not 0 < len(data) <= MAX_WORKFLOW_BYTES
    ):
        raise _error("workflow-file source identity is malformed")
    git_object = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    return {
        "git_blob_sha": hashlib.sha1(
            git_object,
            usedforsecurity=False,
        ).hexdigest(),
        "sha256": sha256_bytes(data),
        "size": len(data),
        "workflow_sha": workflow_sha,
    }


def _project_workflow_source(
    value: object,
    workflow_sha: str,
    expected_bytes: bytes,
) -> dict[str, object]:
    payload = _exact_object(
        value,
        {
            "_links",
            "content",
            "download_url",
            "encoding",
            "git_url",
            "html_url",
            "name",
            "path",
            "sha",
            "size",
            "type",
            "url",
        },
        "GitHub workflow-file contents response",
    )
    if (
        payload["type"] != "file"
        or payload["name"] != Path(WORKFLOW_PATH).name
        or payload["path"] != WORKFLOW_PATH
        or payload["encoding"] != "base64"
    ):
        raise _error("GitHub workflow-file contents response is not the fixed file")
    size = _positive_int(payload["size"], "GitHub workflow-file size")
    if size > MAX_WORKFLOW_BYTES:
        raise _error("GitHub workflow-file size exceeds the fixed bound")
    encoded = payload["content"]
    if (
        not isinstance(encoded, str)
        or not encoded
        or "\r" in encoded
    ):
        raise _error("GitHub workflow-file content is not bounded canonical base64")
    try:
        encoded_ascii = encoded.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise _error(
            "GitHub workflow-file content is not bounded canonical base64"
        ) from error
    if len(encoded_ascii) > ((MAX_WORKFLOW_BYTES + 2) // 3) * 4 + 16_384:
        raise _error("GitHub workflow-file content is not bounded canonical base64")
    compact = encoded.replace("\n", "")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as error:
        raise _error("GitHub workflow-file content is malformed base64") from error
    if (
        not compact
        or base64.b64encode(decoded).decode("ascii") != compact
        or len(decoded) != size
        or decoded != expected_bytes
    ):
        raise _error("GitHub workflow-file bytes differ from the exact clean source")
    projected = _workflow_source_identity(workflow_sha, decoded)
    blob_sha = payload["sha"]
    if not isinstance(blob_sha, str) or blob_sha != projected["git_blob_sha"]:
        raise _error("GitHub workflow-file Git blob identity is invalid")
    api_url = API_ORIGIN + _workflow_contents_api_path(workflow_sha)
    git_url = f"{API_ORIGIN}/repos/{REPOSITORY_FULL_NAME}/git/blobs/{blob_sha}"
    html_url = (
        f"https://github.com/{REPOSITORY_FULL_NAME}/blob/"
        f"{workflow_sha}/{WORKFLOW_PATH}"
    )
    download_url = (
        f"https://raw.githubusercontent.com/{REPOSITORY_FULL_NAME}/"
        f"{workflow_sha}/{WORKFLOW_PATH}"
    )
    if (
        payload["url"] != api_url
        or payload["git_url"] != git_url
        or payload["html_url"] != html_url
        or payload["download_url"] != download_url
        or payload["_links"]
        != {"git": git_url, "html": html_url, "self": api_url}
    ):
        raise _error("GitHub workflow-file URLs escaped the fixed source")
    return projected


def _project_run(value: object, expected_sha: str, run_id: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error("GitHub workflow run response is not an object")
    identifier = _positive_int(value.get("id"), "workflow run id")
    attempt = _positive_int(value.get("run_attempt"), "workflow run attempt")
    run_number = _positive_int(value.get("run_number"), "workflow run number")
    workflow_id = _positive_int(value.get("workflow_id"), "workflow id")
    check_suite_id = _positive_int(
        value.get("check_suite_id"), "workflow check suite id"
    )
    name = _bounded_string(value.get("name"), "workflow name")
    path = _bounded_string(value.get("path"), "workflow path")
    event = _bounded_string(value.get("event"), "workflow event")
    status = _bounded_string(value.get("status"), "workflow status")
    conclusion = _bounded_string(value.get("conclusion"), "workflow conclusion")
    head_sha = _bounded_string(value.get("head_sha"), "workflow head SHA", 40)
    head_branch = _bounded_string(value.get("head_branch"), "workflow head branch", 255)
    if not COMMIT_RE.fullmatch(head_sha) or head_sha != expected_sha:
        raise _error("GitHub workflow run is bound to a different exact head SHA")
    if not BRANCH_RE.fullmatch(head_branch) or head_branch.endswith("."):
        raise _error("GitHub workflow head branch is malformed")
    if (
        identifier != run_id
        or workflow_id != WORKFLOW_ID
        or name != WORKFLOW_NAME
        or path != WORKFLOW_PATH
        or event != EVENT
        or status != "completed"
        or conclusion != "success"
    ):
        raise _error("GitHub workflow run is foreign, incomplete, or not successful")
    repository = _fixed_repository(value.get("repository"), "workflow repository")
    head_repository = _fixed_repository(
        value.get("head_repository"), "workflow head repository"
    )
    api_url = _bounded_string(value.get("url"), "workflow API URL", 2048)
    html_url = _bounded_string(value.get("html_url"), "workflow HTML URL", 2048)
    jobs_url = _bounded_string(value.get("jobs_url"), "workflow jobs URL", 2048)
    check_suite_url = _bounded_string(
        value.get("check_suite_url"), "workflow check suite URL", 2048
    )
    expected_api_url = API_ORIGIN + _run_api_path(run_id)
    expected_check_suite_url = (
        f"{API_ORIGIN}/repos/{REPOSITORY_FULL_NAME}/check-suites/{check_suite_id}"
    )
    expected_html_url = f"https://github.com/{REPOSITORY_FULL_NAME}/actions/runs/{run_id}"
    if (
        api_url != expected_api_url
        or html_url != expected_html_url
        or jobs_url != expected_api_url + "/jobs"
        or check_suite_url != expected_check_suite_url
    ):
        raise _error("GitHub workflow run URL escaped the fixed repository")
    created_at = _timestamp(value.get("created_at"), "workflow created_at")
    run_started_at = _timestamp(value.get("run_started_at"), "workflow run_started_at")
    updated_at = _timestamp(value.get("updated_at"), "workflow updated_at")
    if not (
        _timestamp_value(created_at)
        <= _timestamp_value(run_started_at)
        <= _timestamp_value(updated_at)
    ):
        raise _error("GitHub workflow timestamps are not ordered")
    return {
        "api_url": api_url,
        "check_suite_id": check_suite_id,
        "check_suite_url": check_suite_url,
        "conclusion": conclusion,
        "created_at": created_at,
        "event": event,
        "head_branch": head_branch,
        "head_sha": head_sha,
        "html_url": html_url,
        "id": identifier,
        "jobs_url": jobs_url,
        "run_attempt": attempt,
        "run_number": run_number,
        "run_started_at": run_started_at,
        "status": status,
        "updated_at": updated_at,
        "head_repository": head_repository,
        "repository": repository,
    }


def _project_step(value: object, job_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error(f"GitHub job {job_name!r} contains a malformed step")
    number = _positive_int(value.get("number"), f"GitHub job {job_name!r} step number")
    name = _bounded_string(value.get("name"), f"GitHub job {job_name!r} step name")
    status = _bounded_string(value.get("status"), f"GitHub step {name!r} status")
    conclusion = _bounded_string(
        value.get("conclusion"), f"GitHub step {name!r} conclusion"
    )
    started_at = _timestamp(value.get("started_at"), f"GitHub step {name!r} started_at")
    completed_at = _timestamp(
        value.get("completed_at"), f"GitHub step {name!r} completed_at"
    )
    if status != "completed" or conclusion != "success":
        raise _error(f"GitHub step {name!r} is incomplete, skipped, or not successful")
    if _timestamp_value(started_at) > _timestamp_value(completed_at):
        raise _error(f"GitHub step {name!r} timestamps are not ordered")
    return {
        "completed_at": completed_at,
        "conclusion": conclusion,
        "name": name,
        "number": number,
        "started_at": started_at,
        "status": status,
    }


def _project_job(value: object, run: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error("GitHub jobs response contains a malformed job")
    identifier = _positive_int(value.get("id"), "GitHub job id")
    run_id = _positive_int(value.get("run_id"), "GitHub job run id")
    attempt = _positive_int(value.get("run_attempt"), "GitHub job run attempt")
    name = _bounded_string(value.get("name"), "GitHub job name")
    status = _bounded_string(value.get("status"), f"GitHub job {name!r} status")
    conclusion = _bounded_string(
        value.get("conclusion"), f"GitHub job {name!r} conclusion"
    )
    head_sha = _bounded_string(value.get("head_sha"), f"GitHub job {name!r} head SHA", 40)
    if (
        name not in EXPECTED_JOB_NAMES
        or run_id != run["id"]
        or attempt != run["run_attempt"]
        or head_sha != run["head_sha"]
        or status != "completed"
        or conclusion != "success"
    ):
        raise _error(f"GitHub job {name!r} is foreign, superseded, or not successful")
    api_url = _bounded_string(value.get("url"), f"GitHub job {name!r} API URL", 2048)
    html_url = _bounded_string(value.get("html_url"), f"GitHub job {name!r} HTML URL", 2048)
    expected_api_url = f"{API_ORIGIN}/repos/{REPOSITORY_FULL_NAME}/actions/jobs/{identifier}"
    expected_html_url = (
        f"https://github.com/{REPOSITORY_FULL_NAME}/actions/runs/{run_id}/job/{identifier}"
    )
    if api_url != expected_api_url or html_url != expected_html_url:
        raise _error(f"GitHub job {name!r} URL escaped the fixed repository")
    started_at = _timestamp(value.get("started_at"), f"GitHub job {name!r} started_at")
    completed_at = _timestamp(value.get("completed_at"), f"GitHub job {name!r} completed_at")
    if not (
        _timestamp_value(run["run_started_at"])
        <= _timestamp_value(started_at)
        <= _timestamp_value(completed_at)
        <= _timestamp_value(run["updated_at"])
    ):
        raise _error(f"GitHub job {name!r} timestamps are not ordered within its run")
    raw_steps = value.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps or len(raw_steps) > 256:
        raise _error(f"GitHub job {name!r} has no bounded step list")
    steps = [_project_step(step, name) for step in raw_steps]
    step_numbers = [step["number"] for step in steps]
    if len(set(step_numbers)) != len(step_numbers) or step_numbers != sorted(step_numbers):
        raise _error(f"GitHub job {name!r} step numbers are repeated or reordered")
    step_names = {step["name"] for step in steps}
    if not REQUIRED_JOB_STEP_NAMES[name].issubset(step_names):
        raise _error(f"GitHub job {name!r} is missing required workflow steps")
    workflow_source_steps = [
        step
        for step in steps
        if step["name"].startswith(WORKFLOW_SOURCE_STEP_PREFIX)
    ]
    workflow_source_match = (
        WORKFLOW_SOURCE_STEP_RE.fullmatch(workflow_source_steps[0]["name"])
        if len(workflow_source_steps) == 1
        else None
    )
    if workflow_source_match is None:
        raise _error(
            f"GitHub job {name!r} is not bound to the exact workflow-file source"
        )
    if any(
        _timestamp_value(step["started_at"]) < _timestamp_value(started_at)
        or _timestamp_value(step["completed_at"]) > _timestamp_value(completed_at)
        for step in steps
    ):
        raise _error(f"GitHub job {name!r} step timestamps escaped the job interval")
    return {
        "api_url": api_url,
        "completed_at": completed_at,
        "conclusion": conclusion,
        "head_sha": head_sha,
        "html_url": html_url,
        "id": identifier,
        "name": name,
        "run_attempt": attempt,
        "started_at": started_at,
        "status": status,
        "steps": steps,
        "workflow_source_sha": workflow_source_match.group("sha"),
    }


def _project_jobs(value: object, run: dict[str, Any]) -> list[dict[str, Any]]:
    payload = _exact_object(value, {"jobs", "total_count"}, "GitHub jobs response")
    total = _positive_int(payload["total_count"], "GitHub jobs total_count")
    raw_jobs = payload["jobs"]
    if not isinstance(raw_jobs, list) or total != len(raw_jobs):
        raise _error("GitHub jobs response is incomplete or paginated ambiguously")
    if total != len(EXPECTED_JOB_NAMES):
        raise _error("GitHub workflow has missing or extra jobs")
    jobs = [_project_job(job, run) for job in raw_jobs]
    names = [job["name"] for job in jobs]
    if len(set(names)) != len(names) or set(names) != EXPECTED_JOB_NAMES:
        raise _error("GitHub workflow has missing, repeated, or extra required jobs")
    if len({job["workflow_source_sha"] for job in jobs}) != 1:
        raise _error("GitHub jobs disagree about the exact workflow-file source")
    return sorted(jobs, key=lambda job: job["name"])


def _project_check_run(value: object, run: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error("GitHub check suite contains a malformed check run")
    identifier = _positive_int(value.get("id"), "GitHub check run id")
    name = _bounded_string(value.get("name"), "GitHub check run name")
    head_sha = _bounded_string(
        value.get("head_sha"), f"GitHub check run {name!r} head SHA", 40
    )
    status = _bounded_string(
        value.get("status"), f"GitHub check run {name!r} status"
    )
    conclusion = _bounded_string(
        value.get("conclusion"), f"GitHub check run {name!r} conclusion"
    )
    if (
        name not in EXPECTED_JOB_NAMES
        or head_sha != run["head_sha"]
        or status != "completed"
        or conclusion != "success"
    ):
        raise _error(
            f"GitHub check run {name!r} is foreign, incomplete, or not successful"
        )
    api_url = _bounded_string(
        value.get("url"), f"GitHub check run {name!r} API URL", 2048
    )
    html_url = _bounded_string(
        value.get("html_url"), f"GitHub check run {name!r} HTML URL", 2048
    )
    details_url = _bounded_string(
        value.get("details_url"), f"GitHub check run {name!r} details URL", 2048
    )
    expected_api_url = (
        f"{API_ORIGIN}/repos/{REPOSITORY_FULL_NAME}/check-runs/{identifier}"
    )
    expected_html_url = (
        f"https://github.com/{REPOSITORY_FULL_NAME}/actions/runs/"
        f"{run['id']}/job/{identifier}"
    )
    if (
        api_url != expected_api_url
        or html_url != expected_html_url
        or details_url != expected_html_url
    ):
        raise _error(f"GitHub check run {name!r} URL escaped the fixed repository")
    check_suite = value.get("check_suite")
    if not isinstance(check_suite, dict):
        raise _error(f"GitHub check run {name!r} has no check suite identity")
    check_suite_id = _positive_int(
        check_suite.get("id"), f"GitHub check run {name!r} check suite id"
    )
    if check_suite_id != run["check_suite_id"]:
        raise _error(f"GitHub check run {name!r} escaped the workflow check suite")
    output = value.get("output")
    if not isinstance(output, dict):
        raise _error(f"GitHub check run {name!r} has no output summary")
    annotations_count = output.get("annotations_count")
    if type(annotations_count) is not int or annotations_count != 0:
        raise _error(f"GitHub check run {name!r} contains release diagnostics")
    started_at = _timestamp(
        value.get("started_at"), f"GitHub check run {name!r} started_at"
    )
    completed_at = _timestamp(
        value.get("completed_at"), f"GitHub check run {name!r} completed_at"
    )
    if not (
        _timestamp_value(run["run_started_at"])
        <= _timestamp_value(started_at)
        <= _timestamp_value(completed_at)
        <= _timestamp_value(run["updated_at"])
    ):
        raise _error(
            f"GitHub check run {name!r} timestamps are not ordered within its run"
        )
    return {
        "annotations": {"count": 0, "items": []},
        "api_url": api_url,
        "check_suite_id": check_suite_id,
        "completed_at": completed_at,
        "conclusion": conclusion,
        "details_url": details_url,
        "head_sha": head_sha,
        "html_url": html_url,
        "id": identifier,
        "name": name,
        "started_at": started_at,
        "status": status,
    }


def _project_check_runs(
    value: object,
    run: dict[str, Any],
    jobs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    payload = _exact_object(
        value, {"check_runs", "total_count"}, "GitHub check runs response"
    )
    total = _positive_int(payload["total_count"], "GitHub check runs total_count")
    raw_check_runs = payload["check_runs"]
    if not isinstance(raw_check_runs, list) or total != len(raw_check_runs):
        raise _error("GitHub check runs response is incomplete or paginated ambiguously")
    if total != len(EXPECTED_JOB_NAMES):
        raise _error("GitHub workflow has missing or extra check runs")
    check_runs = [_project_check_run(item, run) for item in raw_check_runs]
    names = [item["name"] for item in check_runs]
    identifiers = [item["id"] for item in check_runs]
    if (
        len(set(names)) != len(names)
        or set(names) != EXPECTED_JOB_NAMES
        or len(set(identifiers)) != len(identifiers)
    ):
        raise _error("GitHub workflow has missing, repeated, or extra check runs")
    jobs_by_id = {job["id"]: job for job in jobs}
    for check_run in check_runs:
        job = jobs_by_id.get(check_run["id"])
        if job is None or (
            check_run["name"],
            check_run["head_sha"],
            check_run["status"],
            check_run["conclusion"],
            check_run["started_at"],
            check_run["completed_at"],
            check_run["html_url"],
        ) != (
            job["name"],
            job["head_sha"],
            job["status"],
            job["conclusion"],
            job["started_at"],
            job["completed_at"],
            job["html_url"],
        ):
            raise _error("GitHub check runs do not match the exact workflow jobs")
    return sorted(check_runs, key=lambda item: item["name"])


def _require_empty_annotations(value: object, check_run: dict[str, Any]) -> None:
    if value != [] or check_run["annotations"] != {"count": 0, "items": []}:
        raise _error(
            f"GitHub check run {check_run['name']!r} contains release diagnostics"
        )


def _workflow_source_bytes(repository: Path) -> bytes:
    try:
        return read_regular(repository.absolute() / WORKFLOW_PATH, MAX_WORKFLOW_BYTES)
    except (OSError, PublicationError) as error:
        raise _error("exact local workflow-file source is unavailable") from error


def _source_binding(repository: Path) -> dict[str, str]:
    repository = repository.absolute()
    try:
        if repository.is_symlink() or repository.resolve(strict=True) != repository:
            raise OSError("repository path is not canonical")
        frozen = verify_frozen_candidate(repository)
        current = current_identity(repository, require_clean=True)
        workflow_bytes = _workflow_source_bytes(repository)
        intent_bytes = read_regular(frozen.intent_path, MAX_RECEIPT_BYTES)
        intent = _strict_json(intent_bytes, "candidate-freeze intent")
    except (CandidateFreezeError, SourceIdentityError, OSError, PublicationError) as error:
        raise _error("hosted CI requires the exact frozen candidate and clean source") from error
    if (
        frozen.product_version != PRODUCT_VERSION
        or frozen.build_number != GA_BUILD
        or frozen.root
        != repository / f"target/candidates/{PRODUCT_VERSION}/ga/{GA_BUILD}"
        or not isinstance(intent, dict)
        or intent.get("document") != "cfm-candidate-freeze-intent-v3"
        or intent.get("repository_commit") != current["repositoryCommit"]
        or intent.get("release_source_sha256") != current["releaseSourceSha256"]
        or sha256_file(frozen.intent_path) != frozen.intent_sha256
    ):
        raise _error("hosted CI source differs from the frozen GA candidate")
    commit = current["repositoryCommit"]
    source_sha256 = current["releaseSourceSha256"]
    if not COMMIT_RE.fullmatch(commit) or not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        raise _error("hosted CI source identity is malformed")
    return {
        "candidate_freeze_intent_sha256": frozen.intent_sha256,
        "release_source_sha256": source_sha256,
        "repository_commit": commit,
        "workflow_sha256": sha256_bytes(workflow_bytes),
    }


def _live_receipt(
    source: dict[str, str],
    run_id: int,
    workflow_bytes: bytes,
) -> dict[str, Any]:
    if source.get("workflow_sha256") != sha256_bytes(workflow_bytes):
        raise _error("local workflow-file bytes differ from the source binding")
    run_before = _project_run(
        _fetch_api_json(_run_api_path(run_id)), source["repository_commit"], run_id
    )
    jobs = _project_jobs(
        _fetch_api_json(_jobs_api_path(run_id, run_before["run_attempt"])),
        run_before,
    )
    workflow_sha = jobs[0]["workflow_source_sha"]
    workflow_source = _project_workflow_source(
        _fetch_api_json(_workflow_contents_api_path(workflow_sha)),
        workflow_sha,
        workflow_bytes,
    )
    check_runs_before = _project_check_runs(
        _fetch_api_json(_check_runs_api_path(run_before["check_suite_id"])),
        run_before,
        jobs,
    )
    for check_run in check_runs_before:
        _require_empty_annotations(
            _fetch_api_json(_annotations_api_path(check_run["id"])),
            check_run,
        )
    run_after = _project_run(
        _fetch_api_json(_run_api_path(run_id)), source["repository_commit"], run_id
    )
    check_runs_after = _project_check_runs(
        _fetch_api_json(_check_runs_api_path(run_after["check_suite_id"])),
        run_after,
        jobs,
    )
    if run_after != run_before or check_runs_after != check_runs_before:
        raise _error("GitHub workflow run changed while its exact checks were read")
    return {
        "api": {
            "accept": API_ACCEPT,
            "origin": API_ORIGIN,
            "version": API_VERSION,
        },
        "check_runs": check_runs_before,
        "document": DOCUMENT,
        "jobs": jobs,
        "repository": {"full_name": REPOSITORY_FULL_NAME, "id": REPOSITORY_ID},
        "run": run_before,
        "schema_version": SCHEMA_VERSION,
        "source": dict(source),
        "workflow": {
            "event": EVENT,
            "id": WORKFLOW_ID,
            "name": WORKFLOW_NAME,
            "path": WORKFLOW_PATH,
            "source": workflow_source,
        },
    }


def _validated_stored_receipt(
    value: object,
    expected_source: dict[str, str],
    workflow_bytes: bytes,
) -> tuple[dict[str, Any], int]:
    receipt = _exact_object(
        value,
        {
            "api",
            "check_runs",
            "document",
            "jobs",
            "repository",
            "run",
            "schema_version",
            "source",
            "workflow",
        },
        "hosted CI receipt",
    )
    workflow = _exact_object(
        receipt["workflow"],
        {"event", "id", "name", "path", "source"},
        "hosted CI workflow identity",
    )
    workflow_source = _exact_object(
        workflow["source"],
        {"git_blob_sha", "sha256", "size", "workflow_sha"},
        "hosted CI workflow-file source identity",
    )
    retained_workflow_sha = workflow_source["workflow_sha"]
    expected_workflow_source = (
        _workflow_source_identity(retained_workflow_sha, workflow_bytes)
        if isinstance(retained_workflow_sha, str)
        else None
    )
    workflow_metadata = {
        key: workflow[key]
        for key in ("event", "id", "name", "path")
    }
    expected_workflow_metadata = {
        "event": EVENT,
        "id": WORKFLOW_ID,
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
    }
    if (
        receipt["document"] != DOCUMENT
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt["api"]
        != {"accept": API_ACCEPT, "origin": API_ORIGIN, "version": API_VERSION}
        or receipt["repository"]
        != {"full_name": REPOSITORY_FULL_NAME, "id": REPOSITORY_ID}
        or workflow_metadata != expected_workflow_metadata
        or expected_source.get("workflow_sha256") != sha256_bytes(workflow_bytes)
        or workflow_source != expected_workflow_source
        or receipt["source"] != expected_source
        or not isinstance(receipt["run"], dict)
    ):
        raise _error("hosted CI receipt identity or source binding is invalid")
    run_value = receipt["run"]
    run_id = _positive_int(run_value.get("id"), "retained workflow run id")
    run_api_value = {
        "check_suite_id": run_value.get("check_suite_id"),
        "check_suite_url": run_value.get("check_suite_url"),
        "conclusion": run_value.get("conclusion"),
        "created_at": run_value.get("created_at"),
        "event": run_value.get("event"),
        "head_branch": run_value.get("head_branch"),
        "head_repository": run_value.get("head_repository"),
        "head_sha": run_value.get("head_sha"),
        "html_url": run_value.get("html_url"),
        "id": run_value.get("id"),
        "jobs_url": run_value.get("jobs_url"),
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
        "repository": run_value.get("repository"),
        "run_attempt": run_value.get("run_attempt"),
        "run_number": run_value.get("run_number"),
        "run_started_at": run_value.get("run_started_at"),
        "status": run_value.get("status"),
        "updated_at": run_value.get("updated_at"),
        "url": run_value.get("api_url"),
        "workflow_id": WORKFLOW_ID,
    }
    normalized_run = _project_run(
        run_api_value, expected_source["repository_commit"], run_id
    )
    if normalized_run != run_value:
        raise _error("hosted CI receipt run schema or fixed identity is invalid")
    retained_jobs = receipt["jobs"]
    if not isinstance(retained_jobs, list):
        raise _error("hosted CI receipt jobs are malformed")
    raw_jobs: list[dict[str, Any]] = []
    for job in retained_jobs:
        if not isinstance(job, dict):
            raise _error("hosted CI receipt contains a malformed job")
        raw_jobs.append(
            {
                "completed_at": job.get("completed_at"),
                "conclusion": job.get("conclusion"),
                "head_sha": job.get("head_sha"),
                "html_url": job.get("html_url"),
                "id": job.get("id"),
                "name": job.get("name"),
                "run_attempt": job.get("run_attempt"),
                "run_id": run_id,
                "started_at": job.get("started_at"),
                "status": job.get("status"),
                "steps": job.get("steps"),
                "url": job.get("api_url"),
            }
        )
    normalized_jobs = _project_jobs(
        {"jobs": raw_jobs, "total_count": len(raw_jobs)}, normalized_run
    )
    if (
        normalized_jobs != retained_jobs
        or any(
            job["workflow_source_sha"] != retained_workflow_sha
            for job in normalized_jobs
        )
    ):
        raise _error("hosted CI receipt job or step schema is invalid")
    retained_check_runs = receipt["check_runs"]
    if not isinstance(retained_check_runs, list):
        raise _error("hosted CI receipt check runs are malformed")
    raw_check_runs: list[dict[str, Any]] = []
    for check_run in retained_check_runs:
        if not isinstance(check_run, dict):
            raise _error("hosted CI receipt contains a malformed check run")
        annotations = check_run.get("annotations")
        raw_check_runs.append(
            {
                "check_suite": {"id": check_run.get("check_suite_id")},
                "completed_at": check_run.get("completed_at"),
                "conclusion": check_run.get("conclusion"),
                "details_url": check_run.get("details_url"),
                "head_sha": check_run.get("head_sha"),
                "html_url": check_run.get("html_url"),
                "id": check_run.get("id"),
                "name": check_run.get("name"),
                "output": {
                    "annotations_count": (
                        annotations.get("count")
                        if isinstance(annotations, dict)
                        else None
                    )
                },
                "started_at": check_run.get("started_at"),
                "status": check_run.get("status"),
                "url": check_run.get("api_url"),
            }
        )
    normalized_check_runs = _project_check_runs(
        {"check_runs": raw_check_runs, "total_count": len(raw_check_runs)},
        normalized_run,
        normalized_jobs,
    )
    if normalized_check_runs != retained_check_runs:
        raise _error("hosted CI receipt check run schema is invalid")
    return receipt, run_id


def _read_receipt_bytes(repository: Path) -> bytes:
    stage_inputs = repository.absolute() / RECEIPT_RELATIVE.parent
    with exclusive_rooted_directory_lock(
        repository, stage_inputs, require_private=True
    ) as descriptor:
        return read_private_pending_locked(
            descriptor,
            stage_inputs,
            RECEIPT_RELATIVE.name,
            MAX_RECEIPT_BYTES,
        )


def _load_receipt(
    repository: Path,
    source: dict[str, str],
    workflow_bytes: bytes,
) -> tuple[dict[str, Any], bytes, int]:
    raw = _read_receipt_bytes(repository)
    value = _strict_json(raw, "hosted CI receipt")
    if _canonical_json(value) != raw:
        raise _error("hosted CI receipt is not canonical JSON")
    validated, run_id = _validated_stored_receipt(value, source, workflow_bytes)
    return validated, raw, run_id


def _publish_receipt(repository: Path, data: bytes) -> None:
    ga_root = repository.absolute() / RECEIPT_RELATIVE.parents[1]
    stage_inputs = repository.absolute() / RECEIPT_RELATIVE.parent
    with exclusive_rooted_directory_lock(
        repository, ga_root, require_private=True
    ) as descriptor:
        ensure_private_directory_locked(descriptor, ga_root, stage_inputs.name)
    with exclusive_rooted_directory_lock(
        repository, stage_inputs, require_private=True
    ) as descriptor:
        write_private_pending_locked(
            descriptor, stage_inputs, RECEIPT_RELATIVE.name, data
        )


def capture_receipt(repository: Path, run_id: int) -> dict[str, Any]:
    """Capture one fixed hosted run and durably create the canonical receipt."""

    run_id = _positive_int(run_id, "workflow run id")
    source_before = _source_binding(repository)
    workflow_before = _workflow_source_bytes(repository)
    if source_before.get("workflow_sha256") != sha256_bytes(workflow_before):
        raise _error("release workflow changed before hosted CI capture")
    receipt = _live_receipt(source_before, run_id, workflow_before)
    source_after = _source_binding(repository)
    workflow_after = _workflow_source_bytes(repository)
    if source_after != source_before or workflow_after != workflow_before:
        raise _error("release source changed while hosted CI was being captured")
    _publish_receipt(repository, _canonical_json(receipt))
    verified = validate_receipt_offline(repository)
    if verified != receipt:
        raise _error("hosted CI receipt changed after durable publication")
    return verified


def validate_receipt_offline(repository: Path) -> dict[str, Any]:
    """Reopen the canonical receipt against the frozen source without networking."""

    source_before = _source_binding(repository)
    workflow_before = _workflow_source_bytes(repository)
    retained, raw_before, _run_id = _load_receipt(
        repository,
        source_before,
        workflow_before,
    )
    source_after = _source_binding(repository)
    workflow_after = _workflow_source_bytes(repository)
    if source_after != source_before or workflow_after != workflow_before:
        raise _error("release source changed while hosted CI receipt was being reopened")
    reopened, raw_after, _reopened_run_id = _load_receipt(
        repository,
        source_after,
        workflow_after,
    )
    if raw_after != raw_before or reopened != retained:
        raise _error("hosted CI receipt changed while it was being reopened")
    return retained


def verify_receipt(repository: Path) -> dict[str, Any]:
    """Reopen one receipt and live-revalidate its run, jobs, and zero-annotation checks."""

    retained = validate_receipt_offline(repository)
    source = retained["source"]
    run_id = _positive_int(retained["run"].get("id"), "retained workflow run id")
    workflow_bytes = _workflow_source_bytes(repository)
    live = _live_receipt(source, run_id, workflow_bytes)
    reopened = validate_receipt_offline(repository)
    if reopened != retained:
        raise _error("hosted CI receipt changed during live verification")
    if retained != live:
        raise _error("retained hosted CI receipt differs from live GitHub state")
    return live


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("--run-id", required=True)
    commands.add_parser("verify")
    arguments = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if arguments.command == "capture" and not DECIMAL_RE.fullmatch(arguments.run_id):
        parser.error("--run-id must be one positive canonical decimal integer")
    return arguments


def main() -> None:
    if __package__:
        from .release_python_runtime import (
            ReleasePythonRuntimeError,
            require_closed_release_runtime,
        )
    else:
        from release_python_runtime import (
            ReleasePythonRuntimeError,
            require_closed_release_runtime,
        )

    try:
        require_closed_release_runtime()
    except ReleasePythonRuntimeError as error:
        raise SystemExit(f"error: hosted CI receipt: {error}") from error
    arguments = _arguments()
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "capture":
            receipt = capture_receipt(repository, int(arguments.run_id, 10))
        else:
            receipt = verify_receipt(repository)
    except (HostedCIReceiptError, PublicationError, OSError, ValueError) as error:
        raise SystemExit(f"error: hosted CI receipt: {error}") from error
    print(
        "hosted CI receipt verified: "
        f"run={receipt['run']['id']} attempt={receipt['run']['run_attempt']} "
        f"head={receipt['run']['head_sha']} "
        f"workflow={receipt['workflow']['source']['workflow_sha']} "
        f"jobs={len(receipt['jobs'])}"
    )


if __name__ == "__main__":
    main()
