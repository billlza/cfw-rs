#!/usr/bin/env python3
"""Capture and live-verify the exact hosted GitHub Actions receipt for GA 40034.

This module is intentionally separate from the deterministic local CI-lane
collector.  A local command result can corroborate a hosted run, but it can
never satisfy this receipt.  Production access is read-only, unauthenticated,
fixed to one public repository/workflow, and revalidates one run around the
attempt-specific jobs response so a rerun cannot be mistaken for the retained
attempt.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
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
    from .publication.common import PublicationError, read_regular, sha256_file
    from .publication.durable_file import (
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from .repository_source_identity import SourceIdentityError, current_identity
else:
    from candidate_freeze import CandidateFreezeError, verify_frozen_candidate
    from publication.common import PublicationError, read_regular, sha256_file
    from publication.durable_file import (
        ensure_private_directory_locked,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from repository_source_identity import SourceIdentityError, current_identity


class HostedCIReceiptError(PublicationError):
    """The hosted-CI receipt is unavailable, ambiguous, or not successful."""


SCHEMA_VERSION: Final = 1
DOCUMENT: Final = "cfw-github-hosted-ci-receipt-v1"
PRODUCT_VERSION: Final = "0.4.0"
GA_BUILD: Final = "40034"

API_ORIGIN: Final = "https://api.github.com"
API_ACCEPT: Final = "application/vnd.github+json"
API_VERSION: Final = "2022-11-28"
API_USER_AGENT: Final = "cfw-rs-release-evidence/0.4.0"
API_TIMEOUT_SECONDS: Final = 30
MAX_API_RESPONSE_BYTES: Final = 8 * 1024 * 1024
MAX_RECEIPT_BYTES: Final = 4 * 1024 * 1024

REPOSITORY_FULL_NAME: Final = "billlza/cfw-rs"
REPOSITORY_ID: Final = 1_306_403_473
WORKFLOW_ID: Final = 316_580_234
WORKFLOW_NAME: Final = "CI"
WORKFLOW_PATH: Final = ".github/workflows/ci.yml"
EVENT: Final = "pull_request"
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
            "Assert exact CI source identity",
            "Verify build-script boundary",
            "Test release tooling",
            "Validate shell scripts",
            "Lint shell scripts with pinned ShellCheck",
        }
    ),
    "macOS Rust supply-chain policy": frozenset(
        {
            "Assert exact CI source identity",
            "Audit exact shipped Rust target graph",
            "Enforce dependency, source, and license policy",
        }
    ),
    "libbox, Network Extension, and app skeleton gates": frozenset(
        {
            "Assert exact CI source identity",
            "Build and verify pinned packet LAN peer",
            "Build source-bound libbox",
            "Build and verify unsigned application skeleton",
        }
    ),
}

RECEIPT_RELATIVE: Final = Path(
    "target/candidates/0.4.0/ga/40034/stage-inputs/hosted-ci.json"
)
COMMIT_RE: Final = re.compile(r"^[0-9a-f]{40}$")
BRANCH_RE: Final = re.compile(r"^[^\x00-\x20\x7f~^:?*\\\[\]]{1,255}$")
TIMESTAMP_RE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DECIMAL_RE: Final = re.compile(r"^[1-9][0-9]{0,19}$")
API_PATH_RE: Final = re.compile(
    rf"^/repos/{re.escape(REPOSITORY_FULL_NAME)}/actions/runs/"
    r"[1-9][0-9]{0,19}"
    r"(?:/attempts/[1-9][0-9]{0,19}/jobs\?per_page=100&page=1)?$"
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


def _project_run(value: object, expected_sha: str, run_id: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error("GitHub workflow run response is not an object")
    identifier = _positive_int(value.get("id"), "workflow run id")
    attempt = _positive_int(value.get("run_attempt"), "workflow run attempt")
    run_number = _positive_int(value.get("run_number"), "workflow run number")
    workflow_id = _positive_int(value.get("workflow_id"), "workflow id")
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
    expected_api_url = API_ORIGIN + _run_api_path(run_id)
    expected_html_url = f"https://github.com/{REPOSITORY_FULL_NAME}/actions/runs/{run_id}"
    if (
        api_url != expected_api_url
        or html_url != expected_html_url
        or jobs_url != expected_api_url + "/jobs"
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
    return sorted(jobs, key=lambda job: job["name"])


def _source_binding(repository: Path) -> dict[str, str]:
    repository = repository.absolute()
    try:
        if repository.is_symlink() or repository.resolve(strict=True) != repository:
            raise OSError("repository path is not canonical")
        frozen = verify_frozen_candidate(repository)
        current = current_identity(repository, require_clean=True)
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
    }


def _live_receipt(source: dict[str, str], run_id: int) -> dict[str, Any]:
    run_before = _project_run(
        _fetch_api_json(_run_api_path(run_id)), source["repository_commit"], run_id
    )
    jobs = _project_jobs(
        _fetch_api_json(_jobs_api_path(run_id, run_before["run_attempt"])),
        run_before,
    )
    run_after = _project_run(
        _fetch_api_json(_run_api_path(run_id)), source["repository_commit"], run_id
    )
    if run_after != run_before:
        raise _error("GitHub workflow run changed while its attempt jobs were read")
    return {
        "api": {
            "accept": API_ACCEPT,
            "origin": API_ORIGIN,
            "version": API_VERSION,
        },
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
        },
    }


def _validated_stored_receipt(
    value: object, expected_source: dict[str, str]
) -> tuple[dict[str, Any], int]:
    receipt = _exact_object(
        value,
        {
            "api",
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
    if (
        receipt["document"] != DOCUMENT
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt["api"]
        != {"accept": API_ACCEPT, "origin": API_ORIGIN, "version": API_VERSION}
        or receipt["repository"]
        != {"full_name": REPOSITORY_FULL_NAME, "id": REPOSITORY_ID}
        or receipt["workflow"]
        != {"event": EVENT, "id": WORKFLOW_ID, "name": WORKFLOW_NAME, "path": WORKFLOW_PATH}
        or receipt["source"] != expected_source
        or not isinstance(receipt["run"], dict)
    ):
        raise _error("hosted CI receipt identity or source binding is invalid")
    run_value = receipt["run"]
    run_id = _positive_int(run_value.get("id"), "retained workflow run id")
    run_api_value = {
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
    if normalized_jobs != retained_jobs:
        raise _error("hosted CI receipt job or step schema is invalid")
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
    repository: Path, source: dict[str, str]
) -> tuple[dict[str, Any], bytes, int]:
    raw = _read_receipt_bytes(repository)
    value = _strict_json(raw, "hosted CI receipt")
    if _canonical_json(value) != raw:
        raise _error("hosted CI receipt is not canonical JSON")
    validated, run_id = _validated_stored_receipt(value, source)
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
    receipt = _live_receipt(source_before, run_id)
    source_after = _source_binding(repository)
    if source_after != source_before:
        raise _error("release source changed while hosted CI was being captured")
    _publish_receipt(repository, _canonical_json(receipt))
    verified = validate_receipt_offline(repository)
    if verified != receipt:
        raise _error("hosted CI receipt changed after durable publication")
    return verified


def validate_receipt_offline(repository: Path) -> dict[str, Any]:
    """Reopen the canonical receipt against the frozen source without networking."""

    source_before = _source_binding(repository)
    retained, raw_before, _run_id = _load_receipt(repository, source_before)
    source_after = _source_binding(repository)
    if source_after != source_before:
        raise _error("release source changed while hosted CI receipt was being reopened")
    reopened, raw_after, _reopened_run_id = _load_receipt(repository, source_after)
    if raw_after != raw_before or reopened != retained:
        raise _error("hosted CI receipt changed while it was being reopened")
    return retained


def verify_receipt(repository: Path) -> dict[str, Any]:
    """Reopen one receipt and live-revalidate its current run attempt and jobs."""

    retained = validate_receipt_offline(repository)
    source = retained["source"]
    run_id = _positive_int(retained["run"].get("id"), "retained workflow run id")
    live = _live_receipt(source, run_id)
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
        f"head={receipt['run']['head_sha']} jobs={len(receipt['jobs'])}"
    )


if __name__ == "__main__":
    main()
