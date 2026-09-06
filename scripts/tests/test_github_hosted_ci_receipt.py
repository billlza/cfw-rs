from __future__ import annotations

import base64
import copy
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import candidate_freeze
from scripts import github_hosted_ci_receipt as hosted
from scripts.publication.common import PublicationError
from scripts.release_executor_source import ExecutorSource, FrozenReleaseSources


RUN_ID = 90_012_345_678
CHECK_SUITE_ID = 80_012_345_678
HEAD_SHA = "a" * 40
WORKFLOW_SHA = "e" * 40
WORKFLOW_BYTES = b"name: CI\non: pull_request\n"
SOURCE = {
    "candidate_freeze_intent_sha256": "b" * 64,
    "release_source_sha256": "c" * 64,
    "repository_commit": HEAD_SHA,
    "workflow_sha256": hashlib.sha256(WORKFLOW_BYTES).hexdigest(),
}


def workflow_response(
    *,
    workflow_sha: str = WORKFLOW_SHA,
    content: bytes = WORKFLOW_BYTES,
) -> dict[str, object]:
    git_object = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    blob_sha = hashlib.sha1(git_object, usedforsecurity=False).hexdigest()
    api_url = hosted.API_ORIGIN + hosted._workflow_contents_api_path(workflow_sha)
    git_url = (
        f"{hosted.API_ORIGIN}/repos/{hosted.REPOSITORY_FULL_NAME}/git/blobs/"
        f"{blob_sha}"
    )
    html_url = (
        f"https://github.com/{hosted.REPOSITORY_FULL_NAME}/blob/"
        f"{workflow_sha}/{hosted.WORKFLOW_PATH}"
    )
    download_url = (
        f"https://raw.githubusercontent.com/{hosted.REPOSITORY_FULL_NAME}/"
        f"{workflow_sha}/{hosted.WORKFLOW_PATH}"
    )
    return {
        "_links": {"git": git_url, "html": html_url, "self": api_url},
        "content": base64.encodebytes(content).decode("ascii"),
        "download_url": download_url,
        "encoding": "base64",
        "git_url": git_url,
        "html_url": html_url,
        "name": "ci.yml",
        "path": hosted.WORKFLOW_PATH,
        "sha": blob_sha,
        "size": len(content),
        "type": "file",
        "url": api_url,
    }


def run_response(*, attempt: int = 2, head_sha: str = HEAD_SHA) -> dict[str, object]:
    api_url = f"https://api.github.com/repos/{hosted.REPOSITORY_FULL_NAME}/actions/runs/{RUN_ID}"
    return {
        "check_suite_id": CHECK_SUITE_ID,
        "check_suite_url": (
            f"https://api.github.com/repos/{hosted.REPOSITORY_FULL_NAME}/"
            f"check-suites/{CHECK_SUITE_ID}"
        ),
        "conclusion": "success",
        "created_at": "2026-08-25T20:00:00Z",
        "event": "pull_request",
        "head_branch": "release/macos-0.4.0",
        "head_repository": {
            "full_name": hosted.REPOSITORY_FULL_NAME,
            "id": hosted.REPOSITORY_ID,
        },
        "head_sha": head_sha,
        "html_url": f"https://github.com/{hosted.REPOSITORY_FULL_NAME}/actions/runs/{RUN_ID}",
        "id": RUN_ID,
        "jobs_url": api_url + "/jobs",
        "name": hosted.WORKFLOW_NAME,
        "path": hosted.WORKFLOW_PATH,
        "repository": {
            "full_name": hosted.REPOSITORY_FULL_NAME,
            "id": hosted.REPOSITORY_ID,
        },
        "run_attempt": attempt,
        "run_number": 431,
        "run_started_at": "2026-08-25T20:01:00Z",
        "status": "completed",
        "updated_at": "2026-08-25T20:20:00Z",
        "url": api_url,
        "workflow_id": hosted.WORKFLOW_ID,
    }


def job_response(name: str, identifier: int, *, attempt: int = 2) -> dict[str, object]:
    step_names = [
        "Set up job",
        hosted.WORKFLOW_SOURCE_STEP_PREFIX + WORKFLOW_SHA,
        *sorted(hosted.REQUIRED_JOB_STEP_NAMES.get(name, frozenset())),
        "Complete job",
    ]
    steps = [
        {
            "completed_at": "2026-08-25T20:14:00Z",
            "conclusion": "success",
            "name": step_name,
            "number": number,
            "started_at": "2026-08-25T20:03:00Z",
            "status": "completed",
        }
        for number, step_name in enumerate(step_names, start=1)
    ]
    return {
        "completed_at": "2026-08-25T20:15:00Z",
        "conclusion": "success",
        "head_sha": HEAD_SHA,
        "html_url": (
            f"https://github.com/{hosted.REPOSITORY_FULL_NAME}/actions/runs/"
            f"{RUN_ID}/job/{identifier}"
        ),
        "id": identifier,
        "name": name,
        "run_attempt": attempt,
        "run_id": RUN_ID,
        "started_at": "2026-08-25T20:02:00Z",
        "status": "completed",
        "steps": steps,
        "url": (
            f"https://api.github.com/repos/{hosted.REPOSITORY_FULL_NAME}/actions/jobs/"
            f"{identifier}"
        ),
    }


def jobs_response() -> dict[str, object]:
    jobs = [
        job_response(name, 7_000 + index)
        for index, name in enumerate(sorted(hosted.EXPECTED_JOB_NAMES), start=1)
    ]
    return {"jobs": jobs, "total_count": len(jobs)}


def check_run_response(job: dict[str, object]) -> dict[str, object]:
    return {
        "check_suite": {"id": CHECK_SUITE_ID},
        "completed_at": job["completed_at"],
        "conclusion": job["conclusion"],
        "details_url": job["html_url"],
        "head_sha": job["head_sha"],
        "html_url": job["html_url"],
        "id": job["id"],
        "name": job["name"],
        "output": {"annotations_count": 0},
        "started_at": job["started_at"],
        "status": job["status"],
        "url": (
            f"https://api.github.com/repos/{hosted.REPOSITORY_FULL_NAME}/"
            f"check-runs/{job['id']}"
        ),
    }


def check_runs_response(
    jobs: dict[str, object] | None = None,
) -> dict[str, object]:
    selected = jobs or jobs_response()
    check_runs = [check_run_response(job) for job in selected["jobs"]]
    return {"check_runs": check_runs, "total_count": len(check_runs)}


class StableAPI:
    def __init__(
        self,
        *,
        run: dict[str, object] | None = None,
        jobs: dict[str, object] | None = None,
        workflow: dict[str, object] | None = None,
        check_runs: dict[str, object] | None = None,
        annotations: dict[int, list[dict[str, object]]] | None = None,
    ) -> None:
        self.run = run or run_response()
        self.jobs = jobs or jobs_response()
        self.workflow = workflow or workflow_response()
        self.check_runs = check_runs or check_runs_response(self.jobs)
        self.annotations = annotations or {}
        self.paths: list[str] = []

    def __call__(self, path: str):
        self.paths.append(path)
        if path == hosted._run_api_path(RUN_ID):
            return copy.deepcopy(self.run)
        if path == hosted._jobs_api_path(RUN_ID, int(self.run["run_attempt"])):
            return copy.deepcopy(self.jobs)
        if path == hosted._workflow_contents_api_path(WORKFLOW_SHA):
            return copy.deepcopy(self.workflow)
        if path == hosted._check_runs_api_path(int(self.run["check_suite_id"])):
            return copy.deepcopy(self.check_runs)
        for check_run in self.check_runs["check_runs"]:
            if path == hosted._annotations_api_path(int(check_run["id"])):
                return copy.deepcopy(self.annotations.get(int(check_run["id"]), []))
        raise AssertionError(path)


class FakeResponse:
    def __init__(
        self,
        data: bytes,
        url: str,
        *,
        status: int = 200,
        content_type: str = "application/json; charset=utf-8",
    ) -> None:
        self.data = io.BytesIO(data)
        self.url = url
        self.status = status
        self.headers = {
            "Content-Length": str(len(data)),
            "Content-Type": content_type,
        }

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self) -> str:
        return self.url

    def read(self, maximum: int) -> bytes:
        return self.data.read(maximum)


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests = []

    def open(self, request, *, timeout: int):
        self.requests.append((request, timeout))
        return self.response


class HostedCIReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        workflow_path = self.repository / hosted.WORKFLOW_PATH
        workflow_path.parent.mkdir(parents=True)
        workflow_path.write_bytes(WORKFLOW_BYTES)
        self.output = self.repository.joinpath(*hosted.RECEIPT_RELATIVE.parts)
        self.output.parent.mkdir(parents=True, mode=0o700)
        self.output.parent.chmod(0o700)
        self.output.parent.parent.chmod(0o700)

    def _capture(self, api: StableAPI | None = None) -> dict[str, object]:
        selected = api or StableAPI()
        with (
            patch.object(hosted, "_source_binding", return_value=dict(SOURCE)),
            patch.object(hosted, "_fetch_api_json", side_effect=selected),
        ):
            return hosted.capture_receipt(self.repository, RUN_ID)

    def _write_receipt(self, api: StableAPI | None = None) -> dict[str, object]:
        selected = api or StableAPI()
        with patch.object(hosted, "_fetch_api_json", side_effect=selected):
            receipt = hosted._live_receipt(dict(SOURCE), RUN_ID, WORKFLOW_BYTES)
        self.output.write_bytes(hosted._canonical_json(receipt))
        self.output.chmod(0o600)
        return receipt

    def test_capture_uses_run_jobs_run_and_writes_fixed_private_canonical_path(self) -> None:
        api = StableAPI()
        receipt = self._capture(api)
        self.assertEqual(receipt["run"]["id"], RUN_ID)
        self.assertEqual(len(receipt["jobs"]), 3)
        expected_calls = [
            hosted._run_api_path(RUN_ID),
            hosted._jobs_api_path(RUN_ID, 2),
            hosted._workflow_contents_api_path(WORKFLOW_SHA),
            hosted._check_runs_api_path(CHECK_SUITE_ID),
            *[
                hosted._annotations_api_path(check_run["id"])
                for check_run in receipt["check_runs"]
            ],
            hosted._run_api_path(RUN_ID),
            hosted._check_runs_api_path(CHECK_SUITE_ID),
        ]
        self.assertEqual(api.paths, expected_calls)
        self.assertEqual(
            [check_run["annotations"] for check_run in receipt["check_runs"]],
            [{"count": 0, "items": []}] * 3,
        )
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        raw = self.output.read_bytes()
        self.assertEqual(raw, hosted._canonical_json(json.loads(raw)))

    def test_capture_creates_missing_private_stage_inputs_under_fixed_ga_root(self) -> None:
        self.output.parent.rmdir()
        self.assertFalse(self.output.parent.exists())
        self._capture()
        self.assertEqual(self.output.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_offline_validation_never_fetches_network(self) -> None:
        retained = self._write_receipt()
        with (
            patch.object(hosted, "_source_binding", return_value=dict(SOURCE)),
            patch.object(
                hosted,
                "_fetch_api_json",
                side_effect=AssertionError("offline validation fetched GitHub"),
            ),
        ):
            self.assertEqual(hosted.validate_receipt_offline(self.repository), retained)

    def test_offline_validation_rejects_local_workflow_drift(self) -> None:
        self._write_receipt()
        (self.repository / hosted.WORKFLOW_PATH).write_bytes(b"name: Drifted CI\n")
        with (
            patch.object(hosted, "_source_binding", return_value=dict(SOURCE)),
            self.assertRaises(hosted.HostedCIReceiptError),
        ):
            hosted.validate_receipt_offline(self.repository)

    def test_existing_receipt_is_never_replaced(self) -> None:
        self.output.write_bytes(b"retained\n")
        self.output.chmod(0o600)
        with self.assertRaises(PublicationError):
            self._capture()
        self.assertEqual(self.output.read_bytes(), b"retained\n")

    def test_attempt_drift_between_run_reads_fails_before_publication(self) -> None:
        before = run_response(attempt=2)
        after = run_response(attempt=3)
        jobs = jobs_response()
        checks = check_runs_response(jobs)
        responses = [
            before,
            jobs,
            workflow_response(),
            checks,
            [],
            [],
            [],
            after,
            checks,
        ]
        with (
            patch.object(hosted, "_source_binding", return_value=dict(SOURCE)),
            patch.object(hosted, "_fetch_api_json", side_effect=responses),
            self.assertRaisesRegex(hosted.HostedCIReceiptError, "changed"),
        ):
            hosted.capture_receipt(self.repository, RUN_ID)
        self.assertFalse(self.output.exists())

    def test_source_drift_during_capture_fails_before_publication(self) -> None:
        drifted = {**SOURCE, "release_source_sha256": "d" * 64}
        with (
            patch.object(hosted, "_source_binding", side_effect=[SOURCE, drifted]),
            patch.object(hosted, "_fetch_api_json", side_effect=StableAPI()),
            self.assertRaisesRegex(hosted.HostedCIReceiptError, "source changed"),
        ):
            hosted.capture_receipt(self.repository, RUN_ID)
        self.assertFalse(self.output.exists())

    def test_workflow_drift_during_capture_fails_before_publication(self) -> None:
        with (
            patch.object(hosted, "_source_binding", return_value=dict(SOURCE)),
            patch.object(
                hosted,
                "_workflow_source_bytes",
                side_effect=[WORKFLOW_BYTES, b"name: Drifted CI\n"],
            ),
            patch.object(hosted, "_fetch_api_json", side_effect=StableAPI()),
            self.assertRaisesRegex(hosted.HostedCIReceiptError, "source changed"),
        ):
            hosted.capture_receipt(self.repository, RUN_ID)
        self.assertFalse(self.output.exists())

    def test_foreign_repository_workflow_event_or_old_sha_is_rejected(self) -> None:
        mutations = (
            lambda run: run["repository"].update(id=7),
            lambda run: run.update(workflow_id=7),
            lambda run: run.update(event="push"),
            lambda run: run.update(head_sha="d" * 40),
            lambda run: run["head_repository"].update(full_name="foreign/fork"),
            lambda run: run.update(check_suite_id=7),
            lambda run: run.update(check_suite_url="https://example.invalid/suite"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                run = run_response()
                mutate(run)
                with self.assertRaises(hosted.HostedCIReceiptError):
                    hosted._project_run(run, HEAD_SHA, RUN_ID)

    def test_missing_extra_failed_or_skipped_job_and_step_are_rejected(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []
        missing = jobs_response()
        missing["jobs"].pop()
        missing["total_count"] = len(missing["jobs"])
        cases.append(("missing", missing))
        extra = jobs_response()
        extra["jobs"].append(job_response("unexpected", 9999))
        extra["total_count"] = len(extra["jobs"])
        cases.append(("extra", extra))
        failed = jobs_response()
        failed["jobs"][0]["conclusion"] = "failure"
        cases.append(("failed", failed))
        skipped = jobs_response()
        skipped["jobs"][0]["steps"][1]["conclusion"] = "skipped"
        cases.append(("skipped", skipped))
        for label, value in cases:
            with self.subTest(label=label), self.assertRaises(hosted.HostedCIReceiptError):
                hosted._project_jobs(value, hosted._project_run(run_response(), HEAD_SHA, RUN_ID))

    def test_xcode_ownership_step_must_be_present_and_successful(self) -> None:
        rust_job_name = "Rust, UI, and script quality gates"
        step_name = "Normalize pinned Xcode ownership"
        for conclusion in (None, "failure", "skipped"):
            with self.subTest(conclusion=conclusion):
                value = jobs_response()
                rust_job = next(
                    job for job in value["jobs"] if job["name"] == rust_job_name
                )
                step = next(
                    item for item in rust_job["steps"] if item["name"] == step_name
                )
                if conclusion is None:
                    rust_job["steps"].remove(step)
                else:
                    step["conclusion"] = conclusion
                with self.assertRaises(hosted.HostedCIReceiptError):
                    hosted._project_jobs(
                        value,
                        hosted._project_run(run_response(), HEAD_SHA, RUN_ID),
                    )

    def test_workflow_source_marker_may_differ_from_tested_head(self) -> None:
        projected = hosted._project_jobs(
            jobs_response(),
            hosted._project_run(run_response(), HEAD_SHA, RUN_ID),
        )
        self.assertNotEqual(WORKFLOW_SHA, HEAD_SHA)
        self.assertEqual(
            {job["workflow_source_sha"] for job in projected},
            {WORKFLOW_SHA},
        )

    def test_workflow_source_marker_is_exact_and_consistent(self) -> None:
        def marker(job: dict[str, object]) -> dict[str, object]:
            return next(
                step
                for step in job["steps"]
                if step["name"].startswith(hosted.WORKFLOW_SOURCE_STEP_PREFIX)
            )

        cases: list[tuple[str, dict[str, object]]] = []
        missing = jobs_response()
        missing["jobs"][0]["steps"].remove(marker(missing["jobs"][0]))
        cases.append(("missing", missing))
        repeated = jobs_response()
        repeated["jobs"][0]["steps"].insert(
            2,
            copy.deepcopy(marker(repeated["jobs"][0])),
        )
        cases.append(("repeated", repeated))
        malformed = jobs_response()
        marker(malformed["jobs"][0])["name"] = (
            hosted.WORKFLOW_SOURCE_STEP_PREFIX + "E" * 40
        )
        cases.append(("malformed", malformed))
        inconsistent = jobs_response()
        marker(inconsistent["jobs"][0])["name"] = (
            hosted.WORKFLOW_SOURCE_STEP_PREFIX + "d" * 40
        )
        cases.append(("inconsistent", inconsistent))
        failed = jobs_response()
        marker(failed["jobs"][0])["conclusion"] = "failure"
        cases.append(("failed", failed))
        skipped = jobs_response()
        marker(skipped["jobs"][0])["conclusion"] = "skipped"
        cases.append(("skipped", skipped))
        for label, value in cases:
            with self.subTest(label=label), self.assertRaises(
                hosted.HostedCIReceiptError
            ):
                hosted._project_jobs(
                    value,
                    hosted._project_run(run_response(), HEAD_SHA, RUN_ID),
                )

    def test_workflow_source_marker_rejects_noncanonical_sha_text(self) -> None:
        invalid_values = (
            "e" * 39,
            "e" * 41,
            "E" * 40,
            "g" * 40,
            "e" * 40 + " ",
        )
        for invalid in invalid_values:
            with self.subTest(invalid=invalid):
                value = jobs_response()
                for job in value["jobs"]:
                    marker = next(
                        step
                        for step in job["steps"]
                        if step["name"].startswith(
                            hosted.WORKFLOW_SOURCE_STEP_PREFIX
                        )
                    )
                    marker["name"] = hosted.WORKFLOW_SOURCE_STEP_PREFIX + invalid
                with self.assertRaises(hosted.HostedCIReceiptError):
                    hosted._project_jobs(
                        value,
                        hosted._project_run(run_response(), HEAD_SHA, RUN_ID),
                    )

    def test_check_run_diagnostics_are_rejected_before_publication(self) -> None:
        checks_with_count = check_runs_response()
        checks_with_count["check_runs"][0]["output"]["annotations_count"] = 1
        first_check_id = int(check_runs_response()["check_runs"][0]["id"])
        cases = (
            StableAPI(check_runs=checks_with_count),
            StableAPI(
                annotations={
                    first_check_id: [
                        {
                            "annotation_level": "warning",
                            "message": "release warning",
                            "path": "src/main.rs",
                        }
                    ]
                }
            ),
        )
        for api in cases:
            with (
                self.subTest(api=api),
                patch.object(hosted, "_source_binding", return_value=dict(SOURCE)),
                patch.object(hosted, "_fetch_api_json", side_effect=api),
                self.assertRaisesRegex(
                    hosted.HostedCIReceiptError, "release diagnostics"
                ),
            ):
                hosted.capture_receipt(self.repository, RUN_ID)
            self.assertFalse(self.output.exists())

    def test_workflow_contents_are_exactly_bound_to_clean_source(self) -> None:
        projected = hosted._project_workflow_source(
            workflow_response(),
            WORKFLOW_SHA,
            WORKFLOW_BYTES,
        )
        self.assertEqual(projected["workflow_sha"], WORKFLOW_SHA)
        self.assertEqual(projected["sha256"], SOURCE["workflow_sha256"])
        self.assertEqual(projected["size"], len(WORKFLOW_BYTES))

    def test_workflow_contents_malformed_or_foreign_state_is_rejected(self) -> None:
        mutations = (
            lambda value: value.update(type="dir"),
            lambda value: value.update(type="symlink"),
            lambda value: value.update(type="submodule"),
            lambda value: value.update(encoding="utf-8"),
            lambda value: value.update(path=".github/workflows/other.yml"),
            lambda value: value.update(size=len(WORKFLOW_BYTES) + 1),
            lambda value: value.update(size=hosted.MAX_WORKFLOW_BYTES + 1),
            lambda value: value.update(content="not base64!"),
            lambda value: value.update(content=value["content"] + " "),
            lambda value: value.update(content=value["content"].rstrip("=\n")),
            lambda value: value.update(content=value["content"] + "\r"),
            lambda value: value.update(sha="f" * 40),
            lambda value: value.update(url="https://example.invalid/workflow"),
            lambda value: value.update(git_url="https://example.invalid/blob"),
            lambda value: value.update(html_url="https://example.invalid/file"),
            lambda value: value.update(
                download_url="https://example.invalid/download"
            ),
            lambda value: value["_links"].update(self="https://example.invalid"),
            lambda value: value.update(unknown="field"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = workflow_response()
                mutate(value)
                with self.assertRaises(hosted.HostedCIReceiptError):
                    hosted._project_workflow_source(
                        value,
                        WORKFLOW_SHA,
                        WORKFLOW_BYTES,
                    )
        with self.assertRaisesRegex(
            hosted.HostedCIReceiptError,
            "differ from the exact clean source",
        ):
            hosted._project_workflow_source(
                workflow_response(content=b"name: Foreign\n"),
                WORKFLOW_SHA,
                WORKFLOW_BYTES,
            )

    def test_capture_rejects_remote_workflow_byte_drift(self) -> None:
        api = StableAPI(workflow=workflow_response(content=b"name: Foreign\n"))
        with self.assertRaisesRegex(
            hosted.HostedCIReceiptError,
            "differ from the exact clean source",
        ):
            self._capture(api)
        self.assertFalse(self.output.exists())

    def test_check_runs_must_match_the_exact_jobs_and_suite(self) -> None:
        mutations = (
            lambda check: check.update(name="foreign check"),
            lambda check: check.update(head_sha="d" * 40),
            lambda check: check["check_suite"].update(id=7),
            lambda check: check.update(details_url="https://example.invalid/check"),
            lambda check: check.update(completed_at="2026-08-25T20:16:00Z"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                checks = check_runs_response()
                mutate(checks["check_runs"][0])
                with (
                    patch.object(
                        hosted, "_source_binding", return_value=dict(SOURCE)
                    ),
                    patch.object(
                        hosted,
                        "_fetch_api_json",
                        side_effect=StableAPI(check_runs=checks),
                    ),
                    self.assertRaises(hosted.HostedCIReceiptError),
                ):
                    hosted.capture_receipt(self.repository, RUN_ID)
                self.assertFalse(self.output.exists())

    def test_check_suite_is_reopened_after_annotation_queries(self) -> None:
        run = run_response()
        jobs = jobs_response()
        before = check_runs_response(jobs)
        after = copy.deepcopy(before)
        after["check_runs"][0]["output"]["annotations_count"] = 1
        responses = [
            run,
            jobs,
            workflow_response(),
            before,
            [],
            [],
            [],
            run,
            after,
        ]
        with (
            patch.object(hosted, "_source_binding", return_value=dict(SOURCE)),
            patch.object(hosted, "_fetch_api_json", side_effect=responses),
            self.assertRaisesRegex(
                hosted.HostedCIReceiptError, "release diagnostics"
            ),
        ):
            hosted.capture_receipt(self.repository, RUN_ID)
        self.assertFalse(self.output.exists())

    def test_rerun_receipt_uses_only_latest_attempt_check_runs(self) -> None:
        current_run = run_response(attempt=2)
        current_jobs = jobs_response()
        current_checks = check_runs_response(current_jobs)
        previous_jobs = {
            "jobs": [
                job_response(name, 6_000 + index, attempt=1)
                for index, name in enumerate(
                    sorted(hosted.EXPECTED_JOB_NAMES), start=1
                )
            ],
            "total_count": len(hosted.EXPECTED_JOB_NAMES),
        }
        all_checks = {
            "check_runs": [
                *current_checks["check_runs"],
                *check_runs_response(previous_jobs)["check_runs"],
            ],
            "total_count": len(hosted.EXPECTED_JOB_NAMES) * 2,
        }
        projected_run = hosted._project_run(current_run, HEAD_SHA, RUN_ID)
        projected_jobs = hosted._project_jobs(current_jobs, projected_run)
        with self.assertRaisesRegex(hosted.HostedCIReceiptError, "extra check runs"):
            hosted._project_check_runs(all_checks, projected_run, projected_jobs)

        api = StableAPI(
            run=current_run,
            jobs=current_jobs,
            check_runs=current_checks,
        )
        receipt = self._capture(api)
        self.assertEqual(
            {check_run["id"] for check_run in receipt["check_runs"]},
            {job["id"] for job in receipt["jobs"]},
        )
        self.assertIn(
            hosted._check_runs_api_path(CHECK_SUITE_ID),
            api.paths,
        )

    def test_successful_post_steps_may_have_strictly_increasing_number_gaps(self) -> None:
        value = jobs_response()
        steps = value["jobs"][0]["steps"]
        steps[-3]["number"] = 24
        steps[-2]["number"] = 47
        steps[-1]["number"] = 48
        projected = hosted._project_jobs(
            value, hosted._project_run(run_response(), HEAD_SHA, RUN_ID)
        )
        self.assertEqual(projected[0]["steps"][-2]["number"], 47)

    def test_offline_validation_rejects_run_job_and_step_schema_drift(self) -> None:
        mutations = (
            lambda receipt: receipt.update(
                document="cfw-github-hosted-ci-receipt-v2"
            ),
            lambda receipt: receipt.update(schema_version=2),
            lambda receipt: receipt["workflow"]["source"].update(
                workflow_sha="d" * 40
            ),
            lambda receipt: receipt["workflow"]["source"].update(
                git_blob_sha="d" * 40
            ),
            lambda receipt: receipt["workflow"].update(unknown="field"),
            lambda receipt: receipt["workflow"]["source"].update(size="1"),
            lambda receipt: receipt["run"].update(status="queued"),
            lambda receipt: receipt["jobs"][0].update(run_attempt=99),
            lambda receipt: receipt["jobs"][0]["steps"][0].update(conclusion="skipped"),
            lambda receipt: receipt["check_runs"][0]["annotations"].update(
                count=1
            ),
            lambda receipt: receipt["check_runs"][0].update(
                details_url="https://example.invalid/check"
            ),
            lambda receipt: receipt["run"].update(unknown="field"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                retained = self._write_receipt()
                mutate(retained)
                self.output.write_bytes(hosted._canonical_json(retained))
                with (
                    patch.object(hosted, "_source_binding", return_value=dict(SOURCE)),
                    self.assertRaises(hosted.HostedCIReceiptError),
                ):
                    hosted.validate_receipt_offline(self.repository)
                self.output.unlink()

    def test_verify_rejects_live_step_drift(self) -> None:
        self._write_receipt()
        changed_jobs = jobs_response()
        changed_jobs["jobs"][0]["steps"][0]["name"] = "Changed setup step"
        api = StableAPI(jobs=changed_jobs)
        with (
            patch.object(hosted, "_source_binding", return_value=dict(SOURCE)),
            patch.object(hosted, "_fetch_api_json", side_effect=api),
            self.assertRaisesRegex(hosted.HostedCIReceiptError, "differs from live"),
        ):
            hosted.verify_receipt(self.repository)

    def test_strict_json_rejects_duplicate_nonfinite_and_oversized_documents(self) -> None:
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(hosted.HostedCIReceiptError):
                hosted._strict_json(raw, "fixture")
        with self.assertRaises(hosted.HostedCIReceiptError):
            hosted._strict_json(b"x" * (hosted.MAX_API_RESPONSE_BYTES + 1), "fixture")

    def test_network_request_has_fixed_origin_headers_and_no_credentials(self) -> None:
        path = hosted._run_api_path(RUN_ID)
        url = hosted.API_ORIGIN + path
        response = FakeResponse(json.dumps(run_response()).encode(), url)
        opener = FakeOpener(response)
        with patch.object(hosted, "_api_opener", return_value=opener):
            self.assertEqual(hosted._fetch_api_json(path)["id"], RUN_ID)
        request, timeout = opener.requests[0]
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(request.full_url, url)
        self.assertEqual(request.method, "GET")
        self.assertEqual(timeout, hosted.API_TIMEOUT_SECONDS)
        self.assertEqual(headers["accept"], hosted.API_ACCEPT)
        self.assertEqual(headers["x-github-api-version"], hosted.API_VERSION)
        self.assertEqual(headers["user-agent"], hosted.API_USER_AGENT)
        self.assertNotIn("authorization", headers)
        for fixed_path in (
            hosted._check_runs_api_path(CHECK_SUITE_ID),
            hosted._annotations_api_path(7_001),
            hosted._workflow_contents_api_path(WORKFLOW_SHA),
        ):
            with self.subTest(fixed_path=fixed_path):
                self.assertEqual(
                    hosted._api_url(fixed_path), hosted.API_ORIGIN + fixed_path
                )
        for escaped in (
            "https://api.github.com/repos/billlza/cfw-rs/actions/runs/1",
            "/repos/billlza/cfw-rs/actions/runs/1/../2",
            "/repos/foreign/repository/actions/runs/1",
            (
                f"/repos/{hosted.REPOSITORY_FULL_NAME}/check-suites/"
                f"{CHECK_SUITE_ID}/check-runs?filter=latest&per_page=100&page=2"
            ),
            (
                f"/repos/{hosted.REPOSITORY_FULL_NAME}/contents/"
                f"{hosted.WORKFLOW_PATH}?ref=main"
            ),
            (
                f"/repos/{hosted.REPOSITORY_FULL_NAME}/contents/"
                f".github/workflows/other.yml?ref={WORKFLOW_SHA}"
            ),
            (
                f"/repos/{hosted.REPOSITORY_FULL_NAME}/contents/"
                f"{hosted.WORKFLOW_PATH}?ref={WORKFLOW_SHA}&page=1"
            ),
            (
                f"/repos/{hosted.REPOSITORY_FULL_NAME}/check-suites/"
                f"{CHECK_SUITE_ID}/check-runs?filter=all&per_page=100&page=1"
            ),
        ):
            with self.subTest(escaped=escaped), self.assertRaises(
                hosted.HostedCIReceiptError
            ):
                hosted._api_url(escaped)

    def test_network_rejects_non_200_redirected_non_json_and_length_mismatch(self) -> None:
        path = hosted._run_api_path(RUN_ID)
        url = hosted.API_ORIGIN + path
        cases = []
        cases.append(FakeResponse(b"{}", url, status=500))
        cases.append(FakeResponse(b"{}", "https://example.invalid/redirect"))
        cases.append(FakeResponse(b"{}", url, content_type="text/plain"))
        wrong_length = FakeResponse(b"{}", url)
        wrong_length.headers["Content-Length"] = "99"
        cases.append(wrong_length)
        for response in cases:
            with (
                self.subTest(response=response),
                patch.object(hosted, "_api_opener", return_value=FakeOpener(response)),
                self.assertRaises(hosted.HostedCIReceiptError),
            ):
                hosted._fetch_api_json(path)

    def test_cli_rejects_noncanonical_run_id_and_caller_selected_paths(self) -> None:
        for arguments in (
            ["capture", "--run-id", "0"],
            ["capture", "--run-id", "+1"],
            ["capture", "--run-id", "01"],
            ["capture", "--run-id", "1", "--output", "elsewhere"],
            ["verify", "--run-id", "1"],
        ):
            with (
                self.subTest(arguments=arguments),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                hosted._arguments(arguments)


class HostedCICommandSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.executor = Path(temporary.name).resolve()
        self.repository = self.executor / "target/release-worktrees/40044"
        workflow_path = self.repository / hosted.WORKFLOW_PATH
        workflow_path.parent.mkdir(parents=True)
        workflow_path.write_bytes(WORKFLOW_BYTES)
        self.output_path = self.repository / hosted.RECEIPT_RELATIVE
        self.output_path.parent.mkdir(parents=True, mode=0o700)
        self.output_path.parent.chmod(0o700)
        self.output_path.parent.parent.chmod(0o700)
        self.sources = FrozenReleaseSources(
            executor=ExecutorSource(self.executor, "d" * 40, "e" * 64),
            artifact=ExecutorSource(self.repository, HEAD_SHA, SOURCE["release_source_sha256"]),
        )
        self.output = io.StringIO()
        self.events: list[str] = []
        self.callbacks: list[candidate_freeze.FreezeVerifier] = []
        self.close_error: OSError | None = None
        self.source_error: PublicationError | None = None
        self.replay_repository = self.repository

    @contextmanager
    def embedded_session(self, repository: Path):
        self.assertEqual(repository, self.repository)
        self.events.append("session-open")
        try:
            yield Mock(name="embedded_proof_verifier")
        finally:
            self.assertEqual(self.output.getvalue(), "")
            self.events.append("session-close")
            if self.close_error is not None:
                raise self.close_error

    def source_binding(self, repository: Path, *, freeze_verifier=None):
        self.assertEqual(repository, self.repository)
        self.assertIsNotNone(freeze_verifier)
        self.callbacks.append(freeze_verifier)
        freeze_verifier(self.replay_repository)
        self.events.append("reopen")
        return dict(SOURCE)

    def unchanged(self, sources: FrozenReleaseSources) -> None:
        self.assertEqual(sources, self.sources)
        self.assertEqual(self.output.getvalue(), "")
        self.events.append("sources-unchanged")
        if self.source_error is not None:
            raise self.source_error

    @contextmanager
    def command(self, command: str):
        arguments = [str(self.executor / "scripts/github_hosted_ci_receipt.py"), command]
        if command == "capture":
            arguments.extend(("--run-id", str(RUN_ID)))
        with (
            patch.object(sys, "argv", arguments),
            patch.object(hosted, "__file__", arguments[0]),
            patch("scripts.release_python_runtime.require_closed_release_runtime"),
            patch.object(hosted, "capture_frozen_release_sources", return_value=self.sources) as capture,
            patch.object(hosted, "require_frozen_sources_unchanged", side_effect=self.unchanged),
            patch.object(candidate_freeze, "production_embedded_verifier_session", self.embedded_session),
            patch.object(candidate_freeze, "verify_frozen_candidate") as freeze,
            patch.object(hosted, "_source_binding", side_effect=self.source_binding),
            patch.object(hosted, "_fetch_api_json", side_effect=StableAPI()),
            redirect_stdout(self.output),
        ):
            yield freeze
        capture.assert_called_once_with(self.executor)

    def test_capture_and_verify_each_replay_four_times_in_one_closed_artifact_session(self) -> None:
        previous_callback = None
        for command in ("capture", "verify"):
            self.output.truncate(0)
            self.output.seek(0)
            self.events.clear()
            self.callbacks.clear()
            with self.subTest(command=command), self.command(command) as freeze:
                hosted.main()
                self.assertEqual(freeze.call_count, 4)
                self.assertEqual(
                    [call.args for call in freeze.call_args_list],
                    [(self.repository,)] * 4,
                )
            self.assertEqual(
                self.events,
                ["session-open", *(["reopen"] * 4), "session-close", "sources-unchanged"],
            )
            self.assertTrue(all(callback is self.callbacks[0] for callback in self.callbacks))
            self.assertIsNot(self.callbacks[0], previous_callback)
            previous_callback = self.callbacks[0]
            with self.assertRaises(candidate_freeze.CandidateFreezeError) as closed:
                previous_callback(self.repository)
            self.assertEqual(closed.exception.code, "verifier_session_closed")
            self.assertIn(f"run={RUN_ID}", self.output.getvalue())
        self.assertTrue(self.output_path.is_file())
        self.assertFalse((self.executor / hosted.RECEIPT_RELATIVE).exists())

    def test_foreign_artifact_path_is_rejected_before_freeze_or_publication(self) -> None:
        self.replay_repository = self.executor
        with self.command("capture") as freeze, self.assertRaises(SystemExit) as rejected:
            hosted.main()
        self.assertIsInstance(rejected.exception.__cause__, candidate_freeze.CandidateFreezeError)
        self.assertEqual(rejected.exception.__cause__.code, "verifier_session_repository_mismatch")
        freeze.assert_not_called()
        self.assertFalse(self.output_path.exists())
        self.assertEqual(self.output.getvalue(), "")

    def test_session_close_failure_preserves_receipt_without_success(self) -> None:
        self.close_error = OSError("private verifier cleanup failed")
        with self.command("capture"), self.assertRaises(SystemExit) as rejected:
            hosted.main()
        self.assertIs(rejected.exception.__cause__, self.close_error)
        self.assertTrue(self.output_path.is_file())
        self.assertEqual(self.events[-1], "session-close")
        self.assertEqual(self.output.getvalue(), "")

    def test_source_drift_after_session_close_preserves_receipt_without_success(self) -> None:
        self.source_error = PublicationError("executor source changed")
        with self.command("capture"), self.assertRaises(SystemExit) as rejected:
            hosted.main()
        self.assertIs(rejected.exception.__cause__, self.source_error)
        self.assertTrue(self.output_path.is_file())
        self.assertEqual(self.events[-2:], ["session-close", "sources-unchanged"])
        self.assertEqual(self.output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
