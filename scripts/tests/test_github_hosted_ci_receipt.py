from __future__ import annotations

import copy
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import github_hosted_ci_receipt as hosted
from scripts.publication.common import PublicationError


RUN_ID = 90_012_345_678
CHECK_SUITE_ID = 80_012_345_678
HEAD_SHA = "a" * 40
SOURCE = {
    "candidate_freeze_intent_sha256": "b" * 64,
    "release_source_sha256": "c" * 64,
    "repository_commit": HEAD_SHA,
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
        check_runs: dict[str, object] | None = None,
        annotations: dict[int, list[dict[str, object]]] | None = None,
    ) -> None:
        self.run = run or run_response()
        self.jobs = jobs or jobs_response()
        self.check_runs = check_runs or check_runs_response(self.jobs)
        self.annotations = annotations or {}
        self.paths: list[str] = []

    def __call__(self, path: str):
        self.paths.append(path)
        if path == hosted._run_api_path(RUN_ID):
            return copy.deepcopy(self.run)
        if path == hosted._jobs_api_path(RUN_ID, int(self.run["run_attempt"])):
            return copy.deepcopy(self.jobs)
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
            receipt = hosted._live_receipt(dict(SOURCE), RUN_ID)
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
        responses = [run, jobs, before, [], [], [], run, after]
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
                document="cfw-github-hosted-ci-receipt-v1"
            ),
            lambda receipt: receipt.update(schema_version=1),
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


if __name__ == "__main__":
    unittest.main()
