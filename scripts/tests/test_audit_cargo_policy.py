from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.audit_cargo_policy import (
    ONLINE_POLICY_ATTEMPTS,
    ONLINE_POLICY_RETRY_PAUSE_SECONDS,
    ONLINE_POLICY_TIMEOUT_SECONDS,
    TRIGGER_RENDER_LIMIT,
    CargoPolicyError,
    _require_policy_config,
    _require_success,
    _transient_fetch_failure,
    parse_policy_result,
    run,
)


def summary(
    names: tuple[str, ...] = ("advisories", "bans", "licenses", "sources"),
    **overrides: dict[str, int],
) -> bytes:
    fields = {
        name: {"errors": 0, "helps": 0, "notes": 0, "warnings": 0}
        for name in names
    }
    fields.update(overrides)
    return (json.dumps({"fields": fields, "type": "summary"}) + "\n").encode()


def log_record(level: str, message: str) -> bytes:
    record = {
        "fields": {
            "level": level,
            "message": message,
            "timestamp": "2026-10-26T21:50:35.69577Z",
        },
        "type": "log",
    }
    return (json.dumps(record) + "\n").encode()


def diagnostic_record(code: str, severity: str, message: str) -> bytes:
    record = {
        "fields": {
            "code": code,
            "graphs": [],
            "labels": [],
            "message": message,
            "notes": [],
            "severity": severity,
        },
        "type": "diagnostic",
    }
    return (json.dumps(record) + "\n").encode()


# Shapes recorded from cargo-deny 0.20.2 on 2026-10-26: the advisory database
# clone that could not reach github.com (exit status 1, one ERROR log record)
# and the crates fetch failure (exit status 0, one ERROR log record, one
# index-failure warning per crate and a summary that counts the warnings).
ADVISORY_DATABASE_FETCH_FAILURE = log_record(
    "ERROR",
    "failed to fetch advisory database https://github.com/RustSec/advisory-db"
    ' with cli: failed to clone: ["clone", "--depth=1", "--branch", "main",'
    ' "https://github.com/RustSec/advisory-db", "/runner/cargo-home/advisory-dbs'
    '/advisory-db-3157b0e258782691"]\nCloning into \'/runner/cargo-home/advisory-dbs'
    "/advisory-db-3157b0e258782691'...\nfatal: unable to access"
    " 'https://github.com/RustSec/advisory-db/': Failed to connect to github.com"
    " port 443 after 8093 ms: Couldn't connect to server\n",
)
CRATES_FETCH_FAILURE = (
    log_record(
        "ERROR",
        "failed to fetch crates: error: failed to get `base64` as a dependency of"
        " package `cfw-tauri-shell`\n",
    )
    + diagnostic_record("index-failure", "warning", "unable to check for yanked crates")
    + diagnostic_record("index-failure", "warning", "unable to check for yanked crates")
    + summary(
        ("advisories",),
        advisories={"errors": 0, "helps": 0, "notes": 0, "warnings": 2},
    )
)
VULNERABILITY_FINDING = diagnostic_record(
    "vulnerability", "error", "security vulnerability detected"
) + summary(
    ("advisories",),
    advisories={"errors": 1, "helps": 0, "notes": 0, "warnings": 0},
)
CLEAN_ADVISORIES = summary(("advisories",))


class CargoPolicyResultTests(unittest.TestCase):
    def test_accepts_one_warning_free_summary(self) -> None:
        parsed = parse_policy_result(
            summary(
                ("bans", "licenses", "sources"),
                licenses={"errors": 0, "helps": 12, "notes": 0, "warnings": 0},
            ),
            ("bans", "licenses", "sources"),
        )
        self.assertEqual(parsed["licenses"]["helps"], 12)

    def test_rejects_a_diagnostic_even_when_the_summary_is_clean(self) -> None:
        diagnostic = json.dumps(
            {"fields": {"level": "ERROR", "message": "fetch failed"}, "type": "log"}
        ).encode()
        with self.assertRaisesRegex(CargoPolicyError, "emitted diagnostics"):
            parse_policy_result(
                diagnostic + b"\n" + summary(("advisories",)),
                ("advisories",),
            )

    def test_rejects_warning_note_and_error_counts(self) -> None:
        for stat_name in ("warnings", "notes", "errors"):
            values = {"errors": 0, "helps": 0, "notes": 0, "warnings": 0}
            values[stat_name] = 1
            with self.subTest(stat_name=stat_name), self.assertRaisesRegex(
                CargoPolicyError, "reported"
            ):
                parse_policy_result(
                    summary(("advisories",), advisories=values),
                    ("advisories",),
                )

    def test_rejects_duplicate_fields_and_boolean_counts(self) -> None:
        with self.assertRaisesRegex(CargoPolicyError, "strict UTF-8 JSON"):
            parse_policy_result(b'{"type":"summary","type":"summary"}\n', ("advisories",))
        malformed = {
            "advisories": {"errors": 0, "helps": 0, "notes": 0, "warnings": 0}
        }
        malformed["advisories"]["warnings"] = False
        with self.assertRaisesRegex(CargoPolicyError, "non-negative integer"):
            parse_policy_result(
                (json.dumps({"fields": malformed, "type": "summary"}) + "\n").encode(),
                ("advisories",),
            )

    def test_nonzero_result_preserves_the_bounded_diagnostic(self) -> None:
        result = subprocess.CompletedProcess(
            ["cargo-deny"], 7, b"", b"registry unavailable\n"
        )
        with self.assertRaisesRegex(
            CargoPolicyError, "status 7: registry unavailable"
        ):
            _require_success(result, "online cargo-deny policy")


class TransientFetchFailureTests(unittest.TestCase):
    def test_names_the_advisory_database_fetch_failure(self) -> None:
        trigger = _transient_fetch_failure(ADVISORY_DATABASE_FETCH_FAILURE)
        self.assertIsNotNone(trigger)
        self.assertTrue(
            trigger.startswith(
                "log ERROR: failed to fetch advisory database"
                " https://github.com/RustSec/advisory-db with cli"
            ),
            trigger,
        )
        self.assertIn("Couldn't connect to server", trigger)
        self.assertNotIn("\n", trigger)

    def test_names_the_crates_fetch_failure_with_its_yank_diagnostics(self) -> None:
        trigger = _transient_fetch_failure(CRATES_FETCH_FAILURE)
        self.assertIsNotNone(trigger)
        self.assertTrue(trigger.startswith("log ERROR: failed to fetch crates: "), trigger)
        only_diagnostics = diagnostic_record(
            "index-failure", "warning", "unable to check for yanked crates"
        ) + summary(
            ("advisories",),
            advisories={"errors": 0, "helps": 0, "notes": 0, "warnings": 1},
        )
        self.assertEqual(
            _transient_fetch_failure(only_diagnostics),
            "diagnostic warning index-failure: unable to check for yanked crates",
        )

    def test_everything_else_is_not_a_reason_to_retry(self) -> None:
        cases = {
            "clean summary": CLEAN_ADVISORIES,
            "empty output": b"",
            "policy finding": VULNERABILITY_FINDING,
            "fetch failure beside a finding": (
                ADVISORY_DATABASE_FETCH_FAILURE + VULNERABILITY_FINDING
            ),
            "yank diagnostics beside a yanked crate": (
                diagnostic_record("index-failure", "warning", "unable to check for yanked crates")
                + diagnostic_record("yanked", "error", "detected yanked crate")
                + summary(("advisories",))
            ),
            "index cache load failure": diagnostic_record(
                "index-cache-load-failure", "error", "failed to load index cache"
            ),
            "warning-level fetch log": log_record(
                "WARN", "failed to fetch crates: slow registry"
            ),
            "other error log": log_record(
                "ERROR", "unable to acquire cargo global package lock: timed out"
            ),
            "log without a message": b'{"fields":{"level":"ERROR"},"type":"log"}\n',
            "unknown record": b'{"fields":{},"type":"sarif"}\n',
            "non-object record": b'["log"]\n',
            "malformed line": b"{not json\n",
        }
        for label, encoded in cases.items():
            with self.subTest(label=label):
                self.assertIsNone(_transient_fetch_failure(encoded))

    def test_renders_the_first_trigger_within_a_fixed_width(self) -> None:
        long_message = "failed to fetch crates: " + "x" * 1000
        trigger = _transient_fetch_failure(
            log_record("ERROR", long_message)
            + diagnostic_record("index-failure", "warning", "unable to check for yanked crates")
        )
        self.assertIsNotNone(trigger)
        self.assertTrue(trigger.startswith("log ERROR: failed to fetch crates: xxx"), trigger)
        self.assertEqual(len(trigger), TRIGGER_RENDER_LIMIT)


class _Clock:
    """Deterministic stand-in for the module's time: no real waiting."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


VALID_POLICY = (
    '[graph]\ntargets = ["aarch64-apple-darwin"]\nall-features = true\n\n'
    '[advisories]\nyanked = "deny"\ndisable-yank-checking = false\n'
)


class _Execution:
    """One run() against scripted cargo-deny results for the online phase."""

    def __init__(
        self,
        root: Path,
        online: list[tuple[int, bytes]],
        *,
        online_elapsed: float = 0.0,
    ) -> None:
        self.repository = root / "repository"
        self.release_home = root / "release-home"
        self.closed_cargo_home = root / "closed-cargo-home"
        for directory in (
            self.repository,
            self.release_home,
            self.closed_cargo_home,
            self.release_home / ".cfm-release-tooling",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
        (self.repository / "deny.toml").write_text(VALID_POLICY, encoding="utf-8")
        self.online = online
        self.online_elapsed = online_elapsed
        self.clock = _Clock()
        self.calls: list[dict[str, object]] = []
        self.stdout = ""
        self.result: int | None = None
        self.error: CargoPolicyError | None = None

    def _completed(self, command, *, cwd, environment, timeout, output_limit):
        cargo_home = Path(environment["CARGO_HOME"])
        self.calls.append(
            {
                "command": list(command),
                "environment": dict(environment),
                "timeout": timeout,
                "cargo_home_mode": stat.S_IMODE(cargo_home.lstat().st_mode),
                "cargo_home_is_dir": cargo_home.is_dir() and not cargo_home.is_symlink(),
            }
        )
        index = len(self.calls)
        if index == 1:
            metadata = json.dumps(
                {"packages": [], "resolve": {"nodes": []}, "workspace_members": []}
            ).encode()
            return subprocess.CompletedProcess(command, 0, metadata, b"")
        if index == 2:
            return subprocess.CompletedProcess(
                command, 0, summary(("bans", "licenses", "sources")), b""
            )
        online_index = index - 3
        if online_index >= len(self.online):
            raise AssertionError("cargo-deny ran more often than scripted")
        self.clock.now += self.online_elapsed
        status, records = self.online[online_index]
        # cargo-deny writes every JSON record to stderr.
        return subprocess.CompletedProcess(command, status, b"", records)

    def execute(self) -> "_Execution":
        environment = {
            "CARGO_HOME": str(self.closed_cargo_home),
            "CARGO_NET_OFFLINE": "true",
            "CFW_RELEASE_CARGO_EXECUTABLE": "/usr/bin/true",
            "CFW_RELEASE_CARGO_DENY_EXECUTABLE": "/usr/bin/false",
            "HOME": str(self.release_home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }
        buffer = io.StringIO()
        with patch.dict(os.environ, environment, clear=True), patch(
            "scripts.audit_cargo_policy.run_bounded_process",
            side_effect=self._completed,
        ), patch("scripts.audit_cargo_policy.time", self.clock), contextlib.redirect_stdout(
            buffer
        ):
            try:
                self.result = run(self.repository)
            except CargoPolicyError as error:
                self.error = error
        self.stdout = buffer.getvalue()
        return self

    @property
    def online_calls(self) -> list[dict[str, object]]:
        return self.calls[2:]


class CargoPolicyExecutionTests(unittest.TestCase):
    def test_policy_config_requires_exact_target_and_live_yanked_checks(self) -> None:
        valid = VALID_POLICY
        replacements = {
            "wrong target": valid.replace(
                'targets = ["aarch64-apple-darwin"]',
                'targets = ["x86_64-apple-darwin"]',
            ),
            "default features": valid.replace(
                "all-features = true", "all-features = false"
            ),
            "warn yanked": valid.replace('yanked = "deny"', 'yanked = "warn"'),
            "disabled yanked": valid.replace(
                "disable-yank-checking = false", "disable-yank-checking = true"
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "deny.toml"
            config_path.write_text(valid, encoding="utf-8")
            _require_policy_config(config_path)
            for label, invalid in replacements.items():
                with self.subTest(label=label):
                    config_path.write_text(invalid, encoding="utf-8")
                    with self.assertRaises(CargoPolicyError):
                        _require_policy_config(config_path)

    def test_execution_separates_closed_and_live_policy_environments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = root / "repository"
            release_home = root / "release-home"
            closed_cargo_home = root / "closed-cargo-home"
            policy_parent = release_home / ".cfm-release-tooling"
            for directory in (
                repository,
                release_home,
                closed_cargo_home,
                policy_parent,
            ):
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                directory.chmod(0o700)
            (repository / "deny.toml").write_text(
                '[graph]\ntargets = ["aarch64-apple-darwin"]\n'
                'all-features = true\n\n[advisories]\nyanked = "deny"\n'
                "disable-yank-checking = false\n",
                encoding="utf-8",
            )

            metadata = json.dumps(
                {"packages": [], "resolve": {"nodes": []}, "workspace_members": []}
            ).encode()
            calls: list[tuple[list[str], dict[str, str]]] = []

            def completed(command, *, cwd, environment, timeout, output_limit):
                calls.append((list(command), dict(environment)))
                if len(calls) == 1:
                    return subprocess.CompletedProcess(command, 0, metadata, b"")
                if len(calls) == 2:
                    output = summary(("bans", "licenses", "sources"))
                else:
                    output = summary(("advisories",))
                return subprocess.CompletedProcess(command, 0, output, b"")

            environment = {
                "CARGO_HOME": str(closed_cargo_home),
                "CARGO_NET_OFFLINE": "true",
                "CFW_RELEASE_CARGO_EXECUTABLE": "/usr/bin/true",
                "CFW_RELEASE_CARGO_DENY_EXECUTABLE": "/usr/bin/false",
                "HOME": str(release_home),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            }
            with patch.dict(os.environ, environment, clear=True), patch(
                "scripts.audit_cargo_policy.run_bounded_process", side_effect=completed
            ):
                self.assertEqual(run(repository), 0)

            self.assertEqual(len(calls), 3)
            metadata_command, metadata_environment = calls[0]
            self.assertEqual(
                metadata_command,
                [
                    "/usr/bin/true",
                    "metadata",
                    "--locked",
                    "--all-features",
                    "--filter-platform",
                    "aarch64-apple-darwin",
                    "--format-version",
                    "1",
                ],
            )
            self.assertEqual(metadata_environment["CARGO_HOME"], str(closed_cargo_home))
            self.assertEqual(metadata_environment["CARGO_NET_OFFLINE"], "true")

            offline_command, offline_environment = calls[1]
            self.assertEqual(
                offline_command[-4:], ["check", "bans", "licenses", "sources"]
            )
            self.assertEqual(offline_environment["CARGO_HOME"], str(closed_cargo_home))
            self.assertEqual(offline_environment["CARGO_NET_OFFLINE"], "true")

            online_command, online_environment = calls[2]
            self.assertEqual(online_command[-2:], ["check", "advisories"])
            self.assertEqual(online_environment["CARGO"], "/usr/bin/true")
            self.assertEqual(online_environment["CARGO_NET_OFFLINE"], "false")
            self.assertNotEqual(
                online_environment["CARGO_HOME"], str(closed_cargo_home)
            )
            self.assertNotIn("CARGO_TARGET_DIR", online_environment)

    def test_online_phase_retries_once_after_the_advisory_database_fetch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            execution = _Execution(
                Path(temporary).resolve(),
                [(1, ADVISORY_DATABASE_FETCH_FAILURE), (0, CLEAN_ADVISORIES)],
                online_elapsed=12.0,
            ).execute()
            policy_parent = (
                execution.release_home / ".cfm-release-tooling" / "cargo-policy-checks"
            )
            self.assertIsNone(execution.error)
            self.assertEqual(execution.result, 0)
            self.assertEqual(len(execution.calls), 4)
            first, second = execution.online_calls
            self.assertEqual(first["command"], second["command"])
            self.assertEqual(first["command"][-2:], ["check", "advisories"])
            homes = [Path(call["environment"]["CARGO_HOME"]) for call in (first, second)]
            self.assertNotEqual(homes[0], homes[1])
            self.assertEqual([home.name for home in homes], ["cargo-home-1", "cargo-home-2"])
            self.assertEqual(homes[0].parent, homes[1].parent)
            self.assertEqual(homes[0].parent.parent, policy_parent)
            for call in (first, second):
                self.assertTrue(call["cargo_home_is_dir"])
                self.assertEqual(call["cargo_home_mode"], 0o700)
                self.assertEqual(call["environment"]["CARGO_NET_OFFLINE"], "false")
                self.assertEqual(
                    call["environment"]["HOME"], first["environment"]["HOME"]
                )
            self.assertEqual(first["timeout"], ONLINE_POLICY_TIMEOUT_SECONDS)
            self.assertEqual(
                second["timeout"],
                ONLINE_POLICY_TIMEOUT_SECONDS - 12.0 - ONLINE_POLICY_RETRY_PAUSE_SECONDS,
            )
            self.assertEqual(execution.clock.sleeps, [ONLINE_POLICY_RETRY_PAUSE_SECONDS])
            lines = execution.stdout.splitlines()
            self.assertEqual(len(lines), 2, execution.stdout)
            self.assertTrue(
                lines[0].startswith(
                    f"online cargo-deny advisory policy attempt 1 of {ONLINE_POLICY_ATTEMPTS}"
                    " failed on a registry fetch; retrying in"
                    f" {ONLINE_POLICY_RETRY_PAUSE_SECONDS} s: log ERROR: failed to fetch"
                    " advisory database https://github.com/RustSec/advisory-db with cli"
                ),
                lines[0],
            )
            self.assertTrue(lines[1].startswith("cargo-deny policy passed: "), lines[1])

    def test_online_phase_retries_after_the_crates_fetch_fails_with_yank_diagnostics(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            execution = _Execution(
                Path(temporary).resolve(),
                [(0, CRATES_FETCH_FAILURE), (0, CLEAN_ADVISORIES)],
            ).execute()
            self.assertIsNone(execution.error)
            self.assertEqual(execution.result, 0)
            self.assertEqual(len(execution.calls), 4)
            self.assertEqual(execution.clock.sleeps, [ONLINE_POLICY_RETRY_PAUSE_SECONDS])
            self.assertIn(
                "attempt 1 of 3 failed on a registry fetch; retrying in 30 s:"
                " log ERROR: failed to fetch crates: error: failed to get `base64`",
                execution.stdout,
            )

    def test_online_phase_does_not_retry_a_policy_finding(self) -> None:
        cases = {
            "vulnerability": VULNERABILITY_FINDING,
            "fetch failure beside a finding": CRATES_FETCH_FAILURE + VULNERABILITY_FINDING,
        }
        for label, records in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                execution = _Execution(
                    Path(temporary).resolve(),
                    [(1, records), (0, CLEAN_ADVISORIES)],
                ).execute()
                self.assertIsNotNone(execution.error)
                self.assertRegex(
                    str(execution.error),
                    "online cargo-deny advisory policy failed with status 1",
                )
                self.assertEqual(len(execution.calls), 3)
                self.assertEqual(execution.clock.sleeps, [])
                self.assertEqual(execution.stdout, "")

    def test_online_phase_stops_after_the_fixed_number_of_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            execution = _Execution(
                Path(temporary).resolve(),
                [(1, ADVISORY_DATABASE_FETCH_FAILURE)] * ONLINE_POLICY_ATTEMPTS
                + [(0, CLEAN_ADVISORIES)],
            ).execute()
            self.assertIsNotNone(execution.error)
            self.assertRegex(
                str(execution.error),
                "online cargo-deny advisory policy failed with status 1: .*"
                "Couldn't connect to server",
            )
            self.assertEqual(len(execution.calls), 2 + ONLINE_POLICY_ATTEMPTS)
            self.assertEqual(
                execution.clock.sleeps,
                [ONLINE_POLICY_RETRY_PAUSE_SECONDS] * (ONLINE_POLICY_ATTEMPTS - 1),
            )
            self.assertEqual(
                [
                    Path(call["environment"]["CARGO_HOME"]).name
                    for call in execution.online_calls
                ],
                [f"cargo-home-{attempt}" for attempt in range(1, ONLINE_POLICY_ATTEMPTS + 1)],
            )
            self.assertIn(
                f"attempt {ONLINE_POLICY_ATTEMPTS - 1} of {ONLINE_POLICY_ATTEMPTS}",
                execution.stdout,
            )
            self.assertNotIn(f"attempt {ONLINE_POLICY_ATTEMPTS} of", execution.stdout)

    def test_online_phase_keeps_one_time_budget_across_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            execution = _Execution(
                Path(temporary).resolve(),
                [(1, ADVISORY_DATABASE_FETCH_FAILURE), (0, CLEAN_ADVISORIES)],
                online_elapsed=ONLINE_POLICY_TIMEOUT_SECONDS
                - ONLINE_POLICY_RETRY_PAUSE_SECONDS,
            ).execute()
            self.assertIsNotNone(execution.error)
            self.assertRegex(
                str(execution.error),
                "online cargo-deny advisory policy failed with status 1",
            )
            self.assertEqual(len(execution.calls), 3)
            self.assertEqual(execution.clock.sleeps, [])
            self.assertEqual(execution.online_calls[0]["timeout"], ONLINE_POLICY_TIMEOUT_SECONDS)
            self.assertIn(
                "attempt 1 of 3 failed on a registry fetch and no time budget remains"
                " for another attempt: log ERROR: failed to fetch advisory database",
                execution.stdout,
            )


if __name__ == "__main__":
    unittest.main()
