from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import ANY, patch

from scripts.audit_cargo_policy import (
    ONLINE_POLICY_ATTEMPTS,
    ONLINE_POLICY_RETRY_PAUSE_SECONDS,
    ONLINE_POLICY_TIMEOUT_SECONDS,
    POLICY_CONFIG_NAMES,
    RENDERED_RECORD_LIMIT,
    RENDERED_RECORD_TEXT_LIMIT,
    TRIGGER_RENDER_LIMIT,
    CargoPolicyError,
    _require_policy_config,
    _require_success,
    _transient_fetch_failure,
    main,
    parse_policy_result,
    run,
)
from scripts.publication.rust_targets import MACOS_TARGET, SHIPPED_TARGETS, WINDOWS_TARGET

REPOSITORY = Path(__file__).resolve().parents[2]


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


def policy_config(target: str) -> str:
    return (
        f'[graph]\ntargets = ["{target}"]\nall-features = true\n\n'
        '[advisories]\nyanked = "deny"\ndisable-yank-checking = false\n'
    )


def closed_policy_fixture(root: Path) -> tuple[Path, dict[str, str]]:
    """Lay out the repository, release home and closed Cargo home run() needs."""

    repository = root / "repository"
    release_home = root / "release-home"
    closed_cargo_home = root / "closed-cargo-home"
    policy_parent = release_home / ".cfm-release-tooling"
    for directory in (repository, release_home, closed_cargo_home, policy_parent):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
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
    return repository, environment


def recorded_policy_calls():
    """A bounded-process stand-in answering metadata, then two clean summaries."""

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

    return calls, completed


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


class _Execution:
    """One run() against scripted cargo-deny results for the online phase."""

    def __init__(
        self,
        root: Path,
        online: list[tuple[int, bytes]],
        *,
        online_elapsed: float = 0.0,
    ) -> None:
        self.repository, self.environment = closed_policy_fixture(root)
        self.release_home = Path(self.environment["HOME"])
        (self.repository / "deny.toml").write_text(
            policy_config(MACOS_TARGET), encoding="utf-8"
        )
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
        buffer = io.StringIO()
        with patch.dict(os.environ, self.environment, clear=True), patch(
            "scripts.audit_cargo_policy.run_bounded_process",
            side_effect=self._completed,
        ), patch("scripts.audit_cargo_policy.time", self.clock), contextlib.redirect_stdout(
            buffer
        ):
            try:
                self.result = run(self.repository, MACOS_TARGET)
            except CargoPolicyError as error:
                self.error = error
        self.stdout = buffer.getvalue()
        return self

    @property
    def online_calls(self) -> list[dict[str, object]]:
        return self.calls[2:]


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
        with self.assertRaisesRegex(
            CargoPolicyError,
            r"cargo-deny advisories check emitted 2 records instead of one summary:\n"
            r"  log ERROR: fetch failed\n"
            r'  summary: \{"advisories": \{"errors": 0, "helps": 0, "notes": 0, '
            r'"warnings": 0\}\}$',
        ):
            parse_policy_result(
                diagnostic + b"\n" + summary(("advisories",)),
                ("advisories",),
            )

    def test_failure_names_the_live_yank_check_records(self) -> None:
        """A hosted failure must say which crate and registry query failed."""

        records = [
            {
                "fields": {
                    "level": "WARN",
                    "message": "unable to open local crates.io index",
                    "timestamp": "2026-10-26T12:18:40Z",
                },
                "type": "log",
            },
            {
                "fields": {
                    "code": "index-failure",
                    "graphs": [{"Krate": {"name": "winreg", "version": "0.56.0"}}],
                    "labels": [
                        {
                            "column": 1,
                            "line": 1,
                            "message": "crate whose registry we failed to query",
                            "span": "winreg 0.56.0",
                        }
                    ],
                    "message": "unable to check for yanked crates",
                    "notes": ["connection timed out"],
                    "severity": "warning",
                },
                "type": "diagnostic",
            },
        ]
        encoded = b"".join(json.dumps(record).encode() + b"\n" for record in records)
        with self.assertRaisesRegex(
            CargoPolicyError,
            r"cargo-deny advisories check emitted 3 records instead of one summary:\n"
            r"  log WARN: unable to open local crates.io index\n"
            r"  warning index-failure: unable to check for yanked crates; "
            r"crate whose registry we failed to query \(winreg 0.56.0\); "
            r"connection timed out\n"
            r"  summary: ",
        ):
            parse_policy_result(encoded + summary(("advisories",)), ("advisories",))

    def test_failure_rendering_is_bounded_per_record_and_in_count(self) -> None:
        diagnostic = json.dumps(
            {
                "fields": {
                    "code": "license-not-encountered",
                    "message": "x" * (RENDERED_RECORD_TEXT_LIMIT + 50),
                    "severity": "warning",
                },
                "type": "diagnostic",
            }
        ).encode()
        encoded = (diagnostic + b"\n") * 30 + summary(("bans", "licenses", "sources"))
        with self.assertRaises(CargoPolicyError) as raised:
            parse_policy_result(encoded, ("bans", "licenses", "sources"))
        lines = str(raised.exception).split("\n")
        self.assertEqual(
            lines[0],
            "cargo-deny bans/licenses/sources check emitted 31 records instead of one summary:",
        )
        self.assertEqual(len(lines), RENDERED_RECORD_LIMIT + 2)
        for line in lines[1 : RENDERED_RECORD_LIMIT + 1]:
            self.assertTrue(line.startswith("  warning license-not-encountered: xxx"))
            self.assertTrue(line.endswith(" [cut]"))
            self.assertEqual(len(line), 2 + RENDERED_RECORD_TEXT_LIMIT + len(" [cut]"))
        self.assertEqual(lines[-1], f"  {31 - RENDERED_RECORD_LIMIT} more records not shown")

    def test_failure_rendering_survives_malformed_records(self) -> None:
        encoded = b"\n".join(
            [
                b"[]",
                b'"text"',
                b'{"fields": "oops", "type": "diagnostic"}',
                b'{"fields": {"a": 1}, "type": "mystery"}',
                summary(("advisories",)),
            ]
        )
        with self.assertRaisesRegex(
            CargoPolicyError,
            r"emitted 5 records instead of one summary:\n"
            r"  malformed record: \[\]\n"
            r'  malformed record: "text"\n'
            r'  malformed record: \{"fields": "oops", "type": "diagnostic"\}\n'
            r'  mystery: \{"a": 1\}\n'
            r"  summary: ",
        ):
            parse_policy_result(encoded, ("advisories",))

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


class CargoPolicyExecutionTests(unittest.TestCase):
    def test_policy_config_requires_exact_target_and_live_yanked_checks(self) -> None:
        valid = policy_config(MACOS_TARGET)
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
            _require_policy_config(config_path, MACOS_TARGET)
            with self.assertRaisesRegex(
                CargoPolicyError, f"deny.toml must select exactly the {WINDOWS_TARGET}"
            ):
                _require_policy_config(config_path, WINDOWS_TARGET)
            for label, invalid in replacements.items():
                with self.subTest(label=label):
                    config_path.write_text(invalid, encoding="utf-8")
                    with self.assertRaises(CargoPolicyError):
                        _require_policy_config(config_path, MACOS_TARGET)

    def test_execution_separates_closed_and_live_policy_environments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, environment = closed_policy_fixture(Path(temporary).resolve())
            (repository / "deny.toml").write_text(
                policy_config(MACOS_TARGET), encoding="utf-8"
            )
            calls, completed = recorded_policy_calls()
            with patch.dict(os.environ, environment, clear=True), patch(
                "scripts.audit_cargo_policy.run_bounded_process", side_effect=completed
            ):
                self.assertEqual(run(repository, MACOS_TARGET), 0)

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
            self.assertEqual(metadata_environment["CARGO_HOME"], environment["CARGO_HOME"])
            self.assertEqual(metadata_environment["CARGO_NET_OFFLINE"], "true")

            offline_command, offline_environment = calls[1]
            self.assertEqual(
                offline_command[-4:], ["check", "bans", "licenses", "sources"]
            )
            self.assertEqual(
                offline_command[offline_command.index("--config") + 1],
                str(repository / "deny.toml"),
            )
            self.assertEqual(
                offline_command[offline_command.index("--target") + 1], MACOS_TARGET
            )
            self.assertEqual(offline_environment["CARGO_HOME"], environment["CARGO_HOME"])
            self.assertEqual(offline_environment["CARGO_NET_OFFLINE"], "true")

            online_command, online_environment = calls[2]
            self.assertEqual(online_command[-2:], ["check", "advisories"])
            self.assertEqual(online_environment["CARGO"], "/usr/bin/true")
            self.assertEqual(online_environment["CARGO_NET_OFFLINE"], "false")
            self.assertNotEqual(online_environment["CARGO_HOME"], environment["CARGO_HOME"])
            self.assertNotIn("CARGO_TARGET_DIR", online_environment)

    def test_windows_target_enforces_the_windows_policy_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, environment = closed_policy_fixture(Path(temporary).resolve())
            (repository / "deny.toml").write_text(
                policy_config(MACOS_TARGET), encoding="utf-8"
            )
            windows_policy = repository / POLICY_CONFIG_NAMES[WINDOWS_TARGET]
            calls, completed = recorded_policy_calls()
            with patch.dict(os.environ, environment, clear=True), patch(
                "scripts.audit_cargo_policy.run_bounded_process", side_effect=completed
            ):
                with self.assertRaisesRegex(
                    CargoPolicyError, "deny.x86_64-pc-windows-msvc.toml is unavailable"
                ):
                    run(repository, WINDOWS_TARGET)
                windows_policy.write_text(policy_config(MACOS_TARGET), encoding="utf-8")
                with self.assertRaisesRegex(
                    CargoPolicyError, f"must select exactly the {WINDOWS_TARGET}"
                ):
                    run(repository, WINDOWS_TARGET)
                self.assertEqual(calls, [])
                windows_policy.write_text(policy_config(WINDOWS_TARGET), encoding="utf-8")
                self.assertEqual(run(repository, WINDOWS_TARGET), 0)

            self.assertEqual(len(calls), 3)
            metadata_command, _ = calls[0]
            self.assertEqual(
                metadata_command[metadata_command.index("--filter-platform") + 1],
                WINDOWS_TARGET,
            )
            for command, _ in calls[1:]:
                self.assertEqual(
                    command[command.index("--config") + 1], str(windows_policy)
                )
                self.assertEqual(command[command.index("--target") + 1], WINDOWS_TARGET)

    def test_unsupported_target_is_refused_before_any_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, environment = closed_policy_fixture(Path(temporary).resolve())
            calls, completed = recorded_policy_calls()
            with patch.dict(os.environ, environment, clear=True), patch(
                "scripts.audit_cargo_policy.run_bounded_process", side_effect=completed
            ), self.assertRaisesRegex(CargoPolicyError, "unsupported shipped Rust target"):
                run(repository, "x86_64-unknown-linux-gnu")
            self.assertEqual(calls, [])


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



class CargoPolicyCommandLineTests(unittest.TestCase):
    def test_default_and_explicit_targets_reach_run(self) -> None:
        for argv, expected in (([], MACOS_TARGET), (["--target", WINDOWS_TARGET], WINDOWS_TARGET)):
            with self.subTest(argv=argv), patch(
                "scripts.audit_cargo_policy.run", return_value=0
            ) as run_mock, patch(
                "sys.argv", ["audit_cargo_policy.py", *argv]
            ), self.assertRaises(SystemExit) as exit_context:
                main()
            self.assertEqual(exit_context.exception.code, 0)
            run_mock.assert_called_once_with(ANY, expected)

    def test_unknown_target_is_rejected_at_the_command_line(self) -> None:
        with patch("scripts.audit_cargo_policy.run") as run_mock, patch(
            "sys.argv", ["audit_cargo_policy.py", "--target", "x86_64-unknown-linux-gnu"]
        ), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
            SystemExit
        ) as exit_context:
            main()
        self.assertEqual(exit_context.exception.code, 2)
        run_mock.assert_not_called()


class ShippedPolicyConfigTests(unittest.TestCase):
    def test_each_program_has_a_policy_naming_its_own_graph(self) -> None:
        self.assertEqual(set(POLICY_CONFIG_NAMES), set(SHIPPED_TARGETS))
        for target in SHIPPED_TARGETS:
            with self.subTest(target=target):
                _require_policy_config(REPOSITORY / POLICY_CONFIG_NAMES[target], target)

    def test_programs_share_every_rule_except_the_license_allowance(self) -> None:
        policies = {}
        for target in SHIPPED_TARGETS:
            with (REPOSITORY / POLICY_CONFIG_NAMES[target]).open("rb") as handle:
                policies[target] = tomllib.load(handle)
        macos = policies[MACOS_TARGET]
        windows = policies[WINDOWS_TARGET]
        self.assertEqual(
            set(macos), {"graph", "advisories", "licenses", "bans", "sources"}
        )
        self.assertEqual(set(windows), set(macos))
        for section in ("advisories", "bans", "sources"):
            with self.subTest(section=section):
                self.assertEqual(windows[section], macos[section])
        self.assertEqual(windows["graph"]["all-features"], macos["graph"]["all-features"])
        self.assertEqual(set(windows["licenses"]), set(macos["licenses"]))
        self.assertEqual(
            windows["licenses"]["confidence-threshold"],
            macos["licenses"]["confidence-threshold"],
        )
        for target, policy in policies.items():
            with self.subTest(target=target):
                allowance = policy["licenses"]["allow"]
                self.assertEqual(allowance, sorted(set(allowance)))


if __name__ == "__main__":
    unittest.main()
