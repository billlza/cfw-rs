from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import ANY, patch

from scripts.audit_cargo_policy import (
    POLICY_CONFIG_NAMES,
    RENDERED_RECORD_LIMIT,
    RENDERED_RECORD_TEXT_LIMIT,
    CargoPolicyError,
    _require_policy_config,
    _require_success,
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
