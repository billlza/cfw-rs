from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.audit_cargo_policy import (
    CargoPolicyError,
    _require_policy_config,
    _require_success,
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


class CargoPolicyExecutionTests(unittest.TestCase):
    def test_policy_config_requires_exact_target_and_live_yanked_checks(self) -> None:
        valid = (
            '[graph]\ntargets = ["aarch64-apple-darwin"]\nall-features = true\n\n'
            '[advisories]\nyanked = "deny"\ndisable-yank-checking = false\n'
        )
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


if __name__ == "__main__":
    unittest.main()
