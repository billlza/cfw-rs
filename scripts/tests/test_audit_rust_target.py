from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.audit_rust_target import (
    AUDIT_TIMEOUT_SECONDS,
    AuditContractError,
    METADATA_TIMEOUT_SECONDS,
    OUTPUT_LIMIT_BYTES,
    parse_audit_result,
    reachable_package_ids,
    render_audit_lock,
    run,
    select_locked_packages,
    target_package_keys,
)
from scripts.publication.bounded_process import BoundedProcessError


def metadata_fixture() -> dict:
    return {
        "workspace_members": ["path+file:///repo#app@0.4.0"],
        "resolve": {
            "nodes": [
                {
                    "id": "path+file:///repo#app@0.4.0",
                    "deps": [
                        {
                            "name": "mac_only",
                            "pkg": "registry+https://example.invalid/index#mac-only@1.0.0",
                        }
                    ],
                },
                {
                    "id": "registry+https://example.invalid/index#mac-only@1.0.0",
                    "deps": [],
                },
            ]
        },
        "packages": [
            {
                "id": "path+file:///repo#app@0.4.0",
                "name": "app",
                "version": "0.4.0",
                "source": None,
            },
            {
                "id": "registry+https://example.invalid/index#mac-only@1.0.0",
                "name": "mac-only",
                "version": "1.0.0",
                "source": "registry+https://example.invalid/index",
            },
        ],
    }


class TargetAuditTests(unittest.TestCase):
    def test_reachable_graph_starts_at_every_workspace_member(self) -> None:
        self.assertEqual(
            reachable_package_ids(metadata_fixture()),
            {
                "path+file:///repo#app@0.4.0",
                "registry+https://example.invalid/index#mac-only@1.0.0",
            },
        )

    def test_target_inventory_excludes_non_resolved_platform_package(self) -> None:
        keys = target_package_keys(metadata_fixture())
        selected = select_locked_packages(
            {
                "version": 4,
                "package": [
                    {"name": "app", "version": "0.4.0"},
                    {
                        "name": "mac-only",
                        "version": "1.0.0",
                        "source": "registry+https://example.invalid/index",
                        "checksum": "abc",
                    },
                    {
                        "name": "linux-only",
                        "version": "1.0.0",
                        "source": "registry+https://example.invalid/index",
                        "checksum": "def",
                    },
                ],
            },
            keys,
        )
        self.assertEqual([package["name"] for package in selected], ["app", "mac-only"])
        rendered = render_audit_lock(selected, "aarch64-apple-darwin")
        self.assertNotIn("linux-only", rendered)
        self.assertNotIn("dependencies =", rendered)

    def test_missing_target_package_fails_closed(self) -> None:
        with self.assertRaisesRegex(AuditContractError, "absent from Cargo.lock"):
            select_locked_packages(
                {"version": 4, "package": [{"name": "app", "version": "0.4.0"}]},
                {("app", "0.4.0", None), ("missing", "1.0.0", None)},
            )

    def test_audit_result_rejects_warnings(self) -> None:
        with self.assertRaisesRegex(AuditContractError, "1 warning"):
            parse_audit_result(
                '{"lockfile":{"dependency-count":2},'
                '"vulnerabilities":{"count":0},'
                '"warnings":{"unmaintained":[{"package":"x"}]}}',
                2,
            )

    def test_audit_result_requires_complete_inventory(self) -> None:
        with self.assertRaisesRegex(AuditContractError, "complete target inventory"):
            parse_audit_result(
                '{"lockfile":{"dependency-count":1},'
                '"vulnerabilities":{"count":0},"warnings":{}}',
                2,
            )


class TargetAuditExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repository = Path(self.directory.name).resolve()
        (self.repository / "Cargo.lock").write_text(
            """version = 4

[[package]]
name = "app"
version = "0.4.0"

[[package]]
name = "mac-only"
version = "1.0.0"
source = "registry+https://example.invalid/index"
checksum = "abc"
""",
            encoding="utf-8",
        )
        self.metadata = json.dumps(metadata_fixture()).encode("utf-8")
        self.audit = json.dumps(
            {
                "lockfile": {"dependency-count": 2},
                "vulnerabilities": {"count": 0},
                "warnings": {},
            }
        ).encode("utf-8")
        self.environment = {
            "CFW_RELEASE_CARGO_EXECUTABLE": "/usr/bin/true",
            "CFW_RELEASE_CARGO_AUDIT_EXECUTABLE": "/usr/bin/false",
            "HOME": str(self.repository),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }

    def test_execution_is_bounded_warning_free_and_all_features(self) -> None:
        for no_fetch in (False, True):
            with self.subTest(no_fetch=no_fetch):
                calls = []

                def completed(command, *, cwd, environment, timeout, output_limit):
                    calls.append(
                        (list(command), cwd, dict(environment), timeout, output_limit)
                    )
                    stdout = self.metadata if len(calls) == 1 else self.audit
                    return subprocess.CompletedProcess(command, 0, stdout, b"")

                with patch.dict(os.environ, self.environment, clear=True), patch(
                    "scripts.audit_rust_target.run_bounded_process",
                    side_effect=completed,
                ):
                    self.assertEqual(run(self.repository, no_fetch=no_fetch), 0)

                self.assertEqual(len(calls), 2)
                metadata_command, metadata_cwd, _, metadata_timeout, metadata_limit = (
                    calls[0]
                )
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
                self.assertEqual(metadata_cwd, self.repository)
                self.assertEqual(metadata_timeout, METADATA_TIMEOUT_SECONDS)
                self.assertEqual(metadata_limit, OUTPUT_LIMIT_BYTES)
                audit_command, _, _, audit_timeout, audit_limit = calls[1]
                self.assertIn("--quiet", audit_command)
                self.assertIn("--no-yanked", audit_command)
                self.assertEqual("--no-fetch" in audit_command, no_fetch)
                self.assertEqual(audit_timeout, AUDIT_TIMEOUT_SECONDS)
                self.assertEqual(audit_limit, OUTPUT_LIMIT_BYTES)

    def test_successful_stderr_is_release_blocking(self) -> None:
        for failing_call in (1, 2):
            with self.subTest(failing_call=failing_call):
                calls = 0

                def completed(command, **_arguments):
                    nonlocal calls
                    calls += 1
                    stdout = self.metadata if calls == 1 else self.audit
                    stderr = b"warning: diagnostic\n" if calls == failing_call else b""
                    return subprocess.CompletedProcess(command, 0, stdout, stderr)

                with patch.dict(os.environ, self.environment, clear=True), patch(
                    "scripts.audit_rust_target.run_bounded_process",
                    side_effect=completed,
                ), self.assertRaisesRegex(AuditContractError, "emitted diagnostics"):
                    run(self.repository, no_fetch=True)

    def test_timeout_and_output_limit_are_typed_failures(self) -> None:
        for reason in ("timeout", "output-limit"):
            with self.subTest(reason=reason), patch.dict(
                os.environ, self.environment, clear=True
            ), patch(
                "scripts.audit_rust_target.run_bounded_process",
                side_effect=BoundedProcessError(
                    reason,
                    "bounded failure",
                    stderr=b"bounded diagnostic",
                ),
            ), self.assertRaisesRegex(
                AuditContractError, f"{reason} boundary: bounded diagnostic"
            ):
                run(self.repository, no_fetch=True)

    def test_nonzero_audit_preserves_bounded_diagnostic(self) -> None:
        results = (
            subprocess.CompletedProcess([], 0, self.metadata, b""),
            subprocess.CompletedProcess([], 7, b"", b"registry unavailable\n"),
        )
        with patch.dict(os.environ, self.environment, clear=True), patch(
            "scripts.audit_rust_target.run_bounded_process", side_effect=results
        ), self.assertRaisesRegex(
            AuditContractError, "status 7: registry unavailable"
        ):
            run(self.repository, no_fetch=True)


if __name__ == "__main__":
    unittest.main()
