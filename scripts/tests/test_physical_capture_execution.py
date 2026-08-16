from __future__ import annotations

import gc
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import warnings
from unittest.mock import patch

from scripts.physical_capture import execution
from scripts.physical_capture.execution import (
    CommandSpec,
    ProbeExecutionError,
    ReadinessSpec,
    command_sha256,
    run_fixed_command,
    start_fixed_command,
)


class PhysicalCaptureExecutionTests(unittest.TestCase):
    def spec(self, *argv: str, **overrides: object) -> CommandSpec:
        values = {
            "role": "test-probe",
            "argv": tuple(argv),
            "cwd": Path("/private/tmp"),
            "timeout_seconds": 2.0,
            "accepted_exit_codes": frozenset({0}),
            "stdout_limit": 1024,
            "stderr_limit": 0,
        }
        values.update(overrides)
        return CommandSpec(**values)  # type: ignore[arg-type]

    def test_captures_bounded_stdout_and_binds_argv_without_shell(self) -> None:
        result = run_fixed_command(self.spec("/bin/echo", "safe value"))
        self.assertEqual(result.stdout, b"safe value\n")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.argv_sha256, command_sha256(["/bin/echo", "safe value"]))
        self.assertGreaterEqual(result.duration_ms, 1)
        self.assertTrue(result.started_at.endswith("Z"))
        self.assertTrue(result.completed_at.endswith("Z"))

    def test_rejects_relative_or_group_writable_executables(self) -> None:
        with self.assertRaisesRegex(ProbeExecutionError, "absolute"):
            run_fixed_command(self.spec("echo", "unsafe"))
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "probe"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o775)
            with self.assertRaisesRegex(ProbeExecutionError, "owner or mode"):
                run_fixed_command(self.spec(str(executable)))

    def test_stderr_and_output_overflow_fail_closed_without_echoing_bytes(self) -> None:
        secret = "must-not-leak-physical-secret"
        cases = (
            self.spec("/bin/sh", "-c", f"printf {secret} >&2"),
            self.spec(
                "/usr/bin/yes",
                secret,
                stdout_limit=32,
                timeout_seconds=1.0,
            ),
        )
        for spec in cases:
            with self.subTest(argv=spec.argv):
                with self.assertRaises(ProbeExecutionError) as captured:
                    run_fixed_command(spec)
                self.assertNotIn(secret, str(captured.exception))

    def test_timeout_kills_the_complete_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant-finished"
            script = Path(directory) / "probe"
            script.write_text(
                "#!/bin/sh\n"
                f"(sleep 1; /usr/bin/touch '{marker}') &\n"
                "sleep 30\n",
                encoding="utf-8",
            )
            script.chmod(0o700)
            with self.assertRaisesRegex(ProbeExecutionError, "timeout"):
                run_fixed_command(
                    self.spec(str(script), timeout_seconds=0.1, stdout_limit=0)
                )
            time.sleep(1.2)
            self.assertFalse(marker.exists())

    def test_signal_and_unexpected_exit_are_not_results(self) -> None:
        for command, diagnostic in (
            (("/bin/sh", "-c", "exit 23"), "unexpected exit"),
            (("/bin/sh", "-c", "kill -TERM $$"), "signal"),
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(ProbeExecutionError, diagnostic):
                    run_fixed_command(self.spec(*command))

    def test_environment_override_and_invalid_limits_are_rejected(self) -> None:
        with self.assertRaisesRegex(ProbeExecutionError, "environment"):
            run_fixed_command(
                self.spec("/bin/echo", "x"), environment={"PATH": "/tmp"}
            )
        with self.assertRaisesRegex(ProbeExecutionError, "stdout limit"):
            run_fixed_command(
                self.spec("/bin/echo", "x", stdout_limit=-1)
            )

    def test_source_bound_private_environment_is_applied_without_opening_new_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            user_home = root / "android-user-home"
            home.mkdir()
            user_home.mkdir()
            spec = self.spec(
                "/usr/bin/env",
                cwd=root,
                stdout_limit=4096,
                environment=(
                    ("HOME", str(home)),
                    ("ANDROID_USER_HOME", str(user_home)),
                    ("ANDROID_ADB_LOG_PATH", str(root / "adb.log")),
                ),
            )
            result = run_fixed_command(spec)
            values = dict(
                line.split("=", 1)
                for line in result.stdout.decode("ascii").splitlines()
                if "=" in line
            )
            self.assertEqual(values["HOME"], str(home))
            self.assertEqual(values["ANDROID_USER_HOME"], str(user_home))
            self.assertEqual(values["ANDROID_ADB_LOG_PATH"], str(root / "adb.log"))
            self.assertEqual(values["ADB_MDNS"], "0")

            with self.assertRaisesRegex(ProbeExecutionError, "unreviewed variable"):
                run_fixed_command(
                    self.spec(
                        "/bin/echo",
                        "x",
                        environment=(("UNREVIEWED", "value"),),
                    )
                )

    def test_started_command_waits_for_one_exact_line_then_returns_command_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "readiness-probe"
            script.write_text(
                "#!/bin/sh\n"
                "printf 'booting\\n' >&2\n"
                "sleep 0.05\n"
                "printf 'READY fixed-probe\\n' >&2\n"
                "printf 'bounded payload\\n'\n",
                encoding="utf-8",
            )
            script.chmod(0o700)
            spec = self.spec(
                str(script),
                cwd=Path(directory),
                stderr_limit=1024,
            )
            with start_fixed_command(spec) as command:
                command.wait_for_readiness(
                    ReadinessSpec(
                        stream="stderr",
                        line=b"READY fixed-probe\n",
                        timeout_seconds=1.0,
                    )
                )
                result = command.finish()

        self.assertEqual(result.stdout, b"bounded payload\n")
        self.assertEqual(result.stderr, b"booting\nREADY fixed-probe\n")
        self.assertEqual(result.argv_sha256, command_sha256([str(script)]))

    def test_process_exit_before_readiness_fails_closed(self) -> None:
        command = start_fixed_command(
            self.spec("/bin/echo", "not-the-ready-line", stdout_limit=1024)
        )
        time.sleep(0.05)
        with self.assertRaisesRegex(ProbeExecutionError, "exited before.*readiness"):
            command.wait_for_readiness(
                ReadinessSpec("stdout", b"READY\n", 1.0)
            )

    def test_readiness_timeout_kills_the_complete_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "readiness-descendant-finished"
            script = Path(directory) / "readiness-timeout-probe"
            script.write_text(
                "#!/bin/sh\n"
                f"(sleep 0.5; /usr/bin/touch '{marker}') &\n"
                "sleep 30\n",
                encoding="utf-8",
            )
            script.chmod(0o700)
            command = start_fixed_command(
                self.spec(
                    str(script),
                    cwd=Path(directory),
                    timeout_seconds=2.0,
                    stdout_limit=64,
                )
            )
            with self.assertRaisesRegex(ProbeExecutionError, "readiness.*timeout"):
                command.wait_for_readiness(
                    ReadinessSpec("stdout", b"READY\n", 0.05)
                )
            time.sleep(0.7)
            self.assertFalse(marker.exists())

    def test_output_overflow_during_readiness_cancels_the_probe(self) -> None:
        command = start_fixed_command(
            self.spec(
                "/usr/bin/yes",
                "not-ready",
                stdout_limit=32,
                timeout_seconds=2.0,
            )
        )
        with self.assertRaisesRegex(ProbeExecutionError, "stdout.*byte bound"):
            command.wait_for_readiness(
                ReadinessSpec("stdout", b"READY\n", 1.0)
            )
        with self.assertRaisesRegex(ProbeExecutionError, "cancelled"):
            command.finish()

    def test_explicit_cancel_terminates_descendants_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "cancelled-descendant-finished"
            script = Path(directory) / "cancel-probe"
            script.write_text(
                "#!/bin/sh\n"
                f"(sleep 0.5; /usr/bin/touch '{marker}') &\n"
                "sleep 30\n",
                encoding="utf-8",
            )
            script.chmod(0o700)
            command = start_fixed_command(
                self.spec(
                    str(script),
                    cwd=Path(directory),
                    timeout_seconds=2.0,
                    stdout_limit=64,
                )
            )
            command.cancel()
            command.cancel()
            time.sleep(0.7)
            self.assertFalse(marker.exists())
            with self.assertRaisesRegex(ProbeExecutionError, "cancelled"):
                command.finish()

    def test_cancel_failure_remains_retryable_until_cleanup_is_proven(self) -> None:
        command = object.__new__(execution.StartedCommand)
        command._result = None
        command._cancelled = False

        with patch.object(
            command,
            "_cleanup",
            side_effect=(ProbeExecutionError("cleanup unproven"), None),
        ) as cleanup:
            with self.assertRaisesRegex(ProbeExecutionError, "cleanup unproven"):
                command.cancel()
            self.assertFalse(command._cancelled)

            command.cancel()
            self.assertTrue(command._cancelled)
            command.cancel()

        self.assertEqual(cleanup.call_count, 2)
        cleanup.assert_called_with(terminate=True)

    def test_readiness_contract_rejects_nonexact_or_unbounded_shapes(self) -> None:
        invalid = (
            ReadinessSpec("combined", b"READY\n", 1.0),
            ReadinessSpec("stdout", b"READY", 1.0),
            ReadinessSpec("stdout", b"READY\n", 3.0),
        )
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", ResourceWarning)
            for readiness in invalid:
                with self.subTest(readiness=readiness):
                    command = start_fixed_command(
                        self.spec("/bin/sleep", "2", stdout_limit=64)
                    )
                    with self.assertRaises(ProbeExecutionError):
                        command.wait_for_readiness(readiness)
                    with self.assertRaisesRegex(ProbeExecutionError, "cancelled"):
                        command.finish()
            del command
            gc.collect()
        self.assertEqual(
            [warning for warning in captured if warning.category is ResourceWarning],
            [],
        )

    def test_duplicate_readiness_line_is_rejected_at_completion(self) -> None:
        command = start_fixed_command(
            self.spec(
                "/bin/sh",
                "-c",
                "printf 'READY\\n'; sleep 0.05; printf 'READY\\n'",
                stdout_limit=64,
            )
        )
        command.wait_for_readiness(ReadinessSpec("stdout", b"READY\n", 1.0))
        with self.assertRaisesRegex(ProbeExecutionError, "absent or duplicated"):
            command.finish()

    def test_successful_parent_cannot_leave_a_silent_descendant_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "silent-descendant-finished"
            script = Path(directory) / "silent-descendant-probe"
            script.write_text(
                "#!/bin/sh\n"
                f"(exec >/dev/null 2>&1; sleep 0.5; /usr/bin/touch '{marker}') &\n"
                "exit 0\n",
                encoding="utf-8",
            )
            script.chmod(0o700)
            with self.assertRaisesRegex(ProbeExecutionError, "descendants remained"):
                run_fixed_command(
                    self.spec(
                        str(script),
                        cwd=Path(directory),
                        timeout_seconds=2.0,
                        stdout_limit=0,
                    )
                )
            time.sleep(0.7)
            self.assertFalse(marker.exists())

    def test_unowned_process_group_cleanup_ambiguity_is_an_error(self) -> None:
        class ReapedProcess:
            pid = 424242

            @staticmethod
            def poll() -> int:
                return 0

        with patch.object(execution.os, "killpg", side_effect=PermissionError):
            with self.assertRaisesRegex(
                ProbeExecutionError,
                "cleanup could not be proven",
            ):
                execution._terminate_process_group(ReapedProcess())  # type: ignore[arg-type]

    def test_sigkill_permission_error_is_typed_cleanup_failure(self) -> None:
        class LiveProcess:
            pid = 424243
            stdout = None
            stderr = None

            @staticmethod
            def poll() -> None:
                return None

            @staticmethod
            def wait(timeout: float) -> None:
                raise subprocess.TimeoutExpired("probe", timeout)

        with patch.object(execution, "_process_group_exists", return_value=True), patch.object(
            execution,
            "_wait_for_process_group_exit",
            return_value=False,
        ), patch.object(
            execution.os,
            "killpg",
            side_effect=(None, PermissionError()),
        ):
            with self.assertRaisesRegex(
                ProbeExecutionError,
                "cleanup could not be proven",
            ):
                execution._terminate_process_group(LiveProcess())  # type: ignore[arg-type]

    def test_cleanup_closes_both_streams_after_termination_failure(self) -> None:
        class Stream:
            def __init__(self, *, fail: bool = False) -> None:
                self.close_count = 0
                self.fail = fail

            def close(self) -> None:
                self.close_count += 1
                if self.fail:
                    raise OSError("stream close failed")

        class Selector:
            def __init__(self) -> None:
                self.close_count = 0

            def close(self) -> None:
                self.close_count += 1

        stdout = Stream(fail=True)
        stderr = Stream()
        selector = Selector()
        command = object.__new__(execution.StartedCommand)
        command._process = type("Process", (), {"stdout": stdout, "stderr": stderr})()
        command._selector = selector
        command._closed = False

        with patch.object(
            execution,
            "_terminate_process_group",
            side_effect=ProbeExecutionError("termination failed"),
        ):
            with self.assertRaisesRegex(ProbeExecutionError, "termination failed"):
                command._cleanup(terminate=True)

        self.assertEqual(selector.close_count, 1)
        self.assertEqual(stdout.close_count, 1)
        self.assertEqual(stderr.close_count, 1)
        self.assertTrue(command._closed)
        command._cleanup(terminate=False)
        self.assertEqual(stdout.close_count, 1)
        self.assertEqual(stderr.close_count, 1)


if __name__ == "__main__":
    unittest.main()
