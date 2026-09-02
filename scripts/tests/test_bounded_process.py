from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from scripts.publication.bounded_process import (
    BoundedProcessError,
    _terminate_group,
    run_bounded_process,
)


class BoundedProcessTests(unittest.TestCase):
    def test_exit_race_reaps_leader_before_accepting_denied_group_signal(self) -> None:
        real_killpg = os.killpg
        denied = []
        with subprocess.Popen(
            ["/bin/sleep", "0.01"],
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process:
            def killpg(group: int, requested_signal: int) -> None:
                self.assertEqual(group, process.pid)
                if requested_signal == signal.SIGKILL:
                    denied.append(group)
                    raise PermissionError("exiting process group")
                real_killpg(group, requested_signal)

            with patch("scripts.publication.bounded_process.os.killpg", side_effect=killpg):
                _terminate_group(process)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(denied, [process.pid])
            self.assert_process_gone(process.pid)

    def test_denied_signal_never_hides_an_unreaped_leader(self) -> None:
        process = Mock(pid=12345)
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("owned child", 5)
        with (
            patch("scripts.publication.bounded_process.os.killpg", side_effect=PermissionError("denied")),
            self.assertRaises(BoundedProcessError) as raised,
        ):
            _terminate_group(process)
        self.assertEqual(raised.exception.reason, "cleanup")
        self.assertIsInstance(raised.exception.__cause__, PermissionError)
        process.wait.assert_called_once_with(timeout=5)

    def test_denied_group_probe_is_not_mistaken_for_absence(self) -> None:
        process = Mock(pid=12345)
        process.poll.return_value = 0
        process.wait.return_value = 0
        with (
            patch("scripts.publication.bounded_process.os.killpg", side_effect=PermissionError("denied")),
            patch("scripts.publication.bounded_process.time.monotonic", side_effect=[0, 6]),
            self.assertRaises(BoundedProcessError) as raised,
        ):
            _terminate_group(process)
        self.assertEqual(raised.exception.reason, "cleanup")
        self.assertIn("descendants", str(raised.exception))
        process.wait.assert_called_once_with(timeout=5)

    def environment(self) -> dict[str, str]:
        return {"HOME": str(Path.home()), "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}

    def assert_process_gone(self, process_id: int) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(process_id, 0)
            except ProcessLookupError:
                return
            time.sleep(0.02)
        self.fail(f"bounded descendant remained alive: {process_id}")

    def test_success_preserves_separate_bounded_streams(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = run_bounded_process(
                [
                    "/bin/bash",
                    "-p",
                    "-c",
                    "printf 'standard output'; printf 'standard error' >&2",
                ],
                cwd=Path(temporary).resolve(),
                environment=self.environment(),
                timeout=2,
                output_limit=1024,
            )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"standard output")
        self.assertEqual(completed.stderr, b"standard error")

    def test_stdout_and_stderr_share_one_hard_output_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(BoundedProcessError) as captured:
                run_bounded_process(
                    [
                        "/bin/bash",
                        "-p",
                        "-c",
                        "i=0; while (( i < 1000 )); do "
                        "printf '1234567890'; printf 'abcdefghij' >&2; "
                        "(( i += 1 )); done",
                    ],
                    cwd=Path(temporary).resolve(),
                    environment=self.environment(),
                    timeout=2,
                    output_limit=1024,
                )
        self.assertEqual(captured.exception.reason, "output-limit")
        self.assertLessEqual(
            len(captured.exception.stdout) + len(captured.exception.stderr), 1024
        )

    def test_timeout_kills_the_complete_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(BoundedProcessError) as captured:
                run_bounded_process(
                    [
                        "/bin/bash",
                        "-p",
                        "-c",
                        "/bin/sleep 30 & child=$!; printf '%s\\n' \"$child\"; wait",
                    ],
                    cwd=Path(temporary).resolve(),
                    environment=self.environment(),
                    timeout=0.2,
                    output_limit=1024,
                )
        self.assertEqual(
            captured.exception.reason, "timeout", str(captured.exception)
        )
        child = int(captured.exception.stdout.strip())
        self.assert_process_gone(child)

    def test_descendant_holding_a_pipe_is_bounded_and_cleaned_up(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(BoundedProcessError) as captured:
                run_bounded_process(
                    [
                        "/bin/bash",
                        "-p",
                        "-c",
                        "/bin/sleep 30 & child=$!; printf '%s\\n' \"$child\"; exit 0",
                    ],
                    cwd=Path(temporary).resolve(),
                    environment=self.environment(),
                    timeout=0.2,
                    output_limit=1024,
                )
        self.assertEqual(
            captured.exception.reason, "timeout", str(captured.exception)
        )
        child = int(captured.exception.stdout.strip())
        self.assert_process_gone(child)

    def test_selector_setup_failure_terminates_the_owned_process(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryFile() as stdout,
            tempfile.TemporaryFile() as stderr,
        ):
            process = Mock(pid=12345, stdout=stdout, stderr=stderr)
            process.poll.return_value = None
            with (
                patch(
                    "scripts.publication.bounded_process.subprocess.Popen",
                    return_value=process,
                ),
                patch(
                    "scripts.publication.bounded_process.selectors.DefaultSelector",
                    side_effect=OSError("selector unavailable"),
                ),
                patch(
                    "scripts.publication.bounded_process._terminate_group"
                ) as terminate,
                self.assertRaisesRegex(OSError, "selector unavailable"),
            ):
                run_bounded_process(
                    ["/bin/sleep", "30"],
                    cwd=Path(temporary).resolve(),
                    environment=self.environment(),
                    timeout=2,
                    output_limit=1024,
                )
            terminate.assert_called_once_with(process)
            self.assertTrue(stdout.closed)
            self.assertTrue(stderr.closed)

    def test_fd_setup_failure_terminates_the_owned_process(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryFile() as stdout,
            tempfile.TemporaryFile() as stderr,
        ):
            process = Mock(pid=12345, stdout=stdout, stderr=stderr)
            process.poll.return_value = None
            with (
                patch(
                    "scripts.publication.bounded_process.subprocess.Popen",
                    return_value=process,
                ),
                patch(
                    "scripts.publication.bounded_process.os.set_blocking",
                    side_effect=OSError("fd setup failed"),
                ),
                patch(
                    "scripts.publication.bounded_process._terminate_group"
                ) as terminate,
                self.assertRaisesRegex(OSError, "fd setup failed"),
            ):
                run_bounded_process(
                    ["/bin/sleep", "30"],
                    cwd=Path(temporary).resolve(),
                    environment=self.environment(),
                    timeout=2,
                    output_limit=1024,
                )
            terminate.assert_called_once_with(process)
            self.assertTrue(stdout.closed)
            self.assertTrue(stderr.closed)


if __name__ == "__main__":
    unittest.main()
