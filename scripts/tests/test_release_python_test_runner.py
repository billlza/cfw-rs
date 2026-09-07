from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import run_release_python_tests


class ReleasePythonTestRunnerTests(unittest.TestCase):
    def test_zero_discovered_tests_is_failure(self) -> None:
        with (
            mock.patch.object(
                run_release_python_tests.unittest.defaultTestLoader,
                "discover",
                return_value=unittest.TestSuite(),
            ),
            mock.patch.object(
                run_release_python_tests.sys,
                "argv",
                ["run_release_python_tests.py"],
            ),
        ):
            self.assertEqual(run_release_python_tests.main(), 1)

    def test_missing_selected_test_file_is_rejected_before_discovery(self) -> None:
        with mock.patch.object(
            run_release_python_tests.sys,
            "argv",
            [
                "run_release_python_tests.py",
                "--pattern",
                "test_no_such_release_test.py",
            ],
        ):
            with self.assertRaisesRegex(SystemExit, "unavailable"):
                run_release_python_tests.main()

    def test_symlink_selected_test_file_is_rejected(self) -> None:
        tests = Path(run_release_python_tests.__file__).resolve().parent / "tests"
        with tempfile.TemporaryDirectory(dir=tests) as temporary:
            temporary_root = Path(temporary)
            target = temporary_root / "target.py"
            target.write_text("pass\n", encoding="utf-8")
            selected = tests / "test_selected_symlink.py"
            selected.symlink_to(target)
            self.addCleanup(selected.unlink, missing_ok=True)
            with mock.patch.object(
                run_release_python_tests.sys,
                "argv",
                [
                    "run_release_python_tests.py",
                    "--pattern",
                    selected.name,
                ],
            ):
                with self.assertRaisesRegex(SystemExit, "safe regular"):
                    run_release_python_tests.main()


if __name__ == "__main__":
    unittest.main()
