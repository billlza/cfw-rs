from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import dormant_app_install as install
from scripts.release_build_identity import ga_signed_native_products_root, ga_signed_root
from scripts.tests.release_app_verifier_fixture import (
    complete_verifier_stderr,
    complete_verifier_stdout,
)


class DormantReleaseVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        self.wrapper = self.repository / "scripts/run_release_app_verifier.sh"
        self.wrapper.parent.mkdir()
        self.wrapper.write_text("#!/bin/bash -p\nexit 0\n", encoding="utf-8")
        self.wrapper.chmod(0o755)
        self.app = ga_signed_root(self.repository) / install.TARGET_NAME
        self.native = ga_signed_native_products_root(self.repository)

    def invoke(self) -> install.CommandResult:
        return install._run_fixed_release_verifier(
            self.repository, self.wrapper, self.app, self.native
        )

    def test_minimal_environment_uses_existing_closed_wrapper(self) -> None:
        expected = install.CommandResult(
            0,
            complete_verifier_stdout(str(self.app)).decode("utf-8"),
            complete_verifier_stderr(str(self.app)).decode("utf-8"),
        )
        with patch.object(
            install, "_run_bounded_process", autospec=True, return_value=expected
        ) as runner:
            self.assertIs(self.invoke(), expected)
        runner.assert_called_once_with(("/bin/bash", "-p", str(self.wrapper)))

    def test_incomplete_or_warning_transcript_cannot_be_success(self) -> None:
        stdout = complete_verifier_stdout(str(self.app)).decode("utf-8")
        stderr = complete_verifier_stderr(str(self.app)).decode("utf-8")
        for result in (
            install.CommandResult(0, "", ""),
            install.CommandResult(0, stdout, stderr + "warning: incomplete\n"),
        ):
            with self.subTest(result=result), patch.object(
                install, "_run_bounded_process", autospec=True, return_value=result
            ), self.assertRaises(install.InstallError) as captured:
                self.invoke()
            self.assertEqual(captured.exception.code, "release_verifier_output_invalid")

    def test_nonzero_verifier_result_is_not_converted_to_success(self) -> None:
        expected = install.CommandResult(1, "", "verification rejected\n")
        with patch.object(
            install, "_run_bounded_process", autospec=True, return_value=expected
        ):
            self.assertIs(self.invoke(), expected)

    def test_other_app_or_native_directory_never_runs_the_wrapper(self) -> None:
        for app, native in (
            (self.app.with_name("Other.app"), self.native),
            (self.app, self.native.with_name("other-native")),
        ):
            with self.subTest(app=app, native=native), patch.object(
                install, "_run_bounded_process", autospec=True
            ) as runner, self.assertRaises(install.InstallError):
                install._run_fixed_release_verifier(
                    self.repository, self.wrapper, app, native
                )
            runner.assert_not_called()

    def test_unsafe_wrapper_is_rejected_before_execution(self) -> None:
        self.wrapper.chmod(0o777)
        with patch.object(
            install, "_run_bounded_process", autospec=True
        ) as runner, self.assertRaises(install.InstallError):
            self.invoke()
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
