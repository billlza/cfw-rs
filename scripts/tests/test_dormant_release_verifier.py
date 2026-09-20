from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import shlex
import subprocess
import sys
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
        with patch.dict(os.environ, {"CFW_RELEASE_RUST_TOOLCHAIN": "private"}), patch.object(
            install, "_run_bounded_process", autospec=True, return_value=expected
        ) as runner:
            self.assertIs(self.invoke(), expected)
        runner.assert_called_once_with(
            ("/bin/bash", "-p", str(self.wrapper)), release_rust_toolchain="private"
        )

    def test_fixed_verifier_forwards_only_the_selected_enum_to_a_real_child(self) -> None:
        code = "import json, os, sys; print(json.dumps(dict(os.environ))); sys.exit(7)"
        self.wrapper.write_text(
            "#!/bin/bash -p\nexec "
            + shlex.join((sys.executable, "-I", "-S", "-B", "-c", code))
            + "\n",
            encoding="utf-8",
        )
        account = pwd.getpwuid(os.geteuid())
        minimal = {
            "HOME": account.pw_dir,
            "LANG": "C",
            "LC_ALL": "C",
            "LOGNAME": account.pw_name,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "USER": account.pw_name,
        }
        inherited = {
            "BASH_ENV": "/must-not-read-shell-startup",
            "CFW_TOOLCHAIN_ROOT": "/must-not-select-tools",
            "DEVELOPER_DIR": "/must-not-select-apple-tools",
            "RUSTUP_HOME": "/must-not-select-rustup",
            "GH_TOKEN": "fixture-private-value",
        }
        for selection, expected in (("private", "private"), ("global", "global"), (None, "global")):
            with self.subTest(selection=selection), patch.dict(os.environ, inherited):
                if selection is None:
                    os.environ.pop("CFW_RELEASE_RUST_TOOLCHAIN", None)
                else:
                    os.environ["CFW_RELEASE_RUST_TOOLCHAIN"] = selection
                with patch.object(
                    install.subprocess, "Popen", wraps=subprocess.Popen
                ) as spawn:
                    result = self.invoke()
                self.assertEqual(result.returncode, 7)
                self.assertEqual(result.stderr, "")
                self.assertEqual(
                    spawn.call_args.kwargs["env"],
                    {**minimal, "CFW_RELEASE_RUST_TOOLCHAIN": expected},
                )
                observed = json.loads(result.stdout)
                self.assertEqual(observed["CFW_RELEASE_RUST_TOOLCHAIN"], expected)
                self.assertTrue(set(inherited).isdisjoint(observed))
                self.assertNotIn("fixture-private-value", result.stdout)

    def test_invalid_selection_is_rejected_before_verifier_or_runner_spawn(self) -> None:
        for selection in ("", "PRIVATE", "private ", " global", "/tmp/private", "private\nglobal"):
            with self.subTest(selection=selection), patch.dict(
                os.environ, {"CFW_RELEASE_RUST_TOOLCHAIN": selection}
            ), patch.object(install.subprocess, "Popen") as spawn:
                with self.assertRaises(install.InstallError) as boundary:
                    self.invoke()
                self.assertEqual(boundary.exception.code, "release_rust_selection_invalid")
                with self.assertRaises(install.InstallError) as runner:
                    install._run_bounded_process(
                        ("/bin/bash", "-p", str(self.wrapper)),
                        release_rust_toolchain=selection,
                    )
                self.assertEqual(runner.exception.code, "release_rust_selection_invalid")
                spawn.assert_not_called()

    def test_ordinary_maintenance_commands_keep_the_exact_minimal_environment(self) -> None:
        account = pwd.getpwuid(os.geteuid())
        with patch.dict(os.environ, {
            "CFW_RELEASE_RUST_TOOLCHAIN": "private",
            "DEVELOPER_DIR": "/not-selected",
            "GH_TOKEN": "fixture-private-value",
        }), patch.object(install.subprocess, "Popen", wraps=subprocess.Popen) as spawn:
            result = install.production_command_runner(
                ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm=")
            )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.strip())
        self.assertEqual(result.stderr, "")
        self.assertEqual(spawn.call_args.kwargs["env"], {
            "HOME": account.pw_dir,
            "LANG": "C",
            "LC_ALL": "C",
            "LOGNAME": account.pw_name,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "USER": account.pw_name,
        })

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
