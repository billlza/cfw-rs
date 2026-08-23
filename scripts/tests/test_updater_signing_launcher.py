from __future__ import annotations

import contextlib
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from typing import Callable, NoReturn, Sequence
from unittest import mock

from scripts import updater_signing_launcher as launcher


REPO_ROOT = Path(__file__).resolve().parents[2]


class _ExecveCaptured(RuntimeError):
    pass


def _completed(
    arguments: object,
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(arguments, returncode, stdout, stderr)


class SigningHome:
    def __init__(self, root: Path) -> None:
        self.home = root / "home"
        self.home.mkdir(mode=0o700)
        self.library = self.home / "Library"
        self.library.mkdir(mode=0o700)
        application_support = self.library / "Application Support"
        application_support.mkdir(mode=0o700)
        release = application_support / "Clash for Mac Release"
        release.mkdir(mode=0o700)
        self.key_directory = release / "Updater"
        self.key_directory.mkdir(mode=0o700)
        self.key = self.home / launcher.PRIVATE_KEY_RELATIVE
        self.key.write_bytes(b"fixture-private-key\n")
        self.key.chmod(0o600)

        self.keychains = self.library / "Keychains"
        self.keychains.mkdir(mode=0o755)
        self.keychain = self.home / launcher.LOGIN_KEYCHAIN_RELATIVE
        self.keychain.write_bytes(b"fixture-keychain-database\n")
        self.keychain.chmod(0o644)

        self.archive = root / "fixture.tar.gz"
        self.archive.write_bytes(b"fixture updater archive\n")
        self.signer = root / "cargo-tauri"
        self.signer.write_bytes(b"fixture signer\n")
        self.signer.chmod(0o755)

    def held_signer(self) -> launcher.HeldSigner:
        descriptor = os.open(self.signer, os.O_RDONLY | os.O_CLOEXEC)
        identity = launcher.PathIdentity.from_stat(
            self.signer,
            os.fstat(descriptor),
        )
        return launcher.HeldSigner(self.signer, descriptor, identity)

    def metadata(self) -> bytes:
        return (
            f'keychain: "{self.keychain}"\n'
            'class: "genp"\n'
            'attributes:\n'
            f'    "acct"<blob>="{launcher.KEYCHAIN_ACCOUNT}"\n'
            f'    "svce"<blob>="{launcher.KEYCHAIN_SERVICE}"\n'
        ).encode("utf-8")


class AclPolicyTests(unittest.TestCase):
    def test_deny_only_default_acl_is_accepted(self) -> None:
        calls: list[dict[str, object]] = []

        def runner(arguments: list[str], **kwargs: object):
            calls.append(kwargs)
            return _completed(
                arguments,
                stdout=(
                    b"drwx------@ 1 user staff 32 Jan 1 00:00 Library\n"
                    b" 0: group:everyone deny delete\n"
                ),
            )

        launcher.require_no_macos_acl_grants(
            Path("/fixture/Library"),
            runner=runner,
        )
        self.assertEqual(calls[0]["stdin"], subprocess.DEVNULL)
        self.assertEqual(
            calls[0]["timeout"],
            launcher.CREDENTIAL_LOOKUP_TIMEOUT_SECONDS,
        )

    def test_allow_acl_and_unknown_acl_action_are_rejected(self) -> None:
        for acl in (
            b" 0: group:everyone allow read\n",
            b" 0: group:everyone audit read\n",
        ):
            with self.subTest(acl=acl):
                def runner(arguments: list[str], **_kwargs: object):
                    return _completed(
                        arguments,
                        stdout=b"-rw-------+ fixture\n" + acl,
                    )

                with self.assertRaises(launcher.UpdaterSigningLaunchError):
                    launcher.require_no_macos_acl_grants(
                        Path("/fixture/key"),
                        runner=runner,
                    )


class KeychainLookupTests(unittest.TestCase):
    def _read(
        self,
        fixture: SigningHome,
        runner: Callable[..., subprocess.CompletedProcess[bytes]],
    ) -> bytearray:
        return launcher.read_fixed_keychain_password(
            home=fixture.home,
            runner=runner,
            acl_checker=lambda _path: None,
        )

    def test_exact_fixed_local_item_is_read_with_no_terminal_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SigningHome(Path(temporary))
            calls: list[tuple[list[str], dict[str, object]]] = []

            def runner(arguments: list[str], **kwargs: object):
                calls.append((arguments, kwargs))
                output = b"fixture-password\n" if "-w" in arguments else fixture.metadata()
                return _completed(arguments, stdout=output)

            password = self._read(fixture, runner)
            self.assertEqual(password, bytearray(b"fixture-password"))
            self.assertEqual(len(calls), 2)
            for arguments, kwargs in calls:
                self.assertEqual(arguments[0], "/usr/bin/security")
                self.assertEqual(arguments[-1], str(fixture.keychain))
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(
                    kwargs["timeout"],
                    launcher.CREDENTIAL_LOOKUP_TIMEOUT_SECONDS,
                )
                environment = kwargs["env"]
                self.assertIsInstance(environment, dict)
                self.assertEqual(environment["HOME"], str(fixture.home))

    def test_denied_empty_duplicate_sync_and_timeout_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SigningHome(Path(temporary))

            scenarios = {
                "denied": lambda args, **_kwargs: _completed(args, returncode=44),
                "empty": lambda args, **_kwargs: _completed(
                    args,
                    stdout=b"" if "-w" in args else fixture.metadata(),
                ),
                "duplicate": lambda args, **_kwargs: _completed(
                    args,
                    stdout=(
                        b"fixture-password\n"
                        if "-w" in args
                        else fixture.metadata() + fixture.metadata()
                    ),
                ),
                "sync": lambda args, **_kwargs: _completed(
                    args,
                    stdout=(
                        b"fixture-password\n"
                        if "-w" in args
                        else fixture.metadata() + b'    "sync"<uint32>=1\n'
                    ),
                ),
            }
            for name, runner in scenarios.items():
                with self.subTest(name=name):
                    calls = 0

                    def counted_runner(arguments: list[str], **kwargs: object):
                        nonlocal calls
                        calls += 1
                        return runner(arguments, **kwargs)

                    with self.assertRaises(launcher.UpdaterSigningLaunchError):
                        self._read(fixture, counted_runner)
                    self.assertEqual(calls, 2 if name == "empty" else 1)

            def timeout(_arguments: list[str], **_kwargs: object):
                raise subprocess.TimeoutExpired("security", 1)

            with self.assertRaises(launcher.UpdaterSigningLaunchError):
                self._read(fixture, timeout)


class LauncherBoundaryTests(unittest.TestCase):
    def _launch(
        self,
        fixture: SigningHome,
        password_reader: Callable[[], bytearray],
        execve: Callable[[str, Sequence[str], dict[str, str]], NoReturn],
        *,
        acl_checker: Callable[[Path], None] = lambda _path: None,
    ) -> None:
        with mock.patch.object(
            launcher,
            "verify_pinned_tauri_signer",
            side_effect=lambda _repository: fixture.held_signer(),
        ):
            launcher.launch_updater_signer(
                fixture.archive,
                home=fixture.home,
                password_reader=password_reader,
                acl_checker=acl_checker,
                execve=execve,
            )

    def test_cli_has_no_caller_selected_signer_argument(self) -> None:
        with mock.patch.object(launcher, "launch_updater_signer") as launch:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    launcher.main(["/tmp/malicious-signer", "/tmp/archive"])
        self.assertEqual(raised.exception.code, 2)
        launch.assert_not_called()

    def test_all_caller_secret_environment_names_fail_before_key_read(self) -> None:
        for name in sorted(launcher.SECRET_ENVIRONMENT_NAMES):
            with self.subTest(name=name):
                reads = 0

                def reader() -> bytearray:
                    nonlocal reads
                    reads += 1
                    return bytearray(b"fixture-password")

                with tempfile.TemporaryDirectory() as temporary:
                    fixture = SigningHome(Path(temporary))
                    with mock.patch.dict(os.environ, {name: "forbidden"}):
                        with self.assertRaises(launcher.UpdaterSigningLaunchError):
                            self._launch(fixture, reader, os.execve)
                self.assertEqual(reads, 0)

    def test_signer_verification_failure_precedes_password_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SigningHome(Path(temporary))
            reads = 0

            def reader() -> bytearray:
                nonlocal reads
                reads += 1
                return bytearray(b"fixture-password")

            with mock.patch.object(
                launcher,
                "verify_pinned_tauri_signer",
                side_effect=launcher.UpdaterSigningLaunchError("wrong signer"),
            ):
                with self.assertRaises(launcher.UpdaterSigningLaunchError):
                    launcher.launch_updater_signer(
                        fixture.archive,
                        home=fixture.home,
                        password_reader=reader,
                        acl_checker=lambda _path: None,
                    )
            self.assertEqual(reads, 0)

    def test_execve_receives_only_fd_key_and_minimal_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SigningHome(Path(temporary))
            password = bytearray(b"fixture-password")
            captured: dict[str, object] = {}

            def execve(
                executable: str,
                arguments: list[str],
                environment: dict[str, str],
            ) -> None:
                captured.update(
                    executable=executable,
                    arguments=list(arguments),
                    environment=dict(environment),
                )
                fd_path = Path(arguments[4])
                descriptor = int(fd_path.name)
                self.assertTrue(os.get_inheritable(descriptor))
                self.assertEqual(fd_path.read_bytes(), fixture.key.read_bytes())
                raise _ExecveCaptured

            with self.assertRaises(_ExecveCaptured):
                self._launch(fixture, lambda: password, execve)

            arguments = captured["arguments"]
            self.assertIsInstance(arguments, list)
            self.assertEqual(arguments[0], str(fixture.signer))
            self.assertEqual(arguments[1:4], ["signer", "sign", "-f"])
            self.assertTrue(arguments[4].startswith("/dev/fd/"))
            self.assertEqual(arguments[5], str(fixture.archive))
            self.assertNotIn("fixture-password", " ".join(arguments))
            self.assertEqual(
                captured["environment"],
                {
                    "PATH": launcher.SYSTEM_PATH,
                    "TAURI_SIGNING_PRIVATE_KEY_PASSWORD": "fixture-password",
                },
            )
            self.assertEqual(password, bytearray(len(password)))

    def test_key_and_parent_mutations_during_password_read_fail_closed(self) -> None:
        mutations = ("replacement", "hardlink", "mode", "parent")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = SigningHome(Path(temporary))
                    exec_calls = 0

                    def reader() -> bytearray:
                        if mutation == "replacement":
                            fixture.key.rename(fixture.key.with_suffix(".old"))
                            fixture.key.write_bytes(b"replacement\n")
                            fixture.key.chmod(0o600)
                        elif mutation == "hardlink":
                            os.link(fixture.key, fixture.key.with_suffix(".alias"))
                        elif mutation == "mode":
                            fixture.key.chmod(0o644)
                        else:
                            moved = fixture.key_directory.with_name("Updater.old")
                            fixture.key_directory.rename(moved)
                            fixture.key_directory.mkdir(mode=0o700)
                            fixture.key.write_bytes(b"replacement\n")
                            fixture.key.chmod(0o600)
                        return bytearray(b"fixture-password")

                    def execve(*_args: object) -> None:
                        nonlocal exec_calls
                        exec_calls += 1
                        raise _ExecveCaptured

                    with self.assertRaises(launcher.UpdaterSigningLaunchError):
                        self._launch(fixture, reader, execve)
                    self.assertEqual(exec_calls, 0)

    def test_acl_and_signer_path_mutation_after_read_fail_closed(self) -> None:
        for mutation in ("acl", "signer"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = SigningHome(Path(temporary))
                    access_grant = False
                    exec_calls = 0

                    def reader() -> bytearray:
                        nonlocal access_grant
                        if mutation == "acl":
                            access_grant = True
                        else:
                            fixture.signer.rename(fixture.signer.with_suffix(".old"))
                            fixture.signer.write_bytes(b"replacement signer\n")
                            fixture.signer.chmod(0o755)
                        return bytearray(b"fixture-password")

                    def acl_checker(_path: Path) -> None:
                        if access_grant:
                            raise launcher.UpdaterSigningLaunchError("ACL grant")

                    def execve(*_args: object) -> None:
                        nonlocal exec_calls
                        exec_calls += 1
                        raise _ExecveCaptured

                    with self.assertRaises(launcher.UpdaterSigningLaunchError):
                        self._launch(
                            fixture,
                            reader,
                            execve,
                            acl_checker=acl_checker,
                        )
                    self.assertEqual(exec_calls, 0)

    def test_archive_replacement_mode_and_acl_drift_fail_closed(self) -> None:
        for mutation in ("replacement", "mode", "acl"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = SigningHome(Path(temporary))
                    archive_acl_grant = False
                    exec_calls = 0

                    def reader() -> bytearray:
                        nonlocal archive_acl_grant
                        if mutation == "replacement":
                            fixture.archive.rename(
                                fixture.archive.with_suffix(".old")
                            )
                            fixture.archive.write_bytes(b"replacement archive\n")
                        elif mutation == "mode":
                            fixture.archive.chmod(0o600)
                        else:
                            archive_acl_grant = True
                        return bytearray(b"fixture-password")

                    def acl_checker(path: Path) -> None:
                        if archive_acl_grant and path == fixture.archive:
                            raise launcher.UpdaterSigningLaunchError(
                                "archive ACL grant"
                            )

                    def execve(*_args: object) -> None:
                        nonlocal exec_calls
                        exec_calls += 1
                        raise _ExecveCaptured

                    with self.assertRaises(launcher.UpdaterSigningLaunchError):
                        self._launch(
                            fixture,
                            reader,
                            execve,
                            acl_checker=acl_checker,
                        )
                    self.assertEqual(exec_calls, 0)

    def test_oserror_is_rendered_without_traceback_and_password_is_wiped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SigningHome(Path(temporary))
            password = bytearray(b"fixture-password")

            def failing_execve(*_args: object) -> None:
                raise OSError("synthetic exec failure")

            with mock.patch.object(
                launcher,
                "verify_pinned_tauri_signer",
                side_effect=lambda _repository: fixture.held_signer(),
            ), mock.patch.object(
                launcher,
                "_home_directory",
                return_value=fixture.home,
            ):
                original_launch = launcher.launch_updater_signer

                def invoke(archive: Path) -> NoReturn:
                    return original_launch(
                        archive,
                        home=fixture.home,
                        password_reader=lambda: password,
                        acl_checker=lambda _path: None,
                        execve=failing_execve,
                    )

                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    with mock.patch.object(
                        launcher,
                        "launch_updater_signer",
                        side_effect=invoke,
                    ):
                        result = launcher.main([str(fixture.archive)])
            self.assertEqual(result, 1)
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertNotIn("fixture-password", stderr.getvalue())
            self.assertEqual(password, bytearray(len(password)))


class PinnedSignerIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "fork"), "requires fork/exec")
    def test_real_pinned_signer_reads_temporary_key_from_dev_fd(self) -> None:
        signer = (
            REPO_ROOT
            / "target/toolchains"
            / f"tauri-cli-{launcher.TAURI_CLI_VERSION}"
            / "bin/cargo-tauri"
        )
        if not signer.is_file():
            if os.environ.get("CFW_REQUIRE_PINNED_SIGNER_INTEGRATION") == "1":
                self.fail("pinned Tauri signer is required by this integration lane")
            self.skipTest("pinned Tauri signer is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SigningHome(Path(temporary))
            password_text = "synthetic-test-password"
            fixture.key.unlink()
            generated = subprocess.run(
                [
                    str(signer),
                    "signer",
                    "generate",
                    "-p",
                    password_text,
                    "-w",
                    str(fixture.key),
                    "--ci",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
                env={"PATH": launcher.SYSTEM_PATH},
            )
            self.assertEqual(generated.returncode, 0, generated.stderr.decode())
            fixture.key.chmod(0o600)
            before = hashlib.sha256(fixture.key.read_bytes()).hexdigest()

            child = os.fork()
            if child == 0:
                try:
                    output = os.open(os.devnull, os.O_WRONLY)
                    os.dup2(output, 1)
                    os.dup2(output, 2)
                    os.close(output)
                    for name in launcher.SECRET_ENVIRONMENT_NAMES:
                        os.environ.pop(name, None)
                    launcher.launch_updater_signer(
                        fixture.archive,
                        home=fixture.home,
                        password_reader=lambda: bytearray(password_text, "utf-8"),
                        acl_checker=lambda _path: None,
                    )
                except BaseException:
                    os._exit(120)
            _, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            signature = fixture.archive.with_name(f"{fixture.archive.name}.sig")
            self.assertTrue(signature.is_file())
            self.assertGreater(signature.stat().st_size, 0)
            self.assertEqual(hashlib.sha256(fixture.key.read_bytes()).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()
