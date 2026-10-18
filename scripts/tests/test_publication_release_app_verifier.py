from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.publication.bounded_process import BoundedProcessError
from scripts.publication.common import PublicationError
from scripts.publication import ga_release_contract, preparer
from scripts.publication import release_app_verifier
from scripts.publication.release_app_verifier import verify_release_app
from scripts.release_app_verifier_output import NotarizationCheck
from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
from scripts.tests.release_app_verifier_fixture import (
    complete_verifier_stderr,
    complete_verifier_stdout,
    sealed_verifier_stdout,
)


GA_BUILD = ACTIVE_RELEASE_IDENTITY.ga_build


REPOSITORY = Path("/private/tmp/release")
APP = REPOSITORY / f"target/candidates/0.5.0/ga/{GA_BUILD}/signed/Clash for Mac.app"
NATIVE_PRODUCTS = (
    REPOSITORY
    / f"target/candidates/0.5.0/ga/{GA_BUILD}/signing-output/signed-native-products"
)


class PublicationReleaseAppVerifierTests(unittest.TestCase):
    def test_top_level_publication_package_import_mode_is_supported(self) -> None:
        scripts_root = Path(__file__).resolve().parents[1]
        source = (
            "import sys\n"
            f"sys.path.insert(0, {str(scripts_root)!r})\n"
            "import publication.preparer\n"
            "import publication.release_app_verifier\n"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", source],
            cwd="/",
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )

    def invoke_verifier(
        self, notarization: NotarizationCheck = NotarizationCheck.LIVE
    ) -> None:
        return verify_release_app(
            repository=REPOSITORY,
            environment={"PATH": "/usr/bin:/bin"},
            notarization=notarization,
        )

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_typed_success_transcript_is_accepted(self, runner: object) -> None:
        runner.return_value = subprocess.CompletedProcess(
            [], 0, complete_verifier_stdout(str(APP)), complete_verifier_stderr(str(APP))
        )
        self.assertIsNone(self.invoke_verifier())
        runner.assert_called_once_with(
            [
                "/bin/bash",
                "-p",
                str(REPOSITORY / "scripts/verify_release_app.sh"),
                str(APP),
                str(NATIVE_PRODUCTS),
                "--context",
                "canonical-native-content",
            ],
            cwd=REPOSITORY,
            environment={"PATH": "/usr/bin:/bin"},
            timeout=600,
            output_limit=384 * 1024,
        )

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_sealed_check_adds_only_the_sealed_flag(self, runner: object) -> None:
        runner.return_value = subprocess.CompletedProcess(
            [], 0, sealed_verifier_stdout(str(APP)), complete_verifier_stderr(str(APP))
        )
        self.assertIsNone(self.invoke_verifier(NotarizationCheck.SEALED))
        runner.assert_called_once_with(
            [
                "/bin/bash",
                "-p",
                str(REPOSITORY / "scripts/verify_release_app.sh"),
                "--sealed-notarization",
                str(APP),
                str(NATIVE_PRODUCTS),
                "--context",
                "canonical-native-content",
            ],
            cwd=REPOSITORY,
            environment={"PATH": "/usr/bin:/bin"},
            timeout=600,
            output_limit=384 * 1024,
        )

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_each_check_accepts_only_its_own_transcript(self, runner: object) -> None:
        for notarization, stdout in (
            (NotarizationCheck.LIVE, sealed_verifier_stdout(str(APP))),
            (NotarizationCheck.SEALED, complete_verifier_stdout(str(APP))),
        ):
            with self.subTest(notarization=notarization):
                runner.return_value = subprocess.CompletedProcess(
                    [], 0, stdout, complete_verifier_stderr(str(APP))
                )
                with self.assertRaisesRegex(PublicationError, "output is invalid"):
                    self.invoke_verifier(notarization)

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_notarization_check_is_a_required_typed_keyword(self, runner: object) -> None:
        self.assertIs(release_app_verifier.NotarizationCheck, NotarizationCheck)
        with self.assertRaises(TypeError):
            verify_release_app(
                repository=REPOSITORY,
                environment={"PATH": "/usr/bin:/bin"},
            )
        for value in ("sealed", None, True):
            with self.subTest(value=value), self.assertRaisesRegex(
                PublicationError, "notarization check is invalid"
            ):
                verify_release_app(
                    repository=REPOSITORY,
                    environment={"PATH": "/usr/bin:/bin"},
                    notarization=value,
                )
        runner.assert_not_called()

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_untyped_success_stderr_is_rejected(self, runner: object) -> None:
        for stderr in (b"", b"unknown diagnostic\n", b"warning: degraded\n"):
            with self.subTest(stderr=stderr):
                runner.return_value = subprocess.CompletedProcess(
                    [], 0, complete_verifier_stdout(str(APP)), stderr
                )
                with self.assertRaisesRegex(PublicationError, "output is invalid"):
                    self.invoke_verifier()

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_nonzero_exit_is_rejected(self, runner: object) -> None:
        runner.return_value = subprocess.CompletedProcess(
            [], 7, b"", b"\x1b[2J/private/secret/path\n"
        )
        with self.assertRaises(PublicationError) as captured:
            self.invoke_verifier()
        self.assertEqual(str(captured.exception), "release app verifier failed with exit code 7")
        # The output reaches the operator only as escaped notes, standard
        # output last, never in the message itself.
        self.assertEqual(
            captured.exception.__notes__,
            [
                "release app verifier stderr (25 bytes) ends with:\n"
                "\\x1b[2J/private/secret/path",
                "release app verifier stdout is empty",
            ],
        )

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_failure_notes_keep_only_the_bounded_end_of_each_stream(
        self, runner: object
    ) -> None:
        limit = release_app_verifier.RELEASE_APP_VERIFIER_DIAGNOSTIC_TAIL_BYTES
        stdout = (
            b"head-marker\n"
            + b"x" * 10_000
            + b"\nThe validate action failed! Error 68.\n"
        )
        stderr = b"y" * 10_000 + b"\ncodesign tail\n"
        runner.return_value = subprocess.CompletedProcess([], 1, stdout, stderr)
        with self.assertRaises(PublicationError) as captured:
            self.invoke_verifier()
        stderr_note, stdout_note = captured.exception.__notes__
        self.assertTrue(
            stderr_note.startswith(
                f"release app verifier stderr ({len(stderr)} bytes) ends with:\n"
            )
        )
        self.assertTrue(stderr_note.endswith("\ncodesign tail"))
        self.assertTrue(
            stdout_note.startswith(
                f"release app verifier stdout ({len(stdout)} bytes) ends with:\n"
            )
        )
        self.assertTrue(stdout_note.endswith("\nThe validate action failed! Error 68."))
        self.assertNotIn("head-marker", stdout_note)
        for note in (stderr_note, stdout_note):
            self.assertLessEqual(len(note.split("\n", 1)[1]), limit)

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_bounded_process_failures_keep_their_output_tails(self, runner: object) -> None:
        for reason, message in (
            ("timeout", "timed out"),
            ("output-limit", "exceeded its fixed bound"),
            ("descendant", "left a descendant process running"),
        ):
            with self.subTest(reason=reason):
                runner.side_effect = BoundedProcessError(
                    reason,
                    "simulated",
                    stdout=b"partial transcript\n",
                    stderr=b"\x07stuck\n",
                )
                with self.assertRaises(PublicationError) as captured:
                    self.invoke_verifier()
                self.assertIn(message, str(captured.exception))
                self.assertEqual(
                    captured.exception.__notes__,
                    [
                        "release app verifier stderr (7 bytes) ends with:\n\\x07stuck",
                        "release app verifier stdout (19 bytes) ends with:\n"
                        "partial transcript",
                    ],
                )
        # A process that never ran, or whose cleanup failed, has no output to
        # show: those reasons carry none.
        for failure in (
            BoundedProcessError("invalid", "simulated"),
            BoundedProcessError("start", "simulated"),
            BoundedProcessError("cleanup", "simulated"),
            OSError("simulated"),
        ):
            with self.subTest(failure=failure):
                runner.side_effect = failure
                with self.assertRaises(PublicationError) as captured:
                    self.invoke_verifier()
                self.assertEqual(getattr(captured.exception, "__notes__", []), [])

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_invalid_transcript_keeps_its_output_tails(self, runner: object) -> None:
        runner.return_value = subprocess.CompletedProcess(
            [], 0, complete_verifier_stdout(str(APP)), b"unknown diagnostic\n"
        )
        with self.assertRaises(PublicationError) as captured:
            self.invoke_verifier()
        self.assertIn("output is invalid", str(captured.exception))
        stderr_note, stdout_note = captured.exception.__notes__
        self.assertEqual(
            stderr_note,
            "release app verifier stderr (19 bytes) ends with:\nunknown diagnostic",
        )
        self.assertTrue(stdout_note.startswith("release app verifier stdout ("))
        self.assertIn(f"release app verified: {APP}", stdout_note)

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_bounded_process_failures_are_typed(self, runner: object) -> None:
        for reason, message in (
            ("timeout", "timed out"),
            ("output-limit", "exceeded its fixed bound"),
            ("descendant", "left a descendant process running"),
            ("invalid", "closed process boundary"),
            ("start", "closed process boundary"),
            ("cleanup", "closed process boundary"),
        ):
            with self.subTest(reason=reason):
                runner.side_effect = BoundedProcessError(reason, "simulated")
                with self.assertRaisesRegex(PublicationError, message):
                    self.invoke_verifier()

        runner.side_effect = OSError("simulated process I/O failure")
        with self.assertRaisesRegex(PublicationError, "closed process boundary"):
            self.invoke_verifier()


class PreparerVerifierBoundaryTests(unittest.TestCase):
    def test_prepare_uses_the_typed_app_verifier_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            candidate = ga_root(repository)
            candidate.mkdir(parents=True)
            candidate.chmod(0o700)
            app = repository / "signed/Clash for Mac.app"
            output = repository / "publication-prepared"
            reviewed = repository / "component-review.json"
            with patch.object(preparer, "load_pins", return_value={}), patch.object(
                preparer, "release_tool_environment", return_value={"PATH": "/usr/bin:/bin"}
            ), patch.object(
                preparer, "require_fixed_signed_app", return_value=app
            ), patch.object(
                preparer, "prepared_root", return_value=output
            ), patch.object(
                preparer, "require_fixed_path"
            ), patch.object(
                preparer,
                "verify_release_app",
                side_effect=PublicationError("typed-verifier-sentinel"),
            ) as verifier:
                with self.assertRaisesRegex(PublicationError, "typed-verifier-sentinel"):
                    preparer.prepare(repository, app, repository, reviewed, output)
            verifier.assert_called_once_with(
                repository=repository,
                environment={"PATH": "/usr/bin:/bin"},
                notarization=NotarizationCheck.LIVE,
            )

    def test_prepare_derives_build_inputs_after_app_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            candidate = ga_root(repository)
            candidate.mkdir(parents=True)
            candidate.chmod(0o700)
            app = repository / "signed/Clash for Mac.app"
            native = repository / "signed-native-products"
            output = repository / "publication-prepared"
            reviewed = repository / "component-review.json"
            with patch.object(preparer, "load_pins", return_value={}), patch.object(
                preparer, "release_tool_environment", return_value={"PATH": "/usr/bin:/bin"}
            ), patch.object(
                preparer, "require_fixed_signed_app", return_value=app
            ), patch.object(
                preparer, "prepared_root", return_value=output
            ), patch.object(
                preparer, "require_fixed_path"
            ), patch.object(
                preparer, "verify_release_app"
            ) as verifier, patch.object(
                preparer,
                "bundle_build_identity",
                return_value=SimpleNamespace(build_version=GA_BUILD),
            ) as build_identity, patch.object(
                preparer, "release_native_products_root", return_value=native
            ) as native_root, patch.object(
                preparer,
                "_require_clean_repository",
                side_effect=PublicationError("post-verifier-sentinel"),
            ):
                with self.assertRaisesRegex(PublicationError, "post-verifier-sentinel"):
                    preparer.prepare(repository, app, repository, reviewed, output)
            verifier.assert_called_once()
            build_identity.assert_called_once_with(app)
            native_root.assert_called_once_with(repository, GA_BUILD)

    def test_source_contract_keeps_the_zero_stderr_graph_runner(self) -> None:
        repository = Path("/private/tmp/release")
        source = repository / "target/sources/sing-box"
        with patch.object(
            preparer, "run", side_effect=PublicationError("source-contract-sentinel")
        ) as graph_runner, patch.object(preparer, "verify_release_app") as verifier:
            with self.assertRaisesRegex(PublicationError, "source-contract-sentinel"):
                preparer._complete_collected_graphs(
                    repository, source, {"PATH": "/usr/bin:/bin"}
                )
        graph_runner.assert_called_once()
        verifier.assert_not_called()


class GAReleaseVerifierBoundaryTests(unittest.TestCase):
    def test_prepackage_validation_uses_the_fixed_app_verifier_adapter(self) -> None:
        environment = {"PATH": "/usr/bin:/bin"}
        for notarization in NotarizationCheck:
            with self.subTest(notarization=notarization), patch.object(
                ga_release_contract, "verify_release_app"
            ) as verifier:
                ga_release_contract._validate_release_application(
                    REPOSITORY, environment, notarization=notarization
                )
                verifier.assert_called_once_with(
                    repository=REPOSITORY,
                    environment=environment,
                    notarization=notarization,
                )
        with patch.object(ga_release_contract, "verify_release_app") as verifier:
            with self.assertRaises(TypeError):
                ga_release_contract._validate_release_application(REPOSITORY, environment)
        verifier.assert_not_called()


if __name__ == "__main__":
    unittest.main()
