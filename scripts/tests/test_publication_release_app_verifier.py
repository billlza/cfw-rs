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
from scripts.publication.release_app_verifier import verify_release_app
from scripts.tests.release_app_verifier_fixture import (
    complete_verifier_stderr,
    complete_verifier_stdout,
)


REPOSITORY = Path("/private/tmp/release")
APP = REPOSITORY / "target/candidates/0.4.0/ga/40038/signed/Clash for Mac.app"
NATIVE_PRODUCTS = (
    REPOSITORY
    / "target/candidates/0.4.0/ga/40038/signing-output/signed-native-products"
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

    def invoke_verifier(self) -> None:
        return verify_release_app(
            repository=REPOSITORY,
            environment={"PATH": "/usr/bin:/bin"},
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

    @patch("scripts.publication.release_app_verifier.run_bounded_process")
    def test_bounded_process_failures_are_typed(self, runner: object) -> None:
        for reason, message in (
            ("timeout", "timed out"),
            ("output-limit", "exceeded its fixed bound"),
            ("start", "closed process boundary"),
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
            )

    def test_prepare_derives_build_inputs_after_app_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
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
                return_value=SimpleNamespace(build_version="40038"),
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
            native_root.assert_called_once_with(repository, "40038")

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
        with patch.object(ga_release_contract, "verify_release_app") as verifier:
            ga_release_contract._validate_release_application(REPOSITORY, environment)
        verifier.assert_called_once_with(
            repository=REPOSITORY,
            environment=environment,
        )


if __name__ == "__main__":
    unittest.main()
