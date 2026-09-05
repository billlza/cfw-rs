from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import candidate_freeze
from scripts import dmg_notarization_transaction as dmg
from scripts import release_artifact_set as artifacts
from scripts import release_artifact_set_cli as artifact_cli
from scripts.notarization_transaction import NOTARY_PROFILE, TransactionError
from scripts.publication.common import PublicationError
from scripts.publication.durable_file import DurabilityOutcomeUnknown
from scripts.publication import ga_release_contract as contract
from scripts.tests import test_release_artifact_transaction as artifact_fixture
from scripts.tests.test_release_artifact_transaction import (
    CLOCK,
    SEALED_SOURCE_IDENTITY,
    SOURCE_IDENTITY,
    SUBMISSION_ID,
    publisher,
    verified_cargo_fixture,
)


class ReleaseVerifierCommandSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name).resolve()
        self.stdout = io.StringIO()
        self.events: list[str] = []
        self.freeze = Mock(name="full_freeze_verifier")
        self.close_error: BaseException | None = None

    @contextmanager
    def session(self, repository: Path):
        self.assertEqual(repository, self.repository)
        self.events.append("session-open")
        try:
            yield self.freeze
        finally:
            self.assertEqual(self.stdout.getvalue(), "")
            self.events.append("session-close")
            if self.close_error is not None:
                raise self.close_error

    def artifact_arguments(self, command: str) -> list[str]:
        arguments = [
            str(Path(artifact_cli.__file__)),
            command,
            "--repository",
            str(self.repository),
            "--version",
            "0.4.0",
        ]
        if command in {"verify-dmg", "verify-updater"}:
            arguments.extend(("--directory", str(self.repository / "set")))
        elif command == "seal-updater":
            destination = artifacts._updater_set_root(self.repository)
            arguments.extend((
                "--staging", str(destination.parent / "updater-stage.fixture"),
                "--destination", str(destination),
            ))
        return arguments

    def run_artifact(self, command: str, execute: Mock) -> None:
        with (
            patch.object(sys, "argv", self.artifact_arguments(command)),
            patch("scripts.release_python_runtime.require_closed_release_runtime"),
            patch.object(candidate_freeze, "frozen_candidate_verification_session", self.session),
            patch.object(artifacts, "_execute_command", execute),
            redirect_stdout(self.stdout),
        ):
            artifact_cli.main()

    def test_artifact_success_is_printed_only_after_session_close(self) -> None:
        def execute(arguments: argparse.Namespace, **callbacks):
            self.events.append("execute")
            self.assertEqual(arguments.repository, self.repository)
            for _ in range(3):
                callbacks["prepackage_stage_verifier"](self.repository)
            callbacks["publication_stage_verifier"](self.repository)
            return ("verified artifact",)

        with (
            patch.object(contract, "verify_prepackage_authorization") as prepackage,
            patch.object(contract, "verify_publication_authorization") as publication,
        ):
            self.run_artifact("verify-dmg", Mock(side_effect=execute))
        self.assertEqual(self.events, ["session-open", "execute", "session-close"])
        self.assertEqual(prepackage.call_count, 3)
        for call in prepackage.call_args_list:
            self.assertEqual(call.args, (self.repository,))
            self.assertEqual(call.kwargs, {"freeze_verifier": self.freeze})
        publication.assert_called_once_with(self.repository, freeze_verifier=self.freeze)
        self.assertEqual(self.stdout.getvalue(), "verified artifact\n")

    def test_artifact_read_only_close_failure_never_prints_success(self) -> None:
        self.close_error = candidate_freeze.CandidateFreezeError(
            "updater_key_possession_invalid", "late verifier source drift"
        )
        with self.assertRaises(SystemExit) as raised:
            self.run_artifact("verify-dmg", Mock(return_value=("must not print",)))
        self.assertEqual(self.stdout.getvalue(), "")
        self.assertIsInstance(raised.exception.__cause__, PublicationError)
        self.assertNotIsInstance(raised.exception.__cause__, DurabilityOutcomeUnknown)
        self.assertIs(raised.exception.__cause__.__cause__, self.close_error)

    def test_artifact_published_set_close_failure_is_unknown(self) -> None:
        self.close_error = OSError("private verifier cleanup failed")
        with self.assertRaises(SystemExit) as raised:
            self.run_artifact("seal-release", Mock(return_value=("must not print",)))
        self.assertEqual(self.stdout.getvalue(), "")
        self.assertIsInstance(raised.exception.__cause__, DurabilityOutcomeUnknown)
        self.assertIs(raised.exception.__cause__.__cause__, self.close_error)

    def test_artifact_primary_and_cleanup_failures_preserve_original_cause(self) -> None:
        original_cause = ValueError("malformed retained proof")
        primary = artifacts.ArtifactSetError("signature validation failed")
        primary.__cause__ = original_cause
        self.close_error = OSError("private verifier cleanup failed")
        with self.assertRaises(SystemExit) as raised:
            self.run_artifact("verify-dmg", Mock(side_effect=primary))
        self.assertIs(raised.exception.__cause__, primary)
        self.assertIs(primary.__cause__, original_cause)
        self.assertIn("secondary artifact verifier session cleanup failure", str(raised.exception))
        self.assertIn("private verifier cleanup failed", str(raised.exception))
        self.assertEqual(self.stdout.getvalue(), "")

    def test_artifact_session_start_failure_does_not_execute_command(self) -> None:
        execute = Mock(return_value=("must not print",))
        error = candidate_freeze.CandidateFreezeError(
            "updater_verifier_unavailable", "verifier build timed out"
        )
        with (
            patch.object(sys, "argv", self.artifact_arguments("verify-dmg")),
            patch("scripts.release_python_runtime.require_closed_release_runtime"),
            patch.object(candidate_freeze, "frozen_candidate_verification_session", side_effect=error),
            patch.object(artifacts, "_execute_command", execute),
            redirect_stdout(self.stdout),
            self.assertRaises(SystemExit),
        ):
            artifact_cli.main()
        execute.assert_not_called()
        self.assertEqual(self.stdout.getvalue(), "")

    def test_artifact_new_output_then_primary_and_close_failure_is_unknown(self) -> None:
        primary = artifacts.ArtifactSetError("post-publication input drift")
        self.close_error = OSError("private verifier cleanup failed")
        destination = artifacts._distribution_set_root(self.repository)

        def execute(_arguments, **_callbacks):
            destination.mkdir(parents=True)
            raise primary

        with self.assertRaises(SystemExit) as raised:
            self.run_artifact("seal-release", Mock(side_effect=execute))
        self.assertIsInstance(raised.exception.__cause__, DurabilityOutcomeUnknown)
        self.assertIs(raised.exception.__cause__.__cause__, primary)
        self.assertTrue(destination.is_dir())
        self.assertEqual(self.stdout.getvalue(), "")

    def test_artifact_preexisting_output_does_not_relabel_primary_failure(self) -> None:
        artifacts._distribution_set_root(self.repository).mkdir(parents=True)
        primary = artifacts.ArtifactSetError("existing release set is invalid")
        self.close_error = OSError("private verifier cleanup failed")
        with self.assertRaises(SystemExit) as raised:
            self.run_artifact("seal-release", Mock(side_effect=primary))
        self.assertIs(raised.exception.__cause__, primary)
        self.assertEqual(self.stdout.getvalue(), "")

    def test_artifact_unreadable_new_publication_state_preserves_unknown(self) -> None:
        primary = artifacts.ArtifactSetError("post-publication verification failed")
        self.close_error = OSError("private verifier cleanup failed")
        destination = artifacts._distribution_set_root(self.repository)
        original_lstat = Path.lstat
        reads = 0

        def lstat(path: Path, *args, **kwargs):
            nonlocal reads
            if path == destination:
                reads += 1
                if reads > 1:
                    raise OSError("publication directory could not be observed")
            return original_lstat(path, *args, **kwargs)

        with patch.object(Path, "lstat", lstat), self.assertRaises(SystemExit) as raised:
            self.run_artifact("seal-release", Mock(side_effect=primary))
        self.assertIsInstance(raised.exception.__cause__, DurabilityOutcomeUnknown)
        self.assertIs(raised.exception.__cause__.__cause__, primary)
        self.assertIn("publication observation failed", str(raised.exception))
        self.assertEqual(self.stdout.getvalue(), "")

    def test_updater_cli_closes_both_sessions_before_reporting_success(self) -> None:
        producer = Mock(name="archive_verifier")

        @contextmanager
        def archive_session(repository: Path):
            self.assertEqual(repository, self.repository)
            self.events.append("archive-open")
            yield producer
            self.assertEqual(self.stdout.getvalue(), "")
            self.events.append("archive-close")

        def execute(_arguments, **callbacks):
            self.assertIs(callbacks["updater_verification_producer"], producer)
            self.events.append("execute")
            return ("updater published",)

        with patch.object(artifacts, "_updater_verification_session", archive_session):
            self.run_artifact("seal-updater", Mock(side_effect=execute))
        self.assertEqual(self.events, [
            "session-open", "archive-open", "execute", "archive-close", "session-close",
        ])
        self.assertEqual(self.stdout.getvalue(), "updater published\n")

    def test_updater_primary_and_both_session_failures_remain_visible(self) -> None:
        cause = ValueError("retained signature is invalid")
        primary = artifacts.ArtifactSetError("signature validation failed")
        primary.__cause__ = cause

        @contextmanager
        def proof_session(repository: Path):
            self.assertEqual(repository, self.repository)
            try:
                yield Mock(name="embedded_proof_verifier")
            finally:
                raise OSError("proof build cleanup failed")

        @contextmanager
        def archive_session(repository: Path):
            self.assertEqual(repository, self.repository)
            try:
                yield Mock(name="archive_verifier")
            finally:
                raise artifacts.ArtifactSetError("archive build cleanup failed")

        with (
            patch.object(sys, "argv", self.artifact_arguments("seal-updater")),
            patch("scripts.release_python_runtime.require_closed_release_runtime"),
            patch.object(candidate_freeze, "production_embedded_verifier_session", proof_session),
            patch.object(artifacts, "_updater_verification_session", archive_session),
            patch.object(artifacts, "_execute_command", side_effect=primary),
            redirect_stdout(self.stdout),
            self.assertRaises(SystemExit) as raised,
        ):
            artifact_cli.main()
        self.assertIs(raised.exception.__cause__, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertIn("archive build cleanup failed", str(raised.exception))
        self.assertIn("proof build cleanup failed", str(raised.exception))
        self.assertEqual(self.stdout.getvalue(), "")

    def dmg_arguments(self, command: str) -> list[str]:
        arguments = [
            str(Path(dmg.__file__)), command,
            "--repository", str(self.repository),
            "--version", "0.4.0", "--build-number", "40043",
            "--notary-profile", NOTARY_PROFILE,
        ]
        if command == "start":
            arguments.extend(("--dmg", str(self.repository / "candidate.dmg")))
        elif command == "recover":
            arguments.extend(("--submission-id", SUBMISSION_ID))
        return arguments

    def run_dmg(self, command: str, operation: Mock) -> None:
        function = {
            "preflight": "preflight_new",
            "start": "execute_transaction",
            "recover": "recover_transaction",
        }[command]
        with (
            patch.object(sys, "argv", self.dmg_arguments(command)),
            patch.object(dmg, "current_identity", return_value=SOURCE_IDENTITY),
            patch.object(dmg, "frozen_candidate_verification_session", self.session),
            patch.object(dmg, function, operation),
            redirect_stdout(self.stdout),
        ):
            dmg.main()

    def test_dmg_preflight_replays_share_session_and_close_before_success(self) -> None:
        def preflight(context, stage_verifier):
            for _ in range(2):
                stage_verifier(context.repository)
            self.events.append("preflight")

        with patch.object(dmg, "verify_prepackage_authorization") as stage:
            self.run_dmg("preflight", Mock(side_effect=preflight))
        self.assertEqual(self.events, ["session-open", "preflight", "session-close"])
        self.assertEqual(stage.call_count, 2)
        for call in stage.call_args_list:
            self.assertEqual(call.kwargs, {"freeze_verifier": self.freeze})
        self.assertEqual(self.stdout.getvalue(), "DMG notarization transaction preflight ok\n")

    def test_direct_dmg_entrypoint_shares_the_contract_freeze_module_identity(self) -> None:
        code = (
            "import runpy, sys; "
            "entry = runpy.run_path(sys.argv[1], run_name='direct_entry'); "
            "from scripts import candidate_freeze; "
            "assert entry['frozen_candidate_verification_session'] "
            "is candidate_freeze.frozen_candidate_verification_session; "
            "assert entry['CandidateFreezeError'] is candidate_freeze.CandidateFreezeError"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-W", "error", "-c", code, str(Path(dmg.__file__).resolve())],
            cwd=self.repository, capture_output=True, check=False, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")

    def test_dmg_preflight_close_failure_is_known_read_failure(self) -> None:
        self.close_error = candidate_freeze.CandidateFreezeError(
            "updater_key_possession_invalid", "late verifier source drift"
        )
        with self.assertRaises(SystemExit) as raised:
            self.run_dmg("preflight", Mock())
        self.assertIs(raised.exception.__cause__, self.close_error)
        self.assertEqual(self.stdout.getvalue(), "")

    def test_dmg_start_and_recovery_close_failure_remain_unknown(self) -> None:
        for command in ("start", "recover"):
            with self.subTest(command=command):
                self.close_error = OSError("verifier cleanup failed")
                with self.assertRaises(SystemExit) as raised:
                    self.run_dmg(command, Mock(return_value=self.repository / "published"))
                error = raised.exception.__cause__
                self.assertIsInstance(error, TransactionError)
                self.assertEqual(error.code, "dmg_verifier_close_outcome_unknown")
                self.assertEqual(error.terminal_state, "outcome_unknown")
                self.assertIs(error.__cause__, self.close_error)
                self.assertEqual(self.stdout.getvalue(), "")

    def test_dmg_primary_unknown_and_cleanup_failure_preserve_both(self) -> None:
        cause = OSError("submission reply was lost")
        primary = TransactionError(
            "submission_outcome_unknown", "submission outcome is unknown",
            terminal_state="outcome_unknown",
        )
        primary.__cause__ = cause
        self.close_error = OSError("verifier cleanup failed")
        with self.assertRaises(SystemExit) as raised:
            self.run_dmg("start", Mock(side_effect=primary))
        self.assertIs(raised.exception.__cause__, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertIn("secondary DMG verifier session cleanup failure", str(raised.exception))
        self.assertEqual(self.stdout.getvalue(), "")

    def test_dmg_new_output_then_primary_and_close_failure_is_unknown(self) -> None:
        primary = artifacts.ArtifactSetError("post-publication input drift")
        self.close_error = OSError("verifier cleanup failed")
        destinations: list[Path] = []

        def execute(context, **_callbacks):
            context.final_root.mkdir(parents=True)
            destinations.append(context.final_root)
            raise primary

        with self.assertRaises(SystemExit) as raised:
            self.run_dmg("start", Mock(side_effect=execute))
        error = raised.exception.__cause__
        self.assertIsInstance(error, TransactionError)
        self.assertEqual(error.terminal_state, "outcome_unknown")
        self.assertIs(error.__cause__, primary)
        self.assertTrue(destinations[0].is_dir())
        self.assertEqual(self.stdout.getvalue(), "")

    def test_dmg_preexisting_output_does_not_relabel_primary_failure(self) -> None:
        context = dmg.DmgContext(
            repository=self.repository, version="0.4.0", build_number="40043",
            notary_profile=NOTARY_PROFILE, source_identity=SOURCE_IDENTITY,
        )
        context.final_root.mkdir(parents=True)
        primary = artifacts.ArtifactSetError("existing DMG set is invalid")
        self.close_error = OSError("verifier cleanup failed")
        with self.assertRaises(SystemExit) as raised:
            self.run_dmg("recover", Mock(side_effect=primary))
        self.assertIs(raised.exception.__cause__, primary)
        self.assertEqual(self.stdout.getvalue(), "")

    def test_dmg_unreadable_new_publication_state_preserves_unknown(self) -> None:
        context = dmg.DmgContext(
            repository=self.repository, version="0.4.0", build_number="40043",
            notary_profile=NOTARY_PROFILE, source_identity=SOURCE_IDENTITY,
        )
        primary = artifacts.ArtifactSetError("post-publication verification failed")
        self.close_error = OSError("verifier cleanup failed")
        original_lstat = Path.lstat
        reads = 0

        def lstat(path: Path, *args, **kwargs):
            nonlocal reads
            if path == context.final_root:
                reads += 1
                if reads > 1:
                    raise OSError("publication directory could not be observed")
            return original_lstat(path, *args, **kwargs)

        with patch.object(Path, "lstat", lstat), self.assertRaises(SystemExit) as raised:
            self.run_dmg("start", Mock(side_effect=primary))
        error = raised.exception.__cause__
        self.assertIsInstance(error, TransactionError)
        self.assertEqual(error.terminal_state, "outcome_unknown")
        self.assertIs(error.__cause__, primary)
        self.assertIn("publication observation failed", str(raised.exception))
        self.assertEqual(self.stdout.getvalue(), "")


class UpdaterProducerSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = artifact_fixture.UpdaterArtifactSetTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def test_updater_sealing_reuses_one_build_for_all_three_real_replays(self) -> None:
        fixture = self.fixture
        builds: list[Path] = []

        @contextmanager
        def compiled(repository: Path):
            builds.append(repository)
            yield fixture.verifier_build

        with (
            patch.object(artifacts, "_compiled_release_verifier", compiled),
            patch.object(
                artifacts,
                "_invoke_release_verifier",
                wraps=artifacts._invoke_release_verifier,
            ) as invoke,
            verified_cargo_fixture(fixture.verifier_build),
        ):
            with artifacts._updater_verification_session(fixture.root) as producer:
                destination = artifacts.seal_updater_set(
                    fixture.staging, fixture.destination,
                    version="0.4.0", source_identity=SEALED_SOURCE_IDENTITY,
                    sealed_at=CLOCK, repository=fixture.root, publisher=publisher,
                    prepackage_stage_verifier=fixture.prepackage_stage,
                    updater_verification_producer=producer,
                )
                self.assertEqual(invoke.call_count, 3)
                artifacts.seal_updater_set(
                    fixture.staging, fixture.destination,
                    version="0.4.0", source_identity=SEALED_SOURCE_IDENTITY,
                    sealed_at=CLOCK, repository=fixture.root, publisher=publisher,
                    prepackage_stage_verifier=fixture.prepackage_stage,
                    updater_verification_producer=producer,
                )
                self.assertEqual(invoke.call_count, 5)
        self.assertEqual(builds, [fixture.root])
        self.assertEqual(destination, fixture.destination)
        self.assertFalse(fixture.staging.exists())


if __name__ == "__main__":
    unittest.main()
