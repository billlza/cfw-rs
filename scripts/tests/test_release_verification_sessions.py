"""Exercise release composition with one compiler lifetime and fresh proof replays."""

from __future__ import annotations

from contextlib import contextmanager
from functools import partial
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from scripts import candidate_freeze
from scripts import ga_runtime_acceptance as runtime
from scripts import ga_runtime_acceptance_cli as runtime_cli
from scripts import production_release_evidence as production
from scripts import updater_key_possession_proof as possession
from scripts.publication import durable_file
from scripts.publication import ga_release_contract as contract
from scripts.publication.common import PublicationError
from scripts.publication.durable_file import DurabilityOutcomeUnknown
from scripts.release_executor_source import ExecutorSource, FrozenReleaseSources
from scripts.tests import test_candidate_freeze as candidate_tests
from scripts.tests import test_production_release_orchestrator as stage_tests
from scripts.tests import test_updater_key_possession_proof as possession_tests


class ReleaseVerificationSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = candidate_tests.CandidateFreezeTests(
            "test_freeze_publishes_fixed_root_and_complete_canonical_intent"
        )
        self.candidate.setUp()
        self.addCleanup(self.candidate.tearDown)
        self.repository = self.candidate.repository
        self.possession = possession_tests.PossessionFixture()
        self.addCleanup(self.possession.cleanup)
        self.stage = stage_tests.StageFixture()
        self.addCleanup(self.stage.cleanup)
        self.enterContext(patch.object(durable_file, "full_fsync", side_effect=os.fsync))

        # Reuse the real freeze fixture with a real proof document. Only signing,
        # compilation and Git/credential inputs remain external fixture boundaries.
        self.candidate.updater_possession_patch.stop()
        proof_root = self.candidate.preflight / possession.PROOF_RELATIVE
        for name in possession.PROOF_FILES:
            (proof_root / name).unlink()
        proof_root.rmdir()
        self.candidate.preflight.chmod(0o700)
        self.tauri_config = self.repository / "apps/cfw-tauri-shell/tauri.conf.json"
        self.tauri_config.parent.mkdir(parents=True)
        self.tauri_config.write_bytes(possession_tests.TAURI_CONFIG_DATA)
        possession.create_possession_proof(
            self.repository,
            source_identity_reader=self._source_identity,
            embedded_verifier=self.possession.embedded_verifier,
            process_runner=self.possession.signer,
        )
        self.enterContext(
            patch.object(
                candidate_freeze,
                "verify_possession_proof",
                new=partial(
                    possession.verify_possession_proof,
                    source_identity_reader=self._source_identity,
                    embedded_verifier=self.possession.embedded_verifier,
                ),
            )
        )
        self.frozen = self.candidate.freeze()
        self.possession.verifier_calls.clear()
        self.events: list[str] = []
        self.session_roots: list[Path] = []
        self.callbacks: list[candidate_freeze.FreezeVerifier] = []
        self.close_error: BaseException | None = None
        self.factory = self.enterContext(
            patch.object(
                candidate_freeze,
                "production_embedded_verifier_session",
                side_effect=self._compiler_session,
            )
        )

    def _source_identity(self, repository: Path) -> dict[str, str]:
        self.assertEqual(repository, self.repository)
        return dict(candidate_tests.SOURCE_IDENTITY)

    @contextmanager
    def _compiler_session(self, repository: Path):
        self.session_roots.append(repository)
        self.events.append("open")

        def replay(selected: Path, challenge: Path, signature: Path):
            self.events.append("proof")
            return self.possession.embedded_verifier(selected, challenge, signature)

        try:
            yield replay
        finally:
            self.events.append("close")
            if self.close_error is not None:
                raise self.close_error

    def _consume(
        self, repository: Path, freeze_verifier: candidate_freeze.FreezeVerifier | None
    ) -> None:
        self.assertEqual(repository, self.repository)
        self.assertIsNotNone(freeze_verifier)
        self.callbacks.append(freeze_verifier)
        self.assertEqual(freeze_verifier(repository).intent_sha256, self.frozen.intent_sha256)

    def _print(self, message: str) -> None:
        self.assertIsInstance(message, str)
        self.events.append("print")

    @contextmanager
    def _runtime_command(self, command: str, operation=None):
        def derive(repository: Path, *, freeze_verifier=None):
            self._consume(repository, freeze_verifier)
            return {"fixture": "runtime expectation"}

        def authorize(repository: Path, *, freeze_verifier=None):
            self._consume(repository, freeze_verifier)
            return {"fixture": "prepackage authorization"}

        def accept(**values):
            self.assertEqual(values["repository"], self.repository)
            self.assertEqual(values["expected"], {"fixture": "runtime expectation"})
            values["prepackage_stage_verifier"](self.repository)
            return {"adapter": {"sha256": "1" * 64}}

        selected_operation = accept if operation is None else operation
        with (
            patch.object(sys, "argv", ["ga_runtime_acceptance_cli.py", command]),
            patch("scripts.release_python_runtime.require_closed_release_runtime"),
            patch.object(runtime, "_repository", return_value=self.repository),
            patch.object(contract, "derive_runtime_expectation", side_effect=derive),
            patch.object(contract, "verify_prepackage_authorization", side_effect=authorize),
            patch.object(runtime, "validate_ga_runtime_acceptance", side_effect=selected_operation),
            patch.object(runtime, "collect_ga_runtime_acceptance", side_effect=selected_operation),
            patch.object(
                runtime,
                "recover_ga_runtime_collection",
                side_effect=operation,
                return_value=self.repository / "archived-runtime",
            ),
            patch("builtins.print", side_effect=self._print) as output,
        ):
            yield output

    @contextmanager
    def _stage_command(self, *arguments: str, prepackage=None):
        def live(repository: Path, *, freeze_verifier=None):
            self._consume(repository, freeze_verifier)
            return {"fixture": "live hosted receipt"}

        def compose(repository: Path, executor_source, *, freeze_verifier=None, **_values):
            self.assertEqual(executor_source, self.stage.executor.identity)
            self._consume(repository, freeze_verifier)
            return self.stage.prepackage_files()

        sources = FrozenReleaseSources(
            executor=self.stage.executor,
            artifact=ExecutorSource(self.repository, "a" * 40, "b" * 64),
        )
        selected_prepackage = compose if prepackage is None else prepackage
        with (
            patch.object(sys, "argv", ["production_release_evidence.py", *arguments]),
            patch.object(production, "require_closed_release_runtime"),
            patch.object(production, "_repository", return_value=self.repository),
            patch.object(production, "capture_frozen_release_sources", return_value=sources),
            patch.object(production, "require_frozen_sources_unchanged"),
            patch.object(contract, "_current_stage_executor", return_value=self.stage.executor),
            patch.object(contract, "require_executor_unchanged"),
            patch.object(contract, "identity_at_commit", return_value=self.stage.executor.identity),
            patch.object(contract, "live_verify_hosted_ci_receipt", side_effect=live),
            patch.object(contract, "_prepackage_files", side_effect=selected_prepackage),
            patch("builtins.print", side_effect=self._print) as output,
        ):
            yield output

    def test_runtime_reuses_one_session_for_both_contracts_and_prints_after_close(self) -> None:
        with self._runtime_command("verify") as output:
            runtime_cli.main()
        self.factory.assert_called_once_with(self.repository)
        self.assertEqual(len(self.possession.verifier_calls), 2)
        self.assertIs(self.callbacks[0], self.callbacks[1])
        self.assertEqual(self.events, ["open", "proof", "proof", "close", "print"])
        self.assertIn("GA runtime acceptance verified", output.call_args.args[0])

    def test_new_runtime_operation_opens_new_session_and_old_callback_is_closed(self) -> None:
        for _attempt in range(2):
            with self._runtime_command("verify"):
                runtime_cli.main()
        self.assertEqual(self.factory.call_count, 2)
        self.assertEqual(len(self.possession.verifier_calls), 4)
        self.assertIsNot(self.callbacks[0], self.callbacks[2])
        for callback in self.callbacks:
            with self.assertRaises(candidate_freeze.CandidateFreezeError) as closed:
                callback(self.repository)
            self.assertEqual(closed.exception.code, "verifier_session_closed")
        self.assertEqual(len(self.possession.verifier_calls), 4)

    def test_runtime_rejects_another_artifact_without_using_the_shared_verifier(self) -> None:
        def changed_artifact(**values):
            values["prepackage_stage_verifier"](self.stage.repository)

        def authorize(repository: Path, *, freeze_verifier):
            return freeze_verifier(repository)

        with self._runtime_command("verify", changed_artifact) as output, patch.object(
            contract, "verify_prepackage_authorization", side_effect=authorize
        ), self.assertRaises(SystemExit) as rejected:
            runtime_cli.main()
        self.assertIsInstance(rejected.exception.__cause__, candidate_freeze.CandidateFreezeError)
        self.assertEqual(rejected.exception.__cause__.code, "verifier_session_repository_mismatch")
        self.assertEqual(self.session_roots, [self.repository])
        self.assertEqual(len(self.possession.verifier_calls), 1)
        output.assert_not_called()

    def test_runtime_source_drift_is_rejected_by_fresh_possession_validation(self) -> None:
        def changed_source(**values):
            self.tauri_config.write_bytes(b'{"plugins":{"updater":{"pubkey":"changed"}}}\n')
            values["prepackage_stage_verifier"](self.repository)

        with self._runtime_command("verify", changed_source) as output, self.assertRaises(
            SystemExit
        ) as rejected:
            runtime_cli.main()
        self.assertIsInstance(rejected.exception.__cause__, candidate_freeze.CandidateFreezeError)
        quarantined = rejected.exception.__cause__
        self.assertEqual(quarantined.code, "candidate_freeze_quarantined")
        self.assertEqual(quarantined.__cause__.code, "updater_key_possession_invalid")
        self.assertIsInstance(quarantined.__cause__.__cause__, possession.UpdaterKeyPossessionError)
        self.assertIn("Tauri configuration", str(quarantined.__cause__.__cause__))
        self.assertEqual(len(self.callbacks), 2)
        self.assertEqual(len(self.possession.verifier_calls), 2)
        self.assertEqual(self.events[-1], "close")
        output.assert_not_called()

    def test_runtime_read_only_cleanup_failure_cannot_report_success(self) -> None:
        self.close_error = possession.UpdaterKeyPossessionError("fixture close failed")
        with self._runtime_command("verify") as output, self.assertRaises(SystemExit) as rejected:
            runtime_cli.main()
        self.assertIsInstance(rejected.exception.__cause__, candidate_freeze.CandidateFreezeError)
        self.assertNotIsInstance(rejected.exception.__cause__, DurabilityOutcomeUnknown)
        output.assert_not_called()

    def test_runtime_session_entry_failure_does_not_run_the_operation(self) -> None:
        self.factory.side_effect = possession.UpdaterKeyPossessionOperationalError("start")
        with self._runtime_command("verify") as output, patch.object(
            runtime, "main"
        ) as operation, self.assertRaises(SystemExit) as rejected:
            runtime_cli.main()
        self.assertIsInstance(rejected.exception.__cause__, candidate_freeze.CandidateFreezeError)
        self.assertEqual(rejected.exception.__cause__.code, "updater_verifier_unavailable")
        operation.assert_not_called()
        output.assert_not_called()

    def test_completed_runtime_mutations_with_cleanup_failure_are_unknown(self) -> None:
        self.close_error = possession.UpdaterKeyPossessionError("fixture close failed")
        for command in ("collect", "recover"):
            with self.subTest(command=command), self._runtime_command(command) as output, self.assertRaises(
                SystemExit
            ) as rejected:
                runtime_cli.main()
            self.assertIsInstance(rejected.exception.__cause__, DurabilityOutcomeUnknown)
            output.assert_not_called()

    def test_runtime_primary_failure_is_rethrown_after_successful_cleanup(self) -> None:
        original = ValueError("fixture original cause")
        primary = runtime.GARuntimeAcceptanceError("fixture runtime primary")
        primary.__cause__ = original

        def failed(**_values):
            raise primary

        with self._runtime_command("verify", failed) as output, self.assertRaises(SystemExit) as rejected:
            runtime_cli.main()
        self.assertIs(rejected.exception.__cause__, primary)
        self.assertIs(primary.__cause__, original)
        self.assertEqual(self.events[-1], "close")
        output.assert_not_called()

    def test_runtime_primary_and_cleanup_failures_preserve_cause_and_both_diagnostics(self) -> None:
        original = ValueError("fixture original cause")
        primary = runtime.GARuntimeAcceptanceError("fixture runtime primary")
        primary.__cause__ = original

        def failed(**_values):
            raise primary

        self.close_error = possession.UpdaterKeyPossessionError("fixture close failed")
        with self._runtime_command("verify", failed) as output, self.assertRaises(SystemExit) as rejected:
            runtime_cli.main()
        runtime_exit = rejected.exception.__cause__
        self.assertIsInstance(runtime_exit, SystemExit)
        self.assertIs(runtime_exit.__cause__, primary)
        self.assertIs(primary.__cause__, original)
        self.assertIn("fixture runtime primary", str(rejected.exception))
        self.assertIn("secondary frozen candidate verifier cleanup failure", str(rejected.exception))
        self.assertEqual(self.events[-1], "close")
        output.assert_not_called()

    def test_new_raw_publication_before_body_and_cleanup_failures_is_unknown(self) -> None:
        _adapter, raw_root = runtime._fixed_paths(self.repository)
        original = ValueError("fixture original cause")
        primary = runtime.GARuntimeAcceptanceError("fixture after raw publication")
        primary.__cause__ = original

        def publish_then_fail(**_values):
            raw_root.mkdir(parents=True, mode=0o700)
            raise primary

        self.close_error = possession.UpdaterKeyPossessionError("fixture close failed")
        with self._runtime_command("collect", publish_then_fail) as output, self.assertRaises(
            SystemExit
        ) as rejected:
            runtime_cli.main()
        unknown = rejected.exception.__cause__
        self.assertIsInstance(unknown, DurabilityOutcomeUnknown)
        self.assertIs(unknown.__cause__.__cause__, primary)
        self.assertIs(primary.__cause__, original)
        self.assertTrue(raw_root.is_dir())
        self.assertIn("fixture after raw publication", str(rejected.exception))
        self.assertIn("secondary frozen candidate verifier cleanup failure", str(rejected.exception))
        output.assert_not_called()

    def test_existing_raw_evidence_does_not_turn_pre_mutation_failure_into_unknown(self) -> None:
        _adapter, raw_root = runtime._fixed_paths(self.repository)
        raw_root.mkdir(parents=True, mode=0o700)

        def fail_before_mutation(**_values):
            raise runtime.GARuntimeAcceptanceError("fixture pre-mutation failure")

        self.close_error = possession.UpdaterKeyPossessionError("fixture close failed")
        with self._runtime_command("collect", fail_before_mutation) as output, self.assertRaises(
            SystemExit
        ) as rejected:
            runtime_cli.main()
        self.assertIsInstance(rejected.exception.__cause__, SystemExit)
        self.assertNotIsInstance(rejected.exception.__cause__, DurabilityOutcomeUnknown)
        self.assertTrue(raw_root.is_dir())
        output.assert_not_called()

    def test_unobservable_runtime_publication_after_close_failure_is_unknown(self) -> None:
        self.close_error = possession.UpdaterKeyPossessionError("fixture close failed")
        with self._runtime_command("collect") as output, patch.object(
            runtime_cli,
            "_existing_runtime_outputs",
            side_effect=[frozenset(), PermissionError("fixture evidence became unreadable")],
        ) as observation, self.assertRaises(SystemExit) as rejected:
            runtime_cli.main()
        self.assertIsInstance(rejected.exception.__cause__, DurabilityOutcomeUnknown)
        self.assertIn("runtime publication observation failed", str(rejected.exception))
        self.assertIn("fixture evidence became unreadable", str(rejected.exception))
        self.assertEqual(observation.call_count, 2)
        output.assert_not_called()

    def test_runtime_body_close_and_observation_failures_preserve_every_diagnostic(self) -> None:
        original = ValueError("fixture original cause")
        primary = runtime.GARuntimeAcceptanceError("fixture runtime primary")
        primary.__cause__ = original

        def failed(**_values):
            raise primary

        self.close_error = candidate_freeze.CandidateFreezeError(
            "fixture_close_failure", "fixture close failed"
        )
        self.close_error.add_note("fixture inner verifier cleanup failed")
        with self._runtime_command("collect", failed) as output, patch.object(
            runtime_cli,
            "_existing_runtime_outputs",
            side_effect=[frozenset(), PermissionError("fixture evidence became unreadable")],
        ), self.assertRaises(SystemExit) as rejected:
            runtime_cli.main()
        unknown = rejected.exception.__cause__
        self.assertIsInstance(unknown, DurabilityOutcomeUnknown)
        self.assertIs(unknown.__cause__.__cause__, primary)
        self.assertIs(primary.__cause__, original)
        diagnostic = str(rejected.exception)
        self.assertIn("fixture runtime primary", diagnostic)
        self.assertIn("fixture close failed", diagnostic)
        self.assertIn("fixture inner verifier cleanup failed", diagnostic)
        self.assertIn("fixture evidence became unreadable", diagnostic)
        output.assert_not_called()

    def test_self_check_runs_real_dispatch_without_opening_a_production_session(self) -> None:
        with patch.object(sys, "argv", ["ga_runtime_acceptance_cli.py", "self-check"]), patch.object(
            runtime, "self_check"
        ) as check, patch("builtins.print") as output:
            runtime_cli.main()
        check.assert_called_once_with()
        self.factory.assert_not_called()
        output.assert_called_once_with("GA runtime acceptance source contract verified")

    def test_stage_publish_and_postverify_share_one_session_and_replay_each_proof(self) -> None:
        with self._stage_command("prepackage") as output:
            production.main()
        self.factory.assert_called_once_with(self.repository)
        self.assertNotEqual(self.repository, self.stage.executor.repository)
        self.assertEqual(len(self.possession.verifier_calls), 3)
        self.assertEqual(len(self.callbacks), 3)
        self.assertTrue(all(callback is self.callbacks[0] for callback in self.callbacks))
        self.assertEqual(self.events, ["open", "proof", "proof", "proof", "close", "print"])
        self.assertTrue((self.repository / contract.PREPACKAGE_OUTPUT / "manifest.json").is_file())
        self.assertIn("prepackage GA seal verified", output.call_args.args[0])

    def test_stage_verify_after_seal_uses_a_new_session(self) -> None:
        with self._stage_command("prepackage"):
            production.main()
        with self._stage_command("verify", "prepackage"):
            production.main()
        self.assertEqual(self.factory.call_count, 2)
        self.assertEqual(len(self.possession.verifier_calls), 4)
        self.assertIsNot(self.callbacks[0], self.callbacks[-1])

    def test_stage_close_failure_after_actual_publication_is_unknown_and_silent(self) -> None:
        self.close_error = possession.UpdaterKeyPossessionError("fixture close failed")
        with self._stage_command("prepackage") as output, self.assertRaises(SystemExit) as rejected:
            production.main()
        self.assertIsInstance(rejected.exception.__cause__, DurabilityOutcomeUnknown)
        self.assertTrue((self.repository / contract.PREPACKAGE_OUTPUT / "manifest.json").is_file())
        self.assertEqual(len(self.possession.verifier_calls), 3)
        output.assert_not_called()

    def test_stage_source_drift_during_postverify_cannot_leave_a_success(self) -> None:
        calls = 0

        def compose(repository, _source, *, freeze_verifier, **_values):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.tauri_config.write_bytes(b'{"plugins":{"updater":{"pubkey":"changed"}}}\n')
                # Exercise the real contract's freeze-error mapping before any
                # missing fixture package inputs could be read.
                contract._verified_prepackage_inputs(repository, freeze_verifier=freeze_verifier)
                self.fail("changed Tauri source passed prepackage proof validation")
            self._consume(repository, freeze_verifier)
            return self.stage.prepackage_files()

        with self._stage_command("prepackage", prepackage=compose) as output, self.assertRaises(
            SystemExit
        ) as rejected:
            production.main()
        self.assertIsInstance(rejected.exception.__cause__, DurabilityOutcomeUnknown)
        quarantined = rejected.exception.__cause__.__cause__.__cause__
        self.assertEqual(quarantined.code, "candidate_freeze_quarantined")
        self.assertEqual(quarantined.__cause__.code, "updater_key_possession_invalid")
        self.assertIn("Tauri configuration", str(quarantined.__cause__.__cause__))
        self.assertTrue((self.repository / contract.PREPACKAGE_OUTPUT / "manifest.json").is_file())
        self.assertEqual(calls, 2)
        self.assertEqual(len(self.possession.verifier_calls), 3)
        output.assert_not_called()

    def test_stage_primary_and_cleanup_failures_preserve_original_cause(self) -> None:
        original = ValueError("fixture original cause")
        primary = PublicationError("fixture stage primary")
        primary.__cause__ = original

        def failed(*_arguments, **_values):
            raise primary

        self.close_error = possession.UpdaterKeyPossessionError("fixture close failed")
        with self._stage_command("prepackage", prepackage=failed) as output, self.assertRaises(
            SystemExit
        ) as rejected:
            production.main()
        self.assertIs(rejected.exception.__cause__, primary)
        self.assertIs(primary.__cause__, original)
        self.assertTrue(any("cleanup failure" in note for note in primary.__notes__))
        self.assertFalse((self.repository / contract.PREPACKAGE_OUTPUT).exists())
        output.assert_not_called()


if __name__ == "__main__":
    unittest.main()
