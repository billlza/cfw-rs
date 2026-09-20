from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import signing_attempt_transaction as transaction
from scripts import signing_reconciliation as reconciliation
from scripts.publication.common import PublicationError, canonical_json
from scripts.release_executor_source import ExecutorSource, ExecutorSourceError
from scripts.tests.test_signing_attempt_transaction import SigningAttemptFixture


class SigningReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SigningAttemptFixture()
        self.addCleanup(self.fixture.cleanup)

        def fail_publish_ready(repository: Path, output: Path) -> dict[str, str]:
            if output.name == transaction.PUBLISH_READY_NAME:
                raise transaction.SigningTransformationError("injected post-verified replay failure")
            return self.fixture.transformation_verify(repository, output)

        with self.assertRaisesRegex(transaction.SigningAttemptError, "private signing transformation failed"):
            self.fixture.run(resume=False, transformation_verifier=fail_publish_ready)
        self.original = self.fixture.load("00000001")
        self.original_records = {
            path.name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
            for path in self.original.root.glob("*.json")
        }
        self.original_output = {
            str(path.relative_to(self.original.publish_ready)): (path.read_bytes(), path.stat().st_ino)
            for path in self.original.publish_ready.rglob("*") if path.is_file()
        }
        self.executor_root = self.fixture.repository / "executor"
        self.executor_root.mkdir()
        self.executor = ExecutorSource(self.executor_root, "1" * 40, "2" * 64)
        self.request = reconciliation.ReconciliationRequest(
            self.executor_root,
            str(self.original.events[-1]["event_sha256"]),
            transaction._sha256_file(self.original.publish_ready / transaction.TRANSFORMATION_RECEIPT_NAME),
        )
        self.root = self.fixture.root / reconciliation.RELATIVE_ROOT
        self.canonical = self.fixture.root / transaction.SIGNING_OUTPUT_RELATIVE
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(transaction, "capture_executor_source", return_value=self.executor))
        self.historical = self.stack.enter_context(patch.object(transaction, "require_historical_executor"))
        self.unchanged = self.stack.enter_context(patch.object(transaction, "require_executor_unchanged"))

    def run_reconciliation(self, **overrides) -> Path:
        def forbidden(*_args: object) -> object:
            self.fail("read-only recovery called a signing helper, receipt creator or signing admission")

        arguments = {
            "resume": True,
            "reconciliation": self.request,
            "helper": forbidden,
            "transformation_creator": forbidden,
            "live_readiness": forbidden,
            **overrides,
        }
        return self.fixture.run(**arguments)

    def assert_original_records_unchanged(self) -> None:
        self.assertEqual(self.fixture.load("00000001").events, self.original.events)
        self.assertEqual({
            path.name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
            for path in self.original.root.glob("*.json")
        }, self.original_records)

    def read_result(self, sequence: int) -> dict[str, object]:
        return json.loads((self.root / f"result-{sequence:08d}.json").read_bytes())

    def test_reconciles_exact_output_without_resigning_or_rewriting_failed_history(self) -> None:
        output = self.run_reconciliation()
        self.assertEqual(output, self.canonical)
        self.assertFalse(self.original.publish_ready.exists())
        self.assertEqual({
            str(path.relative_to(output)): (path.read_bytes(), path.stat().st_ino)
            for path in output.rglob("*") if path.is_file()
        }, self.original_output)
        self.assert_original_records_unchanged()
        self.assertEqual(self.read_result(1)["status"], "passed")
        self.assertTrue((self.root / "completed.json").is_file())
        intent = json.loads((self.root / "intent.json").read_bytes())
        self.assertEqual(intent["executor_source"], self.executor.identity)
        self.assertEqual(intent["artifact_source"]["repositoryCommit"], "b" * 40)
        self.assertEqual(intent["failed_event_sha256"], self.request.failed_event_sha256)
        self.historical.assert_called_once_with(self.fixture.repository, self.executor)

    def test_normal_resume_remains_terminal_and_does_not_create_reconciliation(self) -> None:
        with self.assertRaisesRegex(transaction.SigningAttemptError, "allocate a successor"):
            self.fixture.run(resume=True)
        self.assertFalse(self.root.exists())
        self.assert_original_records_unchanged()

    def test_explicit_digests_must_match_original_event_and_receipt(self) -> None:
        for request in (
            replace(self.request, failed_event_sha256="0" * 64),
            replace(self.request, transformation_receipt_sha256="0" * 64),
            replace(self.request, failed_event_sha256="not-a-digest"),
        ):
            with self.subTest(request=request), self.assertRaises((transaction.SigningAttemptError, PublicationError)):
                self.run_reconciliation(reconciliation=request)
            self.assertFalse(self.canonical.exists())
            self.assertFalse(self.root.exists())
            self.assert_original_records_unchanged()

    def test_fresh_signing_mode_cannot_select_reconciliation(self) -> None:
        with self.assertRaisesRegex(transaction.SigningAttemptError, "cannot enter fresh signing"):
            self.run_reconciliation(resume=False)
        self.assertFalse(self.root.exists())

    def test_input_drift_prevents_publication_and_retains_failed_verification(self) -> None:
        calls = 0

        def frozen_inputs(_repository: Path, **_kwargs: object):
            nonlocal calls
            calls += 1
            return self.fixture.bindings if calls == 1 else replace(
                self.fixture.bindings, release_source_sha256="0" * 64
            )

        with self.assertRaisesRegex(transaction.SigningAttemptError, "inputs or original history changed"):
            self.run_reconciliation(frozen_inputs_verifier=frozen_inputs)
        self.assertEqual(self.read_result(1)["status"], "failed")
        self.assertFalse((self.root / "publication.json").exists())
        self.assertTrue(self.original.publish_ready.is_dir())
        self.assert_original_records_unchanged()

    def test_semantic_failure_is_recorded_without_promoting_then_explicit_replay_can_pass(self) -> None:
        def reject(_repository: Path, _output: Path) -> dict[str, str]:
            raise transaction.SigningTransformationError("fixture signature mismatch")

        with self.assertRaisesRegex(transaction.SigningTransformationError, "signature mismatch"):
            self.run_reconciliation(transformation_verifier=reject)
        failed = (self.root / "result-00000001.json").read_bytes()
        self.assertEqual(self.read_result(1)["status"], "failed")
        self.assertFalse((self.root / "publication.json").exists())
        self.assertEqual(self.run_reconciliation(), self.canonical)
        self.assertEqual((self.root / "result-00000001.json").read_bytes(), failed)
        self.assertEqual(self.read_result(2)["status"], "passed")
        self.assert_original_records_unchanged()

    def test_interrupted_read_only_verification_is_appended_not_overwritten(self) -> None:
        def interrupted(_repository: Path, _output: Path) -> dict[str, str]:
            raise KeyboardInterrupt("fixture interruption before any publish intent")

        with self.assertRaises(KeyboardInterrupt):
            self.run_reconciliation(transformation_verifier=interrupted)
        start = (self.root / "start-00000001.json").read_bytes()
        self.assertFalse((self.root / "result-00000001.json").exists())
        self.assertFalse((self.root / "publication.json").exists())
        self.run_reconciliation()
        self.assertEqual((self.root / "start-00000001.json").read_bytes(), start)
        self.assertEqual(self.read_result(1)["status"], "interrupted")
        self.assertEqual(self.read_result(2)["status"], "passed")
        self.assert_original_records_unchanged()

    def test_publish_reply_loss_reconciles_canonical_without_repeating_rename(self) -> None:
        calls = 0

        def reply_lost(source: Path, destination: Path) -> None:
            nonlocal calls
            calls += 1
            self.fixture.publisher(source, destination)
            raise PublicationError("fixture lost publication reply")

        with self.assertRaises(transaction.SigningAttemptOutcomeUnknown):
            self.run_reconciliation(publisher=reply_lost)
        self.assertTrue(self.canonical.is_dir())
        self.assertTrue((self.root / "publication.json").exists())
        self.assertFalse((self.root / "completed.json").exists())
        publication = (self.root / "publication.json").read_bytes()
        self.run_reconciliation(publisher=reply_lost)
        self.assertEqual(calls, 1)
        self.assertEqual((self.root / "publication.json").read_bytes(), publication)
        self.assertTrue((self.root / "completed.json").exists())
        self.assert_original_records_unchanged()

    def test_failed_rename_reverifies_same_private_output_before_publishing(self) -> None:
        def before_rename(_source: Path, _destination: Path) -> None:
            raise PublicationError("fixture rename did not run")

        with self.assertRaises(transaction.SigningAttemptOutcomeUnknown):
            self.run_reconciliation(publisher=before_rename)
        self.assertTrue(self.original.publish_ready.is_dir())
        self.assertFalse(self.canonical.exists())
        self.assertEqual(self.run_reconciliation(), self.canonical)
        self.assert_original_records_unchanged()

    def test_postpublication_verification_failure_does_not_claim_completion(self) -> None:
        def reject(_repository: Path) -> dict[str, str]:
            raise transaction.SigningTransformationError("canonical verification failed")

        with self.assertRaises(transaction.SigningAttemptOutcomeUnknown):
            self.run_reconciliation(canonical_transformation_verifier=reject)
        self.assertTrue(self.canonical.exists())
        self.assertFalse((self.root / "completed.json").exists())
        self.assertEqual(self.run_reconciliation(), self.canonical)

    def test_changed_executor_cannot_rebind_existing_reconciliation(self) -> None:
        def interrupt(_repository: Path, _output: Path) -> dict[str, str]:
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.run_reconciliation(transformation_verifier=interrupt)
        before = (self.root / "intent.json").read_bytes()
        with patch.object(transaction, "capture_executor_source", return_value=replace(
            self.executor, repository_commit="3" * 40
        )), self.assertRaisesRegex(PublicationError, "cannot be replaced"):
            self.run_reconciliation()
        self.assertEqual((self.root / "intent.json").read_bytes(), before)
        self.assertFalse(self.canonical.exists())

    def test_executor_drift_during_verification_stops_before_publication(self) -> None:
        self.unchanged.side_effect = ExecutorSourceError("executor changed")
        with self.assertRaisesRegex(ExecutorSourceError, "executor changed"):
            self.run_reconciliation()
        self.assertEqual(self.read_result(1)["status"], "failed")
        self.assertFalse((self.root / "publication.json").exists())
        self.assert_original_records_unchanged()

    def test_every_downstream_namespace_blocks_reconciliation(self) -> None:
        for relative in transaction._DOWNSTREAM_RECOVERY_GUARDS:
            with self.subTest(relative=relative):
                path = self.fixture.root / relative
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.mkdir(mode=0o700)
                with self.assertRaisesRegex(transaction.SigningAttemptError, "after notarization or packaging"):
                    self.run_reconciliation()
                path.rmdir()
                self.assertFalse(self.canonical.exists())
                self.assert_original_records_unchanged()

    def test_unrecorded_or_ambiguous_canonical_output_is_rejected(self) -> None:
        self.canonical.mkdir(mode=0o700)
        with self.assertRaisesRegex(transaction.SigningAttemptError, "one exact recorded location"):
            self.run_reconciliation()
        self.assertFalse((self.root / "publication.json").exists())
        self.assert_original_records_unchanged()

    def test_unsafe_reconciliation_root_and_original_receipt_are_rejected(self) -> None:
        outside = self.fixture.repository / "outside"
        outside.mkdir(mode=0o700)
        self.root.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(PublicationError):
            self.run_reconciliation()
        self.assertEqual(list(outside.iterdir()), [])
        self.root.unlink()
        receipt = self.original.publish_ready / transaction.TRANSFORMATION_RECEIPT_NAME
        os.link(receipt, outside / "receipt-alias")
        with self.assertRaises(transaction.SigningAttemptError):
            self.run_reconciliation()
        self.assertFalse(self.canonical.exists())

    def test_concurrent_reconciliation_cannot_start_a_second_verification(self) -> None:
        entered, release = threading.Event(), threading.Event()
        errors: list[BaseException] = []

        def wait_for_release(repository: Path, output: Path) -> dict[str, str]:
            entered.set()
            if not release.wait(10):
                raise AssertionError("fixture release timed out")
            return self.fixture.transformation_verify(repository, output)

        def worker() -> None:
            try:
                self.run_reconciliation(transformation_verifier=wait_for_release)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            self.assertTrue(entered.wait(10))
            with self.assertRaises(PublicationError):
                self.run_reconciliation()
        finally:
            release.set()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertFalse((self.root / "start-00000002.json").exists())
        self.assert_original_records_unchanged()

    def test_verification_attempts_are_bounded_without_deleting_history(self) -> None:
        def reject(_repository: Path, _output: Path) -> dict[str, str]:
            raise transaction.SigningTransformationError("replay still fails")

        for _ in range(reconciliation.MAX_VERIFICATIONS):
            with self.assertRaises(transaction.SigningTransformationError):
                self.run_reconciliation(transformation_verifier=reject)
        with self.assertRaisesRegex(PublicationError, "budget exhausted"):
            self.run_reconciliation()
        self.assertEqual(len(list(self.root.glob("result-*.json"))), reconciliation.MAX_VERIFICATIONS)
        self.assertFalse(self.canonical.exists())

    def test_corrupt_result_or_extra_inventory_cannot_authorize_publication(self) -> None:
        def interrupt(_repository: Path, _output: Path) -> dict[str, str]:
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.run_reconciliation(transformation_verifier=interrupt)
        malformed = {
            "document": reconciliation.DOCUMENT,
            "phase": "result",
            "recorded_at": "2026-08-25T00:00:00.000000Z",
            "verification_sequence": 1,
            "status": [],
            "failure_code": None,
        }
        result = self.root / "result-00000001.json"
        result.write_bytes(canonical_json(malformed))
        result.chmod(0o600)
        with self.assertRaisesRegex(PublicationError, "inconsistent"):
            self.run_reconciliation()
        self.assertFalse(self.canonical.exists())

    def test_unknown_history_entries_are_rejected_without_being_removed(self) -> None:
        def interrupt(_repository: Path, _output: Path) -> dict[str, str]:
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.run_reconciliation(transformation_verifier=interrupt)
        extra = self.root / "unexpected.json"
        extra.write_bytes(b"retain unexpected evidence")
        extra.chmod(0o600)
        with self.assertRaisesRegex(PublicationError, "unexpected reconciliation inventory"):
            self.run_reconciliation()
        self.assertEqual(extra.read_bytes(), b"retain unexpected evidence")
        self.assertFalse(self.canonical.exists())
        self.assert_original_records_unchanged()

    def test_boolean_schema_version_cannot_equal_integer_version(self) -> None:
        def interrupt(_repository: Path, _output: Path) -> dict[str, str]:
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.run_reconciliation(transformation_verifier=interrupt)
        path = self.root / "intent.json"
        malformed = json.loads(path.read_bytes())
        malformed["schema_version"] = True
        path.write_bytes(canonical_json(malformed))
        with self.assertRaisesRegex(PublicationError, "cannot be replaced"):
            self.run_reconciliation()
        self.assertFalse(self.canonical.exists())
        self.assert_original_records_unchanged()

    def test_completed_replay_does_not_rename_or_replace_publication_records(self) -> None:
        self.run_reconciliation()
        before = {name: (self.root / name).read_bytes()
                  for name in ("intent.json", "publication.json", "completed.json")}

        def forbidden(_source: Path, _destination: Path) -> None:
            self.fail("completed reconciliation repeated its publication rename")

        self.assertEqual(self.run_reconciliation(publisher=forbidden), self.canonical)
        self.assertEqual({name: (self.root / name).read_bytes() for name in before}, before)
        self.assert_original_records_unchanged()

    def test_unknown_journal_write_outcomes_resume_exact_lineage(self) -> None:
        for name in ("result-00000001.json", "publication.json", "completed.json"):
            with self.subTest(name=name):
                case = SigningReconciliationTests(methodName="test_reconciles_exact_output_without_resigning_or_rewriting_failed_history")
                case.setUp()
                try:
                    original_write = reconciliation.write_private_pending_locked
                    injected = False

                    def write_then_fail(descriptor, root, leaf, data):
                        nonlocal injected
                        original_write(descriptor, root, leaf, data)
                        if leaf == name and not injected:
                            injected = True
                            raise PublicationError("injected durable-record reply loss")

                    with patch.object(reconciliation, "write_private_pending_locked", side_effect=write_then_fail):
                        with case.assertRaises((PublicationError, transaction.SigningAttemptOutcomeUnknown)):
                            case.run_reconciliation()
                    case.assertTrue(injected)
                    retained = (case.root / name).read_bytes()
                    case.assertEqual(case.run_reconciliation(), case.canonical)
                    case.assertEqual((case.root / name).read_bytes(), retained)
                    case.assert_original_records_unchanged()
                finally:
                    case.doCleanups()

    def test_canonical_output_without_publication_intent_is_not_adopted(self) -> None:
        self.original.publish_ready.rename(self.canonical)
        with self.assertRaisesRegex(transaction.SigningAttemptError, "lacks reconciliation publication intent"):
            self.run_reconciliation()
        self.assertFalse((self.root / "completed.json").exists())
        self.assert_original_records_unchanged()

    def test_failed_before_verified_or_unknown_signing_cannot_enter_this_path(self) -> None:
        for mode in ("helper-failed", "receipt-failed", "publish-unknown"):
            with self.subTest(mode=mode):
                fixture = SigningAttemptFixture()
                try:
                    def reject_receipt(_repository: Path, _output: Path) -> dict[str, str]:
                        raise transaction.SigningTransformationError("no complete receipt")

                    def reject_publish(_source: Path, _destination: Path) -> None:
                        raise PublicationError("ambiguous earlier publication")

                    arguments = {}
                    if mode == "helper-failed":
                        arguments["helper"] = lambda *_args: 2
                    elif mode == "receipt-failed":
                        arguments["transformation_creator"] = reject_receipt
                    else:
                        arguments["publisher"] = reject_publish
                    with self.assertRaises(transaction.SigningAttemptError):
                        fixture.run(resume=False, **arguments)
                    attempt = fixture.load("00000001")
                    request = replace(self.request, failed_event_sha256=str(attempt.events[-1]["event_sha256"]))
                    with self.assertRaisesRegex(transaction.SigningAttemptError, "failed-after-verified"):
                        fixture.run(resume=True, reconciliation=request)
                    self.assertEqual(fixture.load("00000001").events, attempt.events)
                    self.assertFalse((fixture.root / reconciliation.RELATIVE_ROOT).exists())
                finally:
                    fixture.cleanup()

    def test_cli_rejects_partial_or_implicit_reconciliation_arguments(self) -> None:
        for arguments in (
            ["reconcile-failed"],
            ["reconcile-failed", "--artifact-repository", str(self.fixture.repository)],
            ["resume", "--expect-failed-event-sha256", self.request.failed_event_sha256],
            ["run", "--artifact-repository", str(self.fixture.repository)],
        ):
            with self.subTest(arguments=arguments), patch("sys.stderr"), self.assertRaises(SystemExit) as raised:
                transaction.main(arguments)
            self.assertEqual(raised.exception.code, 2)
        self.assertFalse(self.root.exists())

    def cli_arguments(self) -> list[str]:
        return [
            "reconcile-failed",
            "--artifact-repository", str(self.fixture.repository),
            "--expect-failed-event-sha256", self.request.failed_event_sha256,
            "--expect-transformation-sha256", self.request.transformation_receipt_sha256,
        ]

    def test_cli_binds_actual_executor_separately_from_artifact_source(self) -> None:
        with (
            patch.object(transaction, "require_closed_release_runtime") as admission,
            patch.object(transaction, "run_signing_transaction", return_value=self.canonical) as run,
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            self.assertEqual(transaction.main(self.cli_arguments()), 0)
        admission.assert_called_once_with()
        run.assert_called_once_with(
            self.fixture.repository,
            resume=True,
            reconciliation=replace(
                self.request,
                executor_repository=Path(transaction.__file__).resolve().parent.parent,
            ),
        )

    def test_cli_retains_nested_failure_diagnostics(self) -> None:
        failure = transaction.SigningAttemptError("fixture_failure", "outer failure")
        failure.__cause__ = RuntimeError("exact nested fixture failure")
        with (
            patch.object(transaction, "require_closed_release_runtime"),
            patch.object(transaction, "run_signing_transaction", side_effect=failure),
            patch("sys.stderr", new_callable=io.StringIO) as stderr,
        ):
            self.assertEqual(transaction.main(self.cli_arguments()), 1)
        self.assertIn("RuntimeError: exact nested fixture failure", stderr.getvalue())
        self.assertIn("[fixture_failure]", stderr.getvalue())
        self.assertFalse(self.root.exists())

    def test_production_verification_runs_the_artifact_worktrees_script(self) -> None:
        with patch.object(transaction, "run_bounded_process", return_value=SimpleNamespace(
            returncode=0, stdout=b"", stderr=b""
        )) as run:
            transaction.production_verification_runner(
                self.original.publish_ready,
                transaction.CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY,
                repository=self.fixture.repository,
            )
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["cwd"], self.fixture.repository)
        self.assertEqual(
            run.call_args_list[1].args[0][0],
            str(self.fixture.repository / "scripts/verify_release_app.sh"),
        )
        self.assertEqual(run.call_args_list[1].args[0][-1], "signing-attempt-publish-ready")


if __name__ == "__main__":
    unittest.main()
