from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.candidate_freeze import FrozenCandidate
from scripts.publication import durable_file
from scripts.publication.common import PublicationError
from scripts import signing_attempt_transaction as transaction


class SigningAttemptFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        self.root = self.repository / "target/candidates/0.4.0/ga/40031"
        self.root.mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        intent = self.root / "candidate-freeze/intent.json"
        intent.parent.mkdir(mode=0o700)
        intent.write_bytes(b'{"fixture":true}\n')
        intent.chmod(0o600)
        frozen = FrozenCandidate(
            root=self.root,
            intent_path=intent,
            intent_sha256="a" * 64,
            product_version="0.4.0",
            build_number="40031",
            recovered=False,
        )
        self.bindings = transaction.FrozenSigningBindings(
            frozen=frozen,
            repository_commit="b" * 40,
            release_source_sha256="c" * 64,
            signing_preflight_sha256="d" * 64,
            signing_plan_sha256="e" * 64,
            signing_certificate_sha1="A" * 40,
            signing_certificate_sha256="B" * 64,
            updater_key_possession_proof_sha256="f" * 64,
            updater_embedded_public_key_sha256="1" * 64,
            updater_tauri_config_sha256="2" * 64,
        )
        self.clock_count = 0

    def cleanup(self) -> None:
        self.temporary.cleanup()

    def clock(self) -> str:
        self.clock_count += 1
        return f"2026-08-25T00:00:{self.clock_count:02d}.000000Z"

    @staticmethod
    def helper_success(work: Path, sha1: str, sha256: str) -> int:
        if sha1 != "A" * 40 or sha256 != "B" * 64:
            raise AssertionError("unexpected certificate binding")
        app = work / transaction.SIGNED_APP_WITHIN_OUTPUT
        app.mkdir(parents=True)
        (app / "fixture.bin").write_bytes(b"signed-app")
        native = work / "signed-native-products"
        native.mkdir()
        (native / "fixture.bin").write_bytes(b"signed-native")
        return 0

    @staticmethod
    def verification(output: Path) -> None:
        if not (output / transaction.SIGNED_APP_WITHIN_OUTPUT).is_dir():
            raise transaction.SigningAttemptError(
                "fixture_app_missing", "fixture app is missing"
            )
        if not (output / "signed-native-products").is_dir():
            raise transaction.SigningAttemptError(
                "fixture_native_missing", "fixture native products are missing"
            )

    @staticmethod
    def transformation_create(
        _repository: Path, output: Path
    ) -> dict[str, str]:
        receipt = output / transaction.TRANSFORMATION_RECEIPT_NAME
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(receipt, flags, 0o600)
        try:
            os.write(descriptor, b'{"fixture":"verified"}\n')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return {"fixture": "verified"}

    @staticmethod
    def transformation_verify(
        _repository: Path, output: Path
    ) -> dict[str, str]:
        receipt = output / transaction.TRANSFORMATION_RECEIPT_NAME
        if receipt.read_bytes() != b'{"fixture":"verified"}\n':
            raise transaction.SigningAttemptError(
                "fixture_receipt_invalid", "fixture receipt differs"
            )
        if receipt.stat().st_mode & 0o777 != 0o600:
            raise transaction.SigningAttemptError(
                "fixture_receipt_mode", "fixture receipt mode differs"
            )
        return {"fixture": "verified"}

    def canonical_verify(self, repository: Path) -> dict[str, str]:
        return self.transformation_verify(
            repository,
            self.root / transaction.SIGNING_OUTPUT_RELATIVE,
        )

    @staticmethod
    def publisher(source: Path, destination: Path) -> None:
        if os.path.lexists(destination):
            raise PublicationError("fixture destination already exists")
        source.rename(destination)

    @staticmethod
    def confirmer(source: Path, destination: Path) -> None:
        if os.path.lexists(source) or not destination.is_dir():
            raise PublicationError("fixture publication is ambiguous")

    def run(
        self,
        *,
        resume: bool,
        helper=None,
        publisher=None,
        live_readiness=None,
    ) -> Path:
        helper_runner = self.helper_success if helper is None else helper
        selected_publisher = self.publisher if publisher is None else publisher
        readiness = (
            (lambda _root: None) if live_readiness is None else live_readiness
        )
        with patch.object(
            transaction,
            "_verify_frozen_inputs",
            return_value=self.bindings,
        ):
            return transaction.run_signing_transaction(
                self.repository,
                resume=resume,
                clock=self.clock,
                helper_runner=helper_runner,
                verification_runner=self.verification,
                live_readiness_verifier=readiness,
                publisher=selected_publisher,
                confirmer=self.confirmer,
                transformation_creator=self.transformation_create,
                transformation_verifier=self.transformation_verify,
                canonical_transformation_verifier=self.canonical_verify,
            )

    def attempts(self) -> Path:
        return self.root / transaction.ATTEMPTS_RELATIVE

    def load(self, identifier: str) -> transaction.Attempt:
        return transaction._load_attempt(self.attempts(), identifier)


class SigningAttemptTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SigningAttemptFixture()
        self.addCleanup(self.fixture.cleanup)
        durability = patch.object(durable_file, "full_fsync", side_effect=os.fsync)
        durability.start()
        self.addCleanup(durability.stop)

    def test_success_publishes_one_complete_container_after_verified_event(self) -> None:
        output = self.fixture.run(resume=False)
        self.assertEqual(output, self.fixture.root / "signing-output")
        self.assertEqual(
            set(os.listdir(output)),
            {
                "signing-input",
                "signed-native-products",
                "signing-transformation.json",
            },
        )
        attempt = self.fixture.load("00000001")
        self.assertEqual(
            tuple(event["state"] for event in attempt.events),
            ("prepared", "signing", "verified", "publishing", "published"),
        )
        self.assertFalse(attempt.work.exists())
        self.assertFalse(attempt.publish_ready.exists())

    def test_live_profile_readiness_fails_before_attempt_allocation(self) -> None:
        def reject(_root: Path) -> None:
            raise transaction.SigningAttemptError(
                "signing_profile_readiness_invalid",
                "fixture profile expired",
            )

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "fixture profile expired"
        ) as raised:
            self.fixture.run(resume=False, live_readiness=reject)

        self.assertEqual(raised.exception.code, "signing_profile_readiness_invalid")
        self.assertEqual(os.listdir(self.fixture.attempts()), [])

    def test_published_output_reopen_does_not_require_live_profile_validity(self) -> None:
        canonical = self.fixture.run(resume=False)

        def reject(_root: Path) -> None:
            raise AssertionError("published output touched live profile readiness")

        self.assertEqual(
            self.fixture.run(resume=True, live_readiness=reject),
            canonical,
        )

    def test_helper_failure_is_append_only_and_resume_uses_next_attempt(self) -> None:
        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "fixed signing helper failed"
        ):
            self.fixture.run(
                resume=False,
                helper=lambda _work, _sha1, _sha256: 23,
            )
        first = self.fixture.load("00000001")
        self.assertEqual(first.state, "failed")
        self.assertEqual(first.events[-1]["exit_code"], 23)
        self.assertTrue(first.work.is_dir())
        first_intent = (first.root / transaction.INTENT_NAME).read_bytes()
        first_events = tuple(
            (first.root / f"event-{number:08d}.json").read_bytes()
            for number in range(1, len(first.events) + 1)
        )

        self.fixture.run(resume=True)
        second = self.fixture.load("00000002")
        self.assertEqual(second.state, "published")
        self.assertEqual((first.root / transaction.INTENT_NAME).read_bytes(), first_intent)
        self.assertEqual(
            tuple(
                (first.root / f"event-{number:08d}.json").read_bytes()
                for number in range(1, len(first.events) + 1)
            ),
            first_events,
        )

    def test_process_crash_is_recorded_outcome_unknown_before_retry(self) -> None:
        def crash(_work: Path, _sha1: str, _sha256: str) -> int:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.fixture.run(resume=False, helper=crash)
        self.assertEqual(self.fixture.load("00000001").state, "signing")

        self.fixture.run(resume=True)
        first = self.fixture.load("00000001")
        second = self.fixture.load("00000002")
        self.assertEqual(first.state, "outcome_unknown")
        self.assertEqual(
            first.events[-1]["failure_code"],
            "interrupted_before_verified_output",
        )
        self.assertEqual(second.state, "published")

    def test_rename_reply_loss_reconciles_existing_canonical_output(self) -> None:
        def rename_then_lose_reply(source: Path, destination: Path) -> None:
            source.rename(destination)
            raise durable_file.DurabilityOutcomeUnknown("simulated reply loss")

        with self.assertRaisesRegex(
            transaction.SigningAttemptOutcomeUnknown, "resume"
        ):
            self.fixture.run(resume=False, publisher=rename_then_lose_reply)
        canonical = self.fixture.root / "signing-output"
        self.assertTrue(canonical.is_dir())
        self.assertEqual(self.fixture.load("00000001").state, "outcome_unknown")

        self.assertEqual(self.fixture.run(resume=True), canonical)
        self.assertEqual(self.fixture.load("00000001").state, "published")
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])

    def test_pre_rename_failure_retries_same_verified_attempt(self) -> None:
        def fail_before_rename(_source: Path, _destination: Path) -> None:
            raise PublicationError("simulated pre-rename failure")

        with self.assertRaises(transaction.SigningAttemptOutcomeUnknown):
            self.fixture.run(resume=False, publisher=fail_before_rename)
        first = self.fixture.load("00000001")
        self.assertEqual(first.state, "outcome_unknown")
        self.assertTrue(first.publish_ready.is_dir())

        self.fixture.run(resume=True)
        self.assertEqual(self.fixture.load("00000001").state, "published")
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])

    def test_publish_and_outcome_journal_unknown_matrix_resumes_same_attempt(self) -> None:
        original_append = transaction._append_event
        for publication_committed in (False, True):
            for journal_committed in (False, True):
                with self.subTest(
                    publication_committed=publication_committed,
                    journal_committed=journal_committed,
                ):
                    fixture = SigningAttemptFixture()
                    try:
                        def ambiguous_publisher(source: Path, destination: Path) -> None:
                            if publication_committed:
                                source.rename(destination)
                                raise durable_file.DurabilityOutcomeUnknown(
                                    "simulated publication reply loss"
                                )
                            raise PublicationError("simulated publication failure")

                        def ambiguous_outcome_append(
                            repository: Path,
                            attempt: transaction.Attempt,
                            state: str,
                            **kwargs,
                        ) -> transaction.Attempt:
                            if state != "outcome_unknown":
                                return original_append(
                                    repository,
                                    attempt,
                                    state,
                                    **kwargs,
                                )
                            if not journal_committed:
                                raise transaction.SigningAttemptOutcomeUnknown(
                                    "simulated journal pre-commit failure"
                                )
                            original_append(
                                repository,
                                attempt,
                                state,
                                **kwargs,
                            )
                            raise transaction.SigningAttemptOutcomeUnknown(
                                "simulated journal reply loss"
                            )

                        with (
                            patch.object(
                                transaction,
                                "_append_event",
                                side_effect=ambiguous_outcome_append,
                            ),
                            self.assertRaisesRegex(
                                transaction.SigningAttemptOutcomeUnknown,
                                "durability could not be confirmed",
                            ) as caught,
                        ):
                            fixture.run(
                                resume=False,
                                publisher=ambiguous_publisher,
                            )
                        self.assertEqual(
                            caught.exception.code,
                            "signing_publication_outcome_unknown",
                        )
                        cause = caught.exception.__cause__
                        self.assertIsInstance(cause, ExceptionGroup)
                        if not isinstance(cause, ExceptionGroup):
                            self.fail(
                                "outcome-unknown error did not preserve both failures"
                            )
                        self.assertEqual(len(cause.exceptions), 2)
                        self.assertIsInstance(
                            cause.exceptions[0],
                            (
                                durable_file.DurabilityOutcomeUnknown,
                                PublicationError,
                            ),
                        )
                        self.assertIsInstance(
                            cause.exceptions[1],
                            transaction.SigningAttemptError,
                        )
                        self.assertEqual(
                            fixture.load("00000001").state,
                            "outcome_unknown" if journal_committed else "publishing",
                        )
                        self.assertEqual(
                            fixture.run(resume=True),
                            fixture.root / "signing-output",
                        )
                        self.assertEqual(
                            fixture.load("00000001").state,
                            "published",
                        )
                        self.assertEqual(
                            os.listdir(fixture.attempts()),
                            ["00000001"],
                        )
                    finally:
                        fixture.cleanup()

    def test_transformation_failure_never_pollutes_canonical_paths(self) -> None:
        def reject(_repository: Path, _output: Path) -> dict[str, str]:
            raise transaction.SigningTransformationError("fixture mismatch")

        with (
            patch.object(
                transaction,
                "_verify_frozen_inputs",
                return_value=self.fixture.bindings,
            ),
            self.assertRaisesRegex(
                transaction.SigningAttemptError,
                "did not pass complete verification",
            ),
        ):
            transaction.run_signing_transaction(
                self.fixture.repository,
                resume=False,
                clock=self.fixture.clock,
                helper_runner=self.fixture.helper_success,
                verification_runner=self.fixture.verification,
                live_readiness_verifier=lambda _root: None,
                publisher=self.fixture.publisher,
                confirmer=self.fixture.confirmer,
                transformation_creator=reject,
                transformation_verifier=self.fixture.transformation_verify,
                canonical_transformation_verifier=self.fixture.canonical_verify,
            )
        self.assertEqual(self.fixture.load("00000001").state, "failed")
        self.assertFalse((self.fixture.root / "signing-output").exists())
        self.assertFalse((self.fixture.root / "signing-input").exists())
        self.assertFalse((self.fixture.root / "signed-native-products").exists())

    def test_existing_state_requires_explicit_resume(self) -> None:
        with self.assertRaises(transaction.SigningAttemptError):
            self.fixture.run(
                resume=False,
                helper=lambda _work, _sha1, _sha256: 7,
            )
        with self.assertRaisesRegex(transaction.SigningAttemptError, "resume"):
            self.fixture.run(resume=False)

    def test_concurrent_transaction_lock_fails_closed(self) -> None:
        with patch.object(
            transaction,
            "_verify_frozen_inputs",
            return_value=self.fixture.bindings,
        ):
            attempts = transaction._ensure_attempts_root(self.fixture.repository)
            with durable_file.exclusive_rooted_directory_lock(
                self.fixture.repository,
                attempts,
                require_private=True,
            ):
                with self.assertRaisesRegex(
                    transaction.SigningAttemptError, "active|lock"
                ):
                    transaction.run_signing_transaction(
                        self.fixture.repository,
                        resume=False,
                        clock=self.fixture.clock,
                        helper_runner=self.fixture.helper_success,
                        verification_runner=self.fixture.verification,
                        live_readiness_verifier=lambda _root: None,
                        publisher=self.fixture.publisher,
                        confirmer=self.fixture.confirmer,
                        transformation_creator=self.fixture.transformation_create,
                        transformation_verifier=self.fixture.transformation_verify,
                        canonical_transformation_verifier=self.fixture.canonical_verify,
                    )

    def test_frozen_binding_drift_blocks_resume_without_new_attempt(self) -> None:
        with self.assertRaises(transaction.SigningAttemptError):
            self.fixture.run(
                resume=False,
                helper=lambda _work, _sha1, _sha256: 9,
            )
        drifted = replace(self.fixture.bindings, signing_plan_sha256="9" * 64)
        with (
            patch.object(
                transaction,
                "_verify_frozen_inputs",
                return_value=drifted,
            ),
            self.assertRaisesRegex(transaction.SigningAttemptError, "differs"),
        ):
            transaction.run_signing_transaction(
                self.fixture.repository,
                resume=True,
                clock=self.fixture.clock,
                helper_runner=self.fixture.helper_success,
                verification_runner=self.fixture.verification,
                live_readiness_verifier=lambda _root: None,
                publisher=self.fixture.publisher,
                confirmer=self.fixture.confirmer,
                transformation_creator=self.fixture.transformation_create,
                transformation_verifier=self.fixture.transformation_verify,
                canonical_transformation_verifier=self.fixture.canonical_verify,
            )
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])

    def test_legacy_top_level_output_is_explicitly_rejected(self) -> None:
        (self.fixture.root / "signing-input").mkdir()
        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "legacy non-atomic"
        ):
            transaction._reject_legacy_outputs(self.fixture.root)

    def test_directory_publication_rejects_ancestor_destinations(self) -> None:
        source = self.fixture.root / "private-source"
        source.mkdir(mode=0o700)
        with self.assertRaisesRegex(PublicationError, "ancestor"):
            durable_file.publish_private_directory_exclusive(
                source,
                source / "descendant",
            )
        child = source / "child"
        child.mkdir(mode=0o700)
        with self.assertRaisesRegex(PublicationError, "ancestor"):
            durable_file.publish_private_directory_exclusive(child, source)

    def test_private_tree_file_swap_is_detected_during_fsync(self) -> None:
        root = self.fixture.root / "file-swap"
        root.mkdir(mode=0o700)
        path = root / "payload.bin"
        path.write_bytes(b"before")
        original_fsync = os.fsync
        mutated = False

        def fsync_then_swap(descriptor: int) -> None:
            nonlocal mutated
            original_fsync(descriptor)
            if not mutated and os.path.isfile(path):
                mutated = True
                path.rename(root / "payload.old")
                path.write_bytes(b"after")

        with (
            patch.object(durable_file.os, "fsync", side_effect=fsync_then_swap),
            self.assertRaises(durable_file.RootedDirectoryChanged),
        ):
            durable_file.fsync_private_tree(root)

    def test_private_tree_symlink_swap_is_detected_before_publish(self) -> None:
        root = self.fixture.root / "symlink-swap"
        root.mkdir(mode=0o700)
        (root / "first").write_bytes(b"first")
        (root / "second").write_bytes(b"second")
        link = root / "current"
        link.symlink_to("first")
        original_sync = durable_file._sync_regular_file
        swapped = False

        def sync_then_swap(path: Path, expected: os.stat_result) -> None:
            nonlocal swapped
            original_sync(path, expected)
            if not swapped:
                swapped = True
                link.unlink()
                link.symlink_to("second")

        with (
            patch.object(
                durable_file,
                "_sync_regular_file",
                side_effect=sync_then_swap,
            ),
            self.assertRaises(durable_file.RootedDirectoryChanged),
        ):
            durable_file.fsync_private_tree(root)


if __name__ == "__main__":
    unittest.main()
