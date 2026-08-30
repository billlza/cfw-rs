from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.candidate_freeze import FrozenCandidate
from scripts.publication import durable_file
from scripts.publication.common import PublicationError
from scripts import signing_attempt_transaction as transaction
from scripts import updater_key_possession_proof as possession


class SigningAttemptFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        build_number = transaction.ACTIVE_RELEASE_IDENTITY.ga_build
        self.root = (
            self.repository / f"target/candidates/0.4.0/ga/{build_number}"
        )
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
            build_number=build_number,
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
        self.session_count = 0
        self.verification_contexts: list[
            tuple[Path, transaction.CandidateBundleContext]
        ] = []

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
        app.parent.mkdir(parents=True, mode=0o700)
        app.mkdir()
        (app / "fixture.bin").write_bytes(b"signed-app")
        native = work / "signed-native-products"
        native.mkdir(mode=0o700)
        (native / "fixture.bin").write_bytes(b"signed-native")
        return 0

    def verification(
        self,
        output: Path,
        context: transaction.CandidateBundleContext,
    ) -> None:
        self.verification_contexts.append((output, context))
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

    transformation_load = transformation_verify

    @contextmanager
    def embedded_verifier_session(self, repository: Path):
        if repository != self.repository:
            raise AssertionError("verifier session used another repository")

        self.session_count += 1

        def unexpected_embedded_verifier(*_arguments: object) -> object:
            raise AssertionError("fixture unexpectedly invoked embedded verifier")

        yield unexpected_embedded_verifier

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
        transformation_creator=None,
        transformation_verifier=None,
        transformation_receipt_loader=None,
        canonical_transformation_verifier=None,
        frozen_inputs_verifier=None,
    ) -> Path:
        helper_runner = self.helper_success if helper is None else helper
        selected_publisher = self.publisher if publisher is None else publisher
        readiness = (
            (lambda _root: None) if live_readiness is None else live_readiness
        )
        selected_transformation_verifier = (
            self.transformation_verify
            if transformation_verifier is None
            else transformation_verifier
        )
        selected_transformation_creator = (
            self.transformation_create
            if transformation_creator is None
            else transformation_creator
        )
        selected_transformation_receipt_loader = (
            self.transformation_load
            if transformation_receipt_loader is None
            else transformation_receipt_loader
        )
        selected_canonical_transformation_verifier = (
            self.canonical_verify
            if canonical_transformation_verifier is None
            else canonical_transformation_verifier
        )
        selected_frozen_inputs_verifier = (
            (lambda _repository, **_keywords: self.bindings)
            if frozen_inputs_verifier is None
            else frozen_inputs_verifier
        )
        with patch.object(
            transaction,
            "_verify_frozen_inputs",
            side_effect=selected_frozen_inputs_verifier,
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
                transformation_creator=selected_transformation_creator,
                transformation_verifier=selected_transformation_verifier,
                transformation_receipt_loader=(
                    selected_transformation_receipt_loader
                ),
                canonical_transformation_verifier=(
                    selected_canonical_transformation_verifier
                ),
                embedded_verifier_session_factory=(
                    self.embedded_verifier_session
                ),
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

    def enter_verification_blocked(self) -> transaction.Attempt:
        def create_then_block(
            repository: Path,
            output: Path,
        ) -> dict[str, str]:
            self.fixture.transformation_create(repository, output)
            raise transaction.SigningTransformationError(
                "injected operational verifier failure",
                code="candidate_freeze_updater_verifier_unavailable",
            )

        with self.assertRaises(transaction.SigningVerificationBlocked):
            self.fixture.run(
                resume=False,
                transformation_creator=create_then_block,
            )
        attempt = self.fixture.load("00000001")
        self.assertEqual(attempt.state, "verification_blocked")
        self.assertEqual(
            attempt.events[-1]["failure_code"],
            "candidate_freeze_updater_verifier_unavailable",
        )
        return attempt

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
        self.assertEqual(
            tuple(context for _, context in self.fixture.verification_contexts),
            (
                transaction.CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                transaction.CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY,
            ),
        )
        attempt = self.fixture.load("00000001")
        self.assertEqual(
            tuple(event["state"] for event in attempt.events),
            ("prepared", "signing", "verified", "publishing", "published"),
        )
        self.assertFalse(attempt.work.exists())
        self.assertFalse(attempt.publish_ready.exists())

    def test_production_defaults_share_one_embedded_verifier_session(self) -> None:
        session_entries = 0
        session_active = False
        embedded_verifier = object()
        expected_output = self.fixture.root / "session-bound-output"

        @contextmanager
        def session_factory(repository: Path):
            nonlocal session_entries, session_active
            self.assertEqual(repository, self.fixture.repository)
            session_entries += 1
            session_active = True
            try:
                yield embedded_verifier
            finally:
                session_active = False

        def execute_with_bound_verifiers(
            repository: Path,
            **keywords: object,
        ) -> Path:
            self.assertTrue(session_active)
            possession_verifier = keywords["possession_verifier"]
            freeze_verifier = keywords["freeze_verifier"]
            creator = keywords["transformation_creator"]
            verifier = keywords["transformation_verifier"]
            canonical_verifier = keywords["canonical_transformation_verifier"]
            self.assertTrue(callable(possession_verifier))
            self.assertTrue(callable(freeze_verifier))
            self.assertTrue(callable(creator))
            self.assertTrue(callable(verifier))
            self.assertTrue(callable(canonical_verifier))

            with patch.object(
                transaction,
                "verify_possession_proof",
                return_value="possession",
            ) as proof:
                self.assertEqual(
                    possession_verifier(repository, self.fixture.root),
                    "possession",
                )
            self.assertIs(
                proof.call_args.kwargs["embedded_verifier"],
                embedded_verifier,
            )

            with patch.object(
                transaction,
                "verify_frozen_candidate",
                return_value=self.fixture.bindings.frozen,
            ) as frozen:
                self.assertEqual(
                    freeze_verifier(repository),
                    self.fixture.bindings.frozen,
                )
            self.assertIs(
                frozen.call_args.kwargs["possession_verifier"],
                possession_verifier,
            )

            with patch.object(
                transaction,
                "create_attempt_receipt",
                return_value={},
            ) as create:
                creator(repository, self.fixture.root)
            self.assertIs(
                create.call_args.kwargs["freeze_verifier"],
                freeze_verifier,
            )

            with patch.object(
                transaction,
                "verify_attempt_receipt",
                return_value={},
            ) as verify_attempt:
                verifier(repository, self.fixture.root)
            self.assertIs(
                verify_attempt.call_args.kwargs["freeze_verifier"],
                freeze_verifier,
            )

            with patch.object(
                transaction,
                "verify_receipt",
                return_value={},
            ) as verify_canonical:
                canonical_verifier(repository)
            self.assertIs(
                verify_canonical.call_args.kwargs["freeze_verifier"],
                freeze_verifier,
            )
            return expected_output

        with patch.object(
            transaction,
            "_run_signing_transaction_with_verifiers",
            side_effect=execute_with_bound_verifiers,
        ):
            self.assertEqual(
                transaction.run_signing_transaction(
                    self.fixture.repository,
                    resume=False,
                    embedded_verifier_session_factory=session_factory,
                ),
                expected_output,
            )
        self.assertEqual(session_entries, 1)
        self.assertFalse(session_active)

    def test_full_publish_reuses_one_possession_verifier(self) -> None:
        observed: list[tuple[object, object]] = []

        def reopen(
            repository: Path,
            *,
            freeze_verifier: object,
            possession_verifier: object,
        ) -> transaction.FrozenSigningBindings:
            self.assertEqual(repository, self.fixture.repository)
            self.assertTrue(callable(possession_verifier))
            possession_verifier(repository, self.fixture.root)
            observed.append((freeze_verifier, possession_verifier))
            return self.fixture.bindings

        with patch.object(
            transaction,
            "verify_possession_proof",
            return_value=object(),
        ) as direct_proof, patch.object(
            possession,
            "_production_embedded_verifier",
        ) as forbidden_one_shot:
            self.assertEqual(
                self.fixture.run(
                    resume=False,
                    frozen_inputs_verifier=reopen,
                ),
                self.fixture.root / "signing-output",
            )

        self.assertEqual(len(observed), 2)
        self.assertIs(observed[0][0], observed[1][0])
        self.assertIs(observed[0][1], observed[1][1])
        self.assertEqual(self.fixture.session_count, 1)
        self.assertEqual(direct_proof.call_count, 2)
        embedded = {
            call.kwargs["embedded_verifier"]
            for call in direct_proof.call_args_list
        }
        self.assertEqual(len(embedded), 1)
        forbidden_one_shot.assert_not_called()

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
        self.fixture.verification_contexts.clear()

        def reject(_root: Path) -> None:
            raise AssertionError("published output touched live profile readiness")

        self.assertEqual(
            self.fixture.run(resume=True, live_readiness=reject),
            canonical,
        )
        self.assertEqual(
            self.fixture.verification_contexts,
            [
                (
                    canonical,
                    transaction.CandidateBundleContext.CANONICAL_NATIVE_CONTENT,
                )
            ],
        )

    def test_production_verifier_propagates_the_explicit_context(self) -> None:
        output = Path("/private/tmp/cfm-signing-output")
        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "unsigned-host"
        ):
            transaction.production_verification_runner(
                output, transaction.CandidateBundleContext.UNSIGNED_HOST
            )
        for context in transaction.CandidateBundleContext:
            if context is transaction.CandidateBundleContext.UNSIGNED_HOST:
                continue
            with self.subTest(context=context), patch.object(
                transaction,
                "run_bounded_process",
                return_value=SimpleNamespace(returncode=0),
            ) as runner:
                transaction.production_verification_runner(output, context)
                commands = tuple(call.args[0] for call in runner.call_args_list)
                app = output / transaction.SIGNED_APP_WITHIN_OUTPUT
                native = output / transaction.SIGNED_NATIVE_PRODUCTS_NAME
                repository = Path(transaction.__file__).resolve().parent.parent
                self.assertEqual(
                    commands,
                    (
                        (
                            "/usr/bin/codesign",
                            "--verify",
                            "--deep",
                            "--strict",
                            "--verbose=4",
                            str(app),
                        ),
                        (
                            str(repository / "scripts/verify_release_app.sh"),
                            "--pre-notary",
                            str(app),
                            str(native),
                            "--context",
                            context.value,
                        ),
                    ),
                )

    def test_production_verifier_reports_one_stable_failed_phase(self) -> None:
        output = Path("/private/tmp/cfm-signing-output")
        context = transaction.CandidateBundleContext.SIGNING_ATTEMPT_WORK
        cases = (
            (
                [SimpleNamespace(returncode=7)],
                "signing_codesign_failed",
                "codesign verification failed",
            ),
            (
                [SimpleNamespace(returncode=0), SimpleNamespace(returncode=9)],
                "signing_release_app_failed",
                "release_app verification failed",
            ),
        )
        for results, expected_code, expected_message in cases:
            with self.subTest(code=expected_code), patch.object(
                transaction,
                "run_bounded_process",
                side_effect=results,
            ), self.assertRaisesRegex(
                transaction.SigningAttemptError, expected_message
            ) as raised:
                transaction.production_verification_runner(output, context)
            self.assertEqual(raised.exception.code, expected_code)

    def test_helper_work_root_uses_shared_attempt_classifier(self) -> None:
        transactions = self.fixture.root / "transactions"
        attempts = self.fixture.attempts()
        attempt = attempts / "00000001"
        work = attempt / "work"
        work.mkdir(parents=True)
        for path in (transactions, attempts, attempt, work):
            path.chmod(0o700)

        transaction._require_helper_work_root(self.fixture.repository, work)

        invalid_attempt = attempts / "00000000"
        invalid_work = invalid_attempt / "work"
        invalid_work.mkdir(parents=True)
        invalid_attempt.chmod(0o700)
        invalid_work.chmod(0o700)
        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "transaction-owned"
        ):
            transaction._require_helper_work_root(
                self.fixture.repository, invalid_work
            )

        publish_ready = attempt / "publish-ready"
        publish_ready.mkdir(mode=0o700)
        canonical = self.fixture.root / transaction.SIGNING_OUTPUT_RELATIVE
        canonical.mkdir(mode=0o700)
        for rejected in (publish_ready, canonical):
            with self.subTest(rejected=rejected), self.assertRaisesRegex(
                transaction.SigningAttemptError, "exact private work"
            ):
                transaction._require_helper_work_root(
                    self.fixture.repository, rejected
                )

    def test_production_helper_validates_work_before_process_launch(self) -> None:
        work = Path("/private/tmp/cfm-signing-attempt-work")
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        events: list[str] = []

        def validate(_repository: Path, _work: Path) -> None:
            events.append("validate")

        def launch(*_args, **_kwargs):
            events.append("launch")
            return completed

        with patch.object(
            transaction, "_require_helper_work_root", side_effect=validate
        ) as validator, patch.object(
            transaction, "run_bounded_process", side_effect=launch
        ) as runner:
            self.assertEqual(
                transaction.production_helper_runner(work, "A" * 40, "B" * 64),
                0,
            )
        self.assertEqual(events, ["validate", "launch"])
        repository = Path(transaction.__file__).resolve().parent.parent
        validator.assert_called_once_with(repository, work)
        environment = runner.call_args.kwargs["environment"]
        self.assertEqual(environment["CFW_SIGNING_ATTEMPT_WORK"], str(work))

        rejected = transaction.SigningAttemptError(
            "signing_helper_work_root_invalid", "injected invalid work root"
        )
        with patch.object(
            transaction, "_require_helper_work_root", side_effect=rejected
        ), patch.object(transaction, "run_bounded_process") as blocked_runner:
            with self.assertRaisesRegex(
                transaction.SigningAttemptError, "injected invalid work root"
            ):
                transaction.production_helper_runner(
                    work, "A" * 40, "B" * 64
                )
        blocked_runner.assert_not_called()

    def test_helper_failure_is_append_only_and_requires_candidate_retirement(self) -> None:
        def fail_after_partial_output(work: Path, _sha1: str, _sha256: str) -> int:
            marker = work / "partial-signed-product"
            marker.write_bytes(b"private partial signature output")
            marker.chmod(0o600)
            return 23

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "fixed signing helper failed"
        ):
            self.fixture.run(
                resume=False,
                helper=fail_after_partial_output,
            )
        first = self.fixture.load("00000001")
        self.assertEqual(first.state, "failed")
        self.assertEqual(first.events[-1]["failure_code"], "signing_helper_failed")
        self.assertEqual(first.events[-1]["exit_code"], 23)
        self.assertTrue(first.work.is_dir())
        marker = first.work / "partial-signed-product"
        marker_bytes = marker.read_bytes()
        marker_mode = marker.stat().st_mode & 0o777
        first_intent = (first.root / transaction.INTENT_NAME).read_bytes()
        first_events = tuple(
            (first.root / f"event-{number:08d}.json").read_bytes()
            for number in range(1, len(first.events) + 1)
        )
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])
        self.assertFalse((self.fixture.root / "signing-output").exists())

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "use the fixed resume entry"
        ):
            self.fixture.run(resume=False)
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])
        self.assertEqual(marker.read_bytes(), marker_bytes)
        self.assertEqual(marker.stat().st_mode & 0o777, marker_mode)

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "allocate a successor build"
        ) as retirement:
            self.fixture.run(resume=True)
        self.assertEqual(retirement.exception.code, "candidate_retirement_required")
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])
        self.assertEqual((first.root / transaction.INTENT_NAME).read_bytes(), first_intent)
        self.assertEqual(
            tuple(
                (first.root / f"event-{number:08d}.json").read_bytes()
                for number in range(1, len(first.events) + 1)
            ),
            first_events,
        )
        self.assertEqual(marker.read_bytes(), marker_bytes)
        self.assertEqual(marker.stat().st_mode & 0o777, marker_mode)

    def test_process_crash_requires_candidate_retirement_without_retry(self) -> None:
        def crash(_work: Path, _sha1: str, _sha256: str) -> int:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.fixture.run(resume=False, helper=crash)
        self.assertEqual(self.fixture.load("00000001").state, "signing")

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "allocate a successor build"
        ) as retirement:
            self.fixture.run(resume=True)
        first = self.fixture.load("00000001")
        self.assertEqual(retirement.exception.code, "candidate_retirement_required")
        self.assertEqual(first.state, "outcome_unknown")
        self.assertEqual(
            first.events[-1]["failure_code"],
            transaction.INTERRUPTED_DURING_SIGNING,
        )
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "allocate a successor build"
        ):
            self.fixture.run(resume=True)
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])

    def test_publish_ready_before_verified_is_permanently_retired(self) -> None:
        original_append = transaction._append_event

        def crash_before_verified_event(
            repository: Path,
            attempt: transaction.Attempt,
            state: str,
            **keywords: object,
        ) -> transaction.Attempt:
            if state == "verified":
                raise KeyboardInterrupt
            return original_append(repository, attempt, state, **keywords)

        with patch.object(
            transaction,
            "_append_event",
            side_effect=crash_before_verified_event,
        ), self.assertRaises(KeyboardInterrupt):
            self.fixture.run(resume=False)

        first = self.fixture.load("00000001")
        self.assertEqual(first.state, "signing")
        self.assertFalse(first.work.exists())
        self.assertTrue(first.publish_ready.is_dir())
        signed_app = (
            first.publish_ready
            / transaction.SIGNED_APP_WITHIN_OUTPUT
            / "fixture.bin"
        )
        signed_native = first.publish_ready / "signed-native-products/fixture.bin"
        receipt = first.publish_ready / transaction.TRANSFORMATION_RECEIPT_NAME
        ready_bytes = (
            signed_app.read_bytes(),
            signed_native.read_bytes(),
            receipt.read_bytes(),
        )

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "allocate a successor build"
        ) as retirement:
            self.fixture.run(resume=True)
        self.assertEqual(retirement.exception.code, "candidate_retirement_required")
        first = self.fixture.load("00000001")
        self.assertEqual(first.state, "outcome_unknown")
        self.assertEqual(
            first.events[-1]["failure_code"],
            transaction.INTERRUPTED_DURING_SIGNING,
        )
        event_bytes = tuple(
            (first.root / f"event-{number:08d}.json").read_bytes()
            for number in range(1, len(first.events) + 1)
        )

        with self.assertRaisesRegex(
            transaction.SigningAttemptError,
            "only a publication-bound outcome may continue",
        ):
            transaction._append_event(
                self.fixture.repository,
                first,
                "publishing",
                clock=self.fixture.clock,
            )

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "allocate a successor build"
        ):
            self.fixture.run(resume=True)
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])
        self.assertFalse((self.fixture.root / "signing-output").exists())
        self.assertEqual(
            (
                signed_app.read_bytes(),
                signed_native.read_bytes(),
                receipt.read_bytes(),
            ),
            ready_bytes,
        )
        reloaded = self.fixture.load("00000001")
        self.assertEqual(
            tuple(
                (reloaded.root / f"event-{number:08d}.json").read_bytes()
                for number in range(1, len(reloaded.events) + 1)
            ),
            event_bytes,
        )

        canonical = self.fixture.root / "signing-output"
        reloaded.publish_ready.rename(canonical)
        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "allocate a successor build"
        ):
            self.fixture.run(resume=True)
        self.assertTrue(canonical.is_dir())
        self.assertEqual(self.fixture.load("00000001").state, "outcome_unknown")
        self.assertEqual(
            tuple(
                (reloaded.root / f"event-{number:08d}.json").read_bytes()
                for number in range(1, len(reloaded.events) + 1)
            ),
            event_bytes,
        )

    def test_interruption_before_signing_closes_attempt_and_retries_safely(self) -> None:
        original_append = transaction._append_event

        def interrupt_before_signing(
            repository: Path,
            attempt: transaction.Attempt,
            state: str,
            **keywords: object,
        ) -> transaction.Attempt:
            if state == "signing":
                raise KeyboardInterrupt
            return original_append(repository, attempt, state, **keywords)

        with patch.object(
            transaction, "_append_event", side_effect=interrupt_before_signing
        ), self.assertRaises(KeyboardInterrupt):
            self.fixture.run(resume=False)

        first = self.fixture.load("00000001")
        self.assertEqual(first.state, "prepared")
        self.assertEqual(os.listdir(first.work), [])

        self.fixture.run(resume=True)
        first = self.fixture.load("00000001")
        second = self.fixture.load("00000002")
        self.assertEqual(first.state, "failed")
        self.assertEqual(
            first.events[-1]["failure_code"],
            transaction.ABANDONED_BEFORE_SIGNING,
        )
        self.assertEqual(second.state, "published")

    def test_pre_sign_retry_accepts_durable_prepared_attempt_without_work(self) -> None:
        original_append = transaction._append_event

        def interrupt_before_signing(
            repository: Path,
            attempt: transaction.Attempt,
            state: str,
            **keywords: object,
        ) -> transaction.Attempt:
            if state == "signing":
                raise KeyboardInterrupt
            return original_append(repository, attempt, state, **keywords)

        with patch.object(
            transaction, "_append_event", side_effect=interrupt_before_signing
        ), self.assertRaises(KeyboardInterrupt):
            self.fixture.run(resume=False)

        first = self.fixture.load("00000001")
        first.work.rmdir()
        self.assertFalse(os.path.lexists(first.work))

        self.fixture.run(resume=True)
        self.assertEqual(self.fixture.load("00000001").state, "failed")
        self.assertEqual(self.fixture.load("00000002").state, "published")

    def test_pre_sign_retry_rejects_unsafe_work_namespace(self) -> None:
        original_append = transaction._append_event

        for mutation in ("symlink", "wrong-mode", "regular-file"):
            with self.subTest(mutation=mutation):
                fixture = SigningAttemptFixture()
                try:
                    def interrupt_before_signing(
                        repository: Path,
                        attempt: transaction.Attempt,
                        state: str,
                        **keywords: object,
                    ) -> transaction.Attempt:
                        if state == "signing":
                            raise KeyboardInterrupt
                        return original_append(
                            repository, attempt, state, **keywords
                        )

                    with patch.object(
                        transaction,
                        "_append_event",
                        side_effect=interrupt_before_signing,
                    ), self.assertRaises(KeyboardInterrupt):
                        fixture.run(resume=False)

                    first = fixture.load("00000001")
                    if mutation == "symlink":
                        outside = fixture.repository / "outside-empty"
                        outside.mkdir(mode=0o755)
                        first.work.rmdir()
                        first.work.symlink_to(outside, target_is_directory=True)
                    elif mutation == "wrong-mode":
                        first.work.chmod(0o755)
                    else:
                        first.work.rmdir()
                        first.work.write_bytes(b"not a directory")

                    event_bytes = (
                        first.root / "event-00000001.json"
                    ).read_bytes()

                    def unexpected_helper(
                        _work: Path, _sha1: str, _sha256: str
                    ) -> int:
                        raise AssertionError("unsafe pre-sign retry reached codesign")

                    with self.assertRaisesRegex(
                        transaction.SigningAttemptError,
                        "exact private work stage",
                    ):
                        fixture.run(resume=True, helper=unexpected_helper)
                    self.assertEqual(
                        os.listdir(fixture.attempts()), ["00000001"]
                    )
                    self.assertEqual(
                        (first.root / "event-00000001.json").read_bytes(),
                        event_bytes,
                    )
                    self.assertFalse(
                        (fixture.root / "signing-output").exists()
                    )
                finally:
                    fixture.cleanup()

    def test_abandoned_pre_sign_retry_revalidates_work_namespace(self) -> None:
        original_append = transaction._append_event

        def interrupt_before_signing(
            repository: Path,
            attempt: transaction.Attempt,
            state: str,
            **keywords: object,
        ) -> transaction.Attempt:
            if state == "signing":
                raise KeyboardInterrupt
            return original_append(repository, attempt, state, **keywords)

        with patch.object(
            transaction, "_append_event", side_effect=interrupt_before_signing
        ), self.assertRaises(KeyboardInterrupt):
            self.fixture.run(resume=False)

        with patch.object(
            transaction, "_create_attempt", side_effect=KeyboardInterrupt
        ), self.assertRaises(KeyboardInterrupt):
            self.fixture.run(resume=True)
        first = self.fixture.load("00000001")
        self.assertEqual(first.state, "failed")
        self.assertEqual(
            first.events[-1]["failure_code"],
            transaction.ABANDONED_BEFORE_SIGNING,
        )
        outside = self.fixture.repository / "outside-empty"
        outside.mkdir(mode=0o755)
        first.work.rmdir()
        first.work.symlink_to(outside, target_is_directory=True)
        event_bytes = tuple(
            (first.root / f"event-{number:08d}.json").read_bytes()
            for number in range(1, len(first.events) + 1)
        )

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "exact private work stage"
        ):
            self.fixture.run(resume=True)
        self.assertEqual(os.listdir(self.fixture.attempts()), ["00000001"])
        reloaded = self.fixture.load("00000001")
        self.assertEqual(
            tuple(
                (reloaded.root / f"event-{number:08d}.json").read_bytes()
                for number in range(1, len(reloaded.events) + 1)
            ),
            event_bytes,
        )

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
                "private signing transformation failed",
            ) as raised,
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
                transformation_receipt_loader=self.fixture.transformation_load,
                canonical_transformation_verifier=self.fixture.canonical_verify,
                embedded_verifier_session_factory=(
                    self.fixture.embedded_verifier_session
                ),
            )
        self.assertEqual(raised.exception.code, "signing_transformation_failed")
        first = self.fixture.load("00000001")
        self.assertEqual(first.state, "failed")
        self.assertEqual(
            first.events[-1]["failure_code"], "signing_transformation_failed"
        )
        self.assertTrue(first.work.is_dir())
        self.assertFalse(first.publish_ready.exists())
        self.assertFalse((self.fixture.root / "signing-output").exists())
        self.assertFalse((self.fixture.root / "signing-input").exists())
        self.assertFalse((self.fixture.root / "signed-native-products").exists())

        helper_called = False

        def unexpected_helper(_work: Path, _sha1: str, _sha256: str) -> int:
            nonlocal helper_called
            helper_called = True
            return 0

        with self.assertRaisesRegex(
            transaction.SigningAttemptError, "allocate a successor build"
        ) as retirement:
            self.fixture.run(resume=True, helper=unexpected_helper)
        self.assertEqual(retirement.exception.code, "candidate_retirement_required")
        self.assertFalse(helper_called)

    def test_post_receipt_operational_failure_resumes_exact_work_once(self) -> None:
        self.enter_verification_blocked()
        helper_calls = 0
        creator_calls = 0
        observed: list[tuple[object, object]] = []

        def forbidden_helper(_work: Path, _sha1: str, _sha256: str) -> int:
            nonlocal helper_calls
            helper_calls += 1
            raise AssertionError("verification recovery invoked signing helper")

        def forbidden_creator(_repository: Path, _output: Path) -> dict[str, str]:
            nonlocal creator_calls
            creator_calls += 1
            raise AssertionError("verification recovery invoked receipt creator")

        def reopen(
            repository: Path,
            *,
            freeze_verifier: object,
            possession_verifier: object,
        ) -> transaction.FrozenSigningBindings:
            self.assertTrue(callable(possession_verifier))
            possession_verifier(repository, self.fixture.root)
            observed.append((freeze_verifier, possession_verifier))
            return self.fixture.bindings

        with patch.object(
            transaction,
            "verify_possession_proof",
            return_value=object(),
        ) as direct_proof, patch.object(
            possession,
            "_production_embedded_verifier",
        ) as forbidden_one_shot:
            output = self.fixture.run(
                resume=True,
                helper=forbidden_helper,
                transformation_creator=forbidden_creator,
                frozen_inputs_verifier=reopen,
            )

        self.assertEqual(output, self.fixture.root / "signing-output")
        self.assertEqual(helper_calls, 0)
        self.assertEqual(creator_calls, 0)
        self.assertEqual(self.fixture.session_count, 2)
        self.assertEqual(len(observed), 2)
        self.assertIs(observed[0][0], observed[1][0])
        self.assertIs(observed[0][1], observed[1][1])
        self.assertEqual(direct_proof.call_count, 2)
        forbidden_one_shot.assert_not_called()
        attempt = self.fixture.load("00000001")
        self.assertEqual(
            tuple(event["state"] for event in attempt.events),
            (
                "prepared",
                "signing",
                "verification_blocked",
                "verification_recovering",
                "verification_committing",
                "verified",
                "publishing",
                "published",
            ),
        )

    def test_missing_receipt_never_enters_verification_blocked(self) -> None:
        def reject_without_receipt(
            _repository: Path,
            _output: Path,
        ) -> dict[str, str]:
            raise transaction.SigningTransformationError(
                "injected operational verifier failure",
                code="candidate_freeze_updater_verifier_unavailable",
            )

        with self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=False,
                transformation_creator=reject_without_receipt,
            )
        self.assertEqual(caught.exception.code, "signing_transformation_failed")
        attempt = self.fixture.load("00000001")
        self.assertEqual(attempt.state, "failed")
        self.assertEqual(
            attempt.events[-1]["failure_code"],
            "signing_transformation_failed",
        )

    def test_semantic_failure_after_receipt_is_terminal(self) -> None:
        def create_then_reject(
            repository: Path,
            output: Path,
        ) -> dict[str, str]:
            self.fixture.transformation_create(repository, output)
            raise transaction.SigningTransformationError(
                "injected semantic mismatch"
            )

        with self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=False,
                transformation_creator=create_then_reject,
            )
        self.assertEqual(caught.exception.code, "signing_transformation_failed")
        self.assertEqual(self.fixture.load("00000001").state, "failed")

    def test_receipt_write_outcome_unknown_never_enters_blocked(self) -> None:
        def create_outcome_unknown(
            repository: Path,
            output: Path,
        ) -> dict[str, str]:
            self.fixture.transformation_create(repository, output)
            raise transaction.SigningTransformationOutcomeUnknown(
                "injected receipt durability reply loss"
            )

        def operational_reverification_failure(
            _repository: Path,
            _output: Path,
        ) -> dict[str, str]:
            raise transaction.SigningTransformationError(
                "injected operational verifier failure",
                code="candidate_freeze_updater_verifier_unavailable",
            )

        with self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=False,
                transformation_creator=create_outcome_unknown,
                transformation_verifier=operational_reverification_failure,
            )
        self.assertEqual(
            caught.exception.code,
            "signing_transformation_outcome_unknown",
        )
        attempt = self.fixture.load("00000001")
        self.assertEqual(attempt.state, "failed")
        self.assertEqual(
            attempt.events[-1]["failure_code"],
            "signing_transformation_outcome_unknown",
        )

    def test_bounded_recovery_failure_is_terminal_without_resigning(self) -> None:
        self.enter_verification_blocked()
        helper_calls = 0
        creator_calls = 0

        def forbidden_helper(_work: Path, _sha1: str, _sha256: str) -> int:
            nonlocal helper_calls
            helper_calls += 1
            raise AssertionError("verification recovery invoked signing helper")

        def forbidden_creator(_repository: Path, _output: Path) -> dict[str, str]:
            nonlocal creator_calls
            creator_calls += 1
            raise AssertionError("verification recovery invoked receipt creator")

        def still_unavailable(
            _repository: Path,
            _output: Path,
        ) -> dict[str, str]:
            raise transaction.SigningTransformationError(
                "sensitive operational detail must not enter the journal",
                code="candidate_freeze_updater_verifier_unavailable",
            )

        with self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=True,
                helper=forbidden_helper,
                transformation_creator=forbidden_creator,
                transformation_verifier=still_unavailable,
            )
        self.assertEqual(
            caught.exception.code,
            "candidate_freeze_updater_verifier_unavailable",
        )
        self.assertEqual(helper_calls, 0)
        self.assertEqual(creator_calls, 0)
        attempt = self.fixture.load("00000001")
        self.assertEqual(
            tuple(event["state"] for event in attempt.events[-3:]),
            ("verification_blocked", "verification_recovering", "failed"),
        )
        self.assertEqual(
            attempt.events[-1]["failure_code"],
            "candidate_freeze_updater_verifier_unavailable",
        )
        self.assertNotIn(
            "sensitive",
            (attempt.root / "event-00000005.json").read_text(encoding="ascii"),
        )

        with self.assertRaisesRegex(
            transaction.SigningAttemptError,
            "allocate a successor build",
        ):
            self.fixture.run(
                resume=True,
                helper=forbidden_helper,
                transformation_creator=forbidden_creator,
            )
        self.assertEqual(helper_calls, 0)
        self.assertEqual(creator_calls, 0)

    def test_semantic_failure_code_cannot_forge_verification_blocked(self) -> None:
        attempt = self.enter_verification_blocked()
        terminal = attempt.events[-1]
        forged = transaction._event(
            sequence=int(terminal["sequence"]),
            previous=str(attempt.events[-2]["event_sha256"]),
            intent_sha256=attempt.intent_sha256,
            state="verification_blocked",
            recorded_at=str(terminal["recorded_at"]),
            failure_code="signing_transformation_generic",
        )
        event_path = attempt.root / "event-00000003.json"
        event_path.write_bytes(transaction._canonical_json(forged))
        event_path.chmod(0o600)

        with self.assertRaisesRegex(
            transaction.SigningAttemptError,
            "failure evidence",
        ) as caught:
            self.fixture.load("00000001")
        self.assertEqual(caught.exception.code, "invalid_attempt_event")

    def test_interrupted_recovery_is_terminal_without_second_verification(self) -> None:
        attempt = self.enter_verification_blocked()
        attempt = transaction._append_event(
            self.fixture.repository,
            attempt,
            "verification_recovering",
            clock=self.fixture.clock,
        )
        verifier_calls = 0

        def forbidden_verifier(
            _repository: Path,
            _output: Path,
        ) -> dict[str, str]:
            nonlocal verifier_calls
            verifier_calls += 1
            raise AssertionError("interrupted recovery was retried")

        with self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=True,
                transformation_verifier=forbidden_verifier,
            )
        self.assertEqual(
            caught.exception.code,
            transaction.VERIFICATION_RECOVERY_INTERRUPTED,
        )
        self.assertEqual(verifier_calls, 0)
        reloaded = self.fixture.load("00000001")
        self.assertEqual(reloaded.state, "failed")
        self.assertEqual(
            reloaded.events[-1]["failure_code"],
            transaction.VERIFICATION_RECOVERY_INTERRUPTED,
        )

    def test_verification_committing_recovers_pre_rename_failure(self) -> None:
        self.enter_verification_blocked()
        with patch.object(
            transaction,
            "publish_private_directory_exclusive",
            side_effect=PublicationError("injected pre-rename failure"),
        ), self.assertRaises(transaction.SigningAttemptOutcomeUnknown):
            self.fixture.run(resume=True)

        attempt = self.fixture.load("00000001")
        self.assertEqual(attempt.state, "verification_committing")
        self.assertTrue(attempt.work.is_dir())
        self.assertFalse(attempt.publish_ready.exists())

        self.assertEqual(
            self.fixture.run(
                resume=True,
                helper=lambda *_arguments: self.fail("helper was re-run"),
                transformation_creator=lambda *_arguments: self.fail(
                    "receipt creator was re-run"
                ),
            ),
            self.fixture.root / "signing-output",
        )
        self.assertEqual(self.fixture.load("00000001").state, "published")

    def test_verification_committing_recovers_post_rename_reply_loss(self) -> None:
        self.enter_verification_blocked()

        def rename_then_lose_reply(source: Path, destination: Path) -> None:
            source.rename(destination)
            raise durable_file.DurabilityOutcomeUnknown(
                "injected post-rename durability reply loss"
            )

        with patch.object(
            transaction,
            "publish_private_directory_exclusive",
            side_effect=rename_then_lose_reply,
        ), self.assertRaises(transaction.SigningAttemptOutcomeUnknown):
            self.fixture.run(resume=True)

        attempt = self.fixture.load("00000001")
        self.assertEqual(attempt.state, "verification_committing")
        self.assertFalse(attempt.work.exists())
        self.assertTrue(attempt.publish_ready.is_dir())

        self.assertEqual(
            self.fixture.run(
                resume=True,
                helper=lambda *_arguments: self.fail("helper was re-run"),
                transformation_creator=lambda *_arguments: self.fail(
                    "receipt creator was re-run"
                ),
            ),
            self.fixture.root / "signing-output",
        )
        self.assertEqual(self.fixture.load("00000001").state, "published")

    def test_extra_work_inventory_never_enters_verification_blocked(self) -> None:
        def create_extra_then_block(
            repository: Path,
            output: Path,
        ) -> dict[str, str]:
            self.fixture.transformation_create(repository, output)
            (output / "unexpected").write_bytes(b"unexpected")
            raise transaction.SigningTransformationError(
                "injected operational verifier failure",
                code="candidate_freeze_updater_verifier_unavailable",
            )

        with self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=False,
                transformation_creator=create_extra_then_block,
            )
        self.assertEqual(caught.exception.code, "signing_transformation_failed")
        self.assertEqual(self.fixture.load("00000001").state, "failed")

    def test_work_tree_fsync_failure_never_enters_verification_blocked(self) -> None:
        def create_then_block(
            repository: Path,
            output: Path,
        ) -> dict[str, str]:
            self.fixture.transformation_create(repository, output)
            raise transaction.SigningTransformationError(
                "injected operational verifier failure",
                code="candidate_freeze_updater_verifier_unavailable",
            )

        with patch.object(
            transaction,
            "fsync_private_tree",
            side_effect=PublicationError("injected work fsync failure"),
        ), self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=False,
                transformation_creator=create_then_block,
            )
        self.assertEqual(caught.exception.code, "signing_transformation_failed")
        self.assertEqual(self.fixture.load("00000001").state, "failed")

    def test_unsafe_nested_work_tree_never_enters_verification_blocked(self) -> None:
        def create_unsafe_then_block(
            repository: Path,
            output: Path,
        ) -> dict[str, str]:
            self.fixture.transformation_create(repository, output)
            app_file = output / transaction.SIGNED_APP_WITHIN_OUTPUT / "fixture.bin"
            app_file.chmod(0o666)
            raise transaction.SigningTransformationError(
                "injected operational verifier failure",
                code="candidate_freeze_updater_verifier_unavailable",
            )

        with self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=False,
                transformation_creator=create_unsafe_then_block,
            )
        self.assertEqual(caught.exception.code, "signing_transformation_failed")
        self.assertEqual(self.fixture.load("00000001").state, "failed")

    def test_symlinked_signing_input_never_enters_verification_blocked(self) -> None:
        def create_symlink_then_block(
            repository: Path,
            output: Path,
        ) -> dict[str, str]:
            self.fixture.transformation_create(repository, output)
            signing_input = output / "signing-input"
            external = self.fixture.root / "external-signing-input"
            signing_input.rename(external)
            signing_input.symlink_to(external)
            raise transaction.SigningTransformationError(
                "injected operational verifier failure",
                code="candidate_freeze_updater_verifier_unavailable",
            )

        with self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=False,
                transformation_creator=create_symlink_then_block,
            )
        self.assertEqual(caught.exception.code, "signing_transformation_failed")
        self.assertEqual(self.fixture.load("00000001").state, "failed")

    def test_nonprivate_top_level_mode_never_enters_blocked(self) -> None:
        def create_nonprivate_then_block(
            repository: Path,
            output: Path,
        ) -> dict[str, str]:
            self.fixture.transformation_create(repository, output)
            (output / "signed-native-products").chmod(0o755)
            raise transaction.SigningTransformationError(
                "injected operational verifier failure",
                code="candidate_freeze_updater_verifier_unavailable",
            )

        with self.assertRaises(transaction.SigningAttemptError) as caught:
            self.fixture.run(
                resume=False,
                transformation_creator=create_nonprivate_then_block,
            )
        self.assertEqual(caught.exception.code, "signing_transformation_failed")
        self.assertEqual(self.fixture.load("00000001").state, "failed")

    def test_all_downstream_surfaces_block_verification_recovery(self) -> None:
        guarded = (
            transaction.SIGNING_OUTPUT_RELATIVE,
            *transaction._DOWNSTREAM_RECOVERY_GUARDS,
        )
        for relative in guarded:
            with self.subTest(relative=relative):
                fixture = SigningAttemptFixture()
                try:
                    path = fixture.root / relative
                    path.mkdir(parents=True, mode=0o700)
                    with self.assertRaisesRegex(
                        transaction.SigningAttemptError,
                        "downstream state",
                    ) as caught:
                        transaction._require_no_canonical_or_notary_state(
                            fixture.repository
                        )
                    self.assertEqual(
                        caught.exception.code,
                        transaction.VERIFICATION_RECOVERY_PRECONDITION_FAILED,
                    )
                finally:
                    fixture.cleanup()

    def test_ci_stage_inputs_remain_allowed_before_signing(self) -> None:
        stage_inputs = self.fixture.root / "stage-inputs"
        stage_inputs.mkdir(mode=0o700)
        for name in ("hosted-ci.json", "local-ci-lanes.json"):
            (stage_inputs / name).write_bytes(b"fixture")
        transaction._require_no_canonical_or_notary_state(
            self.fixture.repository
        )

    def test_publish_ready_presence_blocks_initial_recovery_boundary(self) -> None:
        attempt = self.enter_verification_blocked()
        attempt.publish_ready.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            transaction.SigningAttemptError,
            "publish-ready",
        ) as caught:
            transaction._require_no_downstream_recovery_state(
                self.fixture.repository,
                attempt,
            )
        self.assertEqual(
            caught.exception.code,
            transaction.VERIFICATION_RECOVERY_PRECONDITION_FAILED,
        )

    def test_private_output_os_error_is_terminal_and_requires_successor(self) -> None:
        def fail_private_output(_repository: Path, _output: Path) -> dict[str, str]:
            raise OSError("fixture private output verification failure")

        with self.assertRaisesRegex(
            transaction.SigningAttemptError,
            "private signed output did not pass complete verification",
        ) as raised:
            self.fixture.run(
                resume=False,
                transformation_creator=fail_private_output,
            )

        self.assertEqual(raised.exception.code, "signed_output_verification_failed")
        before = self.fixture.load("00000001")
        self.assertEqual(
            tuple(event["state"] for event in before.events),
            ("prepared", "signing", "failed"),
        )
        self.assertEqual(
            before.events[-1]["failure_code"],
            "signed_output_verification_failed",
        )
        self.assertIsNone(before.events[-1]["exit_code"])
        self.assertTrue(before.work.is_dir())
        self.assertFalse(before.publish_ready.exists())
        self.assertFalse((self.fixture.root / "signing-output").exists())
        intent_before = (before.root / transaction.INTENT_NAME).read_bytes()
        events_before = tuple(
            path.read_bytes() for path in sorted(before.root.glob("event-*.json"))
        )
        work_before = {
            str(path.relative_to(before.work)): path.read_bytes()
            for path in sorted(before.work.rglob("*"))
            if path.is_file()
        }

        helper_called = False

        def unexpected_helper(_work: Path, _sha1: str, _sha256: str) -> int:
            nonlocal helper_called
            helper_called = True
            return 0

        with self.assertRaisesRegex(
            transaction.SigningAttemptError,
            "allocate a successor build",
        ) as retirement:
            self.fixture.run(resume=True, helper=unexpected_helper)

        self.assertEqual(retirement.exception.code, "candidate_retirement_required")
        self.assertFalse(helper_called)
        after = self.fixture.load("00000001")
        self.assertEqual(after.events, before.events)
        self.assertEqual(
            (after.root / transaction.INTENT_NAME).read_bytes(),
            intent_before,
        )
        self.assertEqual(
            tuple(
                path.read_bytes()
                for path in sorted(after.root.glob("event-*.json"))
            ),
            events_before,
        )
        self.assertEqual(
            {
                str(path.relative_to(after.work)): path.read_bytes()
                for path in sorted(after.work.rglob("*"))
                if path.is_file()
            },
            work_before,
        )

    def test_publish_ready_transformation_failure_is_recorded_and_retired(
        self,
    ) -> None:
        verification_calls = 0

        def fail_second_verification(
            repository: Path, output: Path
        ) -> dict[str, str]:
            nonlocal verification_calls
            verification_calls += 1
            if verification_calls == 2:
                raise transaction.SigningTransformationError(
                    "fixture publish-ready mismatch"
                )
            return self.fixture.transformation_verify(repository, output)

        with self.assertRaisesRegex(
            transaction.SigningAttemptError,
            "private signing transformation failed: fixture publish-ready mismatch",
        ) as raised:
            self.fixture.run(
                resume=False,
                transformation_verifier=fail_second_verification,
            )

        self.assertEqual(raised.exception.code, "signing_transformation_failed")
        attempt = self.fixture.load("00000001")
        self.assertEqual(attempt.state, "failed")
        self.assertEqual(
            attempt.events[-1]["failure_code"],
            "signing_transformation_failed",
        )
        self.assertTrue(attempt.publish_ready.is_dir())
        self.assertFalse((self.fixture.root / "signing-output").exists())

        with self.assertRaisesRegex(
            transaction.SigningAttemptError,
            "allocate a successor build",
        ) as retirement:
            self.fixture.run(resume=True)
        self.assertEqual(
            retirement.exception.code,
            "candidate_retirement_required",
        )
        self.assertEqual(verification_calls, 2)

    def test_outcome_unknown_reverification_failure_requires_retirement(
        self,
    ) -> None:
        def fail_before_rename(_source: Path, _destination: Path) -> None:
            raise PublicationError("simulated pre-rename failure")

        with self.assertRaises(transaction.SigningAttemptOutcomeUnknown):
            self.fixture.run(resume=False, publisher=fail_before_rename)
        before = self.fixture.load("00000001")
        self.assertEqual(before.state, "outcome_unknown")
        self.assertTrue(before.publish_ready.is_dir())

        def reject_publish_ready(
            _repository: Path, _output: Path
        ) -> dict[str, str]:
            raise transaction.SigningTransformationError(
                "fixture recovery mismatch"
            )

        with self.assertRaisesRegex(
            transaction.SigningAttemptError,
            "allocate a successor build",
        ) as retirement:
            self.fixture.run(
                resume=True,
                transformation_verifier=reject_publish_ready,
            )
        self.assertEqual(
            retirement.exception.code,
            "candidate_retirement_required",
        )
        after = self.fixture.load("00000001")
        self.assertEqual(after.events, before.events)
        self.assertTrue(after.publish_ready.is_dir())

    def test_canonical_transformation_failure_has_one_stable_error_code(
        self,
    ) -> None:
        def reject_canonical(_repository: Path) -> dict[str, str]:
            raise transaction.SigningTransformationError(
                "fixture canonical mismatch"
            )

        for resume in (False, True):
            with self.subTest(resume=resume), self.assertRaisesRegex(
                transaction.SigningAttemptError,
                "canonical signing transformation verification failed: "
                "fixture canonical mismatch",
            ) as raised:
                self.fixture.run(
                    resume=resume,
                    canonical_transformation_verifier=reject_canonical,
                )
            self.assertEqual(
                raised.exception.code,
                "canonical_signing_transformation_failed",
            )
            attempt = self.fixture.load("00000001")
            self.assertEqual(attempt.state, "published")
            self.assertTrue((self.fixture.root / "signing-output").is_dir())

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
                        transformation_receipt_loader=(
                            self.fixture.transformation_load
                        ),
                        canonical_transformation_verifier=self.fixture.canonical_verify,
                        embedded_verifier_session_factory=(
                            self.fixture.embedded_verifier_session
                        ),
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
                transformation_receipt_loader=self.fixture.transformation_load,
                canonical_transformation_verifier=self.fixture.canonical_verify,
                embedded_verifier_session_factory=(
                    self.fixture.embedded_verifier_session
                ),
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
