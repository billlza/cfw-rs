from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable
import unittest
from unittest.mock import patch

import scripts.notarization_transaction as transaction_module
from scripts.gatekeeper_assessment import validate_evidence as validate_gatekeeper_evidence
from scripts.notarization_transaction import (
    KNOWN_MACOS_27_COMPATIBILITY_IDENTITY,
    MAX_COMMAND_OUTPUT_BYTES,
    CommandResult,
    CommandRole,
    HostSystemIdentity,
    PreSubmissionPolicyMode,
    TransactionContext,
    TransactionError,
    _claim_attempt,
    _establish_pre_submission_policy,
    _run_bounded_process,
    execute_transaction,
    production_archive_builder,
    production_host_system_identity_reader,
    production_manifest_verifier,
    production_manifest_writer,
    publish_exclusive,
    recover_transaction,
)
from scripts.tests.gatekeeper_fixture import fixture as gatekeeper_fixture
from scripts.tests.notary_fixture import (
    ARCHIVE_BYTES,
    ARCHIVE_SHA256,
    SUBMISSION_ID,
    accepted_log,
    response,
    submit_response,
)
from scripts.verify_notary_log import validate_documents


class SimulatedCrash(BaseException):
    pass


class FakeRunner:
    def __init__(self, archive_name: str) -> None:
        self.archive_name = archive_name
        self.calls: list[CommandRole] = []
        self.command_calls: list[tuple[CommandRole, tuple[str, ...], float]] = []
        self.fail_role: CommandRole | None = None
        self.fail_occurrence = 1
        self.crash_role: CommandRole | None = None
        self.crash_occurrence = 1
        self.role_counts: dict[CommandRole, int] = {}
        self.wait_status = "Accepted"
        self.info_status = "Accepted"
        self.info_created_at = "2026-07-28T04:02:00Z"
        self.history_entries: list[dict[str, str]] | None = None
        self.stderr = ""
        self.message = "Processing complete"
        self.log = accepted_log(archive_name)

    def __call__(
        self,
        role: CommandRole,
        command: list[str],
        timeout: float,
    ) -> CommandResult:
        self.calls.append(role)
        self.command_calls.append((role, tuple(command), timeout))
        occurrence = self.role_counts.get(role, 0) + 1
        self.role_counts[role] = occurrence
        if role == self.crash_role and occurrence == self.crash_occurrence:
            raise SimulatedCrash(role.value)
        if role == self.fail_role and occurrence == self.fail_occurrence:
            return CommandResult(9, "", self.stderr)
        if role == CommandRole.SUBMIT:
            stdout = submit_response(command[3])
        elif role == CommandRole.INFO:
            stdout = json.dumps(
                {
                    "createdDate": self.info_created_at,
                    "id": SUBMISSION_ID,
                    "message": "Successfully received submission info",
                    "name": self.archive_name,
                    "status": self.info_status,
                },
                sort_keys=True,
            )
        elif role == CommandRole.HISTORY:
            history_entries = self.history_entries
            if history_entries is None:
                history_entries = [
                    {
                        "createdDate": self.info_created_at,
                        "id": SUBMISSION_ID,
                        "name": self.archive_name,
                        "status": self.info_status,
                    }
                ]
            stdout = json.dumps(
                {
                    "history": history_entries,
                    "message": "Successfully received submission history.",
                },
                sort_keys=True,
            )
        elif role == CommandRole.WAIT:
            stdout = response(self.wait_status, self.message)
        elif role == CommandRole.FETCH_LOG:
            stdout = json.dumps(self.log, sort_keys=True)
        elif role in (
            CommandRole.NOTARY_READINESS,
            CommandRole.DISTRIBUTION_CHECK,
        ):
            stdout = json.dumps({"output": []})
        else:
            stdout = "ok\n"
        return CommandResult(0, stdout, self.stderr)


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        self.candidate = self.repository / "target/candidates/0.4.0"
        self.build = self.candidate / "validation/40000"
        self.native = self.build / "native-products"
        self.staging = self.candidate / ".signed-stage.fixture"
        self.app = self.staging / "Clash for Mac.app"
        self.native.mkdir(parents=True)
        executable = self.app / "Contents/MacOS/clash-for-mac"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-app")
        executable.chmod(0o755)
        (self.repository / "scripts").mkdir()
        self.context = TransactionContext(
            repository=self.repository,
            build_kind="validation",
            build_number="40000",
            staged_app=self.app,
            native_products=self.native,
            notary_profile="fixture-profile",
            repository_commit="a" * 40,
            release_source_sha256="b" * 64,
            deployment_target="15.0",
            toolchain_metadata={
                "goModuleCacheTreeSha256": "1" * 64,
                "goToolchainTreeSha256": "2" * 64,
                "goToolsTreeSha256": "3" * 64,
                "nodeToolchainTreeSha256": "4" * 64,
                "tauriToolchainTreeSha256": "5" * 64,
                "toolchainSha256": "6" * 64,
                "uiDependenciesTreeSha256": "7" * 64,
                "xcodegenToolchainTreeSha256": "8" * 64,
            },
        )
        self.runner = FakeRunner(self.context.archive_name)

    def close(self) -> None:
        self.temporary.cleanup()

    def archive_builder(self, _app: Path, archive: Path) -> None:
        archive.write_bytes(ARCHIVE_BYTES)
        archive.chmod(0o600)

    def gatekeeper(self, _app: Path, tree_sha256: str) -> dict:
        return gatekeeper_fixture(tree_sha256, "2026-07-28T04:01:00Z")

    def source_identity(self, _repository: Path) -> dict[str, str]:
        return self.context.source_identity

    @staticmethod
    def publisher(source: Path, destination: Path) -> None:
        if os.path.lexists(destination):
            raise AssertionError("publisher must never replace a destination")
        os.rename(source, destination)

    def arguments(self) -> dict:
        return {
            "command_runner": self.runner,
            "archive_builder": self.archive_builder,
            "archive_validator": lambda _archive, _app: None,
            "gatekeeper_capture": self.gatekeeper,
            "source_identity_reader": self.source_identity,
            "toolchain_metadata_reader": lambda _repository: (
                self.context.toolchain_metadata
            ),
            "publisher": self.publisher,
            "clock": lambda: "2026-07-28T04:02:00Z",
            "attempt_id_factory": lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        }

    def execute_context(self, context: TransactionContext, **overrides):
        arguments = self.arguments()
        arguments.update(overrides)
        return execute_transaction(context, **arguments)

    def execute(self, **overrides):
        return self.execute_context(self.context, **overrides)

    def recover(self, submission_id: str = SUBMISSION_ID, **overrides):
        arguments = self.arguments()
        arguments.pop("archive_builder")
        arguments.pop("attempt_id_factory")
        arguments.pop("host_system_identity_reader", None)
        arguments.update(
            recovery_tool_identity_reader=lambda _repository: {
                "repositoryCommit": "c" * 40,
                "releaseSourceSha256": "d" * 64,
            }
        )
        arguments.update(overrides)
        return recover_transaction(
            replace(self.context, staged_app=None),
            submission_id,
            self.repository,
            **arguments,
        )

    def create_orphaned_submit_attempt(self) -> None:
        def legacy_submit_shape(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.SUBMIT:
                self.runner.calls.append(role)
                self.runner.command_calls.append((role, tuple(command), timeout))
                return CommandResult(
                    0,
                    response("In Progress"),
                    "",
                )
            return self.runner(role, command, timeout)

        try:
            self.execute(command_runner=legacy_submit_shape)
        except TransactionError as error:
            if error.code != "invalid_notary_response":
                raise AssertionError(
                    f"unexpected orphan fixture failure: {error.code}"
                ) from error
        else:
            raise AssertionError("legacy submit shape unexpectedly succeeded")


def single_signature_diagnostic(app: Path) -> str:
    return (
        f"Only one signature found in {app.resolve().as_uri()}, "
        "skipping dual signature check\n"
    )


def known_notary_false_positive(app: Path) -> dict[str, str]:
    return {
        "SyspolicyCheckAdditionalInformation": "",
        "SyspolicyCheckAdvice": "",
        "SyspolicyCheckDocumentationLink": (
            "https://developer.apple.com/forums/thread/706442"
        ),
        "SyspolicyCheckErrorFile": str(
            app.resolve() / "Contents/MacOS/clash-for-mac"
        ),
        "SyspolicyCheckErrorLevel": "Fatal",
        "SyspolicyCheckLongError": (
            "Gatekeeper rejected this file. If there isn't a more descriptive "
            "error elsewhere in this output, please file a Feedback through "
            "Feedback Assistant.app so we can continue to improve "
            "syspolicy_check. Please include the app bundle you are checking "
            "and a sysdiagnose taken immediately after running syspolicy_check."
        ),
        "SyspolicyCheckShortError": "Codesign Error",
    }


def known_missing_ticket(app: Path) -> dict[str, str]:
    return {
        "SyspolicyCheckAdditionalInformation": "",
        "SyspolicyCheckAdvice": (
            "If this application has already been uploaded to the Apple notary "
            "service, please make sure to attach the ticket with the `stapler "
            "staple` command. If not, please upload to the Apple notary service "
            "using Xcode or via `notarytool`. "
        ),
        "SyspolicyCheckDocumentationLink": (
            "https://developer.apple.com/documentation/security/"
            "notarizing_macos_software_before_distribution."
        ),
        "SyspolicyCheckErrorFile": str(app.resolve()),
        "SyspolicyCheckErrorLevel": "Fatal",
        "SyspolicyCheckLongError": (
            "A Notarization ticket is not stapled to this application."
        ),
        "SyspolicyCheckShortError": "Notary Ticket Missing",
    }


class ReadinessRunner:
    def __init__(
        self,
        readiness: CommandResult,
        corroboration: CommandResult | None = None,
    ) -> None:
        self.readiness = readiness
        self.corroboration = corroboration
        self.calls: list[CommandRole] = []

    def __call__(
        self,
        role: CommandRole,
        _command: list[str],
        _timeout: float,
    ) -> CommandResult:
        self.calls.append(role)
        if role is CommandRole.NOTARY_READINESS:
            return self.readiness
        if role is CommandRole.NOTARY_READINESS_CORROBORATION:
            if self.corroboration is None:
                raise AssertionError("unexpected corroboration command")
            return self.corroboration
        raise AssertionError(f"unexpected command role: {role}")


class NotarizationReadinessPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.app = Path(self.temporary.name).resolve() / "Clash for Mac.app"
        executable = self.app / "Contents/MacOS/clash-for-mac"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _exact_runner(self, *, diagnostic: str = "") -> ReadinessRunner:
        return ReadinessRunner(
            CommandResult(
                70,
                json.dumps({"output": [known_notary_false_positive(self.app)]}),
                diagnostic,
            ),
            CommandResult(
                70,
                json.dumps({"output": [known_missing_ticket(self.app)]}),
                diagnostic,
            ),
        )

    def test_standard_success_never_uses_beta_adapter(self) -> None:
        for diagnostic in ("", single_signature_diagnostic(self.app)):
            with self.subTest(diagnostic=bool(diagnostic)):
                runner = ReadinessRunner(
                    CommandResult(0, json.dumps({"output": []}), diagnostic)
                )

                def unexpected_identity() -> HostSystemIdentity:
                    raise AssertionError("native readiness must not read host identity")

                mode = _establish_pre_submission_policy(
                    runner,
                    self.app,
                    unexpected_identity,
                )
                self.assertIs(mode, PreSubmissionPolicyMode.NATIVE)
                self.assertEqual(runner.calls, [CommandRole.NOTARY_READINESS])

    def test_accepts_exact_beta_failure_only_after_exact_corroboration(self) -> None:
        for diagnostic in ("", single_signature_diagnostic(self.app)):
            with self.subTest(diagnostic=bool(diagnostic)):
                runner = self._exact_runner(diagnostic=diagnostic)
                mode = _establish_pre_submission_policy(
                    runner,
                    self.app,
                    lambda: KNOWN_MACOS_27_COMPATIBILITY_IDENTITY,
                )
                self.assertIs(
                    mode,
                    PreSubmissionPolicyMode.MACOS_27_26A5388G_COMPATIBILITY,
                )
                self.assertEqual(
                    runner.calls,
                    [
                        CommandRole.NOTARY_READINESS,
                        CommandRole.NOTARY_READINESS_CORROBORATION,
                    ],
                )


class ProductionArchiveBuilderTests(unittest.TestCase):
    def test_uses_the_exact_metadata_stripping_ditto_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            app = parent / "Clash for Mac.app"
            app.mkdir()
            archive = parent / "notary.zip"
            observed: dict[str, object] = {}

            def run(
                command: list[str],
                timeout: float,
                *,
                cwd: Path | None = None,
                environment: dict[str, str] | None = None,
            ) -> CommandResult:
                observed.update(
                    command=command,
                    timeout=timeout,
                    cwd=cwd,
                    environment=environment,
                )
                archive.write_bytes(b"zip")
                return CommandResult(0, "", "")

            with (
                patch(
                    "scripts.notarization_transaction._run_bounded_process",
                    side_effect=run,
                ),
                patch(
                    "scripts.notarization_transaction._fsync_directory"
                ) as fsync_directory,
            ):
                production_archive_builder(app, archive)

            self.assertEqual(
                observed["command"],
                [
                    "/usr/bin/ditto",
                    "-c",
                    "-k",
                    "--keepParent",
                    "--norsrc",
                    "--noextattr",
                    "--noqtn",
                    "--noacl",
                    app.name,
                    archive.name,
                ],
            )
            self.assertEqual(observed["timeout"], 1800)
            self.assertEqual(observed["cwd"], app.parent)
            environment = observed["environment"]
            self.assertIsInstance(environment, dict)
            assert isinstance(environment, dict)
            self.assertEqual(environment["COPYFILE_DISABLE"], "1")
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            fsync_directory.assert_called_once_with(archive.parent)
            with self.assertRaisesRegex(TransactionError, "destination already exists"):
                production_archive_builder(app, archive)
            other_archive = parent / "other/notary.zip"
            with self.assertRaisesRegex(TransactionError, "share the signed app"):
                production_archive_builder(app, other_archive)

    def test_archive_contract_failure_prevents_intent_and_remote_submission(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def reject(_archive: Path, _app: Path) -> None:
            raise ValueError("invalid archive fixture")

        with self.assertRaisesRegex(
            TransactionError,
            "archive validation did not complete",
        ):
            fixture.execute(archive_validator=reject)
        self.assertEqual(fixture.runner.calls, [])
        self.assertFalse((fixture.context.attempt_root / "intent.json").exists())
        self.assertFalse(
            (fixture.context.attempt_root / "submission-receipt.json").exists()
        )
        self.assertTrue(
            (
                fixture.context.attempt_root
                / f"work/{fixture.context.archive_name}"
            ).is_file()
        )


class HostSystemIdentityReaderTests(unittest.TestCase):
    def test_reads_the_exact_absolute_release_host_identity(self) -> None:
        values = {
            ("/usr/bin/sw_vers", "-productName"): "macOS",
            ("/usr/bin/sw_vers", "-productVersion"): "27.0",
            ("/usr/bin/sw_vers", "-buildVersion"): "26A5388g",
            ("/usr/bin/uname", "-s"): "Darwin",
            ("/usr/bin/uname", "-r"): "27.0.0",
            ("/usr/bin/uname", "-m"): "arm64",
        }
        calls: list[tuple[tuple[str, ...], float]] = []

        def run(command: list[str], timeout: float) -> CommandResult:
            key = tuple(command)
            calls.append((key, timeout))
            return CommandResult(0, f"{values[key]}\n", "")

        with patch(
            "scripts.notarization_transaction._run_bounded_process",
            side_effect=run,
        ):
            identity = production_host_system_identity_reader()
        self.assertEqual(identity, KNOWN_MACOS_27_COMPATIBILITY_IDENTITY)
        self.assertEqual(
            calls,
            [(command, 30) for command in values],
        )

    def test_rejects_failed_or_malformed_host_identity_output(self) -> None:
        cases = (
            CommandResult(1, "", ""),
            CommandResult(0, "macOS", ""),
            CommandResult(0, "mac OS\n", ""),
            CommandResult(0, "macOS\n", "warning\n"),
        )
        for result in cases:
            with self.subTest(result=result):
                with patch(
                    "scripts.notarization_transaction._run_bounded_process",
                    return_value=result,
                ):
                    with self.assertRaises(TransactionError):
                        production_host_system_identity_reader()


class NotarizationReadinessPolicyMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.app = Path(self.temporary.name).resolve() / "Clash for Mac.app"
        executable = self.app / "Contents/MacOS/clash-for-mac"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _exact_runner(self) -> ReadinessRunner:
        return ReadinessRunner(
            CommandResult(
                70,
                json.dumps({"output": [known_notary_false_positive(self.app)]}),
                "",
            ),
            CommandResult(
                70,
                json.dumps({"output": [known_missing_ticket(self.app)]}),
                "",
            ),
        )

    def test_rejects_every_host_identity_near_match(self) -> None:
        for field in HostSystemIdentity.__dataclass_fields__:
            with self.subTest(field=field):
                runner = self._exact_runner()
                identity = replace(
                    KNOWN_MACOS_27_COMPATIBILITY_IDENTITY,
                    **{field: "different"},
                )
                with self.assertRaises(TransactionError):
                    _establish_pre_submission_policy(
                        runner,
                        self.app,
                        lambda identity=identity: identity,
                    )
                self.assertEqual(runner.calls, [CommandRole.NOTARY_READINESS])

    def test_rejects_every_notary_finding_and_diagnostic_near_match(self) -> None:
        expected = known_notary_false_positive(self.app)
        mutations: list[tuple[str, CommandResult]] = [
            ("wrong-returncode", CommandResult(69, "{}", "")),
            (
                "empty-output",
                CommandResult(70, json.dumps({"output": []}), ""),
            ),
            (
                "two-findings",
                CommandResult(
                    70,
                    json.dumps({"output": [expected, expected]}),
                    "",
                ),
            ),
            (
                "extra-field",
                CommandResult(
                    70,
                    json.dumps({"output": [{**expected, "extra": "value"}]}),
                    "",
                ),
            ),
        ]
        for field in expected:
            changed = dict(expected)
            changed[field] = f"{changed[field]}x"
            mutations.append(
                (
                    f"field-{field}",
                    CommandResult(70, json.dumps({"output": [changed]}), ""),
                )
            )
        diagnostic = single_signature_diagnostic(self.app)
        for label, value in (
            ("wrong-uri", diagnostic.replace("Clash%20for%20Mac", "Other")),
            ("missing-newline", diagnostic[:-1]),
            ("extra-line", diagnostic + "warning\n"),
        ):
            mutations.append(
                (
                    label,
                    CommandResult(
                        70,
                        json.dumps({"output": [expected]}),
                        value,
                    ),
                )
            )
        for label, readiness in mutations:
            with self.subTest(label=label):
                runner = ReadinessRunner(readiness)
                with self.assertRaises(TransactionError):
                    _establish_pre_submission_policy(
                        runner,
                        self.app,
                        lambda: KNOWN_MACOS_27_COMPATIBILITY_IDENTITY,
                    )
                self.assertEqual(runner.calls, [CommandRole.NOTARY_READINESS])

    def test_rejects_every_missing_ticket_corroboration_near_match(self) -> None:
        exact = self._exact_runner()
        assert exact.corroboration is not None
        expected = known_missing_ticket(self.app)
        mutations: list[tuple[str, CommandResult]] = [
            ("success", CommandResult(0, json.dumps({"output": []}), "")),
            ("wrong-returncode", CommandResult(71, "{}", "")),
            ("empty-output", CommandResult(70, json.dumps({"output": []}), "")),
            (
                "extra-finding",
                CommandResult(
                    70,
                    json.dumps({"output": [expected, expected]}),
                    "",
                ),
            ),
        ]
        for field in expected:
            changed = dict(expected)
            changed[field] = f"{changed[field]}x"
            mutations.append(
                (
                    f"field-{field}",
                    CommandResult(70, json.dumps({"output": [changed]}), ""),
                )
            )
        mutations.append(
            (
                "diagnostic",
                CommandResult(
                    70,
                    json.dumps({"output": [expected]}),
                    single_signature_diagnostic(self.app) + "warning\n",
                ),
            )
        )
        for label, corroboration in mutations:
            with self.subTest(label=label):
                runner = ReadinessRunner(exact.readiness, corroboration)
                with self.assertRaises(TransactionError):
                    _establish_pre_submission_policy(
                        runner,
                        self.app,
                        lambda: KNOWN_MACOS_27_COMPATIBILITY_IDENTITY,
                    )
                self.assertEqual(
                    runner.calls,
                    [
                        CommandRole.NOTARY_READINESS,
                        CommandRole.NOTARY_READINESS_CORROBORATION,
                    ],
                )


class NotarizationTransactionSuccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_success_is_sealed_before_single_directory_publication(self) -> None:
        final_app = self.fixture.execute()
        self.assertEqual(final_app, self.fixture.context.final_root / "Clash for Mac.app")
        self.assertTrue(final_app.is_dir())
        self.assertEqual(
            self.fixture.runner.calls,
            [
                CommandRole.NOTARY_READINESS,
                CommandRole.SUBMIT,
                CommandRole.WAIT,
                CommandRole.FETCH_LOG,
                CommandRole.STAPLE,
                CommandRole.STAPLE_VALIDATE,
                CommandRole.FINAL_VERIFY,
                CommandRole.FINAL_VERIFY,
                CommandRole.DISTRIBUTION_CHECK,
                CommandRole.FINAL_VERIFY,
            ],
        )
        work_app = str(
            self.fixture.context.attempt_root / "work/Clash for Mac.app"
        )
        publish_app = str(
            self.fixture.context.attempt_root / "publish-ready/Clash for Mac.app"
        )
        commands = self.fixture.runner.command_calls
        self.assertEqual(
            commands[0],
            (
                CommandRole.NOTARY_READINESS,
                ("/usr/bin/syspolicy_check", "notary-submission", work_app, "--json"),
                600,
            ),
        )
        submit = commands[1]
        self.assertEqual(submit[0], CommandRole.SUBMIT)
        self.assertEqual(submit[2], 1800)
        self.assertIn("--no-wait", submit[1])
        self.assertIn(self.fixture.context.notary_profile, submit[1])
        self.assertIn(
            str(
                self.fixture.context.attempt_root
                / f"work/{self.fixture.context.archive_name}"
            ),
            submit[1],
        )
        self.assertEqual(commands[2][0], CommandRole.WAIT)
        self.assertIn(SUBMISSION_ID, commands[2][1])
        self.assertEqual(commands[2][2], 7500)
        self.assertEqual(commands[3][0], CommandRole.FETCH_LOG)
        self.assertIn(SUBMISSION_ID, commands[3][1])
        self.assertEqual(commands[4][1][-1], work_app)
        self.assertEqual(commands[5][1][-1], work_app)
        final_verifies = [
            command
            for role, command, _timeout in commands
            if role == CommandRole.FINAL_VERIFY
        ]
        self.assertEqual(final_verifies[0][1], work_app)
        self.assertEqual(final_verifies[1][1], publish_app)
        self.assertEqual(final_verifies[2][1], publish_app)
        distribution = commands[-2]
        self.assertEqual(distribution[0], CommandRole.DISTRIBUTION_CHECK)
        self.assertEqual(
            distribution[1],
            ("/usr/bin/syspolicy_check", "distribution", publish_app, "--json"),
        )
        expected = {
            "Clash for Mac.app",
            "Clash for Mac.app.manifest.json",
            "notarization.json",
            "notarization-log.json",
            "gatekeeper.json",
            self.fixture.context.archive_name,
            f"{self.fixture.context.archive_name}.manifest.json",
        }
        self.assertEqual(
            {path.name for path in self.fixture.context.final_root.iterdir()}, expected
        )
        events = sorted((self.fixture.context.attempt_root / "events").glob("*.json"))
        states = [json.loads(path.read_text(encoding="utf-8"))["state"] for path in events]
        self.assertEqual(
            states,
            [
                "prepared",
                "notary_ready",
                "submitting",
                "submitted",
                "accepted",
                "log_verified",
                "stapling",
                "stapled",
                "gatekeeper_verified",
                "app_verified",
                "distribution_verified",
                "sealed",
            ],
        )
        intent_sha256 = hashlib.sha256(
            (self.fixture.context.attempt_root / "intent.json").read_bytes()
        ).hexdigest()
        previous_sha256 = None
        for sequence, path in enumerate(events, start=1):
            event = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(path.name, f"{sequence:08d}.json")
            self.assertEqual(event["sequence"], sequence)
            self.assertEqual(event["intent_sha256"], intent_sha256)
            self.assertEqual(event["previous_event_sha256"], previous_sha256)
            previous_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()

    def test_exact_beta_compatibility_is_durable_and_never_claims_notary_ready(
        self,
    ) -> None:
        fixture = self.fixture
        work_app = fixture.context.attempt_root / "work/Clash for Mac.app"

        def compatibility_runner(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role in {
                CommandRole.NOTARY_READINESS,
                CommandRole.NOTARY_READINESS_CORROBORATION,
            }:
                fixture.runner.calls.append(role)
                fixture.runner.command_calls.append((role, tuple(command), timeout))
                finding = (
                    known_notary_false_positive(work_app)
                    if role is CommandRole.NOTARY_READINESS
                    else known_missing_ticket(work_app)
                )
                return CommandResult(
                    70,
                    json.dumps({"output": [finding]}),
                    single_signature_diagnostic(work_app),
                )
            return fixture.runner(role, command, timeout)

        final_app = fixture.execute(
            command_runner=compatibility_runner,
            host_system_identity_reader=(
                lambda: KNOWN_MACOS_27_COMPATIBILITY_IDENTITY
            ),
        )
        self.assertTrue(final_app.is_dir())
        self.assertEqual(
            fixture.runner.calls[:3],
            [
                CommandRole.NOTARY_READINESS,
                CommandRole.NOTARY_READINESS_CORROBORATION,
                CommandRole.SUBMIT,
            ],
        )
        events = sorted((fixture.context.attempt_root / "events").glob("*.json"))
        states = [json.loads(path.read_text(encoding="utf-8"))["state"] for path in events]
        self.assertEqual(
            states,
            [
                "prepared",
                "pre_submission_policy_compatibility_applied",
                "submitting",
                "submitted",
                "accepted",
                "log_verified",
                "stapling",
                "stapled",
                "gatekeeper_verified",
                "app_verified",
                "distribution_verified",
                "sealed",
            ],
        )

    def test_beta_near_match_fails_before_submit_and_persists_failure(self) -> None:
        fixture = self.fixture
        work_app = fixture.context.attempt_root / "work/Clash for Mac.app"

        def mismatch_runner(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            fixture.runner.calls.append(role)
            fixture.runner.command_calls.append((role, tuple(command), timeout))
            if role is not CommandRole.NOTARY_READINESS:
                self.fail(f"unexpected command after readiness mismatch: {role}")
            finding = known_notary_false_positive(work_app)
            finding["SyspolicyCheckErrorFile"] = str(work_app.resolve())
            return CommandResult(70, json.dumps({"output": [finding]}), "")

        with self.assertRaises(TransactionError):
            fixture.execute(
                command_runner=mismatch_runner,
                host_system_identity_reader=(
                    lambda: KNOWN_MACOS_27_COMPATIBILITY_IDENTITY
                ),
            )
        self.assertEqual(fixture.runner.calls, [CommandRole.NOTARY_READINESS])
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertFalse(
            (fixture.context.attempt_root / "submission-receipt.json").exists()
        )
        events = sorted((fixture.context.attempt_root / "events").glob("*.json"))
        terminal = json.loads(events[-1].read_text(encoding="utf-8"))
        self.assertEqual(terminal["state"], "failed")
        self.assertEqual(
            terminal["failure_code"],
            "notary-readiness_finding_mismatch",
        )

    def test_beta_corroboration_near_match_is_persisted_before_submit(self) -> None:
        fixture = self.fixture
        work_app = fixture.context.attempt_root / "work/Clash for Mac.app"

        def mismatch_runner(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            fixture.runner.calls.append(role)
            fixture.runner.command_calls.append((role, tuple(command), timeout))
            if role is CommandRole.NOTARY_READINESS:
                finding = known_notary_false_positive(work_app)
            elif role is CommandRole.NOTARY_READINESS_CORROBORATION:
                finding = known_missing_ticket(work_app)
                finding["SyspolicyCheckErrorFile"] = str(
                    work_app.resolve() / "Contents"
                )
            else:
                self.fail(f"unexpected command after corroboration mismatch: {role}")
            return CommandResult(70, json.dumps({"output": [finding]}), "")

        with self.assertRaises(TransactionError):
            fixture.execute(
                command_runner=mismatch_runner,
                host_system_identity_reader=(
                    lambda: KNOWN_MACOS_27_COMPATIBILITY_IDENTITY
                ),
            )
        self.assertEqual(
            fixture.runner.calls,
            [
                CommandRole.NOTARY_READINESS,
                CommandRole.NOTARY_READINESS_CORROBORATION,
            ],
        )
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertFalse(
            (fixture.context.attempt_root / "submission-receipt.json").exists()
        )
        events = sorted((fixture.context.attempt_root / "events").glob("*.json"))
        terminal = json.loads(events[-1].read_text(encoding="utf-8"))
        self.assertEqual(terminal["state"], "failed")
        self.assertEqual(
            terminal["failure_code"],
            "notary-readiness-corroboration_finding_mismatch",
        )

    def test_final_distribution_accepts_only_the_path_bound_benign_diagnostic(
        self,
    ) -> None:
        fixture = self.fixture

        def distribution_diagnostic(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role is CommandRole.DISTRIBUTION_CHECK:
                fixture.runner.calls.append(role)
                fixture.runner.command_calls.append((role, tuple(command), timeout))
                return CommandResult(
                    0,
                    json.dumps({"output": []}),
                    single_signature_diagnostic(Path(command[-2])),
                )
            return fixture.runner(role, command, timeout)

        final_app = fixture.execute(command_runner=distribution_diagnostic)
        self.assertTrue(final_app.is_dir())

    def test_sensitive_command_output_is_never_persisted(self) -> None:
        sentinel = "person@example.test /Users/person private-key fixture-profile"
        self.fixture.runner.stderr = sentinel
        with self.assertRaisesRegex(TransactionError, "unexpected diagnostic"):
            self.fixture.execute()
        for root in (self.fixture.context.attempt_root,):
            for path in root.rglob("*"):
                if path.is_file():
                    self.assertNotIn(sentinel.encode(), path.read_bytes(), path)

    def test_unexpected_wait_message_is_rejected_without_persistence(self) -> None:
        sentinel = "person@example.test /Users/person private-key fixture-profile"
        self.fixture.runner.message = sentinel
        with self.assertRaisesRegex(TransactionError, "unexpected message"):
            self.fixture.execute()
        for path in self.fixture.context.attempt_root.rglob("*"):
            if path.is_file():
                self.assertNotIn(sentinel.encode(), path.read_bytes(), path)

    def test_private_attempt_modes_ignore_ambient_umask(self) -> None:
        previous = os.umask(0o022)
        try:
            self.fixture.execute()
        finally:
            os.umask(previous)
        for path in (
            self.fixture.context.attempt_root,
            self.fixture.context.attempt_root / "events",
        ):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for path in (
            self.fixture.context.attempt_root / "intent.json",
            self.fixture.context.attempt_root / "submission-observation.json",
            self.fixture.context.attempt_root / "submission-receipt.json",
            self.fixture.context.attempt_root / "receipt.json",
        ):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_same_build_is_rejected_before_any_new_external_command(self) -> None:
        self.fixture.execute()
        calls = list(self.fixture.runner.calls)
        with self.assertRaisesRegex(TransactionError, "must not be resubmitted"):
            self.fixture.execute()
        self.assertEqual(self.fixture.runner.calls, calls)

    def test_release_lane_uses_the_global_signed_destination(self) -> None:
        release_native = self.fixture.candidate / "release-build/40001/native-products"
        release_native.mkdir(parents=True)
        context = replace(
            self.fixture.context,
            build_kind="release",
            build_number="40001",
            native_products=release_native,
        )
        self.fixture.runner.archive_name = context.archive_name
        self.fixture.runner.log = accepted_log(context.archive_name)
        final_app = self.fixture.execute_context(context)
        self.assertEqual(final_app, self.fixture.candidate / "signed/Clash for Mac.app")
        manifest = json.loads(
            (final_app.parent / "Clash for Mac.app.manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["algorithm"], "sha256-tree-v2")
        self.assertEqual(manifest["metadata"]["artifactKind"], "notarized-release-v1")
        self.assertEqual(manifest["metadata"]["buildNumber"], "40001")


class NotarizationRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        self.fixture.create_orphaned_submit_attempt()

    def tearDown(self) -> None:
        self.fixture.close()

    def _original_event_bytes(self) -> list[bytes]:
        return [
            path.read_bytes()
            for path in sorted(
                (self.fixture.context.attempt_root / "events").iterdir()
            )[:4]
        ]

    def _reset_runner_observations(self) -> None:
        self.fixture.runner.calls.clear()
        self.fixture.runner.command_calls.clear()
        self.fixture.runner.role_counts.clear()

    def test_frozen_legacy_40001_event_prefix_is_recoverable(self) -> None:
        snapshot_path = (
            Path(__file__).parent
            / "fixtures/notarization_40001_orphan.json"
        )
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        intent_bytes = transaction_module._canonical_json(
            snapshot["intent"]
        ).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(intent_bytes).hexdigest(),
            snapshot["intentSha256"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            event_directory = Path(temporary) / "events"
            event_directory.mkdir(mode=0o700)
            for event in snapshot["events"]:
                event_path = event_directory / f"{event['sequence']:08d}.json"
                event_path.write_bytes(
                    transaction_module._canonical_json(event).encode("utf-8")
                )
                event_path.chmod(0o600)
            journal = transaction_module.EventJournal.load_existing(
                event_directory,
                snapshot["intentSha256"],
                lambda: "2026-07-28T17:41:00Z",
            )
            boundary = transaction_module._require_recoverable_event_prefix(
                journal
            )

        self.assertEqual(boundary[0].isoformat(), "2026-07-28T17:40:01+00:00")
        self.assertEqual(boundary[1].isoformat(), "2026-07-28T17:40:13+00:00")
        self.assertEqual(boundary[3:], (4, None, False, False))
        self.assertEqual(snapshot["archiveSize"], 30062052)
        self.assertEqual(
            snapshot["archiveSha256"],
            "34976cb5eaeef4fd5547304405a305f794d8ddff95676733996971173273839a",
        )

        for invalid_exit_code in (None, 0):
            with self.subTest(invalid_exit_code=invalid_exit_code):
                tampered = dict(journal.documents[-1])
                tampered["failure_code"] = "submit_failed"
                tampered["exit_code"] = invalid_exit_code
                journal.documents[-1] = tampered
                with self.assertRaises(TransactionError):
                    transaction_module._require_recoverable_event_prefix(journal)
        journal.documents[-1] = snapshot["events"][-1]

    def test_reconciles_exact_orphan_without_resubmission(self) -> None:
        original_events = self._original_event_bytes()
        self._reset_runner_observations()

        final_app = self.fixture.recover()

        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, self.fixture.runner.calls)
        self.assertEqual(
            self.fixture.runner.calls[:4],
            [
                CommandRole.FINAL_VERIFY,
                CommandRole.INFO,
                CommandRole.HISTORY,
                CommandRole.FETCH_LOG,
            ],
        )
        event_paths = sorted(
            (self.fixture.context.attempt_root / "events").iterdir()
        )
        self.assertEqual(
            [path.read_bytes() for path in event_paths[:4]],
            original_events,
        )
        states = [
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in event_paths
        ]
        self.assertEqual(
            states,
            [
                "prepared",
                "notary_ready",
                "submitting",
                "outcome_unknown",
                "reconciliation_started",
                "submission_reconciled",
                "finalization_started",
                "accepted",
                "log_verified",
                "stapling",
                "stapled",
                "gatekeeper_verified",
                "app_verified",
                "distribution_verified",
                "sealed",
            ],
        )
        receipt = json.loads(
            (
                self.fixture.context.attempt_root / "submission-receipt.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(receipt["acquisition"], "explicit-recovery")
        self.assertEqual(
            receipt["causal_binding"], "unique-history-window-and-log"
        )
        self.assertIsNone(receipt["submission_observation_sha256"])
        self.assertRegex(receipt["recovery_intent_sha256"], r"^[0-9a-f]{64}$")

    def test_ambiguous_history_fails_before_staple_or_receipt(self) -> None:
        duplicate = {
            "createdDate": self.fixture.runner.info_created_at,
            "id": "22222222-3333-4444-8555-666666666666",
            "name": self.fixture.context.archive_name,
            "status": "Accepted",
        }
        self.fixture.runner.history_entries = [
            {
                "createdDate": self.fixture.runner.info_created_at,
                "id": SUBMISSION_ID,
                "name": self.fixture.context.archive_name,
                "status": "Accepted",
            },
            duplicate,
        ]
        self._reset_runner_observations()

        with self.assertRaisesRegex(TransactionError, "uniquely bind"):
            self.fixture.recover()

        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.STAPLE, self.fixture.runner.calls)
        self.assertFalse(
            (self.fixture.context.attempt_root / "submission-receipt.json").exists()
        )
        terminal = json.loads(
            sorted((self.fixture.context.attempt_root / "events").iterdir())[-1]
            .read_text(encoding="utf-8")
        )
        self.assertEqual(terminal["state"], "failed")
        self.assertEqual(
            terminal["failure_code"], "submission_causal_binding_unproven"
        )

    def test_same_id_can_retry_after_read_only_info_failure(self) -> None:
        self.fixture.runner.fail_role = CommandRole.INFO
        self._reset_runner_observations()
        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover()
        self.assertEqual(raised.exception.code, "info_failed")
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertFalse(
            (self.fixture.context.attempt_root / "submission-receipt.json").exists()
        )

        self.fixture.runner.fail_role = None
        self._reset_runner_observations()
        final_app = self.fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        states = [
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in sorted(
                (self.fixture.context.attempt_root / "events").iterdir()
            )
        ]
        self.assertEqual(
            states[4:8],
            [
                "reconciliation_started",
                "reconciliation_deferred",
                "reconciliation_started",
                "submission_reconciled",
            ],
        )

    def test_same_id_can_retry_after_malformed_read_only_info(self) -> None:
        def malformed_info(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.INFO:
                return CommandResult(0, "{", "")
            return self.fixture.runner(role, command, timeout)

        self._reset_runner_observations()
        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(command_runner=malformed_info)
        self.assertEqual(raised.exception.code, "invalid_command_output")
        terminal = json.loads(
            sorted(
                (self.fixture.context.attempt_root / "events").glob("*.json")
            )[-1].read_text(encoding="utf-8")
        )
        self.assertEqual(terminal["state"], "reconciliation_deferred")

        self._reset_runner_observations()
        final_app = self.fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_recovery_intent_rejects_a_different_submission_id(self) -> None:
        self.fixture.runner.fail_role = CommandRole.INFO
        self._reset_runner_observations()
        with self.assertRaises(TransactionError):
            self.fixture.recover()
        self.fixture.runner.fail_role = None
        self._reset_runner_observations()

        with self.assertRaisesRegex(TransactionError, "differs"):
            self.fixture.recover("22222222-3333-4444-8555-666666666666")

        self.assertEqual(self.fixture.runner.calls, [CommandRole.FINAL_VERIFY])
        self.assertNotIn(CommandRole.INFO, self.fixture.runner.calls)

    def test_wait_failure_reuses_direct_receipt_without_resubmission(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.runner.fail_role = CommandRole.WAIT
        with self.assertRaises(TransactionError) as raised:
            fixture.execute()
        self.assertEqual(raised.exception.code, "wait_failed")
        self.assertTrue(
            (fixture.context.attempt_root / "submission-observation.json").is_file()
        )
        self.assertTrue(
            (fixture.context.attempt_root / "submission-receipt.json").is_file()
        )

        fixture.runner.fail_role = None
        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        final_app = fixture.recover()

        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.HISTORY, fixture.runner.calls)
        receipt = json.loads(
            (fixture.context.attempt_root / "submission-receipt.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(receipt["acquisition"], "submit-no-wait")

    def test_wait_process_crash_after_submitted_event_is_recoverable(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.runner.crash_role = CommandRole.WAIT
        with self.assertRaises(SimulatedCrash):
            fixture.execute()
        states = [
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in sorted(
                (fixture.context.attempt_root / "events").glob("*.json")
            )
        ]
        self.assertEqual(states[-1], "submitted")

        fixture.runner.crash_role = None
        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        final_app = fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_crash_before_submitted_event_reuses_durable_direct_receipt(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        original_append = transaction_module.EventJournal.append

        def crash_before_submitted(
            journal,
            state: str,
            **fields,
        ) -> None:
            if state == "submitted":
                raise SimulatedCrash(state)
            original_append(journal, state, **fields)

        with patch.object(
            transaction_module.EventJournal,
            "append",
            crash_before_submitted,
        ):
            with self.assertRaises(SimulatedCrash):
                fixture.execute()
        self.assertEqual(
            len(list((fixture.context.attempt_root / "events").glob("*.json"))),
            3,
        )

        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        final_app = fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)

    def test_explicit_recovery_receipt_survives_crash_before_journal_event(self) -> None:
        original_writer = transaction_module._write_json_exclusive

        def crash_after_recovery_receipt(path: Path, value: object) -> None:
            original_writer(path, value)
            if (
                path.name == "submission-receipt.json"
                and isinstance(value, dict)
                and value.get("acquisition") == "explicit-recovery"
            ):
                raise SimulatedCrash(path.name)

        self._reset_runner_observations()
        with patch.object(
            transaction_module,
            "_write_json_exclusive",
            crash_after_recovery_receipt,
        ):
            with self.assertRaises(SimulatedCrash):
                self.fixture.recover()

        self._reset_runner_observations()
        final_app = self.fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_reconciled_event_survives_crash_before_finalizer(self) -> None:
        self._reset_runner_observations()
        with patch.object(
            transaction_module,
            "_finalize_accepted_submission",
            side_effect=SimulatedCrash("before-finalizer"),
        ):
            with self.assertRaises(SimulatedCrash):
                self.fixture.recover()
        states = [
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in sorted(
                (self.fixture.context.attempt_root / "events").glob("*.json")
            )
        ]
        self.assertEqual(states[-1], "finalization_started")

        self._reset_runner_observations()
        final_app = self.fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_partial_staple_crash_restarts_from_immutable_source(self) -> None:
        self._reset_runner_observations()

        def partial_staple_crash(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.STAPLE:
                executable = (
                    Path(command[-1])
                    / "Contents/MacOS/clash-for-mac"
                )
                executable.write_bytes(b"partially-mutated-staple-workspace")
                raise SimulatedCrash(role.value)
            return self.fixture.runner(role, command, timeout)

        with self.assertRaises(SimulatedCrash):
            self.fixture.recover(command_runner=partial_staple_crash)

        immutable_executable = (
            self.fixture.context.attempt_root
            / "recovery-source/Clash for Mac.app/Contents/MacOS/clash-for-mac"
        )
        self.assertEqual(immutable_executable.read_bytes(), b"signed-app")

        self._reset_runner_observations()
        final_app = self.fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertEqual(
            (final_app / "Contents/MacOS/clash-for-mac").read_bytes(),
            b"signed-app",
        )
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        states = [
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in sorted(
                (self.fixture.context.attempt_root / "events").glob("*.json")
            )
        ]
        self.assertEqual(states.count("finalization_started"), 2)

    def test_staple_failure_retries_from_immutable_source(self) -> None:
        self.fixture.runner.fail_role = CommandRole.STAPLE
        self._reset_runner_observations()
        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover()
        self.assertEqual(raised.exception.code, "staple_failed")
        self.assertTrue(
            (self.fixture.context.attempt_root / "recovery-source").is_dir()
        )

        self.fixture.runner.fail_role = None
        self._reset_runner_observations()
        final_app = self.fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        states = [
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in sorted(
                (self.fixture.context.attempt_root / "events").glob("*.json")
            )
        ]
        self.assertIn("failed", states)
        self.assertEqual(states.count("finalization_started"), 2)

    def test_history_status_must_match_accepted_info(self) -> None:
        self.fixture.runner.history_entries = [
            {
                "createdDate": self.fixture.runner.info_created_at,
                "id": SUBMISSION_ID,
                "name": self.fixture.context.archive_name,
                "status": "Rejected",
            }
        ]
        self._reset_runner_observations()

        with self.assertRaisesRegex(TransactionError, "uniquely bind"):
            self.fixture.recover()

        self.assertNotIn(CommandRole.STAPLE, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_history_page_must_cover_complete_submit_window(self) -> None:
        self.fixture.runner.history_entries = [
            {
                "createdDate": self.fixture.runner.info_created_at,
                "id": (
                    SUBMISSION_ID
                    if index == 0
                    else f"00000000-0000-4000-8000-{index:012d}"
                ),
                "name": self.fixture.context.archive_name,
                "status": "Accepted",
            }
            for index in range(100)
        ]
        self._reset_runner_observations()

        with self.assertRaisesRegex(TransactionError, "complete submit window"):
            self.fixture.recover()

        self.assertNotIn(CommandRole.STAPLE, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_recovery_log_upload_time_must_follow_info_within_window(self) -> None:
        self.fixture.runner.log["uploadDate"] = "2026-07-28T04:02:01.000Z"
        self._reset_runner_observations()

        with self.assertRaisesRegex(TransactionError, "uploadDate"):
            self.fixture.recover()

        self.assertNotIn(CommandRole.STAPLE, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_legacy_second_window_accepts_same_second_apple_fraction(self) -> None:
        self.fixture.runner.log["uploadDate"] = "2026-07-28T04:02:00.999Z"
        self._reset_runner_observations()

        final_app = self.fixture.recover()

        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_recovery_lock_allows_only_one_reconciler(self) -> None:
        self._reset_runner_observations()
        info_entered = threading.Event()
        release_info = threading.Event()

        def blocking_runner(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.INFO:
                info_entered.set()
                if not release_info.wait(5):
                    raise AssertionError("test did not release blocked info call")
            return self.fixture.runner(role, command, timeout)

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(
                self.fixture.recover,
                command_runner=blocking_runner,
            )
            self.assertTrue(info_entered.wait(2))
            second = executor.submit(
                self.fixture.recover,
                command_runner=blocking_runner,
            )
            try:
                with self.assertRaises(TransactionError) as raised:
                    second.result(timeout=2)
                self.assertEqual(raised.exception.code, "recovery_in_progress")
            finally:
                release_info.set()
            self.assertTrue(first.result(timeout=5).is_dir())

        self.assertEqual(
            self.fixture.runner.calls.count(CommandRole.INFO),
            1,
        )
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_recovery_reserves_event_capacity_before_remote_reads(self) -> None:
        self._reset_runner_observations()
        current_events = len(
            list((self.fixture.context.attempt_root / "events").glob("*.json"))
        )
        with patch.object(
            transaction_module,
            "MAX_EVENT_DOCUMENTS",
            current_events + transaction_module.RECOVERY_SUCCESS_EVENT_RESERVE - 1,
        ):
            with self.assertRaises(TransactionError) as raised:
                self.fixture.recover()

        self.assertEqual(
            raised.exception.code,
            "event_journal_capacity_exceeded",
        )
        self.assertNotIn(CommandRole.INFO, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_recovery_tool_source_drift_blocks_every_finalization_checkpoint(self) -> None:
        for drift_call in (2, 3, 4):
            with self.subTest(drift_call=drift_call):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                fixture.create_orphaned_submit_attempt()
                fixture.runner.calls.clear()
                fixture.runner.command_calls.clear()
                fixture.runner.role_counts.clear()
                identity_calls = 0

                def drifting_recovery_identity(_repository: Path) -> dict[str, str]:
                    nonlocal identity_calls
                    identity_calls += 1
                    return {
                        "repositoryCommit": (
                            "e" * 40 if identity_calls >= drift_call else "c" * 40
                        ),
                        "releaseSourceSha256": (
                            "f" * 64 if identity_calls >= drift_call else "d" * 64
                        ),
                    }

                with self.assertRaises(TransactionError) as raised:
                    fixture.recover(
                        recovery_tool_identity_reader=drifting_recovery_identity
                    )

                self.assertEqual(
                    raised.exception.code,
                    "recovery_tool_identity_drift",
                )
                self.assertFalse(os.path.lexists(fixture.context.final_root))
                self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)


class NotarizationTransactionFailureTests(unittest.TestCase):
    def assert_role_failure_is_durable(self, role: CommandRole) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.runner.fail_role = role
        with self.assertRaises(TransactionError) as raised:
            fixture.execute()
        self.assertEqual(raised.exception.code, f"{role.value}_failed")
        expected_terminal = (
            "outcome_unknown"
            if role in (CommandRole.SUBMIT, CommandRole.WAIT)
            else "failed"
        )
        self.assertEqual(raised.exception.terminal_state, expected_terminal)
        self.assertTrue(fixture.context.attempt_root.is_dir())
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        retained = list(fixture.context.attempt_root.rglob(fixture.context.archive_name))
        self.assertEqual(len(retained), 1)
        calls = list(fixture.runner.calls)
        with self.assertRaisesRegex(TransactionError, "must not be resubmitted"):
            fixture.execute()
        self.assertEqual(fixture.runner.calls, calls)

    def assert_pre_receipt_evidence_tamper_is_rejected(
        self,
        mutator: Callable[[Fixture, Path], None],
        expected_code: str,
    ) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        calls = 0
        publisher_called = False

        def tampering(_repository: Path) -> dict[str, str]:
            nonlocal calls
            calls += 1
            if calls == 4:
                publish_ready = fixture.context.attempt_root / "publish-ready"
                self.assertTrue(publish_ready.is_dir())
                self.assertFalse(
                    (fixture.context.attempt_root / "receipt.json").exists()
                )
                mutator(fixture, publish_ready)
            return fixture.context.source_identity

        def publisher(_source: Path, _destination: Path) -> None:
            nonlocal publisher_called
            publisher_called = True

        with self.assertRaises(TransactionError) as raised:
            fixture.execute(source_identity_reader=tampering, publisher=publisher)
        self.assertEqual(raised.exception.code, expected_code)
        self.assertEqual(raised.exception.terminal_state, "failed")
        self.assertEqual(calls, 5)
        self.assertFalse(publisher_called)
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        self.assertTrue((fixture.context.attempt_root / "publish-ready").is_dir())
        self.assertFalse((fixture.context.attempt_root / "receipt.json").exists())
        events = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted((fixture.context.attempt_root / "events").iterdir())
        ]
        states = [event["state"] for event in events]
        self.assertNotIn("sealed", states)
        self.assertEqual(states[-2:], ["distribution_verified", "failed"])
        self.assertEqual(events[-1]["failure_code"], expected_code)

    def test_each_external_failure_retains_the_attempt(self) -> None:
        for role in (
            CommandRole.NOTARY_READINESS,
            CommandRole.SUBMIT,
            CommandRole.WAIT,
            CommandRole.FETCH_LOG,
            CommandRole.STAPLE,
            CommandRole.STAPLE_VALIDATE,
            CommandRole.FINAL_VERIFY,
            CommandRole.DISTRIBUTION_CHECK,
        ):
            with self.subTest(role=role):
                self.assert_role_failure_is_durable(role)

    def test_each_final_verify_occurrence_is_independently_release_blocking(self) -> None:
        for occurrence in (1, 2, 3):
            with self.subTest(occurrence=occurrence):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                fixture.runner.fail_role = CommandRole.FINAL_VERIFY
                fixture.runner.fail_occurrence = occurrence
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute()
                self.assertEqual(raised.exception.code, "final-verify_failed")
                self.assertEqual(
                    fixture.runner.calls.count(CommandRole.FINAL_VERIFY), occurrence
                )
                self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_rejected_wait_is_terminal_and_never_published(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.runner.wait_status = "Invalid"
        with self.assertRaisesRegex(TransactionError, "rejected") as raised:
            fixture.execute()
        self.assertEqual(raised.exception.terminal_state, "rejected")
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_mismatched_log_never_reaches_staple(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.runner.log["sha256"] = "f" * 64
        with self.assertRaisesRegex(TransactionError, "strict binding"):
            fixture.execute()
        self.assertNotIn(CommandRole.STAPLE, fixture.runner.calls)

    def test_gatekeeper_failure_never_publishes(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def rejected_gatekeeper(_app: Path, _digest: str) -> dict:
            raise ValueError("assessments disabled")

        with self.assertRaisesRegex(TransactionError, "Gatekeeper"):
            fixture.execute(gatekeeper_capture=rejected_gatekeeper)
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_gatekeeper_evidence_must_bind_the_exact_app_tree(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def mismatched_gatekeeper(_app: Path, _digest: str) -> dict:
            return gatekeeper_fixture("f" * 64, "2026-07-28T04:01:00Z")

        with self.assertRaisesRegex(TransactionError, "exact stapled app tree"):
            fixture.execute(gatekeeper_capture=mismatched_gatekeeper)
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_manifest_failure_never_exposes_final_root(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def failing_writer(
            artifact: Path,
            manifest: Path,
            metadata: dict[str, str],
        ) -> None:
            if artifact.name == "Clash for Mac.app":
                raise TransactionError("fixture_manifest_failure", "fixture failure")
            production_manifest_writer(artifact, manifest, metadata)

        with self.assertRaisesRegex(TransactionError, "fixture failure"):
            fixture.execute(manifest_writer=failing_writer)
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        self.assertTrue((fixture.context.attempt_root / "publish-ready").is_dir())

    def test_manifest_verifier_failure_never_exposes_final_root(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def failing_verifier(
            artifact: Path,
            manifest: Path,
            metadata: dict[str, str],
        ) -> None:
            if artifact.name == "Clash for Mac.app":
                raise TransactionError("fixture_verify_failure", "fixture verify failure")
            production_manifest_verifier(artifact, manifest, metadata)

        with self.assertRaisesRegex(TransactionError, "fixture verify failure"):
            fixture.execute(manifest_verifier=failing_verifier)
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_production_manifest_verifier_rejects_manifest_scan_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact"
            artifact.mkdir()
            (artifact / "file").write_text("bytes\n", encoding="utf-8")
            manifest = root / "artifact.manifest.json"
            metadata = {"kind": "fixture"}
            production_manifest_writer(artifact, manifest, metadata)
            original = transaction_module.build_manifest
            changed = False

            def racing_build(
                *arguments: object,
                **keywords: object,
            ) -> dict[str, object]:
                nonlocal changed
                actual = original(*arguments, **keywords)
                if not changed:
                    changed = True
                    document = json.loads(manifest.read_text(encoding="utf-8"))
                    document["metadata"]["kind"] = "tampered"
                    manifest.write_text(
                        json.dumps(document, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                return actual

            with patch(
                "scripts.notarization_transaction.build_manifest",
                side_effect=racing_build,
            ):
                with self.assertRaises(TransactionError) as raised:
                    production_manifest_verifier(artifact, manifest, metadata)
            self.assertEqual(raised.exception.code, "manifest_verification_failed")

    def test_second_manifest_hook_cannot_tamper_with_first_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "app"
            app.mkdir()
            app_file = app / "file"
            app_file.write_text("app\n", encoding="utf-8")
            archive = root / "archive.zip"
            archive.write_bytes(b"archive")
            app_manifest = root / "app.manifest.json"
            archive_manifest = root / "archive.manifest.json"
            app_metadata = {"kind": "app"}
            archive_metadata = {"kind": "archive"}
            production_manifest_writer(app, app_manifest, app_metadata)
            production_manifest_writer(
                archive,
                archive_manifest,
                archive_metadata,
            )

            def second_hook(
                artifact: Path,
                _manifest: Path,
                _metadata: dict[str, str],
            ) -> None:
                if artifact == archive:
                    app_file.write_text("tampered\n", encoding="utf-8")

            with self.assertRaises(TransactionError) as raised:
                transaction_module._run_manifest_verification_barrier(
                    second_hook,
                    (
                        (app, app_manifest, app_metadata),
                        (archive, archive_manifest, archive_metadata),
                    ),
                )
            self.assertEqual(raised.exception.code, "manifest_verification_failed")

    def test_source_drift_before_sealing_never_publishes(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        calls = 0

        def drifting(_repository: Path) -> dict[str, str]:
            nonlocal calls
            calls += 1
            if calls < 3:
                return fixture.context.source_identity
            return {
                "repositoryCommit": "c" * 40,
                "releaseSourceSha256": "d" * 64,
            }

        with self.assertRaisesRegex(TransactionError, "source identity changed"):
            fixture.execute(source_identity_reader=drifting)
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_toolchain_drift_before_publication_never_publishes(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        calls = 0

        def drifting(_repository: Path) -> dict[str, str]:
            nonlocal calls
            calls += 1
            if calls < 3:
                return fixture.context.toolchain_metadata
            return {
                **fixture.context.toolchain_metadata,
                "toolchainSha256": "f" * 64,
            }

        with self.assertRaisesRegex(TransactionError, "toolchain identity changed"):
            fixture.execute(toolchain_metadata_reader=drifting)
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_final_identity_hook_cannot_tamper_with_sealed_evidence(self) -> None:
        expectations = {
            "gatekeeper.json": "gatekeeper_evidence_identity_drift",
            "notarization.json": "notarization_result_identity_drift",
            "notarization-log.json": "accepted_notary_log_identity_drift",
            "Clash for Mac.app.manifest.json": "manifest_verification_failed",
            "unexpected-secret.txt": "preseal_publish_inventory_mismatch",
        }
        for relative, expected_code in expectations.items():
            with self.subTest(relative=relative):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                calls = 0

                def tampering(_repository: Path) -> dict[str, str]:
                    nonlocal calls
                    calls += 1
                    if calls == 3:
                        target = fixture.context.attempt_root / "publish-ready" / relative
                        target.write_text('{"tampered":true}\n', encoding="utf-8")
                    return fixture.context.toolchain_metadata

                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(toolchain_metadata_reader=tampering)
                self.assertEqual(raised.exception.code, expected_code)
                self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_pre_receipt_notarization_message_tamper_is_rejected(self) -> None:
        def mutate(fixture: Fixture, publish_ready: Path) -> None:
            notarization_path = publish_ready / "notarization.json"
            log_path = publish_ready / "notarization-log.json"
            notarization = json.loads(notarization_path.read_text(encoding="utf-8"))
            log = json.loads(log_path.read_text(encoding="utf-8"))
            notarization["message"] = "person@example.test /Users/person secret-like"
            validate_documents(
                notarization,
                log,
                archive_filename=fixture.context.archive_name,
                archive_sha256=ARCHIVE_SHA256,
            )
            notarization_path.write_text(
                json.dumps(notarization, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

        self.assert_pre_receipt_evidence_tamper_is_rejected(
            mutate,
            "notarization_result_identity_drift",
        )

    def test_pre_receipt_gatekeeper_coordinated_tamper_is_rejected(self) -> None:
        def mutate(_fixture: Fixture, publish_ready: Path) -> None:
            path = publish_ready / "gatekeeper.json"
            evidence = json.loads(path.read_text(encoding="utf-8"))
            output = evidence["assessment_output"].replace(
                "/Applications/Clash for Mac.app",
                "/Applications/Other/Clash for Mac.app",
            )
            evidence["assessment_output"] = output
            evidence["assessment_output_sha256"] = hashlib.sha256(
                output.encode("utf-8")
            ).hexdigest()
            validate_gatekeeper_evidence(evidence)
            path.write_text(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

        self.assert_pre_receipt_evidence_tamper_is_rejected(
            mutate,
            "gatekeeper_evidence_identity_drift",
        )

    def test_pre_receipt_notary_log_upload_date_tamper_is_rejected(self) -> None:
        def mutate(fixture: Fixture, publish_ready: Path) -> None:
            notarization = json.loads(
                (publish_ready / "notarization.json").read_text(encoding="utf-8")
            )
            path = publish_ready / "notarization-log.json"
            log = json.loads(path.read_text(encoding="utf-8"))
            log["uploadDate"] = "2026-07-28T04:00:01.000Z"
            validate_documents(
                notarization,
                log,
                archive_filename=fixture.context.archive_name,
                archive_sha256=ARCHIVE_SHA256,
            )
            path.write_text(
                json.dumps(log, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

        self.assert_pre_receipt_evidence_tamper_is_rejected(
            mutate,
            "accepted_notary_log_identity_drift",
        )

    def test_pre_receipt_notary_log_ticket_tamper_is_rejected(self) -> None:
        def mutate(fixture: Fixture, publish_ready: Path) -> None:
            notarization = json.loads(
                (publish_ready / "notarization.json").read_text(encoding="utf-8")
            )
            path = publish_ready / "notarization-log.json"
            log = json.loads(path.read_text(encoding="utf-8"))
            log["ticketContents"][0]["path"] = (
                "Clash for Mac.app/Contents/MacOS/another-code-object"
            )
            log["ticketContents"][0]["cdhash"] = "b" * 40
            validate_documents(
                notarization,
                log,
                archive_filename=fixture.context.archive_name,
                archive_sha256=ARCHIVE_SHA256,
            )
            path.write_text(
                json.dumps(log, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

        self.assert_pre_receipt_evidence_tamper_is_rejected(
            mutate,
            "accepted_notary_log_identity_drift",
        )

    def test_preseal_artifact_and_transaction_tamper_is_not_sealed(self) -> None:
        cases = (
            ("app", "manifest_verification_failed", 5),
            ("archive", "manifest_verification_failed", 5),
            ("app-manifest", "manifest_verification_failed", 5),
            ("archive-manifest", "manifest_verification_failed", 5),
            ("submission-receipt", "submission_receipt_identity_drift", 5),
            ("intent", "notarization_intent_identity_drift", 5),
            ("prior-event", "event_journal_identity_drift", 5),
        )
        for kind, expected_code, expected_calls in cases:
            with self.subTest(kind=kind):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                calls = 0
                publisher_called = False

                def rewrite(path: Path, field: str, value: object) -> None:
                    document = json.loads(path.read_text(encoding="utf-8"))
                    document[field] = value
                    path.write_text(
                        json.dumps(document, sort_keys=True, separators=(",", ":"))
                        + "\n",
                        encoding="utf-8",
                    )

                def mutate() -> None:
                    publish_ready = fixture.context.attempt_root / "publish-ready"
                    if kind == "app":
                        executable = (
                            publish_ready
                            / "Clash for Mac.app/Contents/MacOS/clash-for-mac"
                        )
                        executable.write_bytes(b"tampered-app")
                    elif kind == "archive":
                        (publish_ready / fixture.context.archive_name).write_bytes(
                            b"tampered-archive"
                        )
                    elif kind == "app-manifest":
                        rewrite(
                            publish_ready / "Clash for Mac.app.manifest.json",
                            "metadata",
                            {"kind": "tampered"},
                        )
                    elif kind == "archive-manifest":
                        rewrite(
                            publish_ready
                            / f"{fixture.context.archive_name}.manifest.json",
                            "metadata",
                            {"kind": "tampered"},
                        )
                    elif kind == "submission-receipt":
                        rewrite(
                            fixture.context.attempt_root / "submission-receipt.json",
                            "observed_at",
                            "2026-07-28T04:03:00Z",
                        )
                    elif kind == "intent":
                        rewrite(
                            fixture.context.attempt_root / "intent.json",
                            "prepared_at",
                            "2026-07-28T04:03:00Z",
                        )
                    elif kind == "prior-event":
                        rewrite(
                            fixture.context.attempt_root / "events/00000001.json",
                            "state",
                            "tampered",
                        )
                    else:
                        self.fail(f"unknown tamper kind: {kind}")

                def source_identity(_repository: Path) -> dict[str, str]:
                    nonlocal calls
                    calls += 1
                    if calls == 4:
                        mutate()
                    return fixture.context.source_identity

                def publisher(_source: Path, _destination: Path) -> None:
                    nonlocal publisher_called
                    publisher_called = True

                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(
                        source_identity_reader=source_identity,
                        publisher=publisher,
                    )
                self.assertEqual(raised.exception.code, expected_code)
                self.assertEqual(calls, expected_calls)
                self.assertFalse(publisher_called)
                self.assertFalse(os.path.lexists(fixture.context.final_root))
                self.assertFalse(
                    (fixture.context.attempt_root / "receipt.json").exists()
                )
                events = [
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in sorted(
                        (fixture.context.attempt_root / "events").iterdir()
                    )
                ]
                states = [event["state"] for event in events]
                self.assertNotIn("sealed", states)
                self.assertEqual(states[-1], "failed")
                self.assertEqual(events[-1]["failure_code"], expected_code)

    def test_postseal_tamper_never_reaches_publisher(self) -> None:
        cases = (
            ("app", "manifest_verification_failed"),
            ("archive", "manifest_verification_failed"),
            ("app-manifest", "manifest_verification_failed"),
            ("archive-manifest", "manifest_verification_failed"),
            ("submission-receipt", "submission_receipt_identity_drift"),
            ("intent", "notarization_intent_identity_drift"),
            ("prior-event", "event_journal_identity_drift"),
            ("gatekeeper", "gatekeeper_evidence_identity_drift"),
            ("inventory", "final_publish_inventory_mismatch"),
        )
        for kind, expected_code in cases:
            with self.subTest(kind=kind):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                calls = 0
                publisher_called = False

                def rewrite(path: Path, field: str, value: object) -> None:
                    document = json.loads(path.read_text(encoding="utf-8"))
                    document[field] = value
                    path.write_text(
                        json.dumps(document, sort_keys=True, separators=(",", ":"))
                        + "\n",
                        encoding="utf-8",
                    )

                def mutate() -> None:
                    publish_ready = fixture.context.attempt_root / "publish-ready"
                    if kind == "app":
                        executable = (
                            publish_ready
                            / "Clash for Mac.app/Contents/MacOS/clash-for-mac"
                        )
                        executable.write_bytes(b"postseal-app")
                    elif kind == "archive":
                        (publish_ready / fixture.context.archive_name).write_bytes(
                            b"postseal-archive"
                        )
                    elif kind == "app-manifest":
                        rewrite(
                            publish_ready / "Clash for Mac.app.manifest.json",
                            "metadata",
                            {"kind": "postseal"},
                        )
                    elif kind == "archive-manifest":
                        rewrite(
                            publish_ready
                            / f"{fixture.context.archive_name}.manifest.json",
                            "metadata",
                            {"kind": "postseal"},
                        )
                    elif kind == "submission-receipt":
                        rewrite(
                            fixture.context.attempt_root / "submission-receipt.json",
                            "observed_at",
                            "2026-07-28T04:04:00Z",
                        )
                    elif kind == "intent":
                        rewrite(
                            fixture.context.attempt_root / "intent.json",
                            "prepared_at",
                            "2026-07-28T04:04:00Z",
                        )
                    elif kind == "prior-event":
                        rewrite(
                            fixture.context.attempt_root / "events/00000001.json",
                            "state",
                            "postseal-tampered",
                        )
                    elif kind == "gatekeeper":
                        rewrite(
                            publish_ready / "gatekeeper.json",
                            "captured_at",
                            "2026-07-28T04:04:00Z",
                        )
                    elif kind == "inventory":
                        (publish_ready / "unexpected.txt").write_text(
                            "unexpected\n",
                            encoding="utf-8",
                        )
                    else:
                        self.fail(f"unknown tamper kind: {kind}")

                def toolchain(_repository: Path) -> dict[str, str]:
                    nonlocal calls
                    calls += 1
                    if calls == 4:
                        self.assertTrue(
                            (fixture.context.attempt_root / "receipt.json").is_file()
                        )
                        mutate()
                    return fixture.context.toolchain_metadata

                def publisher(_source: Path, _destination: Path) -> None:
                    nonlocal publisher_called
                    publisher_called = True

                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(
                        toolchain_metadata_reader=toolchain,
                        publisher=publisher,
                    )
                self.assertEqual(raised.exception.code, expected_code)
                self.assertEqual(calls, 4)
                self.assertFalse(publisher_called)
                self.assertFalse(os.path.lexists(fixture.context.final_root))
                self.assertTrue(
                    (fixture.context.attempt_root / "receipt.json").is_file()
                )
                events = [
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in sorted(
                        (fixture.context.attempt_root / "events").iterdir()
                    )
                ]
                states = [event["state"] for event in events]
                self.assertIn("sealed", states)
                self.assertEqual(states[-1], "failed")
                self.assertEqual(events[-1]["failure_code"], expected_code)

    def test_seal_timestamp_callback_tamper_is_revalidated_before_receipt(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        tampered = False

        def clock() -> str:
            nonlocal tampered
            events = fixture.context.attempt_root / "events"
            if events.is_dir() and not tampered:
                paths = sorted(events.iterdir())
                if paths:
                    latest = json.loads(paths[-1].read_text(encoding="utf-8"))
                    if latest["state"] == "distribution_verified":
                        tampered = True
                        path = (
                            fixture.context.attempt_root
                            / "publish-ready/notarization.json"
                        )
                        document = json.loads(path.read_text(encoding="utf-8"))
                        document["message"] = "callback injected raw message"
                        path.write_text(
                            json.dumps(
                                document,
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                            + "\n",
                            encoding="utf-8",
                        )
            return "2026-07-28T04:02:00Z"

        with self.assertRaises(TransactionError) as raised:
            fixture.execute(clock=clock)
        self.assertTrue(tampered)
        self.assertEqual(
            raised.exception.code,
            "notarization_result_identity_drift",
        )
        self.assertFalse((fixture.context.attempt_root / "receipt.json").exists())
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_final_app_mode_or_hardlink_tamper_is_rejected(self) -> None:
        for tamper_kind in ("mode", "hardlink"):
            with self.subTest(tamper_kind=tamper_kind):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                calls = 0

                def tampering(_repository: Path) -> dict[str, str]:
                    nonlocal calls
                    calls += 1
                    if calls == 3:
                        executable = (
                            fixture.context.attempt_root
                            / "publish-ready/Clash for Mac.app/Contents/MacOS/clash-for-mac"
                        )
                        if tamper_kind == "mode":
                            executable.chmod(0o644)
                        else:
                            outside = fixture.repository / "outside-executable"
                            outside.write_bytes(executable.read_bytes())
                            executable.unlink()
                            os.link(outside, executable)
                    return fixture.context.toolchain_metadata

                with self.assertRaises(TransactionError):
                    fixture.execute(toolchain_metadata_reader=tampering)
                self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_malformed_wait_response_is_outcome_unknown(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def malformed_wait(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.WAIT:
                fixture.runner.calls.append(role)
                return CommandResult(0, "{", "")
            return fixture.runner(role, command, timeout)

        with self.assertRaises(TransactionError) as raised:
            fixture.execute(command_runner=malformed_wait)
        self.assertEqual(raised.exception.terminal_state, "outcome_unknown")
        events = sorted((fixture.context.attempt_root / "events").glob("*.json"))
        self.assertEqual(
            json.loads(events[-1].read_text(encoding="utf-8"))["state"],
            "outcome_unknown",
        )

    def test_unknown_submit_field_is_fail_closed_after_safe_identity_projection(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def unknown_submit(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.SUBMIT:
                fixture.runner.calls.append(role)
                return CommandResult(
                    0,
                    json.dumps(
                        {
                            "id": SUBMISSION_ID,
                            "message": "Successfully uploaded file",
                            "path": command[3],
                            "warnings": ["unreviewed semantic field"],
                        }
                    ),
                    "",
                )
            return fixture.runner(role, command, timeout)

        with self.assertRaisesRegex(TransactionError, "unexpected field set") as raised:
            fixture.execute(command_runner=unknown_submit)
        self.assertEqual(raised.exception.terminal_state, "outcome_unknown")
        self.assertFalse(
            (fixture.context.attempt_root / "submission-receipt.json").exists()
        )
        observation_path = (
            fixture.context.attempt_root / "submission-observation.json"
        )
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
        self.assertEqual(observation["submission_id"], SUBMISSION_ID)
        self.assertEqual(observation["path_binding"], "exact")
        self.assertNotIn(b"warnings", observation_path.read_bytes())

        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        final_app = fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.HISTORY, fixture.runner.calls)

    def test_submit_anomalies_preserve_safe_identity_for_read_only_recovery(self) -> None:
        for label, returncode, stderr, expected_code in (
            ("nonzero", 9, "", "submit_failed"),
            ("stderr", 0, "unexpected diagnostic", "submit_stderr"),
        ):
            with self.subTest(label=label):
                fixture = Fixture()
                self.addCleanup(fixture.close)

                def anomalous_submit(
                    role: CommandRole,
                    command: list[str],
                    timeout: float,
                ) -> CommandResult:
                    if role == CommandRole.SUBMIT:
                        fixture.runner.calls.append(role)
                        return CommandResult(
                            returncode,
                            submit_response(command[3]),
                            stderr,
                        )
                    return fixture.runner(role, command, timeout)

                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(command_runner=anomalous_submit)
                self.assertEqual(raised.exception.code, expected_code)
                observation = json.loads(
                    (
                        fixture.context.attempt_root
                        / "submission-observation.json"
                    ).read_text(encoding="utf-8")
                )
                self.assertEqual(observation["submission_id"], SUBMISSION_ID)

                fixture.runner.calls.clear()
                fixture.runner.command_calls.clear()
                fixture.runner.role_counts.clear()
                final_app = fixture.recover()
                self.assertTrue(final_app.is_dir())
                self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
                self.assertNotIn(CommandRole.HISTORY, fixture.runner.calls)

    def test_id_bearing_outcome_rejects_deleted_submit_observation(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def unknown_submit(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.SUBMIT:
                return CommandResult(
                    0,
                    json.dumps(
                        {
                            "id": SUBMISSION_ID,
                            "message": "Successfully uploaded file",
                            "path": command[3],
                            "warnings": ["unknown field"],
                        }
                    ),
                    "",
                )
            return fixture.runner(role, command, timeout)

        with self.assertRaises(TransactionError):
            fixture.execute(command_runner=unknown_submit)
        (
            fixture.context.attempt_root / "submission-observation.json"
        ).unlink()
        fixture.runner.calls.clear()

        with self.assertRaises(TransactionError) as raised:
            fixture.recover()

        self.assertEqual(raised.exception.code, "submission_observation_missing")
        self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)

    def test_missing_observation_keeps_journal_id_and_requires_history(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        original_writer = transaction_module._write_json_exclusive

        def fail_observation(path: Path, value: object) -> None:
            if path.name == "submission-observation.json":
                raise TransactionError(
                    "evidence_write_failed",
                    "simulated observation durability failure",
                )
            original_writer(path, value)

        with patch.object(
            transaction_module,
            "_write_json_exclusive",
            fail_observation,
        ):
            with self.assertRaises(TransactionError) as raised:
                fixture.execute()
        self.assertEqual(raised.exception.code, "submission_observation_failed")

        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        with self.assertRaises(TransactionError) as mismatch:
            fixture.recover("22222222-3333-4444-8555-666666666666")
        self.assertEqual(mismatch.exception.code, "submission_id_mismatch")
        self.assertNotIn(CommandRole.INFO, fixture.runner.calls)

        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        final_app = fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertIn(CommandRole.HISTORY, fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)

    def test_status_shaped_submit_response_is_rejected_without_an_identity_projection(
        self,
    ) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def legacy_submit(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.SUBMIT:
                fixture.runner.calls.append(role)
                return CommandResult(0, response("In Progress"), "")
            return fixture.runner(role, command, timeout)

        with self.assertRaisesRegex(TransactionError, "projectable identity"):
            fixture.execute(command_runner=legacy_submit)
        self.assertFalse(
            (fixture.context.attempt_root / "submission-observation.json").exists()
        )
        self.assertFalse(
            (fixture.context.attempt_root / "submission-receipt.json").exists()
        )

    def test_submit_path_mismatch_is_rejected_before_identity_persistence(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def mismatched_path(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.SUBMIT:
                fixture.runner.calls.append(role)
                return CommandResult(
                    0,
                    submit_response(str(Path(command[3]).with_name("other.zip"))),
                    "",
                )
            return fixture.runner(role, command, timeout)

        with self.assertRaisesRegex(TransactionError, "path differs"):
            fixture.execute(command_runner=mismatched_path)
        self.assertFalse(
            (fixture.context.attempt_root / "submission-observation.json").exists()
        )

    def test_uppercase_submit_id_is_not_silently_canonicalized(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def uppercase_submit(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.SUBMIT:
                fixture.runner.calls.append(role)
                return CommandResult(
                    0,
                    json.dumps(
                        {
                            "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".upper(),
                            "message": "Successfully uploaded file",
                            "path": command[3],
                        }
                    ),
                    "",
                )
            return fixture.runner(role, command, timeout)

        with self.assertRaisesRegex(TransactionError, "canonical UUID text") as raised:
            fixture.execute(command_runner=uppercase_submit)
        self.assertEqual(raised.exception.terminal_state, "outcome_unknown")
        self.assertFalse(
            (fixture.context.attempt_root / "submission-receipt.json").exists()
        )

    def test_syspolicy_finding_is_release_blocking(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def finding(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.NOTARY_READINESS:
                fixture.runner.calls.append(role)
                return CommandResult(
                    0,
                    json.dumps({"output": [{"severity": "warning"}]}),
                    "localized human-readable output",
                )
            return fixture.runner(role, command, timeout)

        with self.assertRaisesRegex(TransactionError, "release-blocking finding"):
            fixture.execute(command_runner=finding)
        self.assertEqual(fixture.runner.calls, [CommandRole.NOTARY_READINESS])
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_distribution_finding_is_release_blocking(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def finding(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role == CommandRole.DISTRIBUTION_CHECK:
                fixture.runner.calls.append(role)
                fixture.runner.command_calls.append((role, tuple(command), timeout))
                return CommandResult(
                    0,
                    json.dumps({"output": [{"severity": "fatal"}]}),
                    "localized human-readable output",
                )
            return fixture.runner(role, command, timeout)

        with self.assertRaisesRegex(TransactionError, "release-blocking finding"):
            fixture.execute(command_runner=finding)
        self.assertIn(CommandRole.DISTRIBUTION_CHECK, fixture.runner.calls)
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_syspolicy_stderr_is_release_blocking_even_without_findings(self) -> None:
        for role in (
            CommandRole.NOTARY_READINESS,
            CommandRole.DISTRIBUTION_CHECK,
        ):
            with self.subTest(role=role):
                fixture = Fixture()
                self.addCleanup(fixture.close)

                def diagnostic(
                    observed_role: CommandRole,
                    command: list[str],
                    timeout: float,
                ) -> CommandResult:
                    if observed_role == role:
                        fixture.runner.calls.append(observed_role)
                        fixture.runner.command_calls.append(
                            (observed_role, tuple(command), timeout)
                        )
                        return CommandResult(
                            0,
                            json.dumps({"output": []}),
                            "warning: degraded policy check",
                        )
                    return fixture.runner(observed_role, command, timeout)

                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(command_runner=diagnostic)
                self.assertEqual(raised.exception.code, f"{role.value}_stderr")
                self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_last_source_identity_drift_prevents_publisher_invocation(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        calls = 0
        publisher_called = False

        def drifting(_repository: Path) -> dict[str, str]:
            nonlocal calls
            calls += 1
            if calls < 6:
                return fixture.context.source_identity
            return {
                "repositoryCommit": "c" * 40,
                "releaseSourceSha256": "d" * 64,
            }

        def publisher(_source: Path, _destination: Path) -> None:
            nonlocal publisher_called
            publisher_called = True

        with self.assertRaisesRegex(TransactionError, "source identity changed"):
            fixture.execute(source_identity_reader=drifting, publisher=publisher)
        self.assertEqual(calls, 6)
        self.assertFalse(publisher_called)
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        self.assertTrue((fixture.context.attempt_root / "receipt.json").is_file())

    def test_publisher_failure_retains_complete_publish_ready_tree(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def fail_publish(_source: Path, _destination: Path) -> None:
            raise TransactionError("atomic_publish_failed", "fixture publish failure")

        with self.assertRaisesRegex(TransactionError, "fixture publish failure"):
            fixture.execute(publisher=fail_publish)
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        publish_ready = fixture.context.attempt_root / "publish-ready"
        self.assertTrue(publish_ready.is_dir())
        self.assertEqual(
            {path.name for path in publish_ready.iterdir()},
            {
                "Clash for Mac.app",
                "Clash for Mac.app.manifest.json",
                "notarization.json",
                "notarization-log.json",
                "gatekeeper.json",
                fixture.context.archive_name,
                f"{fixture.context.archive_name}.manifest.json",
            },
        )
        receipt = json.loads(
            (fixture.context.attempt_root / "receipt.json").read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["state"], "publish-ready")
        events = sorted((fixture.context.attempt_root / "events").glob("*.json"))
        states = [json.loads(path.read_text(encoding="utf-8"))["state"] for path in events]
        self.assertEqual(states[-2:], ["sealed", "failed"])

    def test_post_rename_fsync_failure_is_explicitly_outcome_unknown(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        real_fsync = transaction_module._fsync_directory

        def failing_fsync(path: Path) -> None:
            if path == fixture.context.final_root.parent and os.path.lexists(
                fixture.context.final_root
            ):
                raise OSError("fixture parent fsync failure")
            real_fsync(path)

        with patch(
            "scripts.notarization_transaction._fsync_directory",
            side_effect=failing_fsync,
        ):
            with self.assertRaises(TransactionError) as raised:
                fixture.execute(publisher=publish_exclusive)
        self.assertEqual(raised.exception.code, "publish_durability_unknown")
        self.assertEqual(raised.exception.terminal_state, "outcome_unknown")
        self.assertTrue(fixture.context.final_root.is_dir())
        self.assertFalse((fixture.context.attempt_root / "publish-ready").exists())
        events = sorted((fixture.context.attempt_root / "events").glob("*.json"))
        self.assertEqual(
            json.loads(events[-1].read_text(encoding="utf-8"))["state"],
            "outcome_unknown",
        )

    def test_crash_during_submit_keeps_submitting_without_false_terminal_receipt(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.runner.crash_role = CommandRole.SUBMIT
        with self.assertRaises(SimulatedCrash):
            fixture.execute()
        events = sorted((fixture.context.attempt_root / "events").glob("*.json"))
        states = [json.loads(path.read_text(encoding="utf-8"))["state"] for path in events]
        self.assertEqual(states, ["prepared", "notary_ready", "submitting"])
        self.assertFalse(
            (fixture.context.attempt_root / "submission-receipt.json").exists()
        )

    def test_crash_during_wait_retains_the_submission_id_without_reupload(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.runner.crash_role = CommandRole.WAIT
        with self.assertRaises(SimulatedCrash):
            fixture.execute()
        receipt = json.loads(
            (fixture.context.attempt_root / "submission-receipt.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(receipt["submission_id"], SUBMISSION_ID)
        self.assertEqual(
            fixture.runner.calls,
            [CommandRole.NOTARY_READINESS, CommandRole.SUBMIT, CommandRole.WAIT],
        )

    def test_hardlinked_archive_is_rejected_before_submit(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def hardlinked_archive(_app: Path, archive: Path) -> None:
            archive.write_bytes(ARCHIVE_BYTES)
            os.link(archive, archive.parent / "archive-hardlink")

        with self.assertRaisesRegex(TransactionError, "single-link regular file"):
            fixture.execute(archive_builder=hardlinked_archive)
        self.assertEqual(fixture.runner.calls, [])

    def test_transaction_file_hash_never_reads_past_captured_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "file"
            path.write_bytes(b"1234567")
            requested: list[int] = []

            def endless_read(_descriptor: int, count: int) -> bytes:
                requested.append(count)
                return b"x" * count

            with patch(
                "scripts.notarization_transaction.os.read",
                side_effect=endless_read,
            ):
                with self.assertRaises(TransactionError) as raised:
                    transaction_module._hash_regular_file(path)
            self.assertEqual(raised.exception.code, "file_race")
            self.assertEqual(requested, [7, 1])

    def test_symlinked_attempt_parent_is_rejected_before_submit(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        outside = fixture.repository / "outside"
        outside.mkdir()
        attempts = fixture.candidate / "notary-attempts"
        attempts.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(TransactionError, "real directory"):
            fixture.execute()
        self.assertEqual(fixture.runner.calls, [])

    def test_symlinked_candidate_ancestor_is_rejected_before_submit(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        candidates = fixture.repository / "target/candidates"
        relocated = fixture.repository / "relocated-candidates"
        os.rename(candidates, relocated)
        candidates.symlink_to(relocated, target_is_directory=True)
        with self.assertRaisesRegex(TransactionError, "real directory"):
            fixture.execute()
        self.assertEqual(fixture.runner.calls, [])

    def test_group_writable_candidate_root_is_rejected_before_submit(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.candidate.chmod(0o775)
        with self.assertRaisesRegex(TransactionError, "group/world writable"):
            fixture.execute()
        self.assertEqual(fixture.runner.calls, [])

    def test_crash_after_claim_before_transfer_preserves_the_staged_app(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        with patch(
            "scripts.notarization_transaction.os.rename",
            side_effect=SimulatedCrash("before transfer"),
        ):
            with self.assertRaises(SimulatedCrash):
                fixture.execute()
        self.assertTrue(fixture.context.attempt_root.is_dir())
        self.assertTrue(fixture.app.is_dir())

    def test_failed_event_write_does_not_create_a_sequence_gap(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        real_write = transaction_module._write_json_exclusive
        injected = False

        def flaky_write(path: Path, value: object) -> None:
            nonlocal injected
            if path.name == "00000002.json" and not injected:
                injected = True
                raise TransactionError("event_write_fixture", "event write fixture")
            real_write(path, value)

        with patch(
            "scripts.notarization_transaction._write_json_exclusive",
            side_effect=flaky_write,
        ):
            with self.assertRaisesRegex(TransactionError, "event write fixture"):
                fixture.execute()
        events = sorted((fixture.context.attempt_root / "events").glob("*.json"))
        self.assertEqual([path.name for path in events], ["00000001.json", "00000002.json"])
        terminal = json.loads(events[-1].read_text(encoding="utf-8"))
        self.assertEqual(terminal["sequence"], 2)
        self.assertEqual(terminal["state"], "failed")
        self.assertEqual(
            terminal["previous_event_sha256"],
            hashlib.sha256(events[0].read_bytes()).hexdigest(),
        )


class BoundedProcessTests(unittest.TestCase):
    def test_captures_bounded_stdout_stderr_and_exit_code(self) -> None:
        result = _run_bounded_process(
            [
                sys.executable,
                "-c",
                "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)",
            ],
            5,
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "out\n")
        self.assertEqual(result.stderr, "err\n")

    def test_oversized_output_is_stopped_at_the_in_memory_boundary(self) -> None:
        with self.assertRaisesRegex(TransactionError, "safety limit") as raised:
            _run_bounded_process(
                [
                    sys.executable,
                    "-c",
                    (
                        "import sys; sys.stdout.buffer.write(b'x' * "
                        f"{MAX_COMMAND_OUTPUT_BYTES + 1}); sys.stdout.flush()"
                    ),
                ],
                5,
            )
        self.assertEqual(raised.exception.code, "command_output_oversized")

    def test_invalid_utf8_is_rejected(self) -> None:
        with self.assertRaisesRegex(TransactionError, "not UTF-8") as raised:
            _run_bounded_process(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(b'\\xff')",
                ],
                5,
            )
        self.assertEqual(raised.exception.code, "command_output_invalid_utf8")

    def test_timeout_kills_the_entire_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "child.pid"
            source = (
                "import pathlib, subprocess, sys, time; "
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(30)']); "
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
                "time.sleep(30)"
            )
            with self.assertRaisesRegex(TransactionError, "time limit") as raised:
                _run_bounded_process(
                    [sys.executable, "-c", source, str(pid_path)],
                    0.2,
                )
            self.assertEqual(raised.exception.code, "command_timeout")
            child_pid = int(pid_path.read_text(encoding="utf-8"))
            for _attempt in range(100):
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                os.kill(child_pid, signal.SIGKILL)
                self.fail("bounded runner left its descendant process alive")


class FsyncTreeTests(unittest.TestCase):
    def test_walk_error_is_not_silently_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "publish-ready"
            root.mkdir(mode=0o700)

            def failing_walk(
                _root: Path,
                *,
                topdown: bool,
                onerror,
                followlinks: bool,
            ):
                self.assertTrue(topdown)
                self.assertFalse(followlinks)
                onerror(PermissionError("fixture walk failure"))
                yield from ()

            with patch(
                "scripts.notarization_transaction.os.walk",
                side_effect=failing_walk,
            ):
                with self.assertRaisesRegex(TransactionError, "complete publish tree"):
                    transaction_module._fsync_tree(root)


class ShellCleanupContractTests(unittest.TestCase):
    @staticmethod
    def _cleanup_source() -> str:
        shell = (
            Path(__file__).resolve().parents[2] / "scripts/build_signed_candidate.sh"
        ).read_text(encoding="utf-8")
        return shell[shell.index("cleanup() {") : shell.index("trap cleanup EXIT")]

    def _run_cleanup(self, *, attempt_exists: bool) -> tuple[bool, bool]:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "target/candidates/0.4.0"
            staging = candidate / ".signed-stage.fixture"
            build = candidate / "validation/40000"
            attempt = candidate / "notary-attempts/validation/40000"
            (staging / "Clash for Mac.app").mkdir(parents=True)
            build.mkdir(parents=True)
            if attempt_exists:
                attempt.mkdir(parents=True)
            script = (
                "set -euo pipefail\n"
                'candidate_base="$CANDIDATE_BASE"\n'
                'staging="$STAGING"\n'
                'build_root="$BUILD_ROOT"\n'
                'attempt_root="$ATTEMPT_ROOT"\n'
                "completed=0\n"
                f"{self._cleanup_source()}\n"
                "cleanup\n"
                '[[ -d "$staging" ]] && staging_state=present || staging_state=absent\n'
                '[[ -d "$build_root" ]] && build_state=present || build_state=absent\n'
                'printf "%s %s\\n" "$staging_state" "$build_state"\n'
            )
            environment = {
                **os.environ,
                "CANDIDATE_BASE": str(candidate),
                "STAGING": str(staging),
                "BUILD_ROOT": str(build),
                "ATTEMPT_ROOT": str(attempt),
            }
            completed = subprocess.run(
                ["/bin/bash", "-c", script],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                env=environment,
            )
            states = completed.stdout.split()
            self.assertEqual(len(states), 2)
            return states[0] == "present", states[1] == "present"

    def test_claimed_attempt_preserves_staging_and_build_root(self) -> None:
        self.assertEqual(self._run_cleanup(attempt_exists=True), (True, True))

    def test_pre_attempt_failure_cleans_only_rebuildable_outputs(self) -> None:
        self.assertEqual(self._run_cleanup(attempt_exists=False), (False, False))


class AttemptConcurrencyTests(unittest.TestCase):
    def test_same_lane_and_build_can_only_be_claimed_once(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def claim() -> str:
            try:
                _claim_attempt(fixture.context)
                return "claimed"
            except TransactionError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _index: claim(), range(2)))
        self.assertEqual(sorted(results), ["attempt_exists", "claimed"])

    def test_two_complete_transactions_can_submit_the_build_only_once(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        second_staging = fixture.candidate / ".signed-stage.second"
        second_app = second_staging / "Clash for Mac.app"
        executable = second_app / "Contents/MacOS/clash-for-mac"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-app")
        executable.chmod(0o755)
        contexts = [
            fixture.context,
            replace(fixture.context, staged_app=second_app),
        ]

        def run(context: TransactionContext) -> str:
            try:
                fixture.execute_context(context)
                return "published"
            except TransactionError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(run, contexts))
        self.assertEqual(sorted(results), ["attempt_exists", "published"])
        self.assertEqual(fixture.runner.calls.count(CommandRole.SUBMIT), 1)


class NotarizationCliTests(unittest.TestCase):
    def _common_arguments(self) -> list[str]:
        return [
            "--build-kind",
            "validation",
            "--build-number",
            "40001",
            "--native-products",
            "/tmp/cfw-native-products",
            "--notary-profile",
            "fixture-profile",
            "--repository-commit",
            "a" * 40,
            "--release-source-sha256",
            "b" * 64,
            "--deployment-target",
            "15.0",
            "--go-module-cache-tree-sha256",
            "1" * 64,
            "--go-toolchain-tree-sha256",
            "2" * 64,
            "--go-tools-tree-sha256",
            "3" * 64,
            "--node-toolchain-tree-sha256",
            "4" * 64,
            "--tauri-toolchain-tree-sha256",
            "5" * 64,
            "--toolchain-sha256",
            "6" * 64,
            "--ui-dependencies-tree-sha256",
            "7" * 64,
            "--xcodegen-toolchain-tree-sha256",
            "8" * 64,
        ]

    def _run(self, mode_arguments: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(Path(transaction_module.__file__).resolve()),
                *self._common_arguments(),
                *mode_arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_submit_and_recovery_modes_are_mutually_exclusive(self) -> None:
        result = self._run(
            [
                "--staged-app",
                "/tmp/Clash for Mac.app",
                "--recover-submission-id",
                SUBMISSION_ID,
                "--artifact-repository",
                "/tmp/artifact-repository",
            ]
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not allowed with argument", result.stderr)

    def test_recovery_requires_separate_artifact_repository(self) -> None:
        result = self._run(["--recover-submission-id", SUBMISSION_ID])
        self.assertEqual(result.returncode, 2)
        self.assertIn("recovery requires --artifact-repository", result.stderr)

    def test_recovery_requires_explicit_toolchain_root(self) -> None:
        result = self._run(
            [
                "--recover-submission-id",
                SUBMISSION_ID,
                "--artifact-repository",
                "/tmp/artifact-repository",
            ]
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("recovery requires --toolchain-root", result.stderr)

    def test_recovery_dispatch_separates_artifact_tool_and_toolchain_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifact_repository = root / "artifact-repository"
            toolchain_root = root / "toolchains"
            artifact_repository.mkdir()
            toolchain_root.mkdir()
            final_app = (
                artifact_repository
                / "target/candidates/0.4.0/validation/40001/signed/Clash for Mac.app"
            )
            argv = [
                str(Path(transaction_module.__file__).resolve()),
                *self._common_arguments(),
                "--recover-submission-id",
                SUBMISSION_ID,
                "--artifact-repository",
                str(artifact_repository),
                "--toolchain-root",
                str(toolchain_root),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.dict(os.environ, {}, clear=False),
                patch.object(
                    transaction_module,
                    "recover_transaction",
                    return_value=final_app,
                ) as recover,
                patch("builtins.print"),
            ):
                transaction_module.main()
                self.assertEqual(
                    os.environ["CFW_TOOLCHAIN_ROOT"],
                    str(toolchain_root),
                )

            context, submission_id, recovery_tool_repository = recover.call_args.args
            self.assertEqual(context.repository, artifact_repository)
            self.assertIsNone(context.staged_app)
            self.assertEqual(submission_id, SUBMISSION_ID)
            self.assertEqual(
                recovery_tool_repository,
                Path(transaction_module.__file__).resolve().parent.parent,
            )


class ExclusivePublishTests(unittest.TestCase):
    def test_publish_uses_non_overwriting_atomic_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            destination = root / "destination"
            source.mkdir(mode=0o700)
            (source / "artifact").write_bytes(b"complete")
            publish_exclusive(source, destination)
            self.assertFalse(source.exists())
            self.assertEqual((destination / "artifact").read_bytes(), b"complete")

    def test_existing_destination_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            destination = root / "destination"
            source.mkdir(mode=0o700)
            destination.mkdir()
            with self.assertRaisesRegex(TransactionError, "already exists"):
                publish_exclusive(source, destination)
            self.assertTrue(source.is_dir())

    def test_two_publishers_cannot_replace_the_same_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            sources = [root / "source-a", root / "source-b"]
            destination = root / "destination"
            for index, source in enumerate(sources):
                source.mkdir(mode=0o700)
                (source / "artifact").write_text(str(index), encoding="utf-8")
            barrier = threading.Barrier(2)
            real_lexists = os.path.lexists

            def synchronized_lexists(path: os.PathLike[str] | str) -> bool:
                exists = real_lexists(path)
                if Path(path) == destination and not exists:
                    barrier.wait(timeout=5)
                return exists

            def publish(source: Path) -> str:
                try:
                    publish_exclusive(source, destination)
                    return "published"
                except TransactionError as error:
                    return error.code

            with patch(
                "scripts.notarization_transaction.os.path.lexists",
                side_effect=synchronized_lexists,
            ):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(executor.map(publish, sources))
            self.assertEqual(
                sorted(results), ["publish_destination_exists", "published"]
            )
            self.assertIn(
                (destination / "artifact").read_text(encoding="utf-8"),
                ("0", "1"),
            )
            self.assertEqual(sum(source.exists() for source in sources), 1)


if __name__ == "__main__":
    unittest.main()
