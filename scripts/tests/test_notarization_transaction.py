from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable
import unittest
from unittest.mock import patch
import uuid

import scripts.gatekeeper_assessment as gatekeeper_module
import scripts.notarization_transaction as transaction_module
from scripts.gatekeeper_assessment import validate_evidence as validate_gatekeeper_evidence
from scripts.hash_artifact import build_manifest
from scripts.notarization_transaction import (
    MACOS_27_26A5388G_COMPATIBILITY_IDENTITY,
    MACOS_27_26A5416B_COMPATIBILITY_IDENTITY,
    MACOS_27_26A5421A_COMPATIBILITY_IDENTITY,
    MACOS_27_26A5425A_COMPATIBILITY_IDENTITY,
    MACOS_27_COMPATIBILITY_IDENTITIES,
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
from scripts.tests.gatekeeper_fixture import macos_27_fixture
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
        self.build = self.candidate / "ga/40040"
        self.signing_output = self.build / "signing-output"
        self.native = self.signing_output / "signed-native-products"
        self.staging = self.signing_output / "signing-input"
        self.app = self.staging / "Clash for Mac.app"
        self.native.mkdir(parents=True)
        executable = self.app / "Contents/MacOS/clash-for-mac"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-app")
        executable.chmod(0o755)
        self.signed_app_tree_sha256 = build_manifest(
            self.app, algorithm="sha256-tree-v2"
        )["sha256"]
        self.signing_transformation_receipt = {
            "candidate_freeze_intent_sha256": "f" * 64,
            "code_objects": [
                "Contents/Frameworks/CFWNativeBridge.framework",
                "Contents/Library/HelperTools/CFWGlobalAuthority",
                "Contents/Library/LoginItems/CFWProxyAgent.app",
                (
                    "Contents/Library/SystemExtensions/"
                    "com.bill.clashformac.packet-tunnel.systemextension"
                ),
                "Contents/Library/HelperTools/cfw-helper-tombstone",
                ".",
            ],
            "document": transaction_module.SIGNING_TRANSFORMATION_DOCUMENT,
            "normalized_app_tree_sha256": "9" * 64,
            "pre_sign_app_manifest_sha256": "a" * 64,
            "pre_sign_app_tree_sha256": "b" * 64,
            "product": {"build_number": "40040", "version": "0.4.0"},
            "profiles": {
                "host": "c" * 64,
                "packet_tunnel": "d" * 64,
                "proxy_agent": "e" * 64,
            },
            "removed_signed_profiles": [
                "Contents/embedded.provisionprofile",
                (
                    "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/"
                    "embedded.provisionprofile"
                ),
                (
                    "Contents/Library/SystemExtensions/"
                    "com.bill.clashformac.packet-tunnel.systemextension/Contents/"
                    "embedded.provisionprofile"
                ),
            ],
            "schema_version": transaction_module.SIGNING_TRANSFORMATION_SCHEMA_VERSION,
            "signed_app_tree_sha256": self.signed_app_tree_sha256,
        }
        (self.repository / "scripts").mkdir()
        self.context = TransactionContext(
            repository=self.repository,
            build_kind="ga",
            build_number="40040",
            staged_app=self.app,
            native_products=self.native,
            notary_profile=transaction_module.NOTARY_PROFILE,
            repository_commit="a" * 40,
            release_source_sha256="b" * 64,
            deployment_target="15.0",
            toolchain_metadata={
                "cargoWorkspaceSourcesTreeSha256": "0" * 64,
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
        self.clock: Callable[[], str] = lambda: "2026-07-28T04:02:00Z"

    def close(self) -> None:
        self.temporary.cleanup()

    def archive_builder(self, _app: Path, archive: Path) -> None:
        archive.write_bytes(ARCHIVE_BYTES)
        archive.chmod(0o600)

    def gatekeeper(self, _app: Path, tree_sha256: str) -> dict:
        return gatekeeper_fixture(
            tree_sha256,
            "2026-07-28T04:01:00Z",
            _app,
        )

    def source_identity(self, _repository: Path) -> dict[str, str]:
        return self.context.source_identity

    def signing_transformation(self, _repository: Path) -> dict[str, object]:
        return json.loads(json.dumps(self.signing_transformation_receipt))

    def signing_transformation_binding(self) -> dict[str, str]:
        receipt = self.signing_transformation_receipt
        return {
            "signing_transformation_receipt_sha256": hashlib.sha256(
                transaction_module.canonical_signing_transformation_json(receipt)
            ).hexdigest(),
            "pre_sign_app_manifest_sha256": receipt[
                "pre_sign_app_manifest_sha256"
            ],
            "pre_sign_app_tree_sha256": receipt["pre_sign_app_tree_sha256"],
            "signed_app_tree_sha256": receipt["signed_app_tree_sha256"],
        }

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
            "clock": self.clock,
            "attempt_id_factory": lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "candidate_freeze_verifier": lambda _repository: (
                transaction_module.FrozenCandidate(
                    root=self.build,
                    intent_path=self.build / "candidate-freeze/intent.json",
                    intent_sha256="f" * 64,
                    product_version="0.4.0",
                    build_number="40040",
                    recovered=False,
                )
            ),
            "signing_transformation_verifier": self.signing_transformation,
            "signing_transformation_receipt_reader": self.signing_transformation,
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
        arguments.pop("candidate_freeze_verifier")
        arguments.pop("signing_transformation_verifier")
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


def sole_finalization_run(fixture: Fixture) -> Path:
    runs = list(
        (fixture.context.attempt_root / "finalization-runs").glob("*")
    )
    if len(runs) != 1:
        raise AssertionError(f"expected one finalization run, observed {len(runs)}")
    uuid.UUID(runs[0].name)
    return runs[0]


def current_publish_ready(fixture: Fixture) -> Path | None:
    candidates = list(
        (fixture.context.attempt_root / "finalization-runs").glob(
            "*/publish-ready"
        )
    )
    if len(candidates) > 1:
        raise AssertionError("multiple active publish-ready workspaces")
    return candidates[0] if candidates else None


def sole_finalization_receipt(fixture: Fixture) -> Path:
    receipts = list(
        (fixture.context.attempt_root / "finalization-runs").glob(
            "*/receipt.json"
        )
    )
    if len(receipts) != 1:
        raise AssertionError(
            f"expected one finalization receipt, observed {len(receipts)}"
        )
    return receipts[0]


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
                    lambda: MACOS_27_26A5388G_COMPATIBILITY_IDENTITY,
                )
                self.assertIs(
                    mode,
                    PreSubmissionPolicyMode.MACOS_27_EXACT_BUILD_COMPATIBILITY,
                )
                self.assertEqual(
                    runner.calls,
                    [
                        CommandRole.NOTARY_READINESS,
                        CommandRole.NOTARY_READINESS_CORROBORATION,
                    ],
                )

    def test_accepts_each_reviewed_macOS_27_seed_with_exact_corroboration(
        self,
    ) -> None:
        self.assertEqual(
            MACOS_27_COMPATIBILITY_IDENTITIES,
            frozenset(
                HostSystemIdentity(
                    product_name="macOS",
                    product_version="27.0",
                    build_version=build_version,
                    kernel_name="Darwin",
                    kernel_release="27.0.0",
                    architecture="arm64",
                )
                for build_version in (
                    "26A5388g",
                    "26A5406e",
                    "26A5416b",
                    "26A5421a",
                    "26A5425a",
                )
            ),
        )
        for identity in MACOS_27_COMPATIBILITY_IDENTITIES:
            with self.subTest(build_version=identity.build_version):
                runner = self._exact_runner()
                mode = _establish_pre_submission_policy(
                    runner,
                    self.app,
                    lambda identity=identity: identity,
                )
                self.assertIs(
                    mode,
                    PreSubmissionPolicyMode.MACOS_27_EXACT_BUILD_COMPATIBILITY,
                )
                self.assertEqual(
                    runner.calls,
                    [
                        CommandRole.NOTARY_READINESS,
                        CommandRole.NOTARY_READINESS_CORROBORATION,
                    ],
                )

    def test_exact_host_rejects_a_different_codesign_failure(self) -> None:
        finding = known_notary_false_positive(self.app)
        finding["SyspolicyCheckLongError"] = (
            "Main executable is missing one or more executable bits."
        )
        runner = ReadinessRunner(
            CommandResult(70, json.dumps({"output": [finding]}), "")
        )

        with self.assertRaises(TransactionError) as raised:
            _establish_pre_submission_policy(
                runner,
                self.app,
                lambda: MACOS_27_26A5421A_COMPATIBILITY_IDENTITY,
            )

        self.assertEqual(
            raised.exception.code,
            "notary-readiness_finding_mismatch",
        )
        self.assertEqual(runner.calls, [CommandRole.NOTARY_READINESS])


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
            if not isinstance(environment, dict):
                self.fail("archive builder did not provide an environment")
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
        self.assertEqual(fixture.runner.calls, [CommandRole.NOTARY_READINESS])
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
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
        self.assertEqual(identity, MACOS_27_26A5388G_COMPATIBILITY_IDENTITY)
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
        for allowed_identity in MACOS_27_COMPATIBILITY_IDENTITIES:
            for field in HostSystemIdentity.__dataclass_fields__:
                with self.subTest(
                    build_version=allowed_identity.build_version,
                    field=field,
                ):
                    runner = self._exact_runner()
                    identity = replace(
                        allowed_identity,
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
                        lambda: MACOS_27_26A5421A_COMPATIBILITY_IDENTITY,
                    )
                self.assertEqual(runner.calls, [CommandRole.NOTARY_READINESS])

    def test_rejects_every_missing_ticket_corroboration_near_match(self) -> None:
        exact = self._exact_runner()
        if exact.corroboration is None:
            self.fail("exact readiness fixture lacks corroboration")
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
                        lambda: MACOS_27_26A5421A_COMPATIBILITY_IDENTITY,
                    )
                self.assertEqual(
                    runner.calls,
                    [
                        CommandRole.NOTARY_READINESS,
                        CommandRole.NOTARY_READINESS_CORROBORATION,
                    ],
                )


class ArtifactToolchainReaderTests(unittest.TestCase):
    def test_dispatch_uses_frozen_source_and_maps_its_exact_positional_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            values = [str(index) * 64 for index in range(9)]
            with (
                patch.object(transaction_module, "require_closed_release_runtime") as runtime,
                patch.object(
                    transaction_module,
                    "_run_bounded_process",
                    return_value=CommandResult(0, " ".join(values) + "\n", ""),
                ) as runner,
            ):
                result = transaction_module.production_artifact_toolchain_metadata_reader(repository)
            runtime.assert_called_once_with()
            self.assertEqual(
                result, dict(zip(transaction_module.TOOLCHAIN_METADATA_ORDER, values, strict=True))
            )
            command, timeout = runner.call_args.args
            self.assertEqual(command[:3], ["/bin/bash", "-p", "-c"])
            self.assertIn('source "$1/scripts/release_python_launcher.sh"', command[3])
            self.assertIn('"$1/scripts/candidate_artifact_binding.py" --repository "$1"', command[3])
            self.assertEqual(command[-1], str(repository))
            self.assertEqual(timeout, 1800)
            self.assertEqual(runner.call_args.kwargs, {"cwd": repository})

    def test_verifier_diagnostics_and_every_output_near_match_fail_closed(self) -> None:
        exact = " ".join(str(index) * 64 for index in range(9)) + "\n"
        malformed = (
            CommandResult(1, exact, ""),
            CommandResult(0, exact, "warning\n"),
            CommandResult(0, exact[:-1], ""),
            CommandResult(0, exact + "\n", ""),
            CommandResult(0, " " + exact, ""),
            CommandResult(0, exact.replace(" ", "  ", 1), ""),
            CommandResult(0, exact.replace("0", "A", 1), ""),
            CommandResult(0, " ".join(exact.split(" ")[:-1]) + "\n", ""),
            CommandResult(0, "", ""),
        )
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            for result in malformed:
                with self.subTest(result=result):
                    with (
                        patch.object(transaction_module, "require_closed_release_runtime"),
                        patch.object(transaction_module, "_run_bounded_process", return_value=result),
                        self.assertRaises(TransactionError),
                    ):
                        transaction_module.production_artifact_toolchain_metadata_reader(repository)

    def test_unsealed_runtime_prevents_any_child_verifier(self) -> None:
        with (
            patch.object(
                transaction_module,
                "require_closed_release_runtime",
                side_effect=transaction_module.ReleasePythonRuntimeError("unsealed"),
            ),
            patch.object(transaction_module, "_run_bounded_process") as runner,
            self.assertRaises(transaction_module.ReleasePythonRuntimeError),
        ):
            transaction_module.production_artifact_toolchain_metadata_reader(Path("/unused"))
        runner.assert_not_called()


class FrozenCandidateExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        self.addCleanup(self.fixture.close)
        self.fixture.build.chmod(0o700)
        self.executor = self.fixture.repository / "executor"
        self.executor.mkdir()
        self.identity = {"repositoryCommit": "c" * 40, "releaseSourceSha256": "d" * 64}

    def arguments(self) -> dict:
        return {
            "executor_repository": self.executor,
            "executor_source_reader": lambda _repository: self.identity,
            "executor_historical_reader": lambda _repository, _commit: self.identity,
        }

    def test_first_submission_uses_original_artifact_identity_and_retains_executor(self) -> None:
        fixture = self.fixture
        final_app = fixture.execute(**self.arguments())
        self.assertTrue(final_app.is_dir())
        intent = json.loads((fixture.context.attempt_root / "intent.json").read_bytes())
        self.assertEqual(intent["repository_commit"], fixture.context.repository_commit)
        self.assertEqual(intent["release_source_sha256"], fixture.context.release_source_sha256)
        binding = json.loads(
            (fixture.build / "stage-inputs/notarization-executor.json").read_bytes()
        )
        self.assertEqual(binding["artifact_source"], fixture.context.source_identity)
        self.assertEqual(binding["executor_source"], self.identity)
        verified = PublishedTransactionReceiptValidationTests._validate(fixture)
        self.assertEqual(verified.receipt["submission_id"], SUBMISSION_ID)
        calls = list(fixture.runner.calls)
        with self.assertRaises(TransactionError) as repeated:
            fixture.execute(**self.arguments())
        self.assertEqual(repeated.exception.code, "attempt_exists")
        self.assertEqual(fixture.runner.calls, calls)
        self.assertEqual(calls.count(CommandRole.SUBMIT), 1)

    def test_readiness_failure_writes_no_executor_binding_and_keeps_signed_app(self) -> None:
        self.fixture.runner.fail_role = CommandRole.NOTARY_READINESS
        with self.assertRaises(TransactionError):
            self.fixture.execute(**self.arguments())
        self.assertFalse(self.fixture.context.attempt_root.exists())
        self.assertFalse((self.fixture.build / "stage-inputs").exists())
        self.assertTrue(self.fixture.app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_executor_drift_at_admission_prevents_claim(self) -> None:
        reads = 0

        def source(_repository: Path) -> dict[str, str]:
            nonlocal reads
            reads += 1
            return self.identity if reads == 1 else {**self.identity, "repositoryCommit": "0" * 40}

        arguments = {**self.arguments(), "executor_source_reader": source}
        with self.assertRaises(TransactionError) as raised:
            self.fixture.execute(**arguments)
        self.assertEqual(raised.exception.code, "notarization_executor_identity_failed")
        self.assertFalse(self.fixture.context.attempt_root.exists())
        self.assertTrue(self.fixture.app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_executor_drift_during_archive_preparation_prevents_remote_submit(self) -> None:
        def archive_builder(app: Path, archive: Path) -> None:
            self.fixture.archive_builder(app, archive)
            self.identity = {**self.identity, "repositoryCommit": "0" * 40}

        with self.assertRaises(TransactionError) as raised:
            self.fixture.execute(**self.arguments(), archive_builder=archive_builder)
        self.assertEqual(raised.exception.code, "notarization_executor_identity_failed")
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        events = sorted((self.fixture.context.attempt_root / "events").glob("*.json"))
        terminal = json.loads(events[-1].read_bytes())
        self.assertEqual(terminal["state"], "failed")
        self.assertEqual(terminal["failure_code"], raised.exception.code)
        self.assertTrue(
            (self.fixture.context.attempt_root / "work/Clash for Mac.app").is_dir()
        )

    def test_missing_executor_git_history_blocks_claim(self) -> None:
        def missing(_repository: Path, _commit: str) -> dict[str, str]:
            raise transaction_module.SourceIdentityError("missing Git object")

        arguments = {**self.arguments(), "executor_historical_reader": missing}
        with self.assertRaises(TransactionError) as raised:
            self.fixture.execute(**arguments)
        self.assertEqual(raised.exception.code, "notarization_executor_binding_failed")
        self.assertFalse(self.fixture.context.attempt_root.exists())
        self.assertTrue(self.fixture.app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)


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
        commands = self.fixture.runner.command_calls
        self.assertEqual(
            commands[0],
            (
                CommandRole.NOTARY_READINESS,
                (
                    "/usr/bin/syspolicy_check",
                    "notary-submission",
                    str(self.fixture.app),
                    "--json",
                ),
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
        finalization_work_app = Path(commands[4][1][-1])
        finalization_root = finalization_work_app.parent.parent
        self.assertEqual(
            finalization_root.parent,
            self.fixture.context.attempt_root / "finalization-runs",
        )
        uuid.UUID(finalization_root.name)
        publish_app = str(finalization_root / "publish-ready/Clash for Mac.app")
        self.assertEqual(commands[5][1][-1], str(finalization_work_app))
        final_verifies = [
            command
            for role, command, _timeout in commands
            if role == CommandRole.FINAL_VERIFY
        ]
        verifier = str(
            self.fixture.context.repository / "scripts/verify_release_app.sh"
        )
        native_products = str(self.fixture.context.native_products)
        self.assertEqual(
            final_verifies,
            [
                (
                    verifier,
                    str(finalization_work_app),
                    native_products,
                    "--context",
                    "canonical-native-content",
                ),
                (
                    verifier,
                    publish_app,
                    native_products,
                    "--context",
                    "canonical-native-content",
                ),
                (
                    verifier,
                    publish_app,
                    native_products,
                    "--context",
                    "canonical-native-content",
                ),
            ],
        )
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
                "direct_finalization_preparing",
                "direct_finalization_ready",
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
        intent = json.loads(
            (self.fixture.context.attempt_root / "intent.json").read_text(
                encoding="utf-8"
            )
        )
        submission_receipt = json.loads(
            (
                self.fixture.context.attempt_root / "submission-receipt.json"
            ).read_text(encoding="utf-8")
        )
        publish_ready_receipt = json.loads(
            sole_finalization_receipt(self.fixture).read_text(encoding="utf-8")
        )
        self.assertEqual(intent["schema_version"], 4)
        self.assertEqual(
            intent["notary_profile"],
            transaction_module.NOTARY_PROFILE,
        )
        self.assertNotIn("lane", intent)
        self.assertEqual(intent["candidate_freeze_intent_sha256"], "f" * 64)
        self.assertEqual(submission_receipt["schema_version"], 5)
        self.assertEqual(
            submission_receipt["notary_profile"],
            transaction_module.NOTARY_PROFILE,
        )
        self.assertEqual(
            submission_receipt["candidate_freeze_intent_sha256"],
            "f" * 64,
        )
        self.assertEqual(publish_ready_receipt["schema_version"], 5)
        self.assertEqual(
            publish_ready_receipt["candidate_freeze_intent_sha256"],
            "f" * 64,
        )
        expected_transformation = self.fixture.signing_transformation_binding()
        for field, expected in expected_transformation.items():
            self.assertEqual(intent[field], expected)
            self.assertEqual(submission_receipt[field], expected)
            self.assertEqual(publish_ready_receipt[field], expected)
        self.assertEqual(
            intent["pre_staple_app_tree_sha256"],
            expected_transformation["signed_app_tree_sha256"],
        )

    def test_signing_transformation_is_verified_before_attempt_claim(self) -> None:
        calls = 0

        def rejecting_verifier(repository: Path) -> dict[str, object]:
            nonlocal calls
            calls += 1
            self.assertEqual(repository, self.fixture.repository)
            self.assertFalse(self.fixture.context.attempt_root.exists())
            self.assertTrue(self.fixture.app.is_dir())
            raise ValueError("fixture transformation rejection")

        with self.assertRaises(TransactionError) as raised:
            self.fixture.execute(signing_transformation_verifier=rejecting_verifier)
        self.assertEqual(calls, 1)
        self.assertEqual(
            raised.exception.code,
            "signing_transformation_verification_failed",
        )
        self.assertFalse(self.fixture.context.attempt_root.exists())
        self.assertTrue(self.fixture.app.is_dir())
        self.assertEqual(self.fixture.runner.calls, [])

    def test_signing_transformation_signed_tree_mismatch_fails_preclaim(self) -> None:
        receipt = self.fixture.signing_transformation(self.fixture.repository)
        receipt["signed_app_tree_sha256"] = "0" * 64

        with self.assertRaises(TransactionError) as raised:
            self.fixture.execute(
                signing_transformation_verifier=lambda _repository: receipt
            )
        self.assertEqual(
            raised.exception.code,
            "signing_transformation_app_identity_mismatch",
        )
        self.assertFalse(self.fixture.context.attempt_root.exists())
        self.assertTrue(self.fixture.app.is_dir())
        self.assertEqual(self.fixture.runner.calls, [])

    def test_signing_input_change_during_claim_is_detected_before_submit(self) -> None:
        original_claim = transaction_module._claim_attempt

        def claim_then_mutate(context: TransactionContext) -> tuple[Path, Path]:
            claimed = original_claim(context)
            executable = self.fixture.app / "Contents/MacOS/clash-for-mac"
            executable.write_bytes(b"changed-after-transformation-check")
            return claimed

        with patch.object(
            transaction_module,
            "_claim_attempt",
            side_effect=claim_then_mutate,
        ):
            with self.assertRaises(TransactionError) as raised:
                self.fixture.execute()
        self.assertEqual(
            raised.exception.code,
            "signing_transformation_app_identity_drift",
        )
        self.assertTrue(self.fixture.context.attempt_root.is_dir())
        self.assertFalse(self.fixture.app.exists())
        self.assertEqual(self.fixture.runner.calls, [CommandRole.NOTARY_READINESS])
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_signing_receipt_change_during_claim_is_detected_before_submit(self) -> None:
        changed = self.fixture.signing_transformation(self.fixture.repository)
        changed["pre_sign_app_manifest_sha256"] = "0" * 64

        with self.assertRaises(TransactionError) as raised:
            self.fixture.execute(
                signing_transformation_receipt_reader=lambda _repository: changed
            )
        self.assertEqual(
            raised.exception.code,
            "signing_transformation_receipt_drift",
        )
        self.assertTrue(self.fixture.context.attempt_root.is_dir())
        self.assertFalse(self.fixture.app.exists())
        self.assertEqual(self.fixture.runner.calls, [CommandRole.NOTARY_READINESS])
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_candidate_freeze_is_verified_before_attempt_consumption(self) -> None:
        verifier_called = False

        def rejecting_verifier(repository: Path):
            nonlocal verifier_called
            verifier_called = True
            self.assertEqual(repository, self.fixture.repository)
            self.assertFalse(self.fixture.context.attempt_root.exists())
            self.assertTrue(self.fixture.app.is_dir())
            raise ValueError("fixture freeze rejection")

        with self.assertRaises(TransactionError) as raised:
            self.fixture.execute(candidate_freeze_verifier=rejecting_verifier)
        self.assertTrue(verifier_called)
        self.assertEqual(
            raised.exception.code,
            "candidate_freeze_verification_failed",
        )
        self.assertFalse(self.fixture.context.attempt_root.exists())
        self.assertTrue(self.fixture.app.is_dir())
        self.assertEqual(self.fixture.runner.calls, [])

    def test_candidate_freeze_identity_near_matches_fail_closed(self) -> None:
        exact = transaction_module.FrozenCandidate(
            root=self.fixture.build,
            intent_path=self.fixture.build / "candidate-freeze/intent.json",
            intent_sha256="f" * 64,
            product_version="0.4.0",
            build_number="40040",
            recovered=False,
        )
        mutations = {
            "root": replace(exact, root=self.fixture.build / "other"),
            "intent-path": replace(
                exact,
                intent_path=self.fixture.build / "candidate-freeze/other.json",
            ),
            "digest": replace(exact, intent_sha256="F" * 64),
            "version": replace(exact, product_version="0.4.1"),
            "build-40031": replace(exact, build_number="40031"),
            "build-40032": replace(exact, build_number="40032"),
            "build-40033": replace(exact, build_number="40033"),
            "build-40034": replace(exact, build_number="40034"),
            "build-40035": replace(exact, build_number="40035"),
            "build-40036": replace(exact, build_number="40036"),
            "build-40037": replace(exact, build_number="40037"),
            "build-40038": replace(exact, build_number="40038"),
        }
        for label, frozen in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(TransactionError) as raised:
                    self.fixture.execute(
                        candidate_freeze_verifier=(
                            lambda _repository, frozen=frozen: frozen
                        )
                    )
                self.assertEqual(
                    raised.exception.code,
                    "candidate_freeze_identity_mismatch",
                )
                self.assertFalse(self.fixture.context.attempt_root.exists())
                self.assertTrue(self.fixture.app.is_dir())
                self.assertEqual(self.fixture.runner.calls, [])

    def test_noncanonical_ga_input_paths_are_rejected(self) -> None:
        noncanonical_native = self.fixture.build / "native-products"
        noncanonical_native.mkdir()
        contexts = {
            "native": replace(
                self.fixture.context,
                native_products=noncanonical_native,
            ),
            "app": replace(
                self.fixture.context,
                staged_app=self.fixture.build / "other/Clash for Mac.app",
            ),
        }
        for label, context in contexts.items():
            with self.subTest(label=label):
                with self.assertRaises(TransactionError) as raised:
                    self.fixture.execute_context(context)
                self.assertIn(
                    raised.exception.code,
                    {"unsafe_native_products", "unsafe_staged_app"},
                )
                self.assertFalse(self.fixture.context.attempt_root.exists())
                self.assertEqual(self.fixture.runner.calls, [])

    def test_exact_beta_compatibility_is_durable_and_never_claims_notary_ready(
        self,
    ) -> None:
        fixture = self.fixture
        checked_app = fixture.app

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
                self.assertEqual(Path(command[2]), checked_app)
                self.assertFalse(fixture.context.attempt_root.exists())
                finding = (
                    known_notary_false_positive(checked_app)
                    if role is CommandRole.NOTARY_READINESS
                    else known_missing_ticket(checked_app)
                )
                return CommandResult(
                    70,
                    json.dumps({"output": [finding]}),
                    single_signature_diagnostic(checked_app),
                )
            return fixture.runner(role, command, timeout)

        final_app = fixture.execute(
            command_runner=compatibility_runner,
            host_system_identity_reader=(
                lambda: MACOS_27_26A5425A_COMPATIBILITY_IDENTITY
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
                "direct_finalization_preparing",
                "direct_finalization_ready",
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

    def test_beta_near_match_fails_without_claiming_or_moving_app(self) -> None:
        fixture = self.fixture
        checked_app = fixture.app

        def mismatch_runner(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            fixture.runner.calls.append(role)
            fixture.runner.command_calls.append((role, tuple(command), timeout))
            if role is not CommandRole.NOTARY_READINESS:
                self.fail(f"unexpected command after readiness mismatch: {role}")
            finding = known_notary_false_positive(checked_app)
            finding["SyspolicyCheckErrorFile"] = str(checked_app.resolve())
            return CommandResult(70, json.dumps({"output": [finding]}), "")

        with self.assertRaises(TransactionError) as raised:
            fixture.execute(
                command_runner=mismatch_runner,
                host_system_identity_reader=(
                    lambda: MACOS_27_26A5388G_COMPATIBILITY_IDENTITY
                ),
            )
        self.assertEqual(fixture.runner.calls, [CommandRole.NOTARY_READINESS])
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertFalse(
            (fixture.context.attempt_root / "submission-receipt.json").exists()
        )
        self.assertFalse(fixture.context.attempt_root.exists())
        self.assertTrue(fixture.app.is_dir())
        self.assertEqual(
            raised.exception.code,
            "notary-readiness_finding_mismatch",
        )

    def test_unsupported_beta_host_retains_the_same_first_submission_input(
        self,
    ) -> None:
        fixture = self.fixture
        checked_app = fixture.app

        def readiness_runner(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            fixture.runner.calls.append(role)
            fixture.runner.command_calls.append((role, tuple(command), timeout))
            if role is not CommandRole.NOTARY_READINESS:
                self.fail(f"unexpected command after unsupported host: {role}")
            return CommandResult(
                70,
                json.dumps({"output": [known_notary_false_positive(checked_app)]}),
                single_signature_diagnostic(checked_app),
            )

        unsupported = replace(
            MACOS_27_26A5416B_COMPATIBILITY_IDENTITY,
            build_version="26A5416c",
        )
        with self.assertRaises(TransactionError) as raised:
            fixture.execute(
                command_runner=readiness_runner,
                host_system_identity_reader=lambda: unsupported,
            )
        self.assertEqual(
            raised.exception.code,
            "notary-readiness_compatibility_unsupported_host",
        )
        self.assertEqual(fixture.runner.calls, [CommandRole.NOTARY_READINESS])
        self.assertFalse(fixture.context.attempt_root.exists())
        self.assertTrue(fixture.app.is_dir())
        self.assertEqual(
            build_manifest(fixture.app, algorithm="sha256-tree-v2")["sha256"],
            fixture.signed_app_tree_sha256,
        )
        final_app = fixture.execute()
        self.assertTrue(final_app.is_dir())
        self.assertEqual(fixture.runner.calls.count(CommandRole.SUBMIT), 1)

    def test_beta_corroboration_near_match_retains_canonical_signed_input(self) -> None:
        fixture = self.fixture
        checked_app = fixture.app

        def mismatch_runner(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            fixture.runner.calls.append(role)
            fixture.runner.command_calls.append((role, tuple(command), timeout))
            if role is CommandRole.NOTARY_READINESS:
                finding = known_notary_false_positive(checked_app)
            elif role is CommandRole.NOTARY_READINESS_CORROBORATION:
                finding = known_missing_ticket(checked_app)
                finding["SyspolicyCheckErrorFile"] = str(
                    checked_app.resolve() / "Contents"
                )
            else:
                self.fail(f"unexpected command after corroboration mismatch: {role}")
            return CommandResult(70, json.dumps({"output": [finding]}), "")

        with self.assertRaises(TransactionError) as raised:
            fixture.execute(
                command_runner=mismatch_runner,
                host_system_identity_reader=(
                    lambda: MACOS_27_26A5388G_COMPATIBILITY_IDENTITY
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
        self.assertFalse(fixture.context.attempt_root.exists())
        self.assertTrue(fixture.app.is_dir())
        self.assertEqual(
            raised.exception.code,
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
            next(
                (
                    self.fixture.context.attempt_root / "finalization-runs"
                ).glob("*/receipt.json")
            ),
        ):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_same_build_is_rejected_before_any_new_external_command(self) -> None:
        self.fixture.execute()
        calls = list(self.fixture.runner.calls)
        with self.assertRaisesRegex(TransactionError, "must not be resubmitted"):
            self.fixture.execute()
        self.assertEqual(self.fixture.runner.calls, calls)

    def test_ga_uses_the_fixed_candidate_destinations(self) -> None:
        context = self.fixture.context
        final_app = self.fixture.execute()
        self.assertEqual(
            final_app,
            self.fixture.candidate / "ga/40040/signed/Clash for Mac.app",
        )
        self.assertEqual(
            context.native_products,
            (
                self.fixture.candidate
                / "ga/40040/signing-output/signed-native-products"
            ),
        )
        self.assertEqual(
            context.attempt_root,
            self.fixture.candidate / "ga/40040/transactions/app-notary",
        )
        manifest = json.loads(
            (final_app.parent / "Clash for Mac.app.manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["algorithm"], "sha256-tree-v2")
        self.assertEqual(
            manifest["metadata"]["artifactKind"],
            "notarized-ga-candidate-v1",
        )
        self.assertEqual(manifest["metadata"]["buildNumber"], "40040")

    def test_nonfixed_notary_profile_is_rejected_before_attempt_or_remote_io(
        self,
    ) -> None:
        with self.assertRaises(TransactionError) as raised:
            self.fixture.execute_context(
                replace(
                    self.fixture.context,
                    notary_profile="different-profile",
                )
            )
        self.assertEqual(raised.exception.code, "invalid_notary_profile")
        self.assertFalse(self.fixture.context.attempt_root.exists())
        self.assertEqual(self.fixture.runner.calls, [])


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

    def test_ga_recovery_has_no_parallel_build_claim(self) -> None:
        self._reset_runner_observations()
        final_app = self.fixture.recover()
        self.assertTrue(final_app.is_dir())
        self.assertEqual(
            {path.name for path in self.fixture.candidate.iterdir()},
            {"ga"},
        )

    def test_recovery_rejects_notary_profile_drift_in_intent_before_apple_io(
        self,
    ) -> None:
        intent_path = self.fixture.context.attempt_root / "intent.json"
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        intent["notary_profile"] = "different-profile"
        intent_path.write_bytes(
            transaction_module._canonical_json(intent).encode("utf-8")
        )
        self._reset_runner_observations()

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover()
        self.assertEqual(
            raised.exception.code,
            "notarization_intent_identity_drift",
        )
        self.assertEqual(self.fixture.runner.calls, [])

    def test_recovery_rejects_notary_profile_drift_in_receipt_before_apple_io(
        self,
    ) -> None:
        fixture = Fixture()
        try:
            fixture.runner.crash_role = CommandRole.WAIT
            with self.assertRaises(SimulatedCrash):
                fixture.execute()
            receipt_path = fixture.context.attempt_root / "submission-receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["notary_profile"] = "different-profile"
            receipt_path.write_bytes(
                transaction_module._canonical_json(receipt).encode("utf-8")
            )
            fixture.runner.calls.clear()
            fixture.runner.command_calls.clear()
            fixture.runner.role_counts.clear()

            with self.assertRaises(TransactionError) as raised:
                fixture.recover()
            self.assertEqual(
                raised.exception.code,
                "submission_receipt_identity_drift",
            )
            self.assertEqual(fixture.runner.calls, [])
        finally:
            fixture.close()

    def test_recovery_reopens_exact_signing_transformation_before_apple_reads(
        self,
    ) -> None:
        self._reset_runner_observations()
        changed = self.fixture.signing_transformation(self.fixture.repository)
        changed["pre_sign_app_tree_sha256"] = "0" * 64

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(
                signing_transformation_receipt_reader=lambda _repository: changed
            )
        self.assertEqual(
            raised.exception.code,
            "signing_transformation_receipt_drift",
        )
        self.assertEqual(self.fixture.runner.calls, [])
        self.assertFalse(self.fixture.context.final_root.exists())

    def test_legacy_lane_contexts_are_rejected_before_external_commands(
        self,
    ) -> None:
        for legacy_kind in ("validation", "release"):
            with self.subTest(legacy_kind=legacy_kind):
                self._reset_runner_observations()
                with self.assertRaises(TransactionError) as raised:
                    recover_transaction(
                        replace(
                            self.fixture.context,
                            build_kind=legacy_kind,
                            staged_app=None,
                        ),
                        SUBMISSION_ID,
                        self.fixture.repository,
                        **{
                            key: value
                            for key, value in self.fixture.arguments().items()
                            if key
                            not in {
                                "archive_builder",
                                "attempt_id_factory",
                                "candidate_freeze_verifier",
                                "signing_transformation_verifier",
                            }
                        },
                        recovery_tool_identity_reader=lambda _repository: {
                            "repositoryCommit": "c" * 40,
                            "releaseSourceSha256": "d" * 64,
                        },
                    )
                self.assertEqual(raised.exception.code, "invalid_build_kind")
                self.assertEqual(self.fixture.runner.calls, [])

    @staticmethod
    def _clear_runner_observations(fixture: Fixture) -> None:
        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()

    def _direct_receipt_fixture(self) -> Fixture:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.runner.fail_role = CommandRole.WAIT
        with self.assertRaises(TransactionError) as raised:
            fixture.execute()
        self.assertEqual(raised.exception.code, "wait_failed")
        fixture.runner.fail_role = None
        self._clear_runner_observations(fixture)
        return fixture

    def _crash_after_continuation_marker(
        self,
        fixture: Fixture | None = None,
    ) -> tuple[dict[str, str], Path]:
        target = fixture or self.fixture
        target.runner.fail_role = CommandRole.STAPLE
        self._clear_runner_observations(target)
        with self.assertRaises(TransactionError):
            target.recover()

        continued_identity = {
            "repositoryCommit": "e" * 40,
            "releaseSourceSha256": "f" * 64,
        }
        original_append = transaction_module.EventJournal.append

        def crash_after_marker(journal, state: str, **fields) -> None:
            original_append(journal, state, **fields)
            if state == "recovery_tool_continued":
                raise SimulatedCrash(state)

        target.runner.fail_role = None
        self._clear_runner_observations(target)
        with patch.object(
            transaction_module.EventJournal,
            "append",
            crash_after_marker,
        ):
            with self.assertRaises(SimulatedCrash):
                target.recover(
                    recovery_tool_identity_reader=(
                        lambda _repository: continued_identity
                    )
                )

        marker_path = sorted(
            (target.context.attempt_root / "events").glob("*.json")
        )[-1]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        prior_event_path = marker_path.with_name(
            f"{marker['sequence'] - 1:08d}.json"
        )
        prior_event = json.loads(prior_event_path.read_text(encoding="utf-8"))
        self.assertEqual(marker["state"], "recovery_tool_continued")
        self.assertEqual(
            marker["previous_event_sha256"],
            hashlib.sha256(prior_event_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(prior_event["state"], "failed")
        self.assertFalse(
            (
                target.context.attempt_root
                / "recovery-continuation.json"
            ).exists()
        )
        return continued_identity, marker_path

    @staticmethod
    def _continued_identity() -> dict[str, str]:
        return {
            "repositoryCommit": "e" * 40,
            "releaseSourceSha256": "f" * 64,
        }

    def _expected_continuation_from_tip(
        self,
        fixture: Fixture,
        continued_identity: dict[str, str],
    ) -> tuple[dict[str, object], dict[str, object]]:
        event_paths = sorted(
            (fixture.context.attempt_root / "events").glob("*.json")
        )
        prior_event_path = event_paths[-1]
        prior_event = json.loads(prior_event_path.read_text(encoding="utf-8"))
        recovery_intent_path = (
            fixture.context.attempt_root / "recovery-intent.json"
        )
        recovery_intent = json.loads(
            recovery_intent_path.read_text(encoding="utf-8")
        )
        requested_at = "2026-07-28T04:02:00Z"
        continuation: dict[str, object] = {
            "schema_version": 1,
            "document": transaction_module.RECOVERY_CONTINUATION_DOCUMENT,
            "attempt_id": recovery_intent["attempt_id"],
            "submission_id": SUBMISSION_ID,
            "recovery_intent_sha256": hashlib.sha256(
                recovery_intent_path.read_bytes()
            ).hexdigest(),
            "prior_recovery_tool_repository_commit": "c" * 40,
            "prior_recovery_tool_release_source_sha256": "d" * 64,
            "continuation_tool_repository_commit": continued_identity[
                "repositoryCommit"
            ],
            "continuation_tool_release_source_sha256": continued_identity[
                "releaseSourceSha256"
            ],
            "prior_event_sha256": hashlib.sha256(
                prior_event_path.read_bytes()
            ).hexdigest(),
            "prior_failure_code": prior_event["failure_code"],
            "requested_at": requested_at,
        }
        marker: dict[str, object] = {
            "schema_version": 2,
            "document": transaction_module.EVENT_DOCUMENT_V2,
            "sequence": prior_event["sequence"] + 1,
            "previous_event_sha256": continuation["prior_event_sha256"],
            "intent_sha256": prior_event["intent_sha256"],
            "state": "recovery_tool_continued",
            "recorded_at": requested_at,
            "submission_id": SUBMISSION_ID,
            "failure_code": None,
            "exit_code": None,
            "evidence_sha256": hashlib.sha256(
                transaction_module._canonical_json(continuation).encode("utf-8")
            ).hexdigest(),
        }
        return continuation, marker

    def _direct_preseal_fixture(self, *, before_receipt: bool) -> Fixture:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        with patch.object(
            transaction_module,
            "_append_direct_finalization_preparing",
            side_effect=SimulatedCrash("legacy-direct-boundary"),
        ):
            with self.assertRaises(SimulatedCrash):
                fixture.execute()
        intent_path = fixture.context.attempt_root / "intent.json"
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        intent_sha256 = hashlib.sha256(intent_path.read_bytes()).hexdigest()
        journal = transaction_module.EventJournal.load_existing(
            fixture.context.attempt_root / "events",
            intent_sha256,
            lambda: "2026-07-28T04:02:00Z",
        )
        submission_receipt_path = (
            fixture.context.attempt_root / "submission-receipt.json"
        )
        submission_receipt = json.loads(
            submission_receipt_path.read_text(encoding="utf-8")
        )
        work = fixture.context.attempt_root / "work"
        prepared = transaction_module.PreparedAttempt(
            context=replace(fixture.context, staged_app=None),
            work=work,
            work_app=work / "Clash for Mac.app",
            archive=work / fixture.context.archive_name,
            archive_manifest=(
                work / f"{fixture.context.archive_name}.manifest.json"
            ),
            archive_metadata=transaction_module._archive_metadata(
                fixture.context
            ),
            archive_sha256=intent["archive_sha256"],
            archive_size=intent["archive_size"],
            pre_staple_app_sha256=intent["pre_staple_app_tree_sha256"],
            attempt_id=intent["attempt_id"],
            intent=intent,
            intent_path=intent_path,
            intent_sha256=intent_sha256,
            submission_id=SUBMISSION_ID,
            submission_receipt=submission_receipt,
            submission_receipt_path=submission_receipt_path,
            recovery_intent=None,
            recovery_intent_path=None,
            recovery_continuation=None,
            recovery_continuation_path=None,
            recovery_tool_repository=None,
            recovery_tool_identity=None,
            recovery_tool_identity_reader=None,
        )

        def finalize_legacy_direct() -> None:
            transaction_module._finalize_accepted_submission(
                prepared,
                journal=journal,
                command_runner=fixture.runner,
                gatekeeper_capture=fixture.gatekeeper,
                manifest_writer=transaction_module.production_manifest_writer,
                manifest_verifier=transaction_module.production_manifest_verifier,
                source_identity_reader=fixture.source_identity,
                toolchain_metadata_reader=(
                    lambda _repository: fixture.context.toolchain_metadata
                ),
                publisher=fixture.publisher,
                clock=lambda: "2026-07-28T04:02:00Z",
            )

        if before_receipt:
            real_publish = transaction_module._publish_pending_evidence

            def crash_before_receipt(**arguments) -> None:
                if arguments["destination_path"].name == "receipt.json":
                    raise SimulatedCrash("before-receipt")
                real_publish(**arguments)

            with patch.object(
                transaction_module,
                "_publish_pending_evidence",
                side_effect=crash_before_receipt,
            ):
                with self.assertRaises(SimulatedCrash):
                    finalize_legacy_direct()
        else:
            real_append = transaction_module.EventJournal.append

            def crash_before_sealed(journal, state: str, **fields) -> None:
                if state == "sealed":
                    raise SimulatedCrash("before-sealed")
                real_append(journal, state, **fields)

            with patch.object(
                transaction_module.EventJournal,
                "append",
                crash_before_sealed,
            ):
                with self.assertRaises(SimulatedCrash):
                    finalize_legacy_direct()
        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        return fixture

    def _receipt_durability_unknown_fixture(
        self,
    ) -> tuple[Fixture, Callable[[], str], Path]:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        real_fsync_directory = transaction_module._fsync_directory
        failed_receipt_directory_fsync = False
        failed_receipt_path: Path | None = None
        clock_tick = 0
        clock_origin = datetime(
            2026,
            7,
            28,
            4,
            1,
            59,
            999940,
            tzinfo=timezone.utc,
        )

        def monotonic_clock() -> str:
            nonlocal clock_tick
            clock_tick += 1
            return (
                clock_origin + timedelta(microseconds=clock_tick * 10)
            ).isoformat(timespec="microseconds").replace("+00:00", "Z")

        def fail_once_after_receipt_rename(path: Path) -> None:
            nonlocal failed_receipt_directory_fsync, failed_receipt_path
            receipt_path = path / "receipt.json"
            receipt_pending_path = (
                path / transaction_module.PUBLISH_READY_RECEIPT_PENDING_FILENAME
            )
            if (
                not failed_receipt_directory_fsync
                and path.parent
                == fixture.context.attempt_root / "finalization-runs"
                and receipt_path.is_file()
                and not os.path.lexists(receipt_pending_path)
            ):
                failed_receipt_directory_fsync = True
                failed_receipt_path = receipt_path
                raise OSError("fixture receipt directory fsync failure")
            real_fsync_directory(path)

        with patch.object(
            transaction_module,
            "_fsync_directory",
            side_effect=fail_once_after_receipt_rename,
        ):
            with self.assertRaises(TransactionError) as raised:
                fixture.execute(clock=monotonic_clock)

        self.assertEqual(
            raised.exception.code,
            "atomic_evidence_durability_unknown",
        )
        self.assertTrue(failed_receipt_directory_fsync)
        self.assertIsNotNone(failed_receipt_path)
        if failed_receipt_path is None:
            self.fail("receipt durability fixture did not capture its receipt")
        self.assertTrue(failed_receipt_path.is_file())
        self.assertFalse(
            os.path.lexists(
                failed_receipt_path.parent
                / transaction_module.PUBLISH_READY_RECEIPT_PENDING_FILENAME
            )
        )
        self.assertTrue(
            (failed_receipt_path.parent / "publish-ready").is_dir()
        )
        self._clear_runner_observations(fixture)
        return fixture, monotonic_clock, failed_receipt_path

    def _current_ga_failed_finalization_fixture(self) -> Fixture:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.create_orphaned_submit_attempt()
        fixture.runner.log = accepted_log(fixture.context.archive_name)
        frozen_event_paths = sorted(
            (fixture.context.attempt_root / "events").glob("*.json")
        )
        frozen_event_bytes = [path.read_bytes() for path in frozen_event_paths]
        intent_path = fixture.context.attempt_root / "intent.json"
        intent_sha256 = hashlib.sha256(intent_path.read_bytes()).hexdigest()

        def gatekeeper_failure(_app: Path, _digest: str) -> dict:
            raise ValueError("GA Gatekeeper fixture failure")

        self._clear_runner_observations(fixture)
        with self.assertRaises(TransactionError) as raised:
            fixture.recover(gatekeeper_capture=gatekeeper_failure)
        self.assertEqual(
            raised.exception.code,
            "gatekeeper_verification_failed",
        )
        current_event_paths = sorted(
            (fixture.context.attempt_root / "events").glob("*.json")
        )
        self.assertEqual(
            [path.read_bytes() for path in current_event_paths[:4]],
            frozen_event_bytes,
        )
        self.assertEqual(
            hashlib.sha256(intent_path.read_bytes()).hexdigest(),
            intent_sha256,
        )
        events = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in current_event_paths
        ]
        self.assertEqual(
            [event["state"] for event in events[:4]],
            ["prepared", "notary_ready", "submitting", "outcome_unknown"],
        )
        self.assertIn(
            "recovery_intent_anchored",
            [event["state"] for event in events],
        )
        self.assertEqual(
            events[-1]["failure_code"],
            "gatekeeper_verification_failed",
        )
        reduced = transaction_module._reduce_attempt_events(
            transaction_module.EventJournal.load_existing(
                fixture.context.attempt_root / "events",
                intent_sha256,
                lambda: "2026-07-28T04:02:00Z",
            )
        )
        self.assertEqual(
            reduced.phase,
            transaction_module.AttemptPhase.FINALIZATION_FAILED,
        )
        self.assertTrue(reduced.reconciled)
        self.assertEqual(reduced.finalization_attempt_count, 1)
        self.assertEqual(
            {path.name for path in fixture.context.attempt_root.iterdir()},
            {
                "events",
                "finalization-runs",
                "intent.json",
                "recovery-intent.json",
                "recovery-source",
                "submission-receipt.json",
            },
        )
        recovery_intent = json.loads(
            (
                fixture.context.attempt_root / "recovery-intent.json"
            ).read_text(encoding="utf-8")
        )
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        self.assertEqual(recovery_intent["intent_sha256"], intent_sha256)
        self.assertEqual(
            recovery_intent["archive_sha256"],
            intent["archive_sha256"],
        )
        run = sole_finalization_run(fixture)
        self.assertEqual({path.name for path in run.iterdir()}, {"work"})
        self.assertEqual(
            {path.name for path in (run / "work").iterdir()},
            {
                "Clash for Mac.app",
                fixture.context.archive_name,
                f"{fixture.context.archive_name}.manifest.json",
                "notarization.json",
                "notarization-log.json",
            },
        )
        self._clear_runner_observations(fixture)
        return fixture

    @staticmethod
    def _regular_file_snapshot(root: Path) -> dict[str, bytes]:
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }

    def test_current_ga_fixture_continues_once_then_recovers_locally(self) -> None:
        fixture = self._current_ga_failed_finalization_fixture()
        self.assertEqual(fixture.context.build_number, "40040")
        self.assertEqual(
            fixture.context.archive_name,
            "Clash.for.Mac_0.4.0_40040_notary.zip",
        )
        attempt_root = fixture.context.attempt_root
        original_event_paths = sorted(
            (attempt_root / "events").glob("*.json")
        )
        original_event_bytes = [path.read_bytes() for path in original_event_paths]
        immutable_documents = {
            name: (attempt_root / name).read_bytes()
            for name in (
                "intent.json",
                "recovery-intent.json",
                "submission-receipt.json",
            )
        }
        original_run = sole_finalization_run(fixture)
        original_run_snapshot = self._regular_file_snapshot(original_run)
        continued_identity = self._continued_identity()

        first = fixture.recover(
            recovery_tool_identity_reader=(
                lambda _repository: continued_identity
            )
        )

        self.assertEqual(
            first,
            fixture.candidate / "ga/40040/signed/Clash for Mac.app",
        )
        self.assertTrue(first.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
        self.assertEqual(
            [path.read_bytes() for path in original_event_paths],
            original_event_bytes,
        )
        for name, data in immutable_documents.items():
            self.assertEqual((attempt_root / name).read_bytes(), data)
        self.assertEqual(
            self._regular_file_snapshot(original_run),
            original_run_snapshot,
        )
        runs = self._finalization_runs(fixture)
        self.assertEqual(len(runs), 2)
        self.assertIn(original_run, runs)
        self.assertTrue(
            (attempt_root / "recovery-continuation.json").is_file()
        )
        sealed = transaction_module._reduce_attempt_events(
            transaction_module.EventJournal.load_existing(
                attempt_root / "events",
                hashlib.sha256(
                    (attempt_root / "intent.json").read_bytes()
                ).hexdigest(),
                lambda: "2026-07-28T04:02:00Z",
            )
        )
        self.assertEqual(
            sealed.phase,
            transaction_module.AttemptPhase.SEALED,
        )
        self.assertTrue(sealed.reconciled)
        self.assertEqual(sealed.finalization_attempt_count, 2)
        continuation = json.loads(
            (attempt_root / "recovery-continuation.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            continuation["prior_recovery_tool_release_source_sha256"],
            "d" * 64,
        )
        self.assertEqual(
            continuation["continuation_tool_release_source_sha256"],
            "f" * 64,
        )
        recovery_intent_path = attempt_root / "recovery-intent.json"
        continuation_path = attempt_root / "recovery-continuation.json"
        self.assertEqual(
            continuation["recovery_intent_sha256"],
            hashlib.sha256(recovery_intent_path.read_bytes()).hexdigest(),
        )
        final_event_paths = sorted(
            (attempt_root / "events").glob("*.json")
        )
        final_events = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in final_event_paths
        ]
        self.assertEqual(
            [event["state"] for event in final_events],
            [
                "prepared",
                "notary_ready",
                "submitting",
                "outcome_unknown",
                "recovery_intent_anchored",
                "reconciliation_started",
                "submission_reconciled",
                "finalization_started",
                "accepted",
                "log_verified",
                "stapling",
                "stapled",
                "failed",
                "recovery_tool_continued",
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
        continuation_event = final_events[13]
        self.assertEqual(
            continuation_event["evidence_sha256"],
            hashlib.sha256(continuation_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            continuation_event["previous_event_sha256"],
            hashlib.sha256(final_event_paths[12].read_bytes()).hexdigest(),
        )
        receipt_path = sole_finalization_receipt(fixture)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        intent_sha256 = hashlib.sha256(
            (attempt_root / "intent.json").read_bytes()
        ).hexdigest()
        intent = json.loads(
            (attempt_root / "intent.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            receipt["intent_sha256"],
            intent_sha256,
        )
        self.assertEqual(
            receipt["archive_sha256"],
            intent["archive_sha256"],
        )
        self.assertEqual(
            receipt["pre_staple_app_tree_sha256"],
            intent["pre_staple_app_tree_sha256"],
        )
        self.assertEqual(
            receipt["post_staple_app_tree_sha256"],
            intent["pre_staple_app_tree_sha256"],
        )
        self.assertEqual(receipt["candidate_freeze_intent_sha256"], "f" * 64)
        self.assertEqual(
            receipt["recovery_intent_sha256"],
            hashlib.sha256(recovery_intent_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            receipt["recovery_continuation_sha256"],
            hashlib.sha256(continuation_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            receipt["preseal_event_sha256"],
            hashlib.sha256(final_event_paths[-2].read_bytes()).hexdigest(),
        )
        final_manifest = json.loads(
            (
                fixture.context.final_root
                / "Clash for Mac.app.manifest.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(final_manifest["metadata"]["buildNumber"], "40040")
        self.assertEqual(
            final_manifest["metadata"]["repositoryCommit"],
            "a" * 40,
        )
        self.assertEqual(
            final_manifest["metadata"]["releaseSourceSha256"],
            "b" * 64,
        )
        self._clear_runner_observations(fixture)
        publisher_called = False

        def forbidden_publisher(_source: Path, _destination: Path) -> None:
            nonlocal publisher_called
            publisher_called = True

        second = fixture.recover(
            command_runner=lambda role, _command, _timeout: self.fail(
                f"second GA recovery invoked runner: {role.value}"
            ),
            publisher=forbidden_publisher,
            recovery_tool_identity_reader=(
                lambda _repository: continued_identity
            ),
        )
        self.assertEqual(second, first)
        self.assertEqual(fixture.runner.calls, [])
        self.assertFalse(publisher_called)

    def test_current_ga_fixture_capacity_fails_closed(self) -> None:
        fixture = self._current_ga_failed_finalization_fixture()
        attempt_root = fixture.context.attempt_root
        original_event_paths = sorted(
            (attempt_root / "events").glob("*.json")
        )
        original_event_bytes = [path.read_bytes() for path in original_event_paths]
        original_run = sole_finalization_run(fixture)
        with patch.object(
            transaction_module,
            "MAX_FINALIZATION_RUNS",
            1,
        ):
            with self.assertRaises(TransactionError) as raised:
                fixture.recover(
                    recovery_tool_identity_reader=(
                        lambda _repository: self._continued_identity()
                    )
                )
        self.assertEqual(
            raised.exception.code,
            "finalization_run_quota_exceeded",
        )
        self.assertEqual(
            [path.read_bytes() for path in original_event_paths],
            original_event_bytes,
        )
        self.assertEqual(self._finalization_runs(fixture), [original_run])
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_current_ga_fixture_finalization_fsync_fails_closed(self) -> None:
        fixture = self._current_ga_failed_finalization_fixture()
        attempt_root = fixture.context.attempt_root
        original_event_paths = sorted(
            (attempt_root / "events").glob("*.json")
        )
        original_event_bytes = [path.read_bytes() for path in original_event_paths]
        original_run = sole_finalization_run(fixture)
        real_fsync_tree = transaction_module._fsync_tree
        injected = False

        def fail_new_run_fsync(root: Path) -> None:
            nonlocal injected
            real_fsync_tree(root)
            if (
                not injected
                and root.name == "work"
                and root.parent.parent
                == attempt_root / "finalization-runs"
                and root.parent != original_run
            ):
                injected = True
                raise TransactionError(
                    "fixture_finalization_fsync_failed",
                    "fixture finalization fsync failure",
                )

        with patch.object(
            transaction_module,
            "_fsync_tree",
            side_effect=fail_new_run_fsync,
        ):
            with self.assertRaises(TransactionError) as raised:
                fixture.recover(
                    recovery_tool_identity_reader=(
                        lambda _repository: self._continued_identity()
                    )
                )
        self.assertTrue(injected)
        self.assertEqual(
            raised.exception.code,
            "fixture_finalization_fsync_failed",
        )
        self.assertEqual(
            [path.read_bytes() for path in original_event_paths],
            original_event_bytes,
        )
        self.assertEqual(len(self._finalization_runs(fixture)), 2)
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    @staticmethod
    def _finalization_runs(fixture: Fixture) -> list[Path]:
        root = fixture.context.attempt_root / "finalization-runs"
        if not root.exists():
            return []
        return sorted(root.iterdir(), key=lambda path: path.name)

    def _assert_fresh_uuid_recovery(
        self,
        fixture: Fixture,
        original_runs: list[Path],
    ) -> Path:
        original_names = {run.name for run in original_runs}
        self._clear_runner_observations(fixture)

        recovered_app = fixture.recover()

        self.assertEqual(
            recovered_app,
            fixture.context.final_root / "Clash for Mac.app",
        )
        self.assertTrue(recovered_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
        recovered_runs = self._finalization_runs(fixture)
        self.assertEqual(len(recovered_runs), len(original_runs) + 1)
        recovered_names = {run.name for run in recovered_runs}
        self.assertTrue(original_names < recovered_names)
        for run in recovered_runs:
            with self.subTest(run=run.name):
                self.assertEqual(str(uuid.UUID(run.name)), run.name)
        source_executable = (
            fixture.context.attempt_root
            / "recovery-source/Clash for Mac.app/Contents/MacOS/clash-for-mac"
        )
        self.assertEqual(source_executable.read_bytes(), b"signed-app")
        self.assertFalse((fixture.context.final_root / "fault-marker").exists())

        receipt_paths = list(
            (fixture.context.attempt_root / "finalization-runs").glob(
                "*/receipt.json"
            )
        )
        receipts = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in receipt_paths
        ]
        recovery_receipts = [
            receipt
            for receipt in receipts
            if receipt["recovery_intent_sha256"] is not None
        ]
        self.assertEqual(len(recovery_receipts), 1)
        self.assertIsNone(
            recovery_receipts[0]["recovery_continuation_sha256"]
        )
        for receipt in receipts:
            if receipt is recovery_receipts[0]:
                continue
            self.assertIsNone(receipt["recovery_intent_sha256"])
            self.assertIsNone(receipt["recovery_continuation_sha256"])

        event_paths = sorted(
            (fixture.context.attempt_root / "events").glob("*.json")
        )
        events = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in event_paths
        ]
        ready_entries = [
            (path, event)
            for path, event in zip(event_paths, events, strict=True)
            if event["state"] == "direct_finalization_ready"
        ]
        anchor_entries = [
            (path, event)
            for path, event in zip(event_paths, events, strict=True)
            if event["state"] == "recovery_intent_anchored"
        ]
        self.assertEqual(len(ready_entries), 1)
        self.assertEqual(len(anchor_entries), 1)
        ready_path, _ready = ready_entries[0]
        anchor_path, anchor = anchor_entries[0]
        recovery_intent_path = (
            fixture.context.attempt_root / "recovery-intent.json"
        )
        recovery_intent = json.loads(
            recovery_intent_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            recovery_intent["prior_event_sha256"],
            hashlib.sha256(ready_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            anchor["evidence_sha256"],
            hashlib.sha256(recovery_intent_path.read_bytes()).hexdigest(),
        )
        anchor_prior_path = anchor_path.with_name(
            f"{anchor['sequence'] - 1:08d}.json"
        )
        self.assertEqual(
            anchor["previous_event_sha256"],
            hashlib.sha256(anchor_prior_path.read_bytes()).hexdigest(),
        )
        return recovered_app

    def test_direct_source_boundary_fault_matrix_recovers_without_resubmit(
        self,
    ) -> None:
        for stage in ("work-fsync", "rename-parent-fsync", "source-fsync"):
            for failure_kind in ("typed", "baseexception"):
                with self.subTest(stage=stage, failure_kind=failure_kind):
                    fixture = Fixture()
                    try:
                        real_fsync_tree = transaction_module._fsync_tree
                        real_fsync_directory = (
                            transaction_module._fsync_directory
                        )
                        injected = False

                        def fail() -> None:
                            nonlocal injected
                            injected = True
                            if failure_kind == "typed":
                                raise OSError(f"fixture {stage} failure")
                            raise SimulatedCrash(stage)

                        def faulting_fsync_tree(root: Path) -> None:
                            if (
                                not injected
                                and stage == "work-fsync"
                                and root
                                == fixture.context.attempt_root / "work"
                            ):
                                fail()
                            if (
                                not injected
                                and stage == "source-fsync"
                                and root
                                == fixture.context.attempt_root
                                / "recovery-source"
                            ):
                                fail()
                            real_fsync_tree(root)

                        def faulting_fsync_directory(path: Path) -> None:
                            real_fsync_directory(path)
                            if (
                                not injected
                                and stage == "rename-parent-fsync"
                                and path == fixture.context.attempt_root
                                and (
                                    path / "recovery-source"
                                ).is_dir()
                            ):
                                fail()

                        expected = (
                            TransactionError
                            if failure_kind == "typed"
                            else SimulatedCrash
                        )
                        with patch.object(
                            transaction_module,
                            "_fsync_tree",
                            side_effect=faulting_fsync_tree,
                        ), patch.object(
                            transaction_module,
                            "_fsync_directory",
                            side_effect=faulting_fsync_directory,
                        ):
                            with self.assertRaises(expected):
                                fixture.execute()

                        self.assertTrue(injected)
                        states = [
                            json.loads(path.read_text(encoding="utf-8"))[
                                "state"
                            ]
                            for path in sorted(
                                (
                                    fixture.context.attempt_root / "events"
                                ).glob("*.json")
                            )
                        ]
                        self.assertIn(
                            "direct_finalization_preparing",
                            states,
                        )
                        self.assertNotIn("direct_finalization_ready", states)
                        self._assert_fresh_uuid_recovery(fixture, [])
                    finally:
                        fixture.close()

    def test_direct_workspace_copy_fault_matrix_uses_new_uuid(self) -> None:
        for stage in ("copytree", "copy-fsync"):
            for failure_kind in ("typed", "baseexception"):
                with self.subTest(stage=stage, failure_kind=failure_kind):
                    fixture = Fixture()
                    try:
                        real_copytree = transaction_module.shutil.copytree
                        real_fsync_tree = transaction_module._fsync_tree
                        injected = False

                        def fail() -> None:
                            nonlocal injected
                            injected = True
                            if failure_kind == "typed":
                                if stage == "copytree":
                                    raise OSError("fixture copy failure")
                                raise TransactionError(
                                    "fixture_copy_fsync_failed",
                                    "fixture copy fsync failure",
                                )
                            raise SimulatedCrash(stage)

                        def faulting_copytree(
                            source: Path,
                            destination: Path,
                            *args,
                            **kwargs,
                        ):
                            if (
                                not injected
                                and stage == "copytree"
                                and destination.parent.parent
                                == fixture.context.attempt_root
                                / "finalization-runs"
                            ):
                                fail()
                            return real_copytree(
                                source,
                                destination,
                                *args,
                                **kwargs,
                            )

                        def faulting_fsync_tree(root: Path) -> None:
                            real_fsync_tree(root)
                            if (
                                not injected
                                and stage == "copy-fsync"
                                and root.name == "work"
                                and root.parent.parent
                                == fixture.context.attempt_root
                                / "finalization-runs"
                            ):
                                (root / "fault-marker").write_text(
                                    "old run must not be reused\n",
                                    encoding="utf-8",
                                )
                                fail()

                        expected = (
                            TransactionError
                            if failure_kind == "typed"
                            else SimulatedCrash
                        )
                        with patch.object(
                            transaction_module.shutil,
                            "copytree",
                            side_effect=faulting_copytree,
                        ), patch.object(
                            transaction_module,
                            "_fsync_tree",
                            side_effect=faulting_fsync_tree,
                        ):
                            with self.assertRaises(expected):
                                fixture.execute()

                        self.assertTrue(injected)
                        original_runs = self._finalization_runs(fixture)
                        self.assertEqual(
                            len(original_runs),
                            (
                                0
                                if stage == "copytree"
                                and failure_kind == "typed"
                                else 1
                            ),
                        )
                        self._assert_fresh_uuid_recovery(
                            fixture,
                            original_runs,
                        )
                    finally:
                        fixture.close()

    def test_direct_command_fault_matrix_recovers_from_fresh_uuid(self) -> None:
        cases = (
            (CommandRole.FETCH_LOG, 1),
            (CommandRole.STAPLE, 1),
            (CommandRole.STAPLE_VALIDATE, 1),
            (CommandRole.FINAL_VERIFY, 1),
            (CommandRole.FINAL_VERIFY, 2),
            (CommandRole.FINAL_VERIFY, 3),
            (CommandRole.DISTRIBUTION_CHECK, 1),
        )
        for role, occurrence in cases:
            for failure_kind in ("typed", "baseexception"):
                with self.subTest(
                    role=role,
                    occurrence=occurrence,
                    failure_kind=failure_kind,
                ):
                    fixture = Fixture()
                    try:
                        target_count = 0
                        injected = False

                        def faulting_runner(
                            observed_role: CommandRole,
                            command: list[str],
                            timeout: float,
                        ) -> CommandResult:
                            nonlocal target_count, injected
                            result = fixture.runner(
                                observed_role,
                                command,
                                timeout,
                            )
                            if observed_role == role:
                                target_count += 1
                            if (
                                not injected
                                and observed_role == role
                                and target_count == occurrence
                            ):
                                injected = True
                                runs = self._finalization_runs(fixture)
                                self.assertEqual(len(runs), 1)
                                workspace = current_publish_ready(fixture)
                                if workspace is None:
                                    workspace = runs[0] / "work"
                                (workspace / "fault-marker").write_text(
                                    "old run must not be reused\n",
                                    encoding="utf-8",
                                )
                                if failure_kind == "typed":
                                    return CommandResult(
                                        9,
                                        "",
                                        "fixture command failure",
                                    )
                                raise SimulatedCrash(role.value)
                            return result

                        expected = (
                            TransactionError
                            if failure_kind == "typed"
                            else SimulatedCrash
                        )
                        with self.assertRaises(expected):
                            fixture.execute(command_runner=faulting_runner)

                        self.assertTrue(injected)
                        original_runs = self._finalization_runs(fixture)
                        self.assertEqual(len(original_runs), 1)
                        self.assertTrue(
                            any(original_runs[0].rglob("fault-marker"))
                        )
                        self._assert_fresh_uuid_recovery(
                            fixture,
                            original_runs,
                        )
                        self.assertTrue(
                            any(original_runs[0].rglob("fault-marker"))
                        )
                    finally:
                        fixture.close()

    def test_direct_callback_fault_matrix_recovers_from_fresh_uuid(self) -> None:
        for boundary in ("gatekeeper", "manifest-writer", "manifest-verifier"):
            for failure_kind in ("typed", "baseexception"):
                with self.subTest(
                    boundary=boundary,
                    failure_kind=failure_kind,
                ):
                    fixture = Fixture()
                    try:
                        injected = False

                        def fail(label: str) -> None:
                            nonlocal injected
                            injected = True
                            if failure_kind == "typed":
                                raise TransactionError(
                                    f"fixture_{label}_failed",
                                    f"fixture {label} failure",
                                )
                            raise SimulatedCrash(label)

                        def gatekeeper_capture(
                            app: Path,
                            tree_sha256: str,
                        ) -> dict:
                            if boundary == "gatekeeper" and not injected:
                                (app.parent / "fault-marker").write_text(
                                    "old run must not be reused\n",
                                    encoding="utf-8",
                                )
                                fail(boundary)
                            return fixture.gatekeeper(app, tree_sha256)

                        def manifest_writer(
                            artifact: Path,
                            manifest: Path,
                            metadata: dict[str, str],
                        ) -> None:
                            transaction_module.production_manifest_writer(
                                artifact,
                                manifest,
                                metadata,
                            )
                            if (
                                boundary == "manifest-writer"
                                and not injected
                                and artifact.name == "Clash for Mac.app"
                                and "finalization-runs" in artifact.parts
                            ):
                                (artifact.parent / "fault-marker").write_text(
                                    "old run must not be reused\n",
                                    encoding="utf-8",
                                )
                                fail(boundary)

                        def manifest_verifier(
                            artifact: Path,
                            manifest: Path,
                            metadata: dict[str, str],
                        ) -> None:
                            transaction_module.production_manifest_verifier(
                                artifact,
                                manifest,
                                metadata,
                            )
                            if (
                                boundary == "manifest-verifier"
                                and not injected
                                and artifact.name == "Clash for Mac.app"
                                and "finalization-runs" in artifact.parts
                            ):
                                (artifact.parent / "fault-marker").write_text(
                                    "old run must not be reused\n",
                                    encoding="utf-8",
                                )
                                fail(boundary)

                        expected = (
                            TransactionError
                            if failure_kind == "typed"
                            else SimulatedCrash
                        )
                        with self.assertRaises(expected):
                            fixture.execute(
                                gatekeeper_capture=gatekeeper_capture,
                                manifest_writer=manifest_writer,
                                manifest_verifier=manifest_verifier,
                            )

                        self.assertTrue(injected)
                        original_runs = self._finalization_runs(fixture)
                        self.assertEqual(len(original_runs), 1)
                        self.assertTrue(
                            any(original_runs[0].rglob("fault-marker"))
                        )
                        self._assert_fresh_uuid_recovery(
                            fixture,
                            original_runs,
                        )
                    finally:
                        fixture.close()

    def test_gatekeeper_post_status_regression_retries_from_pristine_source(
        self,
    ) -> None:
        fixture = Fixture()
        try:
            def disabled_post_status(app: Path, tree_sha256: str) -> dict:
                (app.parent / "fault-marker").write_text(
                    "old run must not be reused\n",
                    encoding="utf-8",
                )
                evidence = fixture.gatekeeper(app, tree_sha256)
                evidence["post_status_output"] = "assessments disabled\n"
                evidence["post_status_output_sha256"] = hashlib.sha256(
                    evidence["post_status_output"].encode("utf-8")
                ).hexdigest()
                return evidence

            with self.assertRaises(TransactionError) as raised:
                fixture.execute(gatekeeper_capture=disabled_post_status)

            self.assertEqual(
                raised.exception.code,
                "gatekeeper_verification_failed",
            )
            states = [
                json.loads(path.read_text(encoding="utf-8"))["state"]
                for path in sorted(
                    (fixture.context.attempt_root / "events").glob("*.json")
                )
            ]
            self.assertNotIn("gatekeeper_verified", states)
            original_runs = self._finalization_runs(fixture)
            self.assertEqual(len(original_runs), 1)
            self._assert_fresh_uuid_recovery(fixture, original_runs)
        finally:
            fixture.close()

    def test_direct_receipt_seal_and_fsync_fault_matrix_uses_new_uuid(
        self,
    ) -> None:
        boundaries = (
            "receipt-before",
            "receipt-after",
            "sealed-before",
            "sealed-after",
            "sealed-fsync",
        )
        for boundary in boundaries:
            for failure_kind in ("typed", "baseexception"):
                with self.subTest(
                    boundary=boundary,
                    failure_kind=failure_kind,
                ):
                    fixture = Fixture()
                    try:
                        real_publish_evidence = (
                            transaction_module._publish_pending_evidence
                        )
                        real_append = transaction_module.EventJournal.append
                        real_fsync_tree = transaction_module._fsync_tree
                        injected = False

                        def fail() -> None:
                            nonlocal injected
                            injected = True
                            if failure_kind == "typed":
                                raise TransactionError(
                                    "fixture_local_boundary_failed",
                                    f"fixture {boundary} failure",
                                )
                            raise SimulatedCrash(boundary)

                        def faulting_publish_evidence(**arguments) -> None:
                            destination = arguments["destination_path"]
                            is_finalization_receipt = (
                                destination.name == "receipt.json"
                                and destination.parent.parent
                                == fixture.context.attempt_root
                                / "finalization-runs"
                            )
                            if (
                                is_finalization_receipt
                                and boundary == "receipt-before"
                                and not injected
                            ):
                                publish_ready = (
                                    destination.parent / "publish-ready"
                                )
                                (publish_ready / "fault-marker").write_text(
                                    "old run must not be reused\n",
                                    encoding="utf-8",
                                )
                                fail()
                            real_publish_evidence(**arguments)
                            if (
                                is_finalization_receipt
                                and boundary == "receipt-after"
                                and not injected
                            ):
                                publish_ready = (
                                    destination.parent / "publish-ready"
                                )
                                (publish_ready / "fault-marker").write_text(
                                    "old run must not be reused\n",
                                    encoding="utf-8",
                                )
                                fail()

                        def faulting_append(
                            journal,
                            state: str,
                            **fields,
                        ) -> None:
                            if (
                                state == "sealed"
                                and boundary == "sealed-before"
                                and not injected
                            ):
                                publish_ready = current_publish_ready(fixture)
                                if publish_ready is None:
                                    self.fail("sealed fault lacks publish-ready")
                                (publish_ready / "fault-marker").write_text(
                                    "old run must not be reused\n",
                                    encoding="utf-8",
                                )
                                fail()
                            real_append(journal, state, **fields)
                            if (
                                state == "sealed"
                                and boundary == "sealed-after"
                                and not injected
                            ):
                                publish_ready = current_publish_ready(fixture)
                                if publish_ready is None:
                                    self.fail("sealed fault lacks publish-ready")
                                (publish_ready / "fault-marker").write_text(
                                    "old run must not be reused\n",
                                    encoding="utf-8",
                                )
                                fail()

                        def faulting_fsync_tree(root: Path) -> None:
                            real_fsync_tree(root)
                            if (
                                boundary == "sealed-fsync"
                                and not injected
                                and root.name == "publish-ready"
                                and (root.parent / "receipt.json").is_file()
                            ):
                                event_paths = sorted(
                                    (
                                        fixture.context.attempt_root
                                        / "events"
                                    ).glob("*.json")
                                )
                                latest = json.loads(
                                    event_paths[-1].read_text(
                                        encoding="utf-8"
                                    )
                                )
                                if latest["state"] == "sealed":
                                    (root / "fault-marker").write_text(
                                        "old run must not be reused\n",
                                        encoding="utf-8",
                                    )
                                    fail()

                        expected = (
                            TransactionError
                            if failure_kind == "typed"
                            else SimulatedCrash
                        )
                        with patch.object(
                            transaction_module,
                            "_publish_pending_evidence",
                            side_effect=faulting_publish_evidence,
                        ), patch.object(
                            transaction_module.EventJournal,
                            "append",
                            new=faulting_append,
                        ), patch.object(
                            transaction_module,
                            "_fsync_tree",
                            side_effect=faulting_fsync_tree,
                        ):
                            with self.assertRaises(expected):
                                fixture.execute()

                        self.assertTrue(injected)
                        original_runs = self._finalization_runs(fixture)
                        self.assertEqual(len(original_runs), 1)
                        self.assertTrue(
                            any(original_runs[0].rglob("fault-marker"))
                        )
                        self._assert_fresh_uuid_recovery(
                            fixture,
                            original_runs,
                        )
                    finally:
                        fixture.close()

    def test_direct_publisher_fault_matrix_distinguishes_pre_and_post_rename(
        self,
    ) -> None:
        for position in ("before", "after"):
            for failure_kind in ("typed", "baseexception"):
                with self.subTest(
                    position=position,
                    failure_kind=failure_kind,
                ):
                    fixture = Fixture()
                    try:
                        def faulting_publisher(
                            source: Path,
                            destination: Path,
                        ) -> None:
                            if position == "before":
                                (source / "fault-marker").write_text(
                                    "publisher boundary marker\n",
                                    encoding="utf-8",
                                )
                            else:
                                os.rename(source, destination)
                            if failure_kind == "typed":
                                raise TransactionError(
                                    (
                                        "publish_durability_unknown"
                                        if position == "after"
                                        else "atomic_publish_failed"
                                    ),
                                    f"fixture publisher {position} failure",
                                    terminal_state=(
                                        "outcome_unknown"
                                        if position == "after"
                                        else "failed"
                                    ),
                                )
                            raise SimulatedCrash(
                                f"publisher-{position}"
                            )

                        expected = (
                            TransactionError
                            if failure_kind == "typed"
                            else SimulatedCrash
                        )
                        with self.assertRaises(expected):
                            fixture.execute(publisher=faulting_publisher)

                        original_runs = self._finalization_runs(fixture)
                        self.assertEqual(len(original_runs), 1)
                        if position == "before":
                            self.assertFalse(
                                os.path.lexists(fixture.context.final_root)
                            )
                            self._assert_fresh_uuid_recovery(
                                fixture,
                                original_runs,
                            )
                            continue

                        self.assertTrue(fixture.context.final_root.is_dir())
                        self._clear_runner_observations(fixture)
                        publisher_called = False

                        def forbidden_publisher(
                            _source: Path,
                            _destination: Path,
                        ) -> None:
                            nonlocal publisher_called
                            publisher_called = True

                        recovered_app = fixture.recover(
                            publisher=forbidden_publisher
                        )
                        self.assertEqual(
                            recovered_app,
                            fixture.context.final_root
                            / "Clash for Mac.app",
                        )
                        self.assertEqual(fixture.runner.calls, [])
                        self.assertFalse(publisher_called)
                        self.assertEqual(
                            self._finalization_runs(fixture),
                            original_runs,
                        )
                        self.assertFalse(
                            (
                                fixture.context.attempt_root
                                / "recovery-intent.json"
                            ).exists()
                        )
                        receipt = json.loads(
                            (original_runs[0] / "receipt.json").read_text(
                                encoding="utf-8"
                            )
                        )
                        self.assertIsNone(
                            receipt["recovery_intent_sha256"]
                        )
                        self.assertIsNone(
                            receipt["recovery_continuation_sha256"]
                        )
                        recovered_again = fixture.recover(
                            publisher=forbidden_publisher
                        )
                        self.assertEqual(recovered_again, recovered_app)
                        self.assertEqual(fixture.runner.calls, [])
                        self.assertFalse(publisher_called)
                    finally:
                        fixture.close()

    def test_direct_attempt_lock_spans_submit_wait_and_finalization(self) -> None:
        for blocked_role in (
            CommandRole.SUBMIT,
            CommandRole.WAIT,
            CommandRole.STAPLE,
        ):
            with self.subTest(blocked_role=blocked_role):
                fixture = Fixture()
                try:
                    entered = threading.Event()
                    release = threading.Event()
                    blocked = False

                    def blocking_runner(
                        role: CommandRole,
                        command: list[str],
                        timeout: float,
                    ) -> CommandResult:
                        nonlocal blocked
                        if role == blocked_role and not blocked:
                            blocked = True
                            entered.set()
                            if not release.wait(5):
                                raise AssertionError(
                                    "test did not release direct command"
                                )
                        return fixture.runner(role, command, timeout)

                    with ThreadPoolExecutor(max_workers=2) as executor:
                        executing = executor.submit(
                            fixture.execute,
                            command_runner=blocking_runner,
                        )
                        self.assertTrue(entered.wait(2))
                        calls_before_recovery = list(fixture.runner.calls)
                        with self.assertRaises(TransactionError) as raised:
                            fixture.recover()
                        self.assertEqual(
                            raised.exception.code,
                            "recovery_in_progress",
                        )
                        self.assertEqual(
                            fixture.runner.calls,
                            calls_before_recovery,
                        )
                        release.set()
                        self.assertTrue(
                            executing.result(timeout=5).is_dir()
                        )
                finally:
                    fixture.close()

    def test_direct_attempt_lock_spans_terminal_receipt(self) -> None:
        fixture = Fixture()
        try:
            terminal_entered = threading.Event()
            release_terminal = threading.Event()
            real_append = transaction_module.EventJournal.append

            def blocking_terminal_append(
                journal,
                state: str,
                **fields,
            ) -> None:
                if (
                    state == "failed"
                    and fields.get("failure_code")
                    == "atomic_publish_failed"
                ):
                    terminal_entered.set()
                    if not release_terminal.wait(5):
                        raise AssertionError(
                            "test did not release terminal append"
                        )
                real_append(journal, state, **fields)

            def fail_publisher(_source: Path, _destination: Path) -> None:
                raise TransactionError(
                    "atomic_publish_failed",
                    "fixture publication failure",
                )

            with patch.object(
                transaction_module.EventJournal,
                "append",
                new=blocking_terminal_append,
            ):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    executing = executor.submit(
                        fixture.execute,
                        publisher=fail_publisher,
                    )
                    self.assertTrue(terminal_entered.wait(2))
                    calls_before_recovery = list(fixture.runner.calls)
                    with self.assertRaises(TransactionError) as raised:
                        fixture.recover()
                    self.assertEqual(
                        raised.exception.code,
                        "recovery_in_progress",
                    )
                    self.assertEqual(
                        fixture.runner.calls,
                        calls_before_recovery,
                    )
                    release_terminal.set()
                    with self.assertRaises(TransactionError) as execution_error:
                        executing.result(timeout=5)
                    self.assertEqual(
                        execution_error.exception.code,
                        "atomic_publish_failed",
                    )

            original_runs = self._finalization_runs(fixture)
            self.assertEqual(len(original_runs), 1)
            self._assert_fresh_uuid_recovery(fixture, original_runs)
        finally:
            fixture.close()

    def test_direct_capacity_is_reserved_before_submit(self) -> None:
        fixture = Fixture()
        try:
            expected_direct_reserve = (
                3
                + len(transaction_module.FINALIZATION_EVENT_STATES)
                + 1
            )
            self.assertEqual(
                transaction_module.DIRECT_FINALIZATION_EVENT_RESERVE,
                expected_direct_reserve,
            )
            insufficient_capacity = 2 + 2 + expected_direct_reserve - 1
            with patch.object(
                transaction_module,
                "MAX_EVENT_DOCUMENTS",
                insufficient_capacity,
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute()

            self.assertEqual(
                raised.exception.code,
                "event_journal_capacity_exceeded",
            )
            self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
            self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
            self.assertFalse(
                (
                    fixture.context.attempt_root
                    / "submission-observation.json"
                ).exists()
            )
            self.assertFalse(
                (
                    fixture.context.attempt_root
                    / "submission-receipt.json"
                ).exists()
            )
        finally:
            fixture.close()

    def test_incomplete_direct_boundary_reserves_ready_anchor_and_recovery(
        self,
    ) -> None:
        fixture = Fixture()
        try:
            real_fsync_tree = transaction_module._fsync_tree
            injected = False

            def fail_work_fsync(root: Path) -> None:
                nonlocal injected
                if (
                    not injected
                    and root == fixture.context.attempt_root / "work"
                ):
                    injected = True
                    raise OSError("fixture source fsync failure")
                real_fsync_tree(root)

            with patch.object(
                transaction_module,
                "_fsync_tree",
                side_effect=fail_work_fsync,
            ):
                with self.assertRaises(TransactionError):
                    fixture.execute()
            self.assertTrue(injected)

            event_paths = sorted(
                (fixture.context.attempt_root / "events").glob("*.json")
            )
            original_events = [path.read_bytes() for path in event_paths]
            original_count = len(event_paths)
            expected_boundary_reserve = (
                2 + transaction_module.RECOVERY_SUCCESS_EVENT_RESERVE
            )
            self.assertEqual(
                transaction_module.DIRECT_BOUNDARY_RECOVERY_EVENT_RESERVE,
                expected_boundary_reserve,
            )
            self._clear_runner_observations(fixture)
            with patch.object(
                transaction_module,
                "MAX_EVENT_DOCUMENTS",
                original_count + expected_boundary_reserve - 1,
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.recover()

            self.assertEqual(
                raised.exception.code,
                "event_journal_capacity_exceeded",
            )
            self.assertEqual(
                [path.read_bytes() for path in event_paths],
                original_events,
            )
            self.assertFalse(
                (
                    fixture.context.attempt_root
                    / "recovery-intent.json"
                ).exists()
            )
            self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
            self.assertNotIn(CommandRole.FETCH_LOG, fixture.runner.calls)
            self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
            self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
            states = [
                json.loads(data.decode("utf-8"))["state"]
                for data in original_events
            ]
            self.assertNotIn("direct_finalization_ready", states)
            self._assert_fresh_uuid_recovery(fixture, [])
        finally:
            fixture.close()

    def test_direct_boundary_evidence_tamper_is_rejected_before_remote_io(
        self,
    ) -> None:
        for boundary in (
            "direct_finalization_preparing",
            "direct_finalization_ready",
        ):
            with self.subTest(boundary=boundary):
                fixture = Fixture()
                try:
                    if boundary == "direct_finalization_preparing":
                        with patch.object(
                            transaction_module,
                            "_ensure_immutable_recovery_source",
                            side_effect=SimulatedCrash("after-preparing"),
                        ):
                            with self.assertRaises(SimulatedCrash):
                                fixture.execute()
                    else:
                        with patch.object(
                            transaction_module,
                            "_run_accepted_finalization_locked",
                            side_effect=SimulatedCrash("after-ready"),
                        ):
                            with self.assertRaises(SimulatedCrash):
                                fixture.execute()

                    event_paths = sorted(
                        (
                            fixture.context.attempt_root / "events"
                        ).glob("*.json")
                    )
                    boundary_path = event_paths[-1]
                    event = json.loads(
                        boundary_path.read_text(encoding="utf-8")
                    )
                    self.assertEqual(event["state"], boundary)
                    self.assertEqual(
                        event["document"],
                        transaction_module.EVENT_DOCUMENT_V2,
                    )
                    event["evidence_sha256"] = "0" * 64
                    boundary_path.write_bytes(
                        transaction_module._canonical_json(event).encode(
                            "utf-8"
                        )
                    )
                    self._clear_runner_observations(fixture)
                    publisher_called = False

                    def forbidden_publisher(
                        _source: Path,
                        _destination: Path,
                    ) -> None:
                        nonlocal publisher_called
                        publisher_called = True

                    with self.assertRaises(TransactionError) as raised:
                        fixture.recover(publisher=forbidden_publisher)

                    self.assertEqual(
                        raised.exception.code,
                        "direct_finalization_boundary_mismatch",
                    )
                    self.assertEqual(fixture.runner.calls, [])
                    self.assertFalse(publisher_called)
                    self.assertFalse(
                        (
                            fixture.context.attempt_root
                            / "recovery-intent.json"
                        ).exists()
                    )
                finally:
                    fixture.close()

    def test_finalization_run_count_and_byte_quotas_block_before_copy(self) -> None:
        fixture = Fixture()
        try:
            fixture.runner.fail_role = CommandRole.STAPLE
            with self.assertRaises(TransactionError):
                fixture.execute()
            original_runs = self._finalization_runs(fixture)
            self.assertEqual(len(original_runs), 1)
            self._clear_runner_observations(fixture)
            fixture.runner.fail_role = None
            with patch.object(
                transaction_module,
                "MAX_FINALIZATION_RUNS",
                1,
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.recover()
            self.assertEqual(
                raised.exception.code,
                "finalization_run_quota_exceeded",
            )
            self.assertEqual(self._finalization_runs(fixture), original_runs)
            self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
            self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
        finally:
            fixture.close()

        fixture = Fixture()
        try:
            with patch.object(
                transaction_module,
                "MAX_FINALIZATION_RUNS_BYTES",
                1,
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute()
            self.assertEqual(
                raised.exception.code,
                "finalization_byte_quota_exceeded",
            )
            self.assertEqual(self._finalization_runs(fixture), [])
            self.assertFalse(os.path.lexists(fixture.context.final_root))
        finally:
            fixture.close()

    def test_finalization_quota_contract_is_exactly_eight_runs_and_four_gib(self) -> None:
        self.assertEqual(transaction_module.MAX_FINALIZATION_RUNS, 8)
        self.assertEqual(
            transaction_module.MAX_FINALIZATION_RUNS_BYTES,
            4 * 1024 * 1024 * 1024,
        )

    def test_attempt_inventory_enforces_retained_logical_byte_quota(self) -> None:
        fixture = Fixture()
        try:
            fixture.runner.fail_role = CommandRole.STAPLE
            with self.assertRaises(TransactionError):
                fixture.execute()
            finalization_runs = (
                fixture.context.attempt_root / "finalization-runs"
            )
            _, logical_bytes = (
                transaction_module._bounded_finalization_run_inventory(
                    finalization_runs
                )
            )
            self.assertGreater(logical_bytes, 0)
            allowed_entries = {
                path.name for path in fixture.context.attempt_root.iterdir()
            }

            with patch.object(
                transaction_module,
                "MAX_FINALIZATION_RUNS_BYTES",
                logical_bytes - 1,
            ):
                with self.assertRaises(TransactionError) as raised:
                    transaction_module._decode_attempt_inventory(
                        replace(fixture.context, staged_app=None),
                        allowed_entries=allowed_entries,
                        require_source=True,
                    )

            self.assertEqual(
                raised.exception.code,
                "finalization_byte_quota_exceeded",
            )
        finally:
            fixture.close()

    def test_sibling_growth_during_copy_is_rejected_after_copy(self) -> None:
        byte_limit = 64 * 1024
        for growth in ("run-count", "logical-bytes"):
            with self.subTest(growth=growth):
                fixture = Fixture()
                try:
                    copied = False
                    publisher_called = False
                    real_copytree = shutil.copytree

                    def copy_with_sibling_growth(
                        source: Path,
                        destination: Path,
                        *args,
                        **kwargs,
                    ) -> Path:
                        nonlocal copied
                        result = real_copytree(
                            source,
                            destination,
                            *args,
                            **kwargs,
                        )
                        destination_path = Path(destination)
                        if destination_path.name != "work":
                            return result
                        copied = True
                        sibling = (
                            destination_path.parent.parent
                            / "11111111-2222-4333-8444-555555555555"
                        )
                        sibling.mkdir(mode=0o700)
                        if growth == "logical-bytes":
                            (sibling / "growth.bin").write_bytes(
                                b"x" * byte_limit
                            )
                        return result

                    def forbidden_publisher(
                        _source: Path,
                        _destination: Path,
                    ) -> None:
                        nonlocal publisher_called
                        publisher_called = True

                    limit_patch = (
                        patch.object(
                            transaction_module,
                            "MAX_FINALIZATION_RUNS",
                            1,
                        )
                        if growth == "run-count"
                        else patch.object(
                            transaction_module,
                            "MAX_FINALIZATION_RUNS_BYTES",
                            byte_limit,
                        )
                    )
                    with (
                        patch.object(
                            transaction_module.shutil,
                            "copytree",
                            side_effect=copy_with_sibling_growth,
                        ),
                        limit_patch,
                    ):
                        with self.assertRaises(TransactionError) as raised:
                            fixture.execute(publisher=forbidden_publisher)

                    self.assertTrue(copied)
                    self.assertFalse(publisher_called)
                    self.assertEqual(
                        raised.exception.code,
                        (
                            "finalization_run_quota_exceeded"
                            if growth == "run-count"
                            else "finalization_byte_quota_exceeded"
                        ),
                    )
                    self.assertFalse(
                        os.path.lexists(fixture.context.final_root)
                    )
                finally:
                    fixture.close()

    def test_sibling_growth_after_copy_blocks_before_publication(self) -> None:
        fixture = Fixture()
        try:
            sibling_created = False
            publisher_called = False

            def growing_runner(
                role: CommandRole,
                command: list[str],
                timeout: float,
            ) -> CommandResult:
                nonlocal sibling_created
                result = fixture.runner(role, command, timeout)
                if role is CommandRole.DISTRIBUTION_CHECK:
                    sibling = (
                        fixture.context.attempt_root
                        / "finalization-runs"
                        / "11111111-2222-4333-8444-555555555555"
                    )
                    sibling.mkdir(mode=0o700)
                    sibling_created = True
                return result

            def forbidden_publisher(
                _source: Path,
                _destination: Path,
            ) -> None:
                nonlocal publisher_called
                publisher_called = True

            with patch.object(
                transaction_module,
                "MAX_FINALIZATION_RUNS",
                1,
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(
                        command_runner=growing_runner,
                        publisher=forbidden_publisher,
                    )

            self.assertTrue(sibling_created)
            self.assertFalse(publisher_called)
            self.assertEqual(
                raised.exception.code,
                "finalization_run_quota_exceeded",
            )
            self.assertFalse(os.path.lexists(fixture.context.final_root))
        finally:
            fixture.close()

    def test_sibling_growth_during_publication_is_detected_afterward(self) -> None:
        byte_limit = 64 * 1024
        for growth in ("run-count", "logical-bytes"):
            with self.subTest(growth=growth):
                fixture = Fixture()
                try:
                    publisher_called = False

                    def publisher_with_sibling_growth(
                        source: Path,
                        destination: Path,
                    ) -> None:
                        nonlocal publisher_called
                        publisher_called = True
                        Fixture.publisher(source, destination)
                        sibling = (
                            fixture.context.attempt_root
                            / "finalization-runs"
                            / "11111111-2222-4333-8444-555555555555"
                        )
                        sibling.mkdir(mode=0o700)
                        if growth == "logical-bytes":
                            (sibling / "growth.bin").write_bytes(
                                b"x" * byte_limit
                            )

                    limit_patch = (
                        patch.object(
                            transaction_module,
                            "MAX_FINALIZATION_RUNS",
                            1,
                        )
                        if growth == "run-count"
                        else patch.object(
                            transaction_module,
                            "MAX_FINALIZATION_RUNS_BYTES",
                            byte_limit,
                        )
                    )
                    with limit_patch:
                        with self.assertRaises(TransactionError) as raised:
                            fixture.execute(
                                publisher=publisher_with_sibling_growth
                            )

                    self.assertTrue(publisher_called)
                    self.assertEqual(
                        raised.exception.code,
                        "publish_durability_unknown",
                    )
                    self.assertEqual(
                        raised.exception.terminal_state,
                        "outcome_unknown",
                    )
                    self.assertTrue(fixture.context.final_root.is_dir())
                    last_event = json.loads(
                        sorted(
                            (
                                fixture.context.attempt_root / "events"
                            ).glob("*.json")
                        )[-1].read_text(encoding="utf-8")
                    )
                    self.assertEqual(last_event["state"], "outcome_unknown")
                    self.assertEqual(
                        last_event["failure_code"],
                        "publish_durability_unknown",
                    )
                finally:
                    fixture.close()

    def test_partial_enospc_copy_passes_run_root_to_safe_cleanup(self) -> None:
        fixture = Fixture()
        try:
            partial_work: Path | None = None

            def enospc_copy(
                _source: Path,
                destination: Path,
                *args,
                **kwargs,
            ) -> Path:
                nonlocal partial_work
                del args, kwargs
                partial_work = Path(destination)
                (partial_work / "partial.bin").write_bytes(b"x" * 4096)
                raise OSError(errno.ENOSPC, "fixture disk full")

            with patch.object(
                transaction_module.shutil,
                "copytree",
                side_effect=enospc_copy,
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute()

            self.assertEqual(
                raised.exception.code,
                "recovery_workspace_copy_failed",
            )
            self.assertIsNotNone(partial_work)
            if partial_work is not None:
                self.assertFalse(os.path.lexists(partial_work.parent))
            self.assertEqual(self._finalization_runs(fixture), [])
            self.assertTrue(
                (fixture.context.attempt_root / "recovery-source").is_dir()
            )
            self.assertFalse(os.path.lexists(fixture.context.final_root))
        finally:
            fixture.close()

    def test_enospc_before_first_copy_entry_releases_empty_work_run(self) -> None:
        fixture = Fixture()
        try:
            copy_called = False

            def immediate_enospc(
                _source: Path,
                _destination: Path,
                *args,
                **kwargs,
            ) -> Path:
                nonlocal copy_called
                del args, kwargs
                copy_called = True
                raise OSError(errno.ENOSPC, "fixture disk full")

            with patch.object(
                transaction_module.shutil,
                "copytree",
                side_effect=immediate_enospc,
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute()

            self.assertTrue(copy_called)
            self.assertEqual(
                raised.exception.code,
                "recovery_workspace_copy_failed",
            )
            self.assertEqual(self._finalization_runs(fixture), [])
            self.assertTrue(
                (fixture.context.attempt_root / "recovery-source").is_dir()
            )
            self.assertFalse(os.path.lexists(fixture.context.final_root))
        finally:
            fixture.close()

    def test_large_typed_failed_work_is_cleaned_only_without_ambiguity(
        self,
    ) -> None:
        fixture = Fixture()
        try:
            injected = False

            def failing_runner(
                role: CommandRole,
                command: list[str],
                timeout: float,
            ) -> CommandResult:
                nonlocal injected
                result = fixture.runner(role, command, timeout)
                if role is CommandRole.STAPLE and not injected:
                    injected = True
                    run = sole_finalization_run(fixture)
                    (run / "work/large-failed.bin").write_bytes(b"x" * 4096)
                    return CommandResult(9, "", "fixture staple failure")
                return result

            with patch.object(
                transaction_module,
                "FAILED_FINALIZATION_CLEANUP_MIN_BYTES",
                1,
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(command_runner=failing_runner)
            self.assertTrue(injected)
            self.assertEqual(raised.exception.code, "staple_failed")
            self.assertEqual(self._finalization_runs(fixture), [])
            self.assertTrue(
                (fixture.context.attempt_root / "recovery-source").is_dir()
            )
            self._clear_runner_observations(fixture)
            recovered = fixture.recover()
            self.assertTrue(recovered.is_dir())
            self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
            self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
        finally:
            fixture.close()

    def test_large_baseexception_or_publish_ready_run_is_never_cleaned(self) -> None:
        for ambiguity in ("baseexception", "publish-ready"):
            with self.subTest(ambiguity=ambiguity):
                fixture = Fixture()
                try:
                    if ambiguity == "baseexception":
                        def crash_runner(
                            role: CommandRole,
                            command: list[str],
                            timeout: float,
                        ) -> CommandResult:
                            result = fixture.runner(role, command, timeout)
                            if role is CommandRole.STAPLE:
                                run = sole_finalization_run(fixture)
                                (run / "work/large-crash.bin").write_bytes(
                                    b"x" * 4096
                                )
                                raise SimulatedCrash("large-work")
                            return result

                        with patch.object(
                            transaction_module,
                            "FAILED_FINALIZATION_CLEANUP_MIN_BYTES",
                            1,
                        ):
                            with self.assertRaises(SimulatedCrash):
                                fixture.execute(command_runner=crash_runner)
                    else:
                        def fail_publish(
                            source: Path,
                            _destination: Path,
                        ) -> None:
                            (source / "large-publish.bin").write_bytes(
                                b"x" * 4096
                            )
                            raise TransactionError(
                                "atomic_publish_failed",
                                "fixture publication failure",
                            )

                        with patch.object(
                            transaction_module,
                            "FAILED_FINALIZATION_CLEANUP_MIN_BYTES",
                            1,
                        ):
                            with self.assertRaises(TransactionError):
                                fixture.execute(publisher=fail_publish)
                    runs = self._finalization_runs(fixture)
                    self.assertEqual(len(runs), 1)
                    self.assertTrue(
                        any(runs[0].rglob("large-*.bin"))
                    )
                finally:
                    fixture.close()

    def test_any_retained_publish_ready_run_blocks_large_cleanup(self) -> None:
        fixture = Fixture()
        try:
            sibling_run: Path | None = None

            def failing_runner(
                role: CommandRole,
                command: list[str],
                timeout: float,
            ) -> CommandResult:
                nonlocal sibling_run
                result = fixture.runner(role, command, timeout)
                if role is CommandRole.STAPLE:
                    active_run = sole_finalization_run(fixture)
                    (active_run / "work/large-failed.bin").write_bytes(
                        b"x" * 4096
                    )
                    sibling_run = (
                        fixture.context.attempt_root
                        / "finalization-runs"
                        / "11111111-2222-4333-8444-555555555555"
                    )
                    sibling_run.mkdir(mode=0o700)
                    (sibling_run / "publish-ready").mkdir(mode=0o700)
                    return CommandResult(9, "", "fixture staple failure")
                return result

            with patch.object(
                transaction_module,
                "FAILED_FINALIZATION_CLEANUP_MIN_BYTES",
                1,
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(command_runner=failing_runner)

            self.assertEqual(raised.exception.code, "staple_failed")
            self.assertIsNotNone(sibling_run)
            runs = self._finalization_runs(fixture)
            self.assertEqual(len(runs), 2)
            self.assertTrue(
                any((run / "work/large-failed.bin").is_file() for run in runs)
            )
            if sibling_run is not None:
                self.assertTrue((sibling_run / "publish-ready").is_dir())
        finally:
            fixture.close()

    def test_cleanup_rechecks_sibling_markers_after_workspace_scan(self) -> None:
        fixture = Fixture()
        try:
            sibling_run: Path | None = None
            marker_injected = False
            real_logical_bytes = (
                transaction_module._finalization_tree_logical_bytes
            )

            def failing_runner(
                role: CommandRole,
                command: list[str],
                timeout: float,
            ) -> CommandResult:
                result = fixture.runner(role, command, timeout)
                if role is CommandRole.STAPLE:
                    run = sole_finalization_run(fixture)
                    (run / "work/large-failed.bin").write_bytes(
                        b"x" * 4096
                    )
                    return CommandResult(9, "", "fixture staple failure")
                return result

            def scan_then_publish_marker(
                root: Path,
                *,
                ceiling: int | None,
            ) -> int:
                nonlocal marker_injected, sibling_run
                result = real_logical_bytes(root, ceiling=ceiling)
                if (
                    not marker_injected
                    and (root / "large-failed.bin").is_file()
                ):
                    sibling_run = (
                        fixture.context.attempt_root
                        / "finalization-runs"
                        / "11111111-2222-4333-8444-555555555555"
                    )
                    sibling_run.mkdir(mode=0o700)
                    (sibling_run / "publish-ready").mkdir(mode=0o700)
                    marker_injected = True
                return result

            with (
                patch.object(
                    transaction_module,
                    "FAILED_FINALIZATION_CLEANUP_MIN_BYTES",
                    1,
                ),
                patch.object(
                    transaction_module,
                    "_finalization_tree_logical_bytes",
                    side_effect=scan_then_publish_marker,
                ),
            ):
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(command_runner=failing_runner)

            self.assertEqual(raised.exception.code, "staple_failed")
            self.assertTrue(marker_injected)
            self.assertIsNotNone(sibling_run)
            runs = self._finalization_runs(fixture)
            self.assertEqual(len(runs), 2)
            self.assertTrue(
                any((run / "work/large-failed.bin").is_file() for run in runs)
            )
            if sibling_run is not None:
                self.assertTrue((sibling_run / "publish-ready").is_dir())
        finally:
            fixture.close()

    def test_frozen_legacy_lane_intent_is_not_a_ga_recovery_authority(self) -> None:
        intent_path = self.fixture.context.attempt_root / "intent.json"
        legacy_intent = json.loads(intent_path.read_text(encoding="utf-8"))
        legacy_intent["schema_version"] = 1
        legacy_intent["document"] = "cfw-notarization-attempt-v1"
        legacy_intent["lane"] = "validation"
        del legacy_intent["candidate_freeze_intent_sha256"]
        intent_path.write_bytes(
            transaction_module._canonical_json(legacy_intent).encode("utf-8")
        )
        intent_path.chmod(0o600)
        self._reset_runner_observations()
        with self.assertRaises(TransactionError) as raised:
            transaction_module._load_recovery_intent_document(
                replace(self.fixture.context, staged_app=None)
            )
        self.assertEqual(
            raised.exception.code,
            "notarization_intent_identity_drift",
        )
        self.assertEqual(self.fixture.runner.calls, [])

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
        self.assertEqual(
            self.fixture.runner.command_calls[0],
            (
                CommandRole.FINAL_VERIFY,
                (
                    str(
                        self.fixture.context.repository
                        / "scripts/verify_release_app.sh"
                    ),
                    "--pre-notary",
                    str(
                        self.fixture.context.attempt_root
                        / "work/Clash for Mac.app"
                    ),
                    str(self.fixture.context.native_products),
                    "--context",
                    "canonical-native-content",
                ),
                600,
            ),
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
                "recovery_intent_anchored",
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
        self.assertEqual(receipt["schema_version"], 5)
        self.assertEqual(
            receipt["notary_profile"],
            transaction_module.NOTARY_PROFILE,
        )
        self.assertEqual(receipt["candidate_freeze_intent_sha256"], "f" * 64)
        self.assertEqual(receipt["acquisition"], "explicit-recovery")
        self.assertEqual(
            receipt["causal_binding"], "unique-history-window-and-log"
        )
        self.assertIsNone(receipt["submission_observation_sha256"])
        self.assertRegex(receipt["recovery_intent_sha256"], r"^[0-9a-f]{64}$")
        recovery_intent = json.loads(
            (self.fixture.context.attempt_root / "recovery-intent.json").read_text(
                encoding="utf-8"
            )
        )
        expected_transformation = self.fixture.signing_transformation_binding()
        for field, expected in expected_transformation.items():
            self.assertEqual(recovery_intent[field], expected)
            self.assertEqual(receipt[field], expected)

    def test_first_recovery_intent_is_anchored_before_apple_reads(self) -> None:
        observed_states: list[list[str]] = []

        def inspect_before_apple(
            role: CommandRole,
            command: list[str],
            timeout: float,
        ) -> CommandResult:
            if role in {
                CommandRole.INFO,
                CommandRole.HISTORY,
                CommandRole.FETCH_LOG,
            }:
                observed_states.append(
                    [
                        json.loads(path.read_text(encoding="utf-8"))["state"]
                        for path in sorted(
                            (
                                self.fixture.context.attempt_root / "events"
                            ).glob("*.json")
                        )
                    ]
                )
            return self.fixture.runner(role, command, timeout)

        self._reset_runner_observations()
        self.fixture.recover(command_runner=inspect_before_apple)

        self.assertEqual(len(observed_states), 3)
        for states in observed_states:
            self.assertIn("recovery_intent_anchored", states)
            self.assertLess(
                states.index("recovery_intent_anchored"),
                states.index("reconciliation_started"),
            )

    def test_legacy_explicit_recovery_receipt_remains_an_intent_anchor(self) -> None:
        with (
            patch.object(
                transaction_module,
                "_require_recovery_intent_anchor",
                return_value=False,
            ),
            patch.object(
                transaction_module,
                "_finalize_accepted_submission",
                side_effect=SimulatedCrash("legacy-explicit-recovery"),
            ),
        ):
            with self.assertRaises(SimulatedCrash):
                self.fixture.recover()

        self._reset_runner_observations()
        final_app = self.fixture.recover()

        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, self.fixture.runner.calls)
        states = [
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in sorted(
                (self.fixture.context.attempt_root / "events").glob("*.json")
            )
        ]
        self.assertNotIn("recovery_intent_anchored", states)

    def test_old_direct_receipt_suffix_without_intent_anchor_is_rejected(self) -> None:
        fixture = self._direct_receipt_fixture()
        fixture.runner.fail_role = CommandRole.INFO
        with patch.object(
            transaction_module,
            "_require_recovery_intent_anchor",
            return_value=False,
        ):
            with self.assertRaises(TransactionError):
                fixture.recover()

        fixture.runner.fail_role = None
        self._clear_runner_observations(fixture)
        with self.assertRaises(TransactionError) as raised:
            fixture.recover()

        self.assertEqual(
            raised.exception.code,
            "recovery_intent_anchor_missing",
        )
        self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_direct_receipt_intent_deletion_or_rewrite_is_rejected(self) -> None:
        for mutation in ("delete", "rewrite"):
            with self.subTest(mutation=mutation):
                fixture = self._direct_receipt_fixture()
                fixture.runner.fail_role = CommandRole.STAPLE
                with self.assertRaises(TransactionError):
                    fixture.recover()

                intent_path = (
                    fixture.context.attempt_root / "recovery-intent.json"
                )
                if mutation == "delete":
                    intent_path.unlink()
                else:
                    intent = json.loads(intent_path.read_text(encoding="utf-8"))
                    intent["recovery_tool_repository_commit"] = "e" * 40
                    intent["recovery_tool_release_source_sha256"] = "f" * 64
                    intent_path.write_bytes(
                        transaction_module._canonical_json(intent).encode("utf-8")
                    )

                fixture.runner.fail_role = None
                self._clear_runner_observations(fixture)
                with self.assertRaises(TransactionError) as raised:
                    fixture.recover(
                        recovery_tool_identity_reader=lambda _repository: {
                            "repositoryCommit": "e" * 40,
                            "releaseSourceSha256": "f" * 64,
                        }
                    )

                self.assertIn(
                    raised.exception.code,
                    {
                        "recovery_intent_identity_drift",
                        "recovery_intent_missing",
                    },
                )
                self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
                self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
                self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_marker_first_crash_reconstructs_exact_continuation(self) -> None:
        continued_identity, marker_path = self._crash_after_continuation_marker()
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        self._reset_runner_observations()

        final_app = self.fixture.recover(
            recovery_tool_identity_reader=lambda _repository: continued_identity
        )

        continuation_path = (
            self.fixture.context.attempt_root / "recovery-continuation.json"
        )
        continuation = json.loads(
            continuation_path.read_text(encoding="utf-8")
        )
        self.assertTrue(final_app.is_dir())
        self.assertEqual(
            hashlib.sha256(continuation_path.read_bytes()).hexdigest(),
            marker["evidence_sha256"],
        )
        self.assertEqual(continuation["requested_at"], marker["recorded_at"])
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, self.fixture.runner.calls)

    def test_continuation_pending_zero_partial_or_complete_is_recovered_atomically(
        self,
    ) -> None:
        for pending_kind in ("zero", "partial", "complete"):
            with self.subTest(pending_kind=pending_kind):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                fixture.create_orphaned_submit_attempt()
                fixture.runner.fail_role = CommandRole.STAPLE
                self._clear_runner_observations(fixture)
                with self.assertRaises(TransactionError):
                    fixture.recover()
                continued_identity = self._continued_identity()
                continuation, marker = self._expected_continuation_from_tip(
                    fixture,
                    continued_identity,
                )
                marker_path = (
                    fixture.context.attempt_root
                    / "events"
                    / f"{marker['sequence']:08d}.json"
                )
                marker_path.write_bytes(
                    transaction_module._canonical_json(marker).encode("utf-8")
                )
                marker_path.chmod(0o600)
                expected = transaction_module._canonical_json(continuation).encode(
                    "utf-8"
                )
                pending_path = (
                    fixture.context.attempt_root
                    / transaction_module.RECOVERY_CONTINUATION_PENDING_FILENAME
                )
                pending_data = {
                    "zero": b"",
                    "partial": expected[: max(1, len(expected) // 2)],
                    "complete": expected,
                }[pending_kind]
                pending_path.write_bytes(pending_data)
                pending_path.chmod(0o600)
                fixture.runner.fail_role = None
                self._clear_runner_observations(fixture)

                with patch.object(
                    transaction_module,
                    "_recovery_read_result",
                    side_effect=SimulatedCrash("before-apple-read"),
                ):
                    with self.assertRaises(SimulatedCrash):
                        fixture.recover(
                            recovery_tool_identity_reader=(
                                lambda _repository: continued_identity
                            )
                        )

                final_path = (
                    fixture.context.attempt_root / "recovery-continuation.json"
                )
                self.assertEqual(final_path.read_bytes(), expected)
                self.assertFalse(pending_path.exists())
                self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
                self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
                self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_event_marker_pending_partial_or_complete_is_recovered_atomically(
        self,
    ) -> None:
        for pending_kind in ("zero", "partial", "complete"):
            with self.subTest(pending_kind=pending_kind):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                fixture.create_orphaned_submit_attempt()
                fixture.runner.fail_role = CommandRole.STAPLE
                self._clear_runner_observations(fixture)
                with self.assertRaises(TransactionError):
                    fixture.recover()
                continued_identity = self._continued_identity()
                _continuation, marker = self._expected_continuation_from_tip(
                    fixture,
                    continued_identity,
                )
                expected_marker = transaction_module._canonical_json(marker).encode(
                    "utf-8"
                )
                pending_path = (
                    fixture.context.attempt_root
                    / "events"
                    / f"{marker['sequence']:08d}.pending"
                )
                pending_path.write_bytes(
                    {
                        "zero": b"",
                        "partial": expected_marker[: len(expected_marker) // 2],
                        "complete": expected_marker,
                    }[pending_kind]
                )
                pending_path.chmod(0o600)
                fixture.runner.fail_role = None
                self._clear_runner_observations(fixture)

                with patch.object(
                    transaction_module,
                    "_recovery_read_result",
                    side_effect=SimulatedCrash("before-apple-read"),
                ):
                    with self.assertRaises(SimulatedCrash):
                        fixture.recover(
                            recovery_tool_identity_reader=(
                                lambda _repository: continued_identity
                            )
                        )

                final_marker = pending_path.with_suffix(".json")
                self.assertEqual(final_marker.read_bytes(), expected_marker)
                self.assertFalse(pending_path.exists())
                self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
                self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
                self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_foreign_or_out_of_sequence_event_pending_is_rejected(self) -> None:
        for pending_kind in ("symlink", "hardlink", "out-of-sequence"):
            with self.subTest(pending_kind=pending_kind):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                fixture.create_orphaned_submit_attempt()
                fixture.runner.fail_role = CommandRole.STAPLE
                with self.assertRaises(TransactionError):
                    fixture.recover()
                continued_identity = self._continued_identity()
                _continuation, marker = self._expected_continuation_from_tip(
                    fixture,
                    continued_identity,
                )
                sequence = int(marker["sequence"])
                if pending_kind == "out-of-sequence":
                    pending_path = (
                        fixture.context.attempt_root
                        / "events"
                        / f"{sequence + 1:08d}.pending"
                    )
                    pending_path.write_bytes(
                        transaction_module._canonical_json(marker).encode("utf-8")
                    )
                    pending_path.chmod(0o600)
                else:
                    pending_path = (
                        fixture.context.attempt_root
                        / "events"
                        / f"{sequence:08d}.pending"
                    )
                    foreign = fixture.repository / f"event-{pending_kind}"
                    foreign.write_bytes(b"foreign")
                    if pending_kind == "symlink":
                        pending_path.symlink_to(foreign)
                    else:
                        os.link(foreign, pending_path)
                fixture.runner.fail_role = None
                self._clear_runner_observations(fixture)

                with self.assertRaises(TransactionError) as raised:
                    fixture.recover(
                        recovery_tool_identity_reader=(
                            lambda _repository: continued_identity
                        )
                    )

                self.assertIn(
                    raised.exception.code,
                    {
                        "event_journal_identity_drift",
                        "unsafe_pending_evidence",
                    },
                )
                self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
                self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
                self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_event_marker_rename_fsync_unknown_retries_from_final(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.create_orphaned_submit_attempt()
        fixture.runner.fail_role = CommandRole.STAPLE
        with self.assertRaises(TransactionError):
            fixture.recover()
        continued_identity = self._continued_identity()
        _continuation, marker = self._expected_continuation_from_tip(
            fixture,
            continued_identity,
        )
        pending_path = (
            fixture.context.attempt_root
            / "events"
            / f"{marker['sequence']:08d}.pending"
        )
        pending_path.write_bytes(
            transaction_module._canonical_json(marker).encode("utf-8")
        )
        pending_path.chmod(0o600)
        final_marker = pending_path.with_suffix(".json")
        events_directory = pending_path.parent
        real_fsync_directory = transaction_module._fsync_directory

        def fail_after_event_rename(path: Path) -> None:
            if path == events_directory and final_marker.exists():
                raise OSError("fixture event directory fsync failure")
            real_fsync_directory(path)

        fixture.runner.fail_role = None
        self._clear_runner_observations(fixture)
        with patch.object(
            transaction_module,
            "_fsync_directory",
            side_effect=fail_after_event_rename,
        ):
            with self.assertRaises(TransactionError) as raised:
                fixture.recover(
                    recovery_tool_identity_reader=lambda _repository: continued_identity
                )
        self.assertEqual(
            raised.exception.code,
            "atomic_evidence_durability_unknown",
        )
        self.assertTrue(final_marker.is_file())
        self.assertFalse(pending_path.exists())
        self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
        self._clear_runner_observations(fixture)
        with patch.object(
            transaction_module,
            "_recovery_read_result",
            side_effect=SimulatedCrash("before-apple-read"),
        ):
            with self.assertRaises(SimulatedCrash):
                fixture.recover(
                    recovery_tool_identity_reader=lambda _repository: continued_identity
                )
        self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_continuation_rename_fsync_unknown_retries_from_final(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.create_orphaned_submit_attempt()
        fixture.runner.fail_role = CommandRole.STAPLE
        with self.assertRaises(TransactionError):
            fixture.recover()
        continued_identity = self._continued_identity()
        continuation, marker = self._expected_continuation_from_tip(
            fixture,
            continued_identity,
        )
        marker_path = (
            fixture.context.attempt_root
            / "events"
            / f"{marker['sequence']:08d}.json"
        )
        marker_path.write_bytes(
            transaction_module._canonical_json(marker).encode("utf-8")
        )
        marker_path.chmod(0o600)
        real_fsync_directory = transaction_module._fsync_directory

        def fail_after_continuation_rename(path: Path) -> None:
            if (
                path == fixture.context.attempt_root
                and (
                    fixture.context.attempt_root / "recovery-continuation.json"
                ).exists()
            ):
                raise OSError("fixture continuation directory fsync failure")
            real_fsync_directory(path)

        fixture.runner.fail_role = None
        self._clear_runner_observations(fixture)
        with patch.object(
            transaction_module,
            "_fsync_directory",
            side_effect=fail_after_continuation_rename,
        ):
            with self.assertRaises(TransactionError) as raised:
                fixture.recover(
                    recovery_tool_identity_reader=lambda _repository: continued_identity
                )
        self.assertEqual(
            raised.exception.code,
            "atomic_evidence_durability_unknown",
        )
        final_path = fixture.context.attempt_root / "recovery-continuation.json"
        self.assertEqual(
            final_path.read_bytes(),
            transaction_module._canonical_json(continuation).encode("utf-8"),
        )
        self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
        self._clear_runner_observations(fixture)
        with patch.object(
            transaction_module,
            "_recovery_read_result",
            side_effect=SimulatedCrash("before-apple-read"),
        ):
            with self.assertRaises(SimulatedCrash):
                fixture.recover(
                    recovery_tool_identity_reader=lambda _repository: continued_identity
                )
        self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_foreign_continuation_pending_symlink_or_hardlink_is_rejected(self) -> None:
        for pending_kind in ("symlink", "hardlink", "complete-json"):
            with self.subTest(pending_kind=pending_kind):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                fixture.create_orphaned_submit_attempt()
                fixture.runner.fail_role = CommandRole.STAPLE
                with self.assertRaises(TransactionError):
                    fixture.recover()
                continued_identity = self._continued_identity()
                _continuation, marker = self._expected_continuation_from_tip(
                    fixture,
                    continued_identity,
                )
                marker_path = (
                    fixture.context.attempt_root
                    / "events"
                    / f"{marker['sequence']:08d}.json"
                )
                marker_path.write_bytes(
                    transaction_module._canonical_json(marker).encode("utf-8")
                )
                marker_path.chmod(0o600)
                pending_path = (
                    fixture.context.attempt_root
                    / transaction_module.RECOVERY_CONTINUATION_PENDING_FILENAME
                )
                if pending_kind == "complete-json":
                    pending_path.write_bytes(b"{}\n")
                    pending_path.chmod(0o600)
                else:
                    foreign = fixture.repository / f"foreign-{pending_kind}"
                    foreign.write_bytes(b"foreign")
                    if pending_kind == "symlink":
                        pending_path.symlink_to(foreign)
                    else:
                        os.link(foreign, pending_path)
                fixture.runner.fail_role = None
                self._clear_runner_observations(fixture)

                with self.assertRaises(TransactionError) as raised:
                    fixture.recover(
                        recovery_tool_identity_reader=(
                            lambda _repository: continued_identity
                        )
                    )

                self.assertIn(
                    raised.exception.code,
                    {
                        "pending_evidence_identity_drift",
                        "unsafe_pending_evidence",
                    },
                )
                self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
                self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
                self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_continuation_pending_after_marker_progress_is_rejected(self) -> None:
        self.fixture.runner.fail_role = CommandRole.STAPLE
        with self.assertRaises(TransactionError):
            self.fixture.recover()
        continued_identity = self._continued_identity()
        self._reset_runner_observations()
        with self.assertRaises(TransactionError):
            self.fixture.recover(
                recovery_tool_identity_reader=lambda _repository: continued_identity
            )
        continuation_path = (
            self.fixture.context.attempt_root / "recovery-continuation.json"
        )
        continuation_bytes = continuation_path.read_bytes()
        continuation_path.unlink()
        pending_path = (
            self.fixture.context.attempt_root
            / transaction_module.RECOVERY_CONTINUATION_PENDING_FILENAME
        )
        pending_path.write_bytes(continuation_bytes[: len(continuation_bytes) // 2])
        pending_path.chmod(0o600)
        self.fixture.runner.fail_role = None
        self._reset_runner_observations()

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(
                recovery_tool_identity_reader=lambda _repository: continued_identity
            )

        self.assertEqual(raised.exception.code, "recovery_inventory_mismatch")
        self.assertNotIn(CommandRole.INFO, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, self.fixture.runner.calls)

    def test_continuation_marker_deletion_or_tamper_is_rejected(self) -> None:
        for mutation in ("delete", "tamper"):
            with self.subTest(mutation=mutation):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                fixture.create_orphaned_submit_attempt()
                fixture.runner.fail_role = CommandRole.STAPLE
                self._clear_runner_observations(fixture)
                with self.assertRaises(TransactionError):
                    fixture.recover()
                continued_identity = {
                    "repositoryCommit": "e" * 40,
                    "releaseSourceSha256": "f" * 64,
                }
                self._clear_runner_observations(fixture)
                with self.assertRaises(TransactionError):
                    fixture.recover(
                        recovery_tool_identity_reader=(
                            lambda _repository: continued_identity
                        )
                    )
                marker_path = next(
                    path
                    for path in sorted(
                        (fixture.context.attempt_root / "events").glob("*.json")
                    )
                    if json.loads(path.read_text(encoding="utf-8"))["state"]
                    == "recovery_tool_continued"
                )
                if mutation == "delete":
                    marker_path.unlink()
                else:
                    marker = json.loads(
                        marker_path.read_text(encoding="utf-8")
                    )
                    marker["evidence_sha256"] = "1" * 64
                    marker_path.write_bytes(
                        transaction_module._canonical_json(marker).encode(
                            "utf-8"
                        )
                    )
                fixture.runner.fail_role = None
                self._clear_runner_observations(fixture)

                with self.assertRaises(TransactionError) as raised:
                    fixture.recover(
                        recovery_tool_identity_reader=(
                            lambda _repository: continued_identity
                        )
                    )

                self.assertIn(
                    raised.exception.code,
                    {
                        "event_journal_identity_drift",
                        "recovery_continuation_identity_drift",
                        "recovery_continuation_marker_missing",
                    },
                )
                self.assertNotIn(CommandRole.INFO, fixture.runner.calls)
                self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
                self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_continuation_cannot_predate_its_failed_event(self) -> None:
        continued_identity, marker_path = self._crash_after_continuation_marker()
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        prior_event_path = marker_path.with_name(
            f"{marker['sequence'] - 1:08d}.json"
        )
        prior_event = json.loads(prior_event_path.read_text(encoding="utf-8"))
        recovery_intent_path = (
            self.fixture.context.attempt_root / "recovery-intent.json"
        )
        recovery_intent = json.loads(
            recovery_intent_path.read_text(encoding="utf-8")
        )
        requested_at = "2026-07-28T04:01:59Z"
        continuation = {
            "schema_version": 1,
            "document": transaction_module.RECOVERY_CONTINUATION_DOCUMENT,
            "attempt_id": recovery_intent["attempt_id"],
            "submission_id": SUBMISSION_ID,
            "recovery_intent_sha256": hashlib.sha256(
                recovery_intent_path.read_bytes()
            ).hexdigest(),
            "prior_recovery_tool_repository_commit": "c" * 40,
            "prior_recovery_tool_release_source_sha256": "d" * 64,
            "continuation_tool_repository_commit": continued_identity[
                "repositoryCommit"
            ],
            "continuation_tool_release_source_sha256": continued_identity[
                "releaseSourceSha256"
            ],
            "prior_event_sha256": hashlib.sha256(
                prior_event_path.read_bytes()
            ).hexdigest(),
            "prior_failure_code": prior_event["failure_code"],
            "requested_at": requested_at,
        }
        marker["recorded_at"] = requested_at
        marker["evidence_sha256"] = hashlib.sha256(
            transaction_module._canonical_json(continuation).encode("utf-8")
        ).hexdigest()
        marker_path.write_bytes(
            transaction_module._canonical_json(marker).encode("utf-8")
        )
        self._reset_runner_observations()

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(
                recovery_tool_identity_reader=lambda _repository: continued_identity
            )

        self.assertEqual(
            raised.exception.code,
            "event_journal_identity_drift",
        )
        self.assertFalse(
            (
                self.fixture.context.attempt_root
                / "recovery-continuation.json"
            ).exists()
        )
        self.assertNotIn(CommandRole.INFO, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, self.fixture.runner.calls)

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
            states[5:9],
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

    def test_failed_finalization_can_bind_one_clean_tool_continuation(self) -> None:
        self.fixture.runner.fail_role = CommandRole.STAPLE
        self._reset_runner_observations()
        with self.assertRaises(TransactionError):
            self.fixture.recover()

        self.fixture.runner.fail_role = None
        self._reset_runner_observations()
        continued_identity = {
            "repositoryCommit": "e" * 40,
            "releaseSourceSha256": "f" * 64,
        }
        final_app = self.fixture.recover(
            recovery_tool_identity_reader=lambda _repository: continued_identity
        )

        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        continuation_path = (
            self.fixture.context.attempt_root / "recovery-continuation.json"
        )
        continuation = json.loads(
            continuation_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            continuation["continuation_tool_repository_commit"],
            continued_identity["repositoryCommit"],
        )
        self.assertEqual(
            continuation["prior_failure_code"],
            "staple_failed",
        )
        final_receipts = list(
            (
                self.fixture.context.attempt_root / "finalization-runs"
            ).glob("*/receipt.json")
        )
        self.assertEqual(len(final_receipts), 1)
        final_receipt = json.loads(
            final_receipts[0].read_text(encoding="utf-8")
        )
        self.assertEqual(final_receipt["schema_version"], 5)
        self.assertEqual(
            final_receipt["candidate_freeze_intent_sha256"],
            "f" * 64,
        )
        self.assertEqual(
            final_receipt["recovery_continuation_sha256"],
            hashlib.sha256(continuation_path.read_bytes()).hexdigest(),
        )

    def test_recovery_tool_continuation_cannot_transition_twice(self) -> None:
        self.fixture.runner.fail_role = CommandRole.STAPLE
        self._reset_runner_observations()
        with self.assertRaises(TransactionError):
            self.fixture.recover()

        continued_identity = {
            "repositoryCommit": "e" * 40,
            "releaseSourceSha256": "f" * 64,
        }
        self._reset_runner_observations()
        with self.assertRaises(TransactionError):
            self.fixture.recover(
                recovery_tool_identity_reader=lambda _repository: continued_identity
            )

        self.fixture.runner.fail_role = None
        self._reset_runner_observations()
        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(
                recovery_tool_identity_reader=lambda _repository: {
                    "repositoryCommit": "1" * 40,
                    "releaseSourceSha256": "2" * 64,
                }
            )
        self.assertEqual(
            raised.exception.code,
            "recovery_continuation_identity_drift",
        )
        self.assertNotIn(CommandRole.INFO, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)

    def test_recovery_tool_cannot_change_before_failed_finalization(self) -> None:
        self.fixture.runner.fail_role = CommandRole.INFO
        self._reset_runner_observations()
        with self.assertRaises(TransactionError):
            self.fixture.recover()

        self.fixture.runner.fail_role = None
        self._reset_runner_observations()
        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(
                recovery_tool_identity_reader=lambda _repository: {
                    "repositoryCommit": "e" * 40,
                    "releaseSourceSha256": "f" * 64,
                }
            )
        self.assertEqual(
            raised.exception.code,
            "recovery_tool_transition_unavailable",
        )
        self.assertNotIn(CommandRole.INFO, self.fixture.runner.calls)

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
        event_paths = sorted(
            (self.fixture.context.attempt_root / "events").glob("*.json")
        )
        original_events = [path.read_bytes() for path in event_paths]
        current_events = len(event_paths)
        expected_base_reserve = (
            2
            + 1
            + len(transaction_module.FINALIZATION_EVENT_STATES)
            + 1
        )
        self.assertEqual(
            transaction_module.RECOVERY_SUCCESS_EVENT_RESERVE,
            expected_base_reserve,
        )
        with patch.object(
            transaction_module,
            "MAX_EVENT_DOCUMENTS",
            current_events + expected_base_reserve,
        ):
            with self.assertRaises(TransactionError) as raised:
                self.fixture.recover()

        self.assertEqual(
            raised.exception.code,
            "event_journal_capacity_exceeded",
        )
        self.assertEqual(
            [path.read_bytes() for path in event_paths],
            original_events,
        )
        self.assertTrue(
            (self.fixture.context.attempt_root / "recovery-intent.json").is_file()
        )
        self.assertFalse(
            (
                self.fixture.context.attempt_root
                / "recovery-continuation.json"
            ).exists()
        )
        self.assertNotIn(CommandRole.INFO, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.HISTORY, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.FETCH_LOG, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, self.fixture.runner.calls)

    def test_existing_intent_anchor_is_not_reserved_twice(self) -> None:
        self.fixture.runner.fail_role = CommandRole.INFO
        self._reset_runner_observations()
        with self.assertRaises(TransactionError):
            self.fixture.recover()
        self.fixture.runner.fail_role = None
        self._reset_runner_observations()
        current_events = len(
            list((self.fixture.context.attempt_root / "events").glob("*.json"))
        )

        with patch.object(
            transaction_module,
            "MAX_EVENT_DOCUMENTS",
            current_events + transaction_module.RECOVERY_SUCCESS_EVENT_RESERVE,
        ):
            final_app = self.fixture.recover()

        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, self.fixture.runner.calls)

    def test_existing_continuation_marker_is_not_reserved_twice(self) -> None:
        continued_identity, _marker_path = self._crash_after_continuation_marker()
        self._reset_runner_observations()
        current_events = len(
            list((self.fixture.context.attempt_root / "events").glob("*.json"))
        )
        reconciled_failure_reserve = (
            1 + len(transaction_module.FINALIZATION_EVENT_STATES) + 1
        )

        with patch.object(
            transaction_module,
            "MAX_EVENT_DOCUMENTS",
            current_events + reconciled_failure_reserve,
        ):
            final_app = self.fixture.recover(
                recovery_tool_identity_reader=lambda _repository: continued_identity
            )

        self.assertTrue(final_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, self.fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, self.fixture.runner.calls)

    def test_completed_recovery_is_idempotently_recognized(self) -> None:
        final_app = self.fixture.recover()
        self._reset_runner_observations()
        publisher_called = False

        def forbidden_publisher(_source: Path, _destination: Path) -> None:
            nonlocal publisher_called
            publisher_called = True
            raise AssertionError("published recovery must not invoke publisher")

        recovered_app = self.fixture.recover(publisher=forbidden_publisher)

        self.assertEqual(recovered_app, final_app)
        self.assertFalse(publisher_called)
        self.assertEqual(self.fixture.runner.calls, [])

    def test_post_rename_baseexception_is_idempotently_recovered(self) -> None:
        def publish_then_crash(source: Path, destination: Path) -> None:
            os.rename(source, destination)
            raise SimulatedCrash("after-rename")

        with self.assertRaises(SimulatedCrash):
            self.fixture.recover(publisher=publish_then_crash)
        self.assertTrue(self.fixture.context.final_root.is_dir())
        self._reset_runner_observations()

        recovered_app = self.fixture.recover(
            publisher=lambda _source, _destination: self.fail(
                "published recovery invoked publisher"
            )
        )

        self.assertEqual(
            recovered_app,
            self.fixture.context.final_root / "Clash for Mac.app",
        )
        self.assertEqual(self.fixture.runner.calls, [])

    def test_publish_durability_unknown_is_idempotently_recovered(self) -> None:
        def publish_then_unknown(source: Path, destination: Path) -> None:
            os.rename(source, destination)
            raise TransactionError(
                "publish_durability_unknown",
                "fixture durability is unknown",
                terminal_state="outcome_unknown",
            )

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(publisher=publish_then_unknown)
        self.assertEqual(raised.exception.code, "publish_durability_unknown")
        terminal = json.loads(
            sorted(
                (self.fixture.context.attempt_root / "events").glob("*.json")
            )[-1].read_text(encoding="utf-8")
        )
        self.assertEqual(terminal["state"], "outcome_unknown")
        self._reset_runner_observations()

        recovered_app = self.fixture.recover(
            publisher=lambda _source, _destination: self.fail(
                "published recovery invoked publisher"
            )
        )

        self.assertTrue(recovered_app.is_dir())
        self.assertEqual(self.fixture.runner.calls, [])

    def test_foreign_published_destination_is_rejected_without_mutation(self) -> None:
        final_root = self.fixture.context.final_root
        final_root.mkdir(mode=0o700)
        (final_root / "foreign").write_bytes(b"foreign")
        self._reset_runner_observations()

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(
                publisher=lambda _source, _destination: self.fail(
                    "foreign destination invoked publisher"
                )
            )

        self.assertEqual(raised.exception.code, "recovery_intent_missing")
        self.assertEqual(self.fixture.runner.calls, [])
        self.assertEqual({path.name for path in final_root.iterdir()}, {"foreign"})
        self.assertFalse(
            (self.fixture.context.attempt_root / "recovery-intent.json").exists()
        )

    def test_tampered_published_candidate_is_rejected_without_remote_reads(self) -> None:
        final_app = self.fixture.recover()
        executable = final_app / "Contents/MacOS/clash-for-mac"
        executable.write_bytes(b"tampered-published-app")
        self._reset_runner_observations()

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(
                publisher=lambda _source, _destination: self.fail(
                    "tampered destination invoked publisher"
                )
            )

        self.assertEqual(raised.exception.code, "published_candidate_unrecognized")
        self.assertEqual(self.fixture.runner.calls, [])

    def test_tampered_published_receipt_is_rejected_without_remote_reads(self) -> None:
        self.fixture.recover()
        receipt_path = next(
            (
                self.fixture.context.attempt_root / "finalization-runs"
            ).glob("*/receipt.json")
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["state"] = "tampered"
        receipt_path.write_bytes(
            transaction_module._canonical_json(receipt).encode("utf-8")
        )
        self._reset_runner_observations()

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover()

        self.assertEqual(raised.exception.code, "published_candidate_unrecognized")
        self.assertEqual(self.fixture.runner.calls, [])

    def test_tampered_published_freeze_binding_is_rejected_without_remote_reads(
        self,
    ) -> None:
        self.fixture.recover()
        receipt_path = sole_finalization_receipt(self.fixture)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["candidate_freeze_intent_sha256"] = "e" * 64
        receipt_path.write_bytes(
            transaction_module._canonical_json(receipt).encode("utf-8")
        )
        self._reset_runner_observations()

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover()

        self.assertEqual(raised.exception.code, "published_candidate_unrecognized")
        self.assertEqual(self.fixture.runner.calls, [])

    def test_multiple_matching_published_receipts_are_rejected(self) -> None:
        self.fixture.recover()
        finalization_runs = (
            self.fixture.context.attempt_root / "finalization-runs"
        )
        receipt_path = next(finalization_runs.glob("*/receipt.json"))
        duplicate_run = (
            finalization_runs / "11111111-2222-4333-8444-555555555555"
        )
        duplicate_run.mkdir(mode=0o700)
        duplicate_receipt = duplicate_run / "receipt.json"
        duplicate_receipt.write_bytes(receipt_path.read_bytes())
        duplicate_receipt.chmod(0o600)
        self._reset_runner_observations()

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover()

        self.assertEqual(raised.exception.code, "published_candidate_ambiguous")
        self.assertEqual(self.fixture.runner.calls, [])

    def test_published_candidate_toctou_is_rejected(self) -> None:
        final_app = self.fixture.recover()
        executable = final_app / "Contents/MacOS/clash-for-mac"
        real_fsync_tree = transaction_module._fsync_tree
        mutated = False

        def mutate_after_fsync(root: Path) -> None:
            nonlocal mutated
            real_fsync_tree(root)
            if root == self.fixture.context.final_root and not mutated:
                executable.write_bytes(b"changed-after-first-validation")
                mutated = True

        self._reset_runner_observations()
        with patch.object(
            transaction_module,
            "_fsync_tree",
            side_effect=mutate_after_fsync,
        ):
            with self.assertRaises(TransactionError) as raised:
                self.fixture.recover()

        self.assertTrue(mutated)
        self.assertEqual(raised.exception.code, "published_candidate_unrecognized")
        self.assertEqual(self.fixture.runner.calls, [])

    def test_direct_post_rename_baseexception_is_recovered_locally(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def publish_then_crash(source: Path, destination: Path) -> None:
            os.rename(source, destination)
            raise SimulatedCrash("direct-after-rename")

        with self.assertRaises(SimulatedCrash):
            fixture.execute(publisher=publish_then_crash)
        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()

        recovered_app = fixture.recover(
            publisher=lambda _source, _destination: self.fail(
                "direct post-rename recovery invoked publisher"
            )
        )

        self.assertEqual(
            recovered_app,
            fixture.context.final_root / "Clash for Mac.app",
        )
        self.assertEqual(fixture.runner.calls, [])
        self.assertFalse(
            (fixture.context.attempt_root / "recovery-intent.json").exists()
        )

    def test_direct_publish_durability_unknown_is_recovered_locally(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def publish_then_unknown(source: Path, destination: Path) -> None:
            os.rename(source, destination)
            raise TransactionError(
                "publish_durability_unknown",
                "direct durability unknown fixture",
                terminal_state="outcome_unknown",
            )

        with self.assertRaises(TransactionError):
            fixture.execute(publisher=publish_then_unknown)
        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()

        recovered_app = fixture.recover()

        self.assertTrue(recovered_app.is_dir())
        self.assertEqual(fixture.runner.calls, [])
        self.assertFalse(
            (fixture.context.attempt_root / "recovery-intent.json").exists()
        )

    def test_direct_publish_ready_is_validated_then_published_locally(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def fail_before_rename(_source: Path, _destination: Path) -> None:
            raise TransactionError(
                "atomic_publish_failed",
                "direct pre-rename fixture",
            )

        with self.assertRaises(TransactionError):
            fixture.execute(publisher=fail_before_rename)
        original_run = sole_finalization_run(fixture)
        original_publish_ready = original_run / "publish-ready"
        self.assertTrue(original_publish_ready.is_dir())
        original_receipt = json.loads(
            (original_run / "receipt.json").read_text(encoding="utf-8")
        )
        self.assertIsNone(original_receipt["recovery_intent_sha256"])
        self.assertIsNone(original_receipt["recovery_continuation_sha256"])
        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        publisher_calls = 0

        def local_publisher(source: Path, destination: Path) -> None:
            nonlocal publisher_calls
            publisher_calls += 1
            os.rename(source, destination)

        recovered_app = fixture.recover(publisher=local_publisher)

        self.assertTrue(recovered_app.is_dir())
        self.assertEqual(publisher_calls, 1)
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
        self.assertTrue(original_publish_ready.is_dir())
        runs = list(
            (fixture.context.attempt_root / "finalization-runs").glob("*")
        )
        self.assertEqual(len(runs), 2)
        for run in runs:
            with self.subTest(run=run.name):
                self.assertEqual(str(uuid.UUID(run.name)), run.name)
        self.assertTrue(
            (fixture.context.attempt_root / "recovery-intent.json").is_file()
        )
        recovery_receipts = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in (
                fixture.context.attempt_root / "finalization-runs"
            ).glob("*/receipt.json")
        ]
        self.assertEqual(len(recovery_receipts), 2)
        self.assertEqual(
            sum(
                receipt["recovery_intent_sha256"] is not None
                for receipt in recovery_receipts
            ),
            1,
        )

    def test_direct_foreign_destination_is_rejected_without_local_publish(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def fail_before_rename(_source: Path, _destination: Path) -> None:
            raise TransactionError("atomic_publish_failed", "fixture pre-rename")

        with self.assertRaises(TransactionError):
            fixture.execute(publisher=fail_before_rename)
        fixture.context.final_root.mkdir(mode=0o700)
        (fixture.context.final_root / "foreign").write_bytes(b"foreign")
        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        publisher_called = False

        def forbidden_publisher(_source: Path, _destination: Path) -> None:
            nonlocal publisher_called
            publisher_called = True

        with self.assertRaises(TransactionError) as raised:
            fixture.recover(publisher=forbidden_publisher)

        self.assertEqual(raised.exception.code, "published_candidate_unrecognized")
        self.assertFalse(publisher_called)
        self.assertEqual(fixture.runner.calls, [])
        self.assertFalse(
            (fixture.context.attempt_root / "recovery-intent.json").exists()
        )

    def test_direct_coordinated_invalid_observation_is_rejected(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def fail_before_rename(_source: Path, _destination: Path) -> None:
            raise TransactionError("atomic_publish_failed", "fixture pre-rename")

        with self.assertRaises(TransactionError):
            fixture.execute(publisher=fail_before_rename)
        observation_path = (
            fixture.context.attempt_root / "submission-observation.json"
        )
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
        observation["path_binding"] = "tampered"
        observation_path.write_bytes(
            transaction_module._canonical_json(observation).encode("utf-8")
        )
        submission_receipt_path = (
            fixture.context.attempt_root / "submission-receipt.json"
        )
        submission_receipt = json.loads(
            submission_receipt_path.read_text(encoding="utf-8")
        )
        submission_receipt["submission_observation_sha256"] = hashlib.sha256(
            observation_path.read_bytes()
        ).hexdigest()
        submission_receipt_path.write_bytes(
            transaction_module._canonical_json(submission_receipt).encode("utf-8")
        )
        receipt_path = sole_finalization_receipt(fixture)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["submission_receipt_sha256"] = hashlib.sha256(
            submission_receipt_path.read_bytes()
        ).hexdigest()
        receipt_path.write_bytes(
            transaction_module._canonical_json(receipt).encode("utf-8")
        )
        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()

        with self.assertRaises(TransactionError) as raised:
            fixture.recover()

        self.assertEqual(
            raised.exception.code,
            "submission_observation_identity_drift",
        )
        self.assertEqual(fixture.runner.calls, [])

    def test_direct_publisher_returning_two_locations_is_rejected(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def fail_before_rename(_source: Path, _destination: Path) -> None:
            raise TransactionError("atomic_publish_failed", "fixture pre-rename")

        with self.assertRaises(TransactionError):
            fixture.execute(publisher=fail_before_rename)

        def ambiguous_publisher(source: Path, destination: Path) -> None:
            os.rename(source, destination)
            source.mkdir(mode=0o700)

        fixture.runner.calls.clear()
        fixture.runner.command_calls.clear()
        fixture.runner.role_counts.clear()
        with self.assertRaises(TransactionError) as raised:
            fixture.recover(publisher=ambiguous_publisher)

        self.assertEqual(raised.exception.code, "publish_result_ambiguous")
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)

    def test_direct_crash_before_receipt_or_sealed_is_recovered_locally(self) -> None:
        for before_receipt in (True, False):
            with self.subTest(before_receipt=before_receipt):
                fixture = self._direct_preseal_fixture(
                    before_receipt=before_receipt
                )
                recovered_app = fixture.recover(
                    publisher=lambda source, destination: os.rename(
                        source,
                        destination,
                    )
                )

                self.assertTrue(recovered_app.is_dir())
                self.assertEqual(fixture.runner.calls, [])
                states = [
                    json.loads(path.read_text(encoding="utf-8"))["state"]
                    for path in sorted(
                        (fixture.context.attempt_root / "events").glob("*.json")
                    )
                ]
                self.assertEqual(states.count("sealed"), 1)
                self.assertFalse(
                    (fixture.context.attempt_root / "recovery-intent.json").exists()
                )

    def test_direct_receipt_pending_zero_partial_or_complete_is_recovered(self) -> None:
        for pending_kind in ("zero", "partial", "complete"):
            with self.subTest(pending_kind=pending_kind):
                fixture = self._direct_preseal_fixture(before_receipt=False)
                receipt_path = fixture.context.attempt_root / "receipt.json"
                expected = receipt_path.read_bytes()
                receipt_path.unlink()
                pending_path = (
                    fixture.context.attempt_root
                    / transaction_module.PUBLISH_READY_RECEIPT_PENDING_FILENAME
                )
                pending_path.write_bytes(
                    {
                        "zero": b"",
                        "partial": expected[: len(expected) // 2],
                        "complete": expected,
                    }[pending_kind]
                )
                pending_path.chmod(0o600)

                recovered_app = fixture.recover(
                    publisher=lambda source, destination: os.rename(
                        source,
                        destination,
                    )
                )

                self.assertTrue(recovered_app.is_dir())
                self.assertTrue(receipt_path.is_file())
                self.assertFalse(pending_path.exists())
                self.assertEqual(fixture.runner.calls, [])

    def test_direct_sealed_event_pending_zero_partial_or_complete_is_recovered(
        self,
    ) -> None:
        for pending_kind in ("zero", "partial", "complete"):
            with self.subTest(pending_kind=pending_kind):
                fixture = self._direct_preseal_fixture(before_receipt=False)
                receipt = json.loads(
                    (
                        fixture.context.attempt_root / "receipt.json"
                    ).read_text(encoding="utf-8")
                )
                event_paths = sorted(
                    (fixture.context.attempt_root / "events").glob("*.json")
                )
                prior_event = json.loads(
                    event_paths[-1].read_text(encoding="utf-8")
                )
                sealed_event = {
                    "schema_version": 1,
                    "document": transaction_module.EVENT_DOCUMENT,
                    "sequence": prior_event["sequence"] + 1,
                    "previous_event_sha256": hashlib.sha256(
                        event_paths[-1].read_bytes()
                    ).hexdigest(),
                    "intent_sha256": prior_event["intent_sha256"],
                    "state": "sealed",
                    "recorded_at": receipt["sealed_at"],
                    "submission_id": SUBMISSION_ID,
                    "failure_code": None,
                    "exit_code": None,
                }
                expected = transaction_module._canonical_json(sealed_event).encode(
                    "utf-8"
                )
                pending_path = (
                    fixture.context.attempt_root
                    / "events"
                    / f"{sealed_event['sequence']:08d}.pending"
                )
                pending_path.write_bytes(
                    {
                        "zero": b"",
                        "partial": expected[: len(expected) // 2],
                        "complete": expected,
                    }[pending_kind]
                )
                pending_path.chmod(0o600)

                recovered_app = fixture.recover(
                    publisher=lambda source, destination: os.rename(
                        source,
                        destination,
                    )
                )

                self.assertTrue(recovered_app.is_dir())
                self.assertFalse(pending_path.exists())
                self.assertEqual(fixture.runner.calls, [])

    def test_direct_foreign_or_partial_final_receipt_is_rejected(self) -> None:
        for receipt_kind in ("foreign-pending", "partial-final"):
            with self.subTest(receipt_kind=receipt_kind):
                fixture = self._direct_preseal_fixture(before_receipt=False)
                receipt_path = fixture.context.attempt_root / "receipt.json"
                if receipt_kind == "foreign-pending":
                    receipt_path.unlink()
                    pending_path = (
                        fixture.context.attempt_root
                        / transaction_module.PUBLISH_READY_RECEIPT_PENDING_FILENAME
                    )
                    pending_path.write_bytes(b"{}\n")
                    pending_path.chmod(0o600)
                else:
                    receipt_path.write_bytes(b"{\n")

                with self.assertRaises(TransactionError):
                    fixture.recover()

                states = [
                    json.loads(path.read_text(encoding="utf-8"))["state"]
                    for path in sorted(
                        (fixture.context.attempt_root / "events").glob("*.json")
                    )
                ]
                self.assertNotIn("sealed", states)
                self.assertEqual(fixture.runner.calls, [])

    def test_direct_receipt_rename_fsync_unknown_retries_from_final(self) -> None:
        fixture = self._direct_preseal_fixture(before_receipt=True)
        receipt_path = fixture.context.attempt_root / "receipt.json"
        real_fsync_directory = transaction_module._fsync_directory

        def fail_after_receipt_rename(path: Path) -> None:
            if path == fixture.context.attempt_root and receipt_path.exists():
                raise OSError("fixture receipt directory fsync failure")
            real_fsync_directory(path)

        with patch.object(
            transaction_module,
            "_fsync_directory",
            side_effect=fail_after_receipt_rename,
        ):
            with self.assertRaises(TransactionError) as raised:
                fixture.recover()
        self.assertEqual(
            raised.exception.code,
            "atomic_evidence_durability_unknown",
        )
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(fixture.runner.calls, [])
        recovered_app = fixture.recover(
            publisher=lambda source, destination: os.rename(source, destination)
        )
        self.assertTrue(recovered_app.is_dir())
        self.assertEqual(fixture.runner.calls, [])

    def test_execute_receipt_durability_unknown_recovers_locally(self) -> None:
        fixture, monotonic_clock, original_receipt_path = (
            self._receipt_durability_unknown_fixture()
        )

        event_paths = sorted(
            (fixture.context.attempt_root / "events").glob("*.json")
        )
        events = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in event_paths
        ]
        self.assertEqual(
            [event["state"] for event in events[-2:]],
            ["distribution_verified", "outcome_unknown"],
        )
        self.assertEqual(
            events[-1]["failure_code"],
            "atomic_evidence_durability_unknown",
        )
        self.assertIsNone(events[-1]["exit_code"])
        original_distribution_path = event_paths[-2]
        original_distribution = events[-2]
        original_distribution_sha256 = hashlib.sha256(
            original_distribution_path.read_bytes()
        ).hexdigest()
        original_receipt = json.loads(
            original_receipt_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            original_receipt["preseal_event_sha256"],
            original_distribution_sha256,
        )
        original_run = original_receipt_path.parent

        recovered_app = fixture.recover(
            publisher=lambda source, destination: os.rename(
                source,
                destination,
            ),
            clock=monotonic_clock,
        )

        self.assertTrue(recovered_app.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)
        self.assertNotIn(CommandRole.WAIT, fixture.runner.calls)
        recovery_intent_path = (
            fixture.context.attempt_root / "recovery-intent.json"
        )
        self.assertTrue(recovery_intent_path.is_file())
        self.assertTrue((original_run / "publish-ready").is_dir())
        self.assertTrue(fixture.context.final_root.is_dir())

        event_paths = sorted(
            (fixture.context.attempt_root / "events").glob("*.json")
        )
        events = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in event_paths
        ]
        self.assertEqual(events[-2]["state"], "distribution_verified")
        self.assertEqual(events[-1]["state"], "sealed")
        self.assertEqual(
            sum(event["state"] == "sealed" for event in events),
            1,
        )
        self.assertEqual(
            sum(event["state"] == "distribution_verified" for event in events),
            2,
        )
        recovery_distribution_path, _sealed_path = event_paths[-2:]
        recovery_distribution, sealed = events[-2:]
        recovery_distribution_sha256 = hashlib.sha256(
            recovery_distribution_path.read_bytes()
        ).hexdigest()
        self.assertEqual(
            sealed["previous_event_sha256"],
            recovery_distribution_sha256,
        )
        receipt_paths = list(
            (fixture.context.attempt_root / "finalization-runs").glob(
                "*/receipt.json"
            )
        )
        self.assertEqual(len(receipt_paths), 2)
        recovery_receipt_path = next(
            path for path in receipt_paths if path != original_receipt_path
        )
        recovery_receipt = json.loads(
            recovery_receipt_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            recovery_receipt["preseal_event_sha256"],
            recovery_distribution_sha256,
        )
        self.assertEqual(
            recovery_receipt["recovery_intent_sha256"],
            hashlib.sha256(recovery_intent_path.read_bytes()).hexdigest(),
        )
        self.assertIsNone(recovery_receipt["recovery_continuation_sha256"])
        original_distribution_at = transaction_module._parse_utc_timestamp(
            original_distribution["recorded_at"],
            "fixture distribution recorded_at",
        )[1]
        original_receipt_at = transaction_module._parse_utc_timestamp(
            original_receipt["sealed_at"],
            "fixture receipt sealed_at",
        )[1]
        unknown_event = next(
            event
            for event in events
            if event["failure_code"]
            == "atomic_evidence_durability_unknown"
        )
        unknown_at = transaction_module._parse_utc_timestamp(
            unknown_event["recorded_at"],
            "fixture receipt durability outcome recorded_at",
        )[1]
        recovery_distribution_at = transaction_module._parse_utc_timestamp(
            recovery_distribution["recorded_at"],
            "fixture recovery distribution recorded_at",
        )[1]
        recovery_receipt_at = transaction_module._parse_utc_timestamp(
            recovery_receipt["sealed_at"],
            "fixture recovery receipt sealed_at",
        )[1]
        sealed_at = transaction_module._parse_utc_timestamp(
            sealed["recorded_at"],
            "fixture recovery sealed recorded_at",
        )[1]
        self.assertLessEqual(original_distribution_at, original_receipt_at)
        self.assertLessEqual(original_receipt_at, unknown_at)
        self.assertLessEqual(unknown_at, recovery_distribution_at)
        self.assertLessEqual(recovery_distribution_at, recovery_receipt_at)
        self.assertEqual(recovery_receipt_at, sealed_at)

    def test_receipt_durability_unknown_invalid_variants_fail_closed(
        self,
    ) -> None:
        cases = (
            ("boundary-evidence", "event_journal_identity_drift"),
            ("previous-hash", "event_journal_identity_drift"),
            ("chronology", "event_journal_identity_drift"),
            ("submission-receipt", "submission_receipt_identity_drift"),
            ("source", "app_identity_drift"),
        )
        for mutation, expected_code in cases:
            with self.subTest(mutation=mutation):
                fixture, monotonic_clock, _receipt_path = (
                    self._receipt_durability_unknown_fixture()
                )
                event_paths = sorted(
                    (fixture.context.attempt_root / "events").glob("*.json")
                )
                outcome_path = event_paths[-1]
                outcome = json.loads(
                    outcome_path.read_text(encoding="utf-8")
                )
                if mutation == "boundary-evidence":
                    boundary_path = next(
                        path
                        for path in event_paths
                        if json.loads(path.read_text(encoding="utf-8"))[
                            "state"
                        ]
                        == "direct_finalization_ready"
                    )
                    boundary = json.loads(
                        boundary_path.read_text(encoding="utf-8")
                    )
                    boundary["evidence_sha256"] = "0" * 64
                    boundary_path.write_bytes(
                        transaction_module._canonical_json(boundary).encode(
                            "utf-8"
                        )
                    )
                elif mutation == "previous-hash":
                    outcome["previous_event_sha256"] = "0" * 64
                    outcome_path.write_bytes(
                        transaction_module._canonical_json(outcome).encode(
                            "utf-8"
                        )
                    )
                elif mutation == "chronology":
                    outcome["recorded_at"] = "2026-07-28T04:01:59Z"
                    outcome_path.write_bytes(
                        transaction_module._canonical_json(outcome).encode(
                            "utf-8"
                        )
                    )
                elif mutation == "submission-receipt":
                    submission_receipt_path = (
                        fixture.context.attempt_root
                        / "submission-receipt.json"
                    )
                    submission_receipt = json.loads(
                        submission_receipt_path.read_text(encoding="utf-8")
                    )
                    submission_receipt["causal_binding"] = "tampered"
                    submission_receipt_path.write_bytes(
                        transaction_module._canonical_json(
                            submission_receipt
                        ).encode("utf-8")
                    )
                else:
                    (
                        fixture.context.attempt_root
                        / "recovery-source/Clash for Mac.app/Contents/MacOS/clash-for-mac"
                    ).write_bytes(
                        b"tampered-immutable-source"
                    )

                publisher_called = False

                def forbidden_publisher(
                    _source: Path,
                    _destination: Path,
                ) -> None:
                    nonlocal publisher_called
                    publisher_called = True

                with self.assertRaises(TransactionError) as raised:
                    fixture.recover(
                        publisher=forbidden_publisher,
                        clock=monotonic_clock,
                    )

                self.assertEqual(raised.exception.code, expected_code)
                states = [
                    json.loads(path.read_text(encoding="utf-8"))["state"]
                    for path in sorted(
                        (fixture.context.attempt_root / "events").glob(
                            "*.json"
                        )
                    )
                ]
                self.assertNotIn("sealed", states)
                self.assertFalse(publisher_called)
                self.assertEqual(fixture.runner.calls, [])
                self.assertFalse(os.path.lexists(fixture.context.final_root))
                self.assertTrue(
                    (_receipt_path.parent / "publish-ready").is_dir()
                )

    def test_direct_receipt_cannot_predate_distribution_verification(self) -> None:
        fixture = self._direct_preseal_fixture(before_receipt=False)
        receipt_path = fixture.context.attempt_root / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["sealed_at"] = "2026-07-28T04:01:59Z"
        receipt_path.write_bytes(
            transaction_module._canonical_json(receipt).encode("utf-8")
        )

        with self.assertRaises(TransactionError) as raised:
            fixture.recover()

        self.assertEqual(
            raised.exception.code,
            "receipt_preseal_lineage_mismatch",
        )
        states = [
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in sorted(
                (fixture.context.attempt_root / "events").glob("*.json")
            )
        ]
        self.assertNotIn("sealed", states)
        self.assertEqual(fixture.runner.calls, [])

    def test_direct_preseal_wrong_head_or_artifact_tamper_does_not_seal(self) -> None:
        for mutation in ("wrong-head", "manifest", "extra-entry"):
            with self.subTest(mutation=mutation):
                fixture = self._direct_preseal_fixture(before_receipt=True)
                if mutation == "wrong-head":
                    intent_sha256 = hashlib.sha256(
                        (fixture.context.attempt_root / "intent.json").read_bytes()
                    ).hexdigest()
                    journal = transaction_module.EventJournal.load_existing(
                        fixture.context.attempt_root / "events",
                        intent_sha256,
                        lambda: "2026-07-28T04:03:00Z",
                    )
                    journal.append(
                        "failed",
                        submission_id=SUBMISSION_ID,
                        failure_code="internal_error",
                    )
                elif mutation == "manifest":
                    (
                        fixture.context.attempt_root
                        / "publish-ready/Clash for Mac.app.manifest.json"
                    ).write_bytes(b"{}\n")
                else:
                    (
                        fixture.context.attempt_root / "publish-ready/extra"
                    ).write_bytes(b"extra")
                publisher_called = False

                def forbidden_publisher(_source: Path, _destination: Path) -> None:
                    nonlocal publisher_called
                    publisher_called = True

                with self.assertRaises(TransactionError):
                    fixture.recover(publisher=forbidden_publisher)

                states = [
                    json.loads(path.read_text(encoding="utf-8"))["state"]
                    for path in sorted(
                        (fixture.context.attempt_root / "events").glob("*.json")
                    )
                ]
                self.assertNotIn("sealed", states)
                self.assertFalse(
                    (fixture.context.attempt_root / "receipt.json").exists()
                )
                self.assertFalse(publisher_called)
                self.assertEqual(fixture.runner.calls, [])

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
    def test_macos_27_absent_origin_evidence_can_finalize(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def current_gatekeeper(_app: Path, digest: str) -> dict:
            return macos_27_fixture(
                digest,
                "2026-07-28T04:01:00Z",
                _app,
            )

        final_app = fixture.execute(gatekeeper_capture=current_gatekeeper)

        self.assertTrue(final_app.is_dir())
        persisted = json.loads(
            (fixture.context.final_root / "gatekeeper.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIsNone(persisted["origin"])
        self.assertEqual(
            persisted["identity_source"],
            "codesign-leaf-authority",
        )

    def test_gatekeeper_capture_rejects_target_tree_change_between_commands(self) -> None:
        expected_tree = "a" * 64
        evidence = gatekeeper_fixture(
            expected_tree,
            "2026-07-28T04:02:00Z",
            Path("/tmp/Clash for Mac.app"),
        )
        core = {
            key: value
            for key, value in evidence.items()
            if key != "captured_at"
        }
        with (
            patch.object(
                transaction_module,
                "_app_tree_sha256",
                side_effect=[expected_tree, "b" * 64],
            ),
            patch.object(
                transaction_module,
                "capture_gatekeeper",
                return_value=core,
            ),
        ):
            with self.assertRaises(TransactionError) as raised:
                transaction_module.production_gatekeeper_capture(
                    Path("/tmp/Clash for Mac.app"),
                    expected_tree,
                )

        self.assertEqual(raised.exception.code, "gatekeeper_target_mismatch")

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
        finalization_roles = {
            CommandRole.FETCH_LOG,
            CommandRole.STAPLE,
            CommandRole.STAPLE_VALIDATE,
            CommandRole.FINAL_VERIFY,
            CommandRole.DISTRIBUTION_CHECK,
        }
        if role in finalization_roles:
            self.assertEqual(len(retained), 2)
            self.assertTrue(
                (
                    fixture.context.attempt_root
                    / f"recovery-source/{fixture.context.archive_name}"
                ).is_file()
            )
            run = sole_finalization_run(fixture)
            self.assertTrue(
                any(
                    path.is_file()
                    for path in (
                        run / f"work/{fixture.context.archive_name}",
                        run / f"publish-ready/{fixture.context.archive_name}",
                    )
                )
            )
        else:
            self.assertEqual(len(retained), 1)
            self.assertTrue(
                (
                    fixture.context.attempt_root
                    / f"work/{fixture.context.archive_name}"
                ).is_file()
            )
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
        mutated_publish_ready: Path | None = None

        def tampering(_repository: Path) -> dict[str, str]:
            nonlocal calls, mutated_publish_ready
            calls += 1
            publish_ready = current_publish_ready(fixture)
            if publish_ready is not None and mutated_publish_ready is None:
                event_paths = sorted(
                    (fixture.context.attempt_root / "events").glob("*.json")
                )
                latest = json.loads(
                    event_paths[-1].read_text(encoding="utf-8")
                )
                if latest["state"] == "distribution_verified":
                    self.assertFalse(
                        (publish_ready.parent / "receipt.json").exists()
                    )
                    mutated_publish_ready = publish_ready
                    mutator(fixture, publish_ready)
            return fixture.context.source_identity

        def publisher(_source: Path, _destination: Path) -> None:
            nonlocal publisher_called
            publisher_called = True

        with self.assertRaises(TransactionError) as raised:
            fixture.execute(source_identity_reader=tampering, publisher=publisher)
        self.assertEqual(raised.exception.code, expected_code)
        self.assertEqual(raised.exception.terminal_state, "failed")
        self.assertGreaterEqual(calls, 1)
        self.assertIsNotNone(mutated_publish_ready)
        self.assertFalse(publisher_called)
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        if mutated_publish_ready is None:
            self.fail("test fault was not injected at publish-ready")
        self.assertTrue(mutated_publish_ready.is_dir())
        self.assertFalse((mutated_publish_ready.parent / "receipt.json").exists())
        events = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted((fixture.context.attempt_root / "events").iterdir())
        ]
        states = [event["state"] for event in events]
        self.assertNotIn("sealed", states)
        self.assertEqual(states[-2:], ["distribution_verified", "failed"])
        self.assertEqual(events[-1]["failure_code"], expected_code)

    def test_local_readiness_failure_preserves_input_without_claiming_attempt(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.runner.fail_role = CommandRole.NOTARY_READINESS
        with self.assertRaises(TransactionError) as raised:
            fixture.execute()
        self.assertEqual(raised.exception.code, "notary-readiness_failed")
        self.assertEqual(raised.exception.exit_code, 9)
        self.assertFalse(fixture.context.attempt_root.exists())
        self.assertFalse(fixture.context.final_root.exists())
        self.assertTrue(fixture.app.is_dir())
        self.assertEqual(
            build_manifest(fixture.app, algorithm="sha256-tree-v2")["sha256"],
            fixture.signed_app_tree_sha256,
        )
        self.assertEqual(fixture.runner.calls, [CommandRole.NOTARY_READINESS])

    def test_each_post_claim_external_failure_retains_the_attempt(self) -> None:
        for role in (
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
            return gatekeeper_fixture(
                "f" * 64,
                "2026-07-28T04:01:00Z",
                _app,
            )

        with self.assertRaisesRegex(TransactionError, "exact stapled app tree"):
            fixture.execute(gatekeeper_capture=mismatched_gatekeeper)
        self.assertFalse(os.path.lexists(fixture.context.final_root))

    def test_gatekeeper_open_policy_cannot_substitute_for_app_execution(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def open_policy_gatekeeper(_app: Path, digest: str) -> dict:
            evidence = gatekeeper_fixture(
                digest,
                "2026-07-28T04:01:00Z",
                _app,
            )
            evidence["assessment_type"] = "open"
            evidence["primary_signature_context"] = True
            return evidence

        with self.assertRaises(TransactionError) as raised:
            fixture.execute(gatekeeper_capture=open_policy_gatekeeper)
        self.assertEqual(raised.exception.code, "gatekeeper_verification_failed")
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
        publish_ready = current_publish_ready(fixture)
        self.assertIsNotNone(publish_ready)
        if publish_ready is None:
            self.fail("manifest failure lost its UUID publish-ready workspace")
        self.assertTrue(publish_ready.is_dir())

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
                mutated = False

                def tampering(_repository: Path) -> dict[str, str]:
                    nonlocal calls, mutated
                    calls += 1
                    publish_ready = current_publish_ready(fixture)
                    if publish_ready is not None and not mutated:
                        event_paths = sorted(
                            (fixture.context.attempt_root / "events").glob(
                                "*.json"
                            )
                        )
                        latest = json.loads(
                            event_paths[-1].read_text(encoding="utf-8")
                        )
                        if latest["state"] != "distribution_verified":
                            return fixture.context.toolchain_metadata
                        mutated = True
                        target = publish_ready / relative
                        target.write_text('{"tampered":true}\n', encoding="utf-8")
                    return fixture.context.toolchain_metadata

                with self.assertRaises(TransactionError) as raised:
                    fixture.execute(toolchain_metadata_reader=tampering)
                self.assertEqual(raised.exception.code, expected_code)
                self.assertTrue(mutated)
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
            original_target = evidence["assessed_target"]
            replacement_target = "/Applications/Other/Clash for Mac.app"
            output = evidence["assessment_output"].replace(
                original_target,
                replacement_target,
            )
            evidence["assessment_output"] = output
            evidence["assessment_output_sha256"] = hashlib.sha256(
                output.encode("utf-8")
            ).hexdigest()
            evidence["assessed_target"] = replacement_target
            evidence["assessment_command"][-1] = replacement_target
            evidence["codesign_command"][-1] = replacement_target
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
            ("app", "manifest_verification_failed"),
            ("archive", "manifest_verification_failed"),
            ("app-manifest", "manifest_verification_failed"),
            ("archive-manifest", "manifest_verification_failed"),
            ("submission-receipt", "submission_receipt_identity_drift"),
            ("freeze-submission-binding", "submission_receipt_identity_drift"),
            ("intent", "notarization_intent_identity_drift"),
            ("prior-event", "event_journal_identity_drift"),
        )
        for kind, expected_code in cases:
            with self.subTest(kind=kind):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                calls = 0
                publisher_called = False
                mutated = False

                def rewrite(path: Path, field: str, value: object) -> None:
                    document = json.loads(path.read_text(encoding="utf-8"))
                    document[field] = value
                    path.write_text(
                        json.dumps(document, sort_keys=True, separators=(",", ":"))
                        + "\n",
                        encoding="utf-8",
                    )

                def mutate() -> None:
                    publish_ready = current_publish_ready(fixture)
                    if publish_ready is None:
                        self.fail("preseal mutation lacks publish-ready workspace")
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
                    elif kind == "freeze-submission-binding":
                        rewrite(
                            fixture.context.attempt_root / "submission-receipt.json",
                            "candidate_freeze_intent_sha256",
                            "e" * 64,
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
                    nonlocal calls, mutated
                    calls += 1
                    publish_ready = current_publish_ready(fixture)
                    if publish_ready is not None and not mutated:
                        event_paths = sorted(
                            (fixture.context.attempt_root / "events").glob(
                                "*.json"
                            )
                        )
                        latest = json.loads(
                            event_paths[-1].read_text(encoding="utf-8")
                        )
                        if (
                            latest["state"] == "distribution_verified"
                            and not (publish_ready.parent / "receipt.json").exists()
                        ):
                            mutated = True
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
                self.assertGreaterEqual(calls, 1)
                self.assertTrue(mutated)
                self.assertFalse(publisher_called)
                self.assertFalse(os.path.lexists(fixture.context.final_root))
                self.assertEqual(
                    list(
                        (
                            fixture.context.attempt_root / "finalization-runs"
                        ).glob("*/receipt.json")
                    ),
                    [],
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
            ("freeze-intent-binding", "notarization_intent_identity_drift"),
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
                mutated = False

                def rewrite(path: Path, field: str, value: object) -> None:
                    document = json.loads(path.read_text(encoding="utf-8"))
                    document[field] = value
                    path.write_text(
                        json.dumps(document, sort_keys=True, separators=(",", ":"))
                        + "\n",
                        encoding="utf-8",
                    )

                def mutate() -> None:
                    publish_ready = current_publish_ready(fixture)
                    if publish_ready is None:
                        self.fail("postseal mutation lacks publish-ready workspace")
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
                    elif kind == "freeze-intent-binding":
                        rewrite(
                            fixture.context.attempt_root / "intent.json",
                            "candidate_freeze_intent_sha256",
                            "e" * 64,
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
                    nonlocal calls, mutated
                    calls += 1
                    publish_ready = current_publish_ready(fixture)
                    if publish_ready is not None and not mutated:
                        event_paths = sorted(
                            (fixture.context.attempt_root / "events").glob(
                                "*.json"
                            )
                        )
                        latest = json.loads(
                            event_paths[-1].read_text(encoding="utf-8")
                        )
                        if (
                            latest["state"] == "sealed"
                            and (publish_ready.parent / "receipt.json").is_file()
                        ):
                            mutated = True
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
                self.assertGreaterEqual(calls, 1)
                self.assertTrue(mutated)
                self.assertFalse(publisher_called)
                self.assertFalse(os.path.lexists(fixture.context.final_root))
                self.assertTrue(sole_finalization_receipt(fixture).is_file())
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
                        publish_ready = current_publish_ready(fixture)
                        if publish_ready is None:
                            self.fail("seal callback lacks publish-ready workspace")
                        path = publish_ready / "notarization.json"
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
        drifted = False

        def drifting(_repository: Path) -> dict[str, str]:
            nonlocal calls, drifted
            calls += 1
            publish_ready = current_publish_ready(fixture)
            if publish_ready is not None:
                event_paths = sorted(
                    (fixture.context.attempt_root / "events").glob("*.json")
                )
                latest = json.loads(
                    event_paths[-1].read_text(encoding="utf-8")
                )
                if (
                    latest["state"] == "sealed"
                    and (publish_ready.parent / "receipt.json").is_file()
                ):
                    drifted = True
                    return {
                        "repositoryCommit": "c" * 40,
                        "releaseSourceSha256": "d" * 64,
                    }
            return fixture.context.source_identity

        def publisher(_source: Path, _destination: Path) -> None:
            nonlocal publisher_called
            publisher_called = True

        with self.assertRaisesRegex(TransactionError, "source identity changed"):
            fixture.execute(source_identity_reader=drifting, publisher=publisher)
        self.assertGreaterEqual(calls, 1)
        self.assertTrue(drifted)
        self.assertFalse(publisher_called)
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        self.assertTrue(sole_finalization_receipt(fixture).is_file())

    def test_publisher_failure_retains_complete_publish_ready_tree(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def fail_publish(_source: Path, _destination: Path) -> None:
            raise TransactionError("atomic_publish_failed", "fixture publish failure")

        with self.assertRaisesRegex(TransactionError, "fixture publish failure"):
            fixture.execute(publisher=fail_publish)
        self.assertFalse(os.path.lexists(fixture.context.final_root))
        publish_ready = current_publish_ready(fixture)
        self.assertIsNotNone(publish_ready)
        if publish_ready is None:
            self.fail("publisher failure lost its UUID publish-ready workspace")
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
            (publish_ready.parent / "receipt.json").read_text(encoding="utf-8")
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
        self.assertEqual(fixture.runner.calls, [CommandRole.NOTARY_READINESS])
        self.assertNotIn(CommandRole.SUBMIT, fixture.runner.calls)

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
        transactions = fixture.build / "transactions"
        transactions.symlink_to(outside, target_is_directory=True)
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
        real_publish = transaction_module._publish_pending_evidence
        injected = False

        def flaky_publish(**arguments) -> None:
            nonlocal injected
            if (
                arguments["destination_path"].name == "00000002.json"
                and not injected
            ):
                injected = True
                raise TransactionError("event_write_fixture", "event write fixture")
            real_publish(**arguments)

        with patch(
            "scripts.notarization_transaction._publish_pending_evidence",
            side_effect=flaky_publish,
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
    def test_shared_runner_failure_reasons_remain_distinct(self) -> None:
        expected = {
            "invalid": "command_contract_invalid",
            "start": "command_start_failed",
            "timeout": "command_timeout",
            "output-limit": "command_output_oversized",
            "descendant": "command_descendant_survived",
            "cleanup": "command_cleanup_failed",
            "unrecognized": "command_error_contract_drift",
        }
        for reason, code in expected.items():
            with self.subTest(reason=reason):
                with (
                    patch.object(
                        transaction_module,
                        "run_release_bounded_process",
                        side_effect=transaction_module.BoundedProcessError(reason, "failure"),
                    ),
                    self.assertRaises(TransactionError) as raised,
                ):
                    _run_bounded_process(["/bin/false"], 5)
                self.assertEqual(raised.exception.code, code)

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
    def test_full_fsync_failure_after_evidence_rename_is_outcome_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            pending = root / "evidence.pending"
            destination = root / "evidence.json"
            with patch.object(
                transaction_module,
                "full_fsync",
                side_effect=OSError(errno.EIO, "injected full-fsync failure"),
            ):
                with self.assertRaises(TransactionError) as raised:
                    transaction_module._publish_pending_evidence(
                        pending_path=pending,
                        destination_path=destination,
                        data=b'{"status":"passed"}\n',
                        allow_partial_rebuild=False,
                    )
            self.assertEqual(
                raised.exception.code,
                "atomic_evidence_durability_unknown",
            )
            self.assertEqual(raised.exception.terminal_state, "outcome_unknown")
            self.assertTrue(destination.is_file())
            self.assertFalse(pending.exists())

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


class BuildSignedCandidateRoutingTests(unittest.TestCase):
    @staticmethod
    def _production_routing_source() -> str:
        source = (
            Path(__file__).resolve().parents[2] / "scripts/build_signed_candidate.sh"
        ).read_text(encoding="utf-8")
        parse_start = source.index('candidate_operation=""')
        parse_end_marker = "readonly notarization_recovery_id"
        parse_end = source.index(parse_end_marker, parse_start) + len(parse_end_marker)
        function_start = source.index("run_candidate_transactions() {")
        function_end_marker = "\nrun_candidate_transactions\n"
        function_end = (
            source.index(function_end_marker, function_start)
            + len(function_end_marker)
        )
        return source[parse_start:parse_end] + "\n" + source[function_start:function_end]

    def _run_route(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        routing = self._production_routing_source()
        harness = f"""
set -euo pipefail
die() {{
  printf 'error: %s\\n' "$*" >&2
  exit 1
}}
repo_root=/release
candidate_root=/release/target/candidates/0.4.0/ga/40040
staged_app="$candidate_root/signing-output/signing-input/Clash for Mac.app"
toolchain_root=/release/target/toolchains
CFW_BUILD_NUMBER=40040
signed_native_products="$candidate_root/signing-output/signed-native-products"
NOTARY_PROFILE=clashformac-notary
repository_commit={'a' * 40}
release_source_sha256={'b' * 64}
MACOS_DEPLOYMENT_TARGET=15.0
cargo_workspace_sources_tree_sha256={'c' * 64}
go_module_cache_tree_sha256={'d' * 64}
go_toolchain_tree_sha256={'e' * 64}
go_tools_tree_sha256={'f' * 64}
node_toolchain_tree_sha256={'1' * 64}
tauri_toolchain_tree_sha256={'2' * 64}
toolchain_sha256={'3' * 64}
ui_dependencies_tree_sha256={'4' * 64}
xcodegen_toolchain_tree_sha256={'5' * 64}
run_isolated_python_script() {{
  "$ROUTE_LOGGER" -c \
    'import json,sys; print(json.dumps(sys.argv[1:], separators=(",", ":")))' \
    "$@"
}}
{routing}
"""
        return subprocess.run(
            ["/bin/bash", "-p", "-c", harness, "routing-fixture", *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            env={"PATH": "/usr/bin:/bin", "ROUTE_LOGGER": sys.executable},
        )

    @staticmethod
    def _calls(completed: subprocess.CompletedProcess[str]) -> list[list[str]]:
        return [json.loads(line) for line in completed.stdout.splitlines()]

    @staticmethod
    def _fixed_verification_calls() -> list[list[str]]:
        return [
            ["/release/scripts/candidate_freeze.py", "verify"],
            ["/release/scripts/release_signing_plan.py", "verify-frozen"],
            ["/release/scripts/updater_key_possession_proof.py", "verify-frozen"],
        ]

    @staticmethod
    def _notary_call(*mode: str) -> list[str]:
        return [
            "/release/scripts/notarization_transaction.py",
            "--build-kind",
            "ga",
            "--build-number",
            "40040",
            *mode,
            "--native-products",
            "/release/target/candidates/0.4.0/ga/40040/signing-output/signed-native-products",
            "--notary-profile",
            "clashformac-notary",
            "--repository-commit",
            "a" * 40,
            "--release-source-sha256",
            "b" * 64,
            "--deployment-target",
            "15.0",
            "--cargo-workspace-sources-tree-sha256",
            "c" * 64,
            "--go-module-cache-tree-sha256",
            "d" * 64,
            "--go-toolchain-tree-sha256",
            "e" * 64,
            "--go-tools-tree-sha256",
            "f" * 64,
            "--node-toolchain-tree-sha256",
            "1" * 64,
            "--tauri-toolchain-tree-sha256",
            "2" * 64,
            "--toolchain-sha256",
            "3" * 64,
            "--ui-dependencies-tree-sha256",
            "4" * 64,
            "--xcodegen-toolchain-tree-sha256",
            "5" * 64,
        ]

    def test_build_and_signing_resume_keep_full_signing_verification(self) -> None:
        staged = (
            "--staged-app",
            "/release/target/candidates/0.4.0/ga/40040/signing-output/"
            "signing-input/Clash for Mac.app",
        )
        cases = (
            ("--ga", "run"),
            ("--resume-signing", "resume"),
        )
        for argument, signing_command in cases:
            with self.subTest(argument=argument):
                completed = self._run_route(argument)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                self.assertEqual(
                    self._calls(completed),
                    [
                        *self._fixed_verification_calls(),
                        [
                            "/release/scripts/signing_attempt_transaction.py",
                            signing_command,
                        ],
                        [
                            "/release/scripts/verify_signing_transformation.py",
                            "verify",
                        ],
                        self._notary_call(*staged),
                    ],
                )

    def test_notarization_recovery_never_reenters_signing_or_fresh_submit(self) -> None:
        for recovery_id in (SUBMISSION_ID, "not-a-canonical-uuid"):
            with self.subTest(recovery_id=recovery_id):
                completed = self._run_route(
                    "--recover-notarization-id", recovery_id
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                self.assertEqual(
                    self._calls(completed),
                    [
                        *self._fixed_verification_calls(),
                        self._notary_call(
                            "--recover-submission-id",
                            recovery_id,
                            "--artifact-repository",
                            "/release",
                            "--toolchain-root",
                            "/release/target/toolchains",
                        ),
                    ],
                )

    def test_empty_notarization_recovery_id_fails_before_any_transaction(self) -> None:
        completed = self._run_route("--recover-notarization-id", "")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertIn("requires one non-empty submission UUID", completed.stderr)


class ShellCleanupContractTests(unittest.TestCase):
    @staticmethod
    def _cleanup_source() -> str:
        shell = (
            Path(__file__).resolve().parents[2] / "scripts/build_signed_candidate.sh"
        ).read_text(encoding="utf-8")
        return shell[shell.index("cleanup() {") : shell.index("trap cleanup EXIT")]

    def _run_cleanup(
        self,
        *,
        freeze_intent_exists: bool = False,
        frozen_exists: bool = False,
    ) -> tuple[bool, bool]:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "target/candidates/0.4.0"
            preflight = candidate / "ga-preflight/40040"
            frozen = candidate / "ga/40040"
            preflight.mkdir(parents=True)
            if freeze_intent_exists:
                intent = preflight / "candidate-freeze/intent.json"
                intent.parent.mkdir(mode=0o700)
                intent.write_text("{}\n", encoding="utf-8")
            if frozen_exists:
                frozen.mkdir(parents=True)
            script = (
                "set -euo pipefail\n"
                'preflight_root="$PREFLIGHT_ROOT"\n'
                'frozen_root="$FROZEN_ROOT"\n'
                'candidate_cargo_home=""\n'
                "completed=0\n"
                f"{self._cleanup_source()}\n"
                "cleanup\n"
                '[[ -d "$preflight_root" ]] && preflight_state=present || preflight_state=absent\n'
                '[[ -d "$frozen_root" ]] && frozen_state=present || frozen_state=absent\n'
                'printf "%s %s\n" "$preflight_state" "$frozen_state"\n'
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", script],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                env={
                    **os.environ,
                    "PREFLIGHT_ROOT": str(preflight),
                    "FROZEN_ROOT": str(frozen),
                },
            )
            states = completed.stdout.split()
            self.assertEqual(len(states), 2)
            return tuple(state == "present" for state in states)

    def test_unconsumed_preflight_failure_cleans_rebuildable_tree(self) -> None:
        self.assertEqual(self._run_cleanup(), (False, False))

    def test_freeze_intent_preserves_consumed_preflight_tree(self) -> None:
        self.assertEqual(
            self._run_cleanup(freeze_intent_exists=True),
            (True, False),
        )

    def test_existing_frozen_root_is_never_cleaned(self) -> None:
        self.assertEqual(
            self._run_cleanup(frozen_exists=True),
            (True, True),
        )


class AttemptConcurrencyTests(unittest.TestCase):
    def test_initial_claim_holds_recovery_lock_before_attempt_creation(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        entered_claim = threading.Event()
        release_claim = threading.Event()
        real_claim = transaction_module._claim_attempt

        def blocking_claim(context: TransactionContext) -> tuple[Path, Path]:
            self.assertFalse(context.attempt_root.exists())
            entered_claim.set()
            if not release_claim.wait(5):
                raise AssertionError("test did not release the initial claim")
            return real_claim(context)

        with patch.object(
            transaction_module,
            "_claim_attempt",
            side_effect=blocking_claim,
        ), ThreadPoolExecutor(max_workers=2) as executor:
            executing = executor.submit(fixture.execute)
            try:
                self.assertTrue(entered_claim.wait(2))
                self.assertTrue((fixture.build / "transactions").is_dir())
                self.assertFalse(fixture.context.attempt_root.exists())
                with self.assertRaises(TransactionError) as raised:
                    fixture.recover()
                self.assertEqual(
                    raised.exception.code,
                    "recovery_in_progress",
                )
                self.assertEqual(fixture.runner.calls, [CommandRole.NOTARY_READINESS])
            finally:
                release_claim.set()
            self.assertTrue(executing.result(timeout=5).is_dir())

    def test_local_readiness_holds_the_lock_before_claiming_or_moving_input(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def readiness(role: CommandRole, command: list[str], timeout: float) -> CommandResult:
            if role is CommandRole.NOTARY_READINESS:
                self.assertFalse(fixture.context.attempt_root.exists())
                self.assertTrue(fixture.app.is_dir())
                self.assertEqual(Path(command[2]), fixture.app)
                with self.assertRaises(TransactionError) as raised:
                    fixture.execute()
                self.assertEqual(raised.exception.code, "recovery_in_progress")
            return fixture.runner(role, command, timeout)

        self.assertTrue(fixture.execute(command_runner=readiness).is_dir())
        self.assertEqual(fixture.runner.calls.count(CommandRole.SUBMIT), 1)

    def test_fixed_ga_attempt_can_only_be_claimed_once(self) -> None:
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
        self.assertTrue(fixture.context.attempt_root.is_dir())

    def test_legacy_build_kinds_are_rejected_before_attempt_creation(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        for legacy_kind in ("validation", "release"):
            with self.subTest(legacy_kind=legacy_kind):
                context = replace(fixture.context, build_kind=legacy_kind)
                with self.assertRaises(TransactionError) as raised:
                    transaction_module._validate_context(context)
                self.assertEqual(raised.exception.code, "invalid_build_kind")
                self.assertFalse(fixture.context.attempt_root.exists())

    def test_non_active_build_number_is_rejected_before_attempt_creation(self) -> None:
        for build_number in (
            "40031",
            "40032",
            "40033",
            "40034",
            "40035",
            "40036",
            "40037",
            "40038",
        ):
            with self.subTest(build_number=build_number):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                context = replace(fixture.context, build_number=build_number)
                with self.assertRaises(TransactionError) as raised:
                    transaction_module._validate_context(context)
                self.assertEqual(raised.exception.code, "invalid_build_number")
                self.assertFalse(fixture.context.attempt_root.exists())

    def test_concurrent_ga_claims_meet_at_one_exclusive_attempt_root(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        claim_barrier = threading.Barrier(2)
        real_mkdir_private = transaction_module._mkdir_private

        def synchronized_mkdir(path: Path, *, exclusive: bool) -> None:
            if path == fixture.context.attempt_root:
                claim_barrier.wait(timeout=5)
            real_mkdir_private(path, exclusive=exclusive)

        def claim() -> str:
            try:
                _claim_attempt(fixture.context)
                return "claimed"
            except TransactionError as error:
                return error.code

        with patch.object(
            transaction_module,
            "_mkdir_private",
            side_effect=synchronized_mkdir,
        ), ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _index: claim(), range(2)))
        self.assertEqual(sorted(results), ["attempt_exists", "claimed"])

    def test_crash_before_attempt_creation_is_safely_retryable(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        real_mkdir = transaction_module._mkdir_private

        def crash_before_attempt(path: Path, *, exclusive: bool) -> None:
            if path == fixture.context.attempt_root:
                raise SimulatedCrash("after-build-number-claim")
            real_mkdir(path, exclusive=exclusive)

        with patch.object(
            transaction_module,
            "_mkdir_private",
            side_effect=crash_before_attempt,
        ):
            with self.assertRaises(SimulatedCrash):
                _claim_attempt(fixture.context)
        self.assertTrue((fixture.build / "transactions").is_dir())
        self.assertFalse(fixture.context.attempt_root.exists())
        events, work = _claim_attempt(fixture.context)
        self.assertTrue(events.is_dir())
        self.assertTrue(work.is_dir())

    def test_unsafe_transactions_roots_fail_closed(self) -> None:
        for kind in ("file", "symlink", "wrong-mode"):
            with self.subTest(kind=kind):
                fixture = Fixture()
                try:
                    transactions = fixture.build / "transactions"
                    if kind == "file":
                        transactions.write_bytes(b"not a directory")
                    elif kind == "symlink":
                        target = fixture.candidate / "transactions-target"
                        target.mkdir(mode=0o700)
                        transactions.symlink_to(target, target_is_directory=True)
                    else:
                        transactions.mkdir(mode=0o755)
                    with self.assertRaises(TransactionError):
                        _claim_attempt(fixture.context)
                    self.assertFalse(fixture.context.attempt_root.exists())
                finally:
                    fixture.close()

    def test_two_complete_transactions_can_submit_the_build_only_once(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def run() -> str:
            try:
                fixture.execute()
                return "published"
            except TransactionError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _index: run(), range(2)))
        self.assertEqual(sorted(results), ["published", "recovery_in_progress"])
        self.assertEqual(fixture.runner.calls.count(CommandRole.SUBMIT), 1)

    def test_legacy_transaction_cannot_race_the_ga_submission(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        contexts = [
            fixture.context,
            replace(fixture.context, build_kind="release"),
        ]

        def run(context: TransactionContext) -> str:
            try:
                fixture.execute_context(context)
                return "published"
            except TransactionError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(run, contexts))
        self.assertEqual(sorted(results), ["invalid_build_kind", "published"])
        self.assertEqual(fixture.runner.calls.count(CommandRole.SUBMIT), 1)


class NotarizationCliTests(unittest.TestCase):
    def _common_arguments(
        self,
        *,
        build_kind: str = "ga",
        build_number: str = "40040",
    ) -> list[str]:
        return [
            "--build-kind",
            build_kind,
            "--build-number",
            build_number,
            "--native-products",
            "/tmp/cfw-native-products",
            "--notary-profile",
            transaction_module.NOTARY_PROFILE,
            "--repository-commit",
            "a" * 40,
            "--release-source-sha256",
            "b" * 64,
            "--deployment-target",
            "15.0",
            "--cargo-workspace-sources-tree-sha256",
            "0" * 64,
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

    def _run(
        self,
        mode_arguments: list[str],
        *,
        build_kind: str = "ga",
        build_number: str = "40040",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(Path(transaction_module.__file__).resolve()),
                *self._common_arguments(
                    build_kind=build_kind,
                    build_number=build_number,
                ),
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

    def test_frozen_submission_requires_artifact_and_toolchain_roots(self) -> None:
        for extra, message in (
            ([], "frozen submission requires --artifact-repository"),
            (
                ["--artifact-repository", "/tmp/artifact-repository"],
                "frozen submission requires --toolchain-root",
            ),
        ):
            with self.subTest(message=message):
                result = self._run(["--submit-frozen-candidate", *extra])
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)

    def test_frozen_submission_cannot_mix_with_submit_or_recovery(self) -> None:
        for other in (
            ["--staged-app", "/tmp/Clash for Mac.app"],
            ["--recover-submission-id", SUBMISSION_ID],
        ):
            with self.subTest(other=other):
                result = self._run(["--submit-frozen-candidate", *other])
                self.assertEqual(result.returncode, 2)
                self.assertIn("not allowed with argument", result.stderr)

    def test_frozen_submission_rejects_symlinked_toolchain_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            toolchains = root / "toolchains"
            toolchains.mkdir()
            alias = root / "alias"
            alias.symlink_to(toolchains, target_is_directory=True)
            result = self._run(
                [
                    "--submit-frozen-candidate",
                    "--artifact-repository", str(root),
                    "--toolchain-root", str(alias),
                ]
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--toolchain-root must be an absolute real directory", result.stderr)

    def test_frozen_submission_dispatch_derives_only_the_canonical_signed_app(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifact_repository = root / "artifact-repository"
            toolchain_root = root / "toolchains"
            artifact_repository.mkdir()
            toolchain_root.mkdir()
            final_app = (
                artifact_repository
                / "target/candidates/0.4.0/ga/40040/signed/Clash for Mac.app"
            )
            argv = [
                str(Path(transaction_module.__file__).resolve()),
                *self._common_arguments(),
                "--submit-frozen-candidate",
                "--artifact-repository", str(artifact_repository),
                "--toolchain-root", str(toolchain_root),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.dict(os.environ, {}, clear=False),
                patch.object(transaction_module, "execute_transaction", return_value=final_app) as execute,
                patch.object(transaction_module, "require_closed_release_runtime") as runtime,
                patch.object(transaction_module, "recover_transaction") as recover,
                patch("builtins.print"),
            ):
                transaction_module.main()
                self.assertEqual(os.environ["CFW_TOOLCHAIN_ROOT"], str(toolchain_root))
            context = execute.call_args.args[0]
            self.assertEqual(context.repository, artifact_repository)
            self.assertEqual(
                context.staged_app,
                artifact_repository
                / "target/candidates/0.4.0/ga/40040/signing-output/signing-input/Clash for Mac.app",
            )
            self.assertEqual(
                execute.call_args.kwargs,
                {
                    "executor_repository": Path(transaction_module.__file__).resolve().parent.parent,
                    "toolchain_metadata_reader": transaction_module.production_artifact_toolchain_metadata_reader,
                },
            )
            recover.assert_not_called()
            runtime.assert_called_once_with()

    def test_frozen_submission_rejects_unsealed_python_before_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = self._run(
                [
                    "--submit-frozen-candidate",
                    "--artifact-repository", str(root),
                    "--toolchain-root", str(root),
                ]
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("notarization runtime admission", result.stderr)
            self.assertFalse((root / "target").exists())

    def test_notary_shell_entry_uses_the_existing_closed_environment(self) -> None:
        wrapper = Path(transaction_module.__file__).with_name("run_notarization_transaction.sh")
        source = wrapper.read_text(encoding="utf-8")
        self.assertTrue(source.startswith("#!/bin/bash -p\n"))
        self.assertTrue(wrapper.stat().st_mode & stat.S_IXUSR)
        self.assertIn("cfw_seal_release_tool_environment production", source)
        self.assertIn("cfw_select_release_apple_toolchain", source)
        self.assertIn("cfw_run_release_python_script", source)
        self.assertIn('"$repo_root/scripts/notarization_transaction.py"', source)
        result = subprocess.run(
            ["/bin/bash", "-p", "-n", str(wrapper)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_legacy_build_kinds_are_explicitly_rejected(self) -> None:
        for legacy_kind in ("validation", "release"):
            with self.subTest(legacy_kind=legacy_kind):
                result = self._run(
                    ["--staged-app", "/tmp/Clash for Mac.app"],
                    build_kind=legacy_kind,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid choice", result.stderr)
                self.assertIn("choose from 'ga'", result.stderr)

    def test_non_active_build_number_is_explicitly_rejected(self) -> None:
        for build_number in (
            "40031",
            "40032",
            "40033",
            "40034",
            "40035",
            "40036",
            "40037",
            "40038",
        ):
            with self.subTest(build_number=build_number):
                result = self._run(
                    ["--staged-app", "/tmp/Clash for Mac.app"],
                    build_number=build_number,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid choice", result.stderr)
                self.assertIn("choose from '40040'", result.stderr)

    def test_recovery_dispatch_separates_artifact_tool_and_toolchain_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifact_repository = root / "artifact-repository"
            toolchain_root = root / "toolchains"
            artifact_repository.mkdir()
            toolchain_root.mkdir()
            final_app = (
                artifact_repository
                / "target/candidates/0.4.0/ga/40040/signed/Clash for Mac.app"
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
            self.assertEqual(
                recover.call_args.kwargs,
                {"toolchain_metadata_reader": transaction_module.production_artifact_toolchain_metadata_reader},
            )


class PublishedTransactionReceiptValidationTests(unittest.TestCase):
    @staticmethod
    def _tree_digest(root: Path) -> str:
        return build_manifest(root, algorithm="sha256-tree-v2")["sha256"]

    @staticmethod
    def _validate(fixture: Fixture):
        def historical_identity(_repository: Path, commit: str) -> dict[str, str]:
            if commit == "c" * 40:
                digest = "d" * 64
            elif commit == "e" * 40:
                digest = "f" * 64
            else:
                raise AssertionError(f"unexpected historical commit: {commit}")
            return {"repositoryCommit": commit, "releaseSourceSha256": digest}

        context = replace(fixture.context, staged_app=None)
        with (
            patch.object(
                transaction_module,
                "production_source_identity_reader",
                side_effect=fixture.source_identity,
            ),
            patch.object(
                transaction_module,
                "production_toolchain_metadata_reader",
                side_effect=lambda _repository: fixture.context.toolchain_metadata,
            ),
            patch.object(
                transaction_module,
                "production_archive_validator",
                side_effect=lambda _archive, _app: None,
            ),
            patch.object(
                transaction_module,
                "identity_at_commit",
                side_effect=historical_identity,
            ),
        ):
            return transaction_module.validate_published_transaction_receipt(context)

    def test_current_direct_publication_validates_without_mutating_attempt(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.execute()
        before = self._tree_digest(fixture.context.attempt_root)
        evidence = self._validate(fixture)
        after = self._tree_digest(fixture.context.attempt_root)
        self.assertEqual(after, before)
        self.assertEqual(evidence.receipt["state"], "publish-ready")
        self.assertEqual(evidence.receipt_path, sole_finalization_receipt(fixture))
        self.assertEqual(evidence.prepared_at, "2026-07-28T04:02:00Z")

    def test_unique_recovery_publication_validates_without_mutating_attempt(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.create_orphaned_submit_attempt()
        fixture.recover()
        before = self._tree_digest(fixture.context.attempt_root)
        evidence = self._validate(fixture)
        after = self._tree_digest(fixture.context.attempt_root)
        self.assertEqual(after, before)
        self.assertEqual(evidence.receipt_path, sole_finalization_receipt(fixture))
        self.assertIsNotNone(evidence.receipt["recovery_intent_sha256"])

    def test_ambiguous_recovery_receipts_fail_without_mutating_attempt(self) -> None:
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.create_orphaned_submit_attempt()
        fixture.recover()
        receipt_path = sole_finalization_receipt(fixture)
        duplicate = (
            fixture.context.attempt_root
            / "finalization-runs/11111111-2222-4333-8444-555555555555"
        )
        duplicate.mkdir(mode=0o700)
        (duplicate / "receipt.json").write_bytes(receipt_path.read_bytes())
        (duplicate / "receipt.json").chmod(0o600)
        before = self._tree_digest(fixture.context.attempt_root)
        with self.assertRaisesRegex(TransactionError, "one exact sealed receipt"):
            self._validate(fixture)
        self.assertEqual(self._tree_digest(fixture.context.attempt_root), before)

    def test_recovery_intent_disappearance_or_replacement_never_recreates_it(self) -> None:
        for attack in ("delete", "replace"):
            with self.subTest(attack=attack):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                fixture.create_orphaned_submit_attempt()
                fixture.recover()
                intent_path = fixture.context.attempt_root / "recovery-intent.json"
                real_read = transaction_module._read_regular_bytes
                attacked_tree: str | None = None
                intent_reads = 0

                def attack_after_first_read(path: Path, maximum: int = transaction_module.MAX_JSON_BYTES):
                    nonlocal attacked_tree, intent_reads
                    data = real_read(path, maximum)
                    if path == intent_path:
                        intent_reads += 1
                        if intent_reads == 1:
                            if attack == "delete":
                                intent_path.unlink()
                            else:
                                intent_path.write_bytes(b'{"replaced":true}')
                                intent_path.chmod(0o600)
                            attacked_tree = self._tree_digest(
                                fixture.context.attempt_root
                            )
                    return data

                with patch.object(
                    transaction_module,
                    "_read_regular_bytes",
                    side_effect=attack_after_first_read,
                ):
                    with self.assertRaises(TransactionError):
                        self._validate(fixture)
                self.assertIsNotNone(attacked_tree)
                self.assertEqual(
                    self._tree_digest(fixture.context.attempt_root),
                    attacked_tree,
                )
                if attack == "delete":
                    self.assertFalse(intent_path.exists())
                else:
                    self.assertEqual(intent_path.read_bytes(), b'{"replaced":true}')

    def test_selected_direct_and_recovery_receipt_replacement_is_revalidated(self) -> None:
        for recovery in (False, True):
            with self.subTest(recovery=recovery):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                if recovery:
                    fixture.create_orphaned_submit_attempt()
                    fixture.recover()
                else:
                    fixture.execute()
                real_unique = transaction_module._unique_matching_published_receipt
                attacked_tree: str | None = None

                def replace_selected_receipt(*args, **kwargs):
                    nonlocal attacked_tree
                    path = real_unique(*args, **kwargs)
                    receipt = json.loads(path.read_text(encoding="utf-8"))
                    receipt["state"] = "replaced-after-selection"
                    path.write_bytes(
                        transaction_module._canonical_json(receipt).encode("utf-8")
                    )
                    path.chmod(0o600)
                    attacked_tree = self._tree_digest(fixture.context.attempt_root)
                    return path

                with patch.object(
                    transaction_module,
                    "_unique_matching_published_receipt",
                    side_effect=replace_selected_receipt,
                ):
                    with self.assertRaises(TransactionError):
                        self._validate(fixture)
                self.assertIsNotNone(attacked_tree)
                self.assertEqual(
                    self._tree_digest(fixture.context.attempt_root),
                    attacked_tree,
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
