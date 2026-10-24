from __future__ import annotations

import ast
import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import release_driver, release_driver_acceptance
from scripts.release_driver import (
    BUILD_FREE_GIB,
    STAGES,
    STAGES_BY_NAME,
    command_next,
    command_run,
    command_shipped,
    command_status,
)
from scripts.release_driver_context import (
    MACHINE,
    PREREQUISITE,
    USAGE,
    Completed,
    Context,
    DriverError,
    Machine,
    Release,
    path_present,
    read_record,
    release_for,
    write_record,
)
from scripts.release_driver_review import read_ledger

COMMIT = "a" * 40
PINS = {"XCODE_VERSION": "27.1", "XCODE_BUILD_VERSION": "27A9275", "PYTHON_VERSION": "3.14.7"}
XCODE = "Xcode 27.1\nBuild version 27A9275\n"


class FakeMachine(Machine):
    """Answers the driver's observations from a table and records every command."""

    def __init__(self, home: Path) -> None:
        super().__init__(home)
        self.answers: dict[tuple[str, ...], Completed] = {}
        self.executed: list[tuple[list[str], Path]] = []
        self.statuses: list[int] = []
        self.outputs: list[str] = []
        self.free = 100.0
        self.terminal = True
        self.ssh = False

    def answer(self, prefix: tuple[str, ...], status: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.answers[prefix] = Completed(status, stdout, stderr)

    def read(self, argv, *, timeout=60, cwd=None):
        argv = tuple(argv)
        for length in range(len(argv), 0, -1):
            if argv[:length] in self.answers:
                return self.answers[argv[:length]]
        raise AssertionError(f"unexpected observation: {argv}")

    def execute(self, argv, *, cwd, log, extra_environment={}, attach_terminal=False, keep_awake=True):
        self.executed.append((list(argv), cwd))
        output = self.outputs.pop(0) if self.outputs else ""
        with log.open("a", encoding="utf-8") as stream:
            stream.write(output)
        return self.statuses.pop(0) if self.statuses else 0

    def free_gib(self):
        return self.free

    def stdin_is_terminal(self):
        return self.terminal

    def over_ssh(self):
        return self.ssh


class DriverFixture(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name)
        self.release = Release(
            version="0.5.0",
            build="90002",
            home=self.home / ".cfm-release-tooling/releases/0.5.0",
            sing_box_version="v1.14.2",
        )
        self.machine = FakeMachine(self.home)
        for checkout in (self.release.operator, self.release.artifact):
            prefix = ("/usr/bin/env", "GIT_OPTIONAL_LOCKS=0", "/usr/bin/git", "-C", str(checkout))
            self.machine.answer(prefix + ("rev-parse", "--verify", "HEAD"), stdout=COMMIT + "\n")
            self.machine.answer(prefix + ("status", "--porcelain"), stdout="")
        self.machine.answer(("/usr/bin/pgrep",), status=1)
        self.machine.answer(("/usr/bin/xcodebuild", "-version"), stdout=XCODE)

    def context(self, *arguments: str) -> Context:
        return Context(self.release, release_driver.REPOSITORY, PINS, self.machine, arguments=arguments)

    def enroll(self) -> None:
        (self.release.artifact / "target").mkdir(parents=True)
        write_record(self.release, "enroll", {"commit": COMMIT, "inputs": "/inputs"})

    def touch(self, path: Path, content: str = "{}") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def next_stage(self) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            command_next(self.context())
        first = output.getvalue().splitlines()[0]
        return first.split()[1]


class StageOrderTests(DriverFixture):
    def test_a_fresh_release_offers_only_enrollment_with_its_input(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            command_next(self.context())
        self.assertIn("next: enroll", output.getvalue())
        self.assertIn("run enroll --inputs DEVELOPMENT_WORKTREE", output.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as status:
            command_status(self.context())
        self.assertIn("[NEXT] enroll", status.getvalue())

    def test_each_published_artifact_advances_the_next_stage(self) -> None:
        self.enroll()
        ga, inputs = self.release.ga, self.release.stage_inputs
        steps = [
            ("prepare", lambda: write_record(self.release, "prepare", {"commit": COMMIT})),
            ("ci", lambda: write_record(self.release, "ci", {"commit": COMMIT, "run_id": 7})),
            ("build", lambda: [self.touch(ga / "signed" / name) for name in
                               ("Clash for Mac.app", "notarization.json", "gatekeeper.json")]),
            ("receipt", lambda: self.touch(inputs / "hosted-ci.json")),
            ("review-template", lambda: self.touch(inputs / "component-review.json")),
            ("review", lambda: self.touch(self.release.review / "component-review-reviewed.json")),
            ("publication-prepare", lambda: (inputs / "publication-prepared").mkdir(parents=True)),
            ("draft", lambda: self.touch(inputs / "machine-closure.draft.json")),
            ("legal-review", lambda: [self.touch(inputs / "legal-review.json"),
                                      self.touch(self.release.review / "approval.json")]),
            ("finalize", lambda: self.touch(inputs / "publication/inventory.json")),
            ("preserve", lambda: self.touch(self.release.preserved_publication / "tree-identity.json")),
            ("seal-prepackage", lambda: self.touch(ga / "prepackage/manifest.json")),
            ("dmg", lambda: self.touch(self.release.package_seal("dmg"))),
            ("updater", lambda: self.touch(self.release.package_seal("updater"))),
            ("install", lambda: write_record(self.release, "install", {
                "archive-history": True, "decommission": True, "install": True, "recommission": True})),
            ("export", lambda: (self.release.acceptance / "migration-journals").mkdir(parents=True)),
            ("acceptance", lambda: self.touch(self.release.acceptance / "runtime-acceptance.json")),
            ("seal-ga-acceptance", lambda: self.touch(ga / "ga-acceptance/manifest.json")),
            ("seal-publication", lambda: [self.touch(ga / "publication/manifest.json"),
                                          self.touch(self.release.package_seal("distribution"))]),
            ("publish", lambda: write_record(self.release, "publish", {"allowlist": "printed"})),
            ("verify-remote", lambda: write_record(self.release, "verify-remote", {"seal_sha256": "0" * 64})),
        ]
        self.assertEqual([name for name, _ in steps], [stage.name for stage in STAGES[1:]])
        for name, complete in steps:
            self.assertEqual(self.next_stage(), name)
            complete()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            command_next(self.context())
        self.assertIn("is released and verified", output.getvalue())

    def test_a_frozen_but_unsigned_candidate_names_only_its_recovery(self) -> None:
        self.enroll()
        write_record(self.release, "prepare", {"commit": COMMIT})
        write_record(self.release, "ci", {"commit": COMMIT, "run_id": 7})
        self.touch(self.release.ga / "candidate-freeze/intent.json")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            command_next(self.context())
        self.assertIn("Never rerun the builder with --ga", output.getvalue())
        self.assertNotIn("run:", output.getvalue())
        with self.assertRaisesRegex(DriverError, "already frozen"):
            command_run(self.context("--ga"), "build")

    def test_run_refuses_a_stage_out_of_order_and_a_completed_stage(self) -> None:
        self.enroll()
        with self.assertRaisesRegex(DriverError, "run prepare first"):
            command_run(self.context(), "dmg")
        write_record(self.release, "prepare", {"commit": COMMIT})
        with self.assertRaisesRegex(DriverError, "already complete"):
            command_run(self.context(), "prepare")
        self.assertEqual(self.machine.executed, [])

    def test_a_shipped_build_offers_no_stage(self) -> None:
        ledger = self.home / ".cfm-release-tooling/releases/shipped.json"
        self.touch(ledger, json.dumps({"document": "cfm-shipped-releases-v1", "releases": [
            {"version": "0.5.0", "build": "90002", "artifact": "/a", "review": "/r"}]}))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            command_next(self.context())
        self.assertIn("is shipped and verified", output.getvalue())
        with self.assertRaisesRegex(DriverError, "is shipped"):
            command_run(self.context(), "enroll")


class GuardTests(DriverFixture):
    def setUp(self) -> None:
        super().setUp()
        self.enroll()

    def test_a_dirty_checkout_refuses_before_any_command(self) -> None:
        prefix = ("/usr/bin/env", "GIT_OPTIONAL_LOCKS=0", "/usr/bin/git", "-C", str(self.release.artifact))
        self.machine.answer(prefix + ("status", "--porcelain"), stdout=" M scripts/x.py\n")
        with self.assertRaisesRegex(DriverError, "uncommitted"):
            command_run(self.context(), "prepare")
        self.assertEqual(self.machine.executed, [])

    def test_another_release_command_refuses(self) -> None:
        self.machine.answer(("/usr/bin/pgrep",), stdout="4242\n")
        with self.assertRaisesRegex(DriverError, "pids 4242") as raised:
            command_run(self.context(), "prepare")
        self.assertEqual(raised.exception.status, MACHINE)

    def test_an_xcode_other_than_the_pin_refuses(self) -> None:
        self.machine.answer(("/usr/bin/xcodebuild", "-version"), stdout="Xcode 27.2\nBuild version 27B1\n")
        with self.assertRaisesRegex(DriverError, "pins Xcode 27.1"):
            command_run(self.context(), "prepare")

    def test_the_builder_needs_more_free_space_and_a_desktop_terminal(self) -> None:
        write_record(self.release, "prepare", {"commit": COMMIT})
        write_record(self.release, "ci", {"commit": COMMIT, "run_id": 7})
        self.machine.free = BUILD_FREE_GIB - 1
        with self.assertRaisesRegex(DriverError, "GiB is free"):
            command_run(self.context(), "build")
        self.machine.free = 100.0
        self.machine.ssh = True
        with self.assertRaisesRegex(DriverError, "not over SSH"):
            command_run(self.context(), "build")
        self.assertEqual(self.machine.executed, [])

    def test_the_builder_requires_hosted_ci_of_the_release_commit(self) -> None:
        write_record(self.release, "prepare", {"commit": COMMIT})
        write_record(self.release, "ci", {"commit": "b" * 40, "run_id": 7})
        # The ci record of another commit leaves ci as the pending stage.
        with self.assertRaisesRegex(DriverError, "run ci first"):
            command_run(self.context(), "build")


class RecordAndLogTests(DriverFixture):
    def test_logs_are_numbered_and_never_reused(self) -> None:
        context = self.context()
        first, second = context.new_log("prepare"), context.new_log("prepare")
        self.assertEqual((first.name, second.name), ("001-prepare.log", "002-prepare.log"))
        self.assertEqual(oct(first.stat().st_mode & 0o777), "0o600")

    def test_a_record_of_another_build_is_refused(self) -> None:
        path = write_record(self.release, "ci", {"commit": COMMIT, "run_id": 7})
        document = json.loads(path.read_text())
        document["build"] = "90001"
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(DriverError, "does not belong"):
            read_record(self.release, "ci")

    def test_a_record_that_is_not_json_is_refused(self) -> None:
        path = write_record(self.release, "ci", {"commit": COMMIT, "run_id": 7})
        path.write_text('{"build": "90002"', encoding="utf-8")
        with self.assertRaisesRegex(DriverError, "is not JSON") as raised:
            read_record(self.release, "ci")
        self.assertEqual(raised.exception.status, PREREQUISITE)

    def test_only_absence_makes_a_path_not_present(self) -> None:
        self.assertFalse(path_present(self.home / "absent"))
        (self.home / "dangling").symlink_to(self.home / "absent")
        self.assertTrue(path_present(self.home / "dangling"))
        locked = self.home / "locked"
        locked.mkdir(mode=0o000)
        self.addCleanup(locked.chmod, 0o700)
        with self.assertRaises(PermissionError):
            path_present(locked / "output")


class RunLockTests(DriverFixture):
    def test_a_second_run_of_the_same_release_is_refused_until_the_first_ends(self) -> None:
        release = release_for(release_driver.REPOSITORY, self.home)
        with release_driver._exclusive_run(release):
            with self.assertRaisesRegex(DriverError, "in progress") as raised:
                release_driver.main(["run", "prepare"], machine=self.machine)
            self.assertEqual(raised.exception.status, MACHINE)
        with release_driver._exclusive_run(release):
            pass

    def test_a_refusal_before_any_stage_state_leaves_no_trace(self) -> None:
        with self.assertRaisesRegex(DriverError, "unknown stage"):
            command_run(self.context(), "no-such-stage")
        self.touch(self.home / ".cfm-release-tooling/releases/shipped.json", json.dumps({
            "document": "cfm-shipped-releases-v1",
            "releases": [{"version": "0.5.0", "build": "90002", "artifact": "/a", "review": "/r"}]}))
        with self.assertRaisesRegex(DriverError, "is shipped"):
            command_run(self.context(), "prepare")
        self.assertFalse(path_present(self.release.home))


class MachineTests(unittest.TestCase):
    def test_parsed_output_never_includes_diagnostics(self) -> None:
        # gcloud prints update notices on stderr whenever it decides to; they
        # must never reach the address the acceptance stage compares.
        with tempfile.TemporaryDirectory() as directory:
            completed = Machine(Path(directory)).read(
                ["/bin/sh", "-c", "echo 203.0.113.7; echo 'Updates are available for some components.' >&2"]
            )
        self.assertEqual(completed.stdout, "203.0.113.7\n")
        self.assertEqual(completed.stderr, "Updates are available for some components.\n")
        self.assertEqual(completed.reason(), "Updates are available for some components.")

    def test_a_command_that_does_not_finish_is_a_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                self.assertRaisesRegex(DriverError, "/bin/sleep 5 did not finish within 0.2 s") as raised:
            Machine(Path(directory)).read(["/bin/sleep", "5"], timeout=0.2)
        self.assertEqual(raised.exception.status, MACHINE)

    def test_a_missing_tool_is_a_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(DriverError, "cannot start") as raised:
                Machine(Path(directory)).read([str(Path(directory) / "absent-tool"), "--version"])
        self.assertEqual(raised.exception.status, PREREQUISITE)


class LedgerTests(unittest.TestCase):
    ENTRY = {"version": "0.5.0", "build": "90001", "artifact": "/a", "review": "/r"}

    def read(self, content: str) -> list:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            ledger = home / ".cfm-release-tooling/releases/shipped.json"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(content, encoding="utf-8")
            return read_ledger(home)

    def document(self, *entries: object) -> str:
        return json.dumps({"document": "cfm-shipped-releases-v1", "releases": list(entries)})

    def test_a_well_formed_ledger_is_read(self) -> None:
        self.assertEqual(self.read(self.document(self.ENTRY)), [self.ENTRY])

    def test_a_ledger_that_is_not_json_is_refused(self) -> None:
        with self.assertRaisesRegex(DriverError, "is not JSON"):
            self.read('{"document": ')

    def test_a_malformed_entry_is_refused(self) -> None:
        for entry in ("90001", {**self.ENTRY, "extra": "x"}, {**self.ENTRY, "build": 90001}):
            with self.subTest(entry=entry), self.assertRaisesRegex(DriverError, "malformed entry"):
                self.read(self.document(entry))
        with self.assertRaisesRegex(DriverError, "canonical positive decimal integer"):
            self.read(self.document({**self.ENTRY, "build": "090001"}))


class OperatorArgumentTests(DriverFixture):
    def test_an_enrollment_input_that_does_not_exist_is_a_usage_error(self) -> None:
        prefix = ("/usr/bin/env", "GIT_OPTIONAL_LOCKS=0", "/usr/bin/git", "-C", str(release_driver.REPOSITORY))
        self.machine.answer(prefix + ("rev-parse", "--verify", "HEAD"), stdout=COMMIT + "\n")
        self.machine.answer(prefix + ("status", "--porcelain"), stdout="")
        with self.assertRaisesRegex(DriverError, "the input worktree does not exist") as raised:
            command_run(self.context("--inputs", str(self.home / "absent")), "enroll")
        self.assertEqual(raised.exception.status, USAGE)

    def test_registering_a_shipped_release_checks_its_arguments(self) -> None:
        present = str(self.home)
        with self.assertRaisesRegex(DriverError, "the shipped artifact checkout does not exist") as raised:
            command_shipped(self.home, ["0.5.0", "90001", str(self.home / "absent"), present])
        self.assertEqual(raised.exception.status, USAGE)
        with self.assertRaisesRegex(DriverError, "canonical positive decimal integer") as raised:
            command_shipped(self.home, ["0.5.0", "090001", present, present])
        self.assertEqual(raised.exception.status, USAGE)

    def test_an_offline_seal_that_does_not_exist_is_a_usage_error(self) -> None:
        self.enroll()
        context = self.context("--trusted-distribution-seal", str(self.home / "absent"), "--sha256", "0" * 64)
        with self.assertRaisesRegex(DriverError, "the offline distribution seal does not exist") as raised:
            release_driver._verify_remote(context)
        self.assertEqual(raised.exception.status, USAGE)

    def test_verify_remote_stays_pending_when_the_ledger_refuses_the_build(self) -> None:
        self.enroll()
        self.touch(self.release.package_seal("distribution"), "seal")
        offline = self.home / "offline-seal.json"
        offline.write_text("seal", encoding="utf-8")
        context = self.context("--trusted-distribution-seal", str(offline), "--sha256", "0" * 64)
        refusal = DriverError("the approval chain does not verify", PREREQUISITE)
        with patch.object(release_driver, "add_shipped", side_effect=refusal), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(DriverError, "approval chain"):
            release_driver._verify_remote(context)
        self.assertEqual(self.machine.executed[0][0][0], "./scripts/run_verify_remote_release.sh")
        self.assertIsNone(read_record(self.release, "verify-remote"))


class StageCommandTests(DriverFixture):
    def setUp(self) -> None:
        super().setUp()
        self.enroll()
        write_record(self.release, "prepare", {"commit": COMMIT})

    def test_ci_records_the_one_run_the_preflight_reports(self) -> None:
        self.machine.outputs = [f"hosted CI preflight passed: run=4242 attempt=1 head={COMMIT} jobs=3\n"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(command_run(self.context(), "ci"), 0)
        self.assertEqual(self.machine.executed[0][0], ["./scripts/run_hosted_ci_preflight.sh"])
        self.assertEqual(self.machine.executed[0][1], self.release.artifact)
        self.assertEqual(read_record(self.release, "ci")["run_id"], 4242)

    def test_ci_refuses_a_preflight_of_another_commit(self) -> None:
        self.machine.outputs = [f"hosted CI preflight passed: run=4242 attempt=1 head={'b' * 40} jobs=3\n"]
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(DriverError, "did not report"):
            command_run(self.context(), "ci")
        self.assertIsNone(read_record(self.release, "ci"))

    def test_the_receipt_must_test_the_release_commit_itself(self) -> None:
        write_record(self.release, "ci", {"commit": COMMIT, "run_id": 4242})
        for name in ("Clash for Mac.app", "notarization.json", "gatekeeper.json"):
            self.touch(self.release.ga / "signed" / name)
        self.touch(self.release.stage_inputs / "hosted-ci.json",
                   json.dumps({"tested_source": {"repository_commit": "b" * 40}}))
        # The capture tool published a receipt; the stage is then complete,
        # so drive the receipt function directly to check its own guard.
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(DriverError, "tested b{40}"):
            release_driver._receipt(self.context())
        self.assertEqual(self.machine.executed[0][0][-2:], ["--capture-hosted-ci", "4242"])

    def test_install_resumes_after_the_last_recorded_transaction(self) -> None:
        self.complete_packaging()
        write_record(self.release, "install", {"archive-history": True, "decommission": True})
        self.machine.statuses = [7]
        with patch.object(release_driver, "_previous_build", return_value="90001"), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(command_run(self.context(), "install"), 7)
        self.assertEqual([argv for argv, _ in self.machine.executed],
                         [["./scripts/run_dormant_app_install.sh", "--install"]])
        self.assertIn("run `run install --recover-install`", output.getvalue())
        self.assertNotIn("install", {k for k, v in read_record(self.release, "install").items() if v is True})

    def test_install_archives_the_active_predecessor_first(self) -> None:
        self.complete_packaging()
        self.machine.statuses = [0, 9]
        with patch.object(release_driver, "_previous_build", return_value="90001"), \
                contextlib.redirect_stdout(io.StringIO()):
            command_run(self.context(), "install")
        self.assertEqual(self.machine.executed[0][0],
                         ["./scripts/run_archive_install_history.sh", "--previous-build", "90001"])
        self.assertTrue(read_record(self.release, "install")["archive-history"])

    def test_a_recovered_installation_is_recorded_and_the_sequence_resumes_after_it(self) -> None:
        self.complete_packaging()
        write_record(self.release, "install", {"archive-history": True, "decommission": True})
        self.machine.outputs = ["dormant install transaction installed: 0.5.0 (90002); application was not launched\n"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(command_run(self.context("--recover-install"), "install"), 0)
        self.assertIs(read_record(self.release, "install")["install"], True)
        with patch.object(release_driver, "_previous_build", return_value="90001"), \
                patch.object(release_driver, "installed_build", return_value="90002"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(command_run(self.context(), "install"), 0)
        self.assertEqual([argv for argv, _ in self.machine.executed][-1],
                         ["./scripts/run_current_service_transaction.sh", "--recommission"])

    def test_a_recovered_service_transaction_records_the_phase_it_reports(self) -> None:
        self.complete_packaging()
        write_record(self.release, "install", {"archive-history": True})
        self.machine.outputs = ["current-service transaction decommissioned: 90002\n"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(command_run(self.context("--recover-service"), "install"), 0)
        record = read_record(self.release, "install")
        self.assertIs(record["decommission"], True)
        self.assertNotIn("recommission", record)
        write_record(self.release, "install", {"archive-history": True, "decommission": True, "install": True})
        self.machine.outputs = ["current-service transaction recommissioned: 90002\n"]
        with patch.object(release_driver, "installed_build", return_value="90001"), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(DriverError, "holds build 90001, not 90002") as raised:
            command_run(self.context("--recover-service"), "install")
        self.assertEqual(raised.exception.status, MACHINE)
        self.assertTrue(release_driver._install_done(self.context()))

    def test_a_recovery_without_its_proof_line_records_nothing(self) -> None:
        self.complete_packaging()
        write_record(self.release, "install", {"archive-history": True, "decommission": True})
        self.machine.outputs = ["recovered\n"]
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(DriverError, "did not report"):
            command_run(self.context("--recover-install"), "install")
        self.assertNotIn("install", read_record(self.release, "install"))
        self.machine.outputs = ["DNS observation continuation recorded\n"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(command_run(self.context("--continue-after-dns-change"), "install"), 0)
        self.assertNotIn("install", read_record(self.release, "install"))

    def complete_packaging(self) -> None:
        ga, inputs = self.release.ga, self.release.stage_inputs
        write_record(self.release, "ci", {"commit": COMMIT, "run_id": 7})
        for path in (
            *(ga / "signed" / name for name in ("Clash for Mac.app", "notarization.json", "gatekeeper.json")),
            inputs / "hosted-ci.json", inputs / "component-review.json",
            self.release.review / "component-review-reviewed.json", inputs / "machine-closure.draft.json",
            inputs / "legal-review.json", self.release.review / "approval.json", inputs / "publication/inventory.json",
            self.release.preserved_publication / "tree-identity.json", ga / "prepackage/manifest.json",
            self.release.package_seal("dmg"), self.release.package_seal("updater"),
        ):
            self.touch(path)


class PathContractTests(unittest.TestCase):
    def test_driver_paths_match_the_release_contract(self) -> None:
        from scripts.publication import ga_release_contract as contract
        from scripts.release_artifact_set import DISTRIBUTION_SEAL_NAME, DMG_SEAL_NAME, UPDATER_SEAL_NAME

        release = Release("0.5.0", contract.GA_BUILD, Path("/h"), "v1.14.2")
        artifact = release.artifact
        self.assertEqual(release.ga, artifact / contract.GA_ROOT)
        self.assertEqual(release.stage_inputs / "hosted-ci.json", artifact / contract.HOSTED_CI_INPUT)
        self.assertEqual(release.acceptance / "runtime-acceptance.json", artifact / contract.RUNTIME_ACCEPTANCE_INPUT)
        self.assertEqual(release.ga / "prepackage", artifact / contract.PREPACKAGE_OUTPUT)
        self.assertEqual(release.package_seal("dmg"), artifact / contract.DMG_SET / DMG_SEAL_NAME)
        self.assertEqual(release.package_seal("updater"), artifact / contract.UPDATER_SET / UPDATER_SEAL_NAME)
        self.assertEqual(release.package_seal("distribution").name, DISTRIBUTION_SEAL_NAME)

    def test_every_stage_has_a_unique_name(self) -> None:
        self.assertEqual(len(STAGES_BY_NAME), len(STAGES))


class AcceptanceTests(DriverFixture):
    def test_loopback_proxies_in_any_dictionary_are_found(self) -> None:
        text = """<dictionary> {
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  SOCKSEnable : 0
  SOCKSProxy : 127.0.0.1
  __SCOPED__ : <dictionary> {
    en0 : <dictionary> {
      HTTPSEnable : 1
      HTTPSPort : 8080
      HTTPSProxy : localhost
    }
  }
  ExceptionsList : <array> {
    0 : *.local
  }
}
"""
        self.assertEqual(release_driver_acceptance.loopback_proxies(text),
                         ["HTTPS localhost:8080", "HTTP 127.0.0.1:7890"])
        self.assertEqual(release_driver_acceptance.loopback_proxies(text.replace("Enable : 1", "Enable : 0")), [])

    def test_system_extension_rows_that_no_approval_can_fix(self) -> None:
        def row(version: str, state: str, team: str = "YKUPL7Z869", flags: str = "\t") -> str:
            return f"{flags}\t{team}\tcom.bill.clashformac.packet-tunnel ({version})\tClash for Mac Packet Tunnel\t{state}"

        problem = release_driver_acceptance.system_extension_problem
        retained = row("0.5.0/90001", "[terminated waiting to uninstall on reboot]")
        self.assertIsNone(problem("\n".join([retained, row("0.5.0/90002", "[activated enabled]", flags="*\t*")]), "90002"))
        # Before collect the previous build may still be the active one.
        self.assertIsNone(problem(row("0.5.0/90001", "[activated enabled]", flags="*\t*"), "90002"))
        self.assertRegex(problem(row("0.5.0/90003", "[activated enabled]"), "90002"), "later")
        self.assertRegex(problem(row("0.5.0/90002", "[terminated waiting to uninstall on reboot]"), "90002"), "removed")
        self.assertRegex(problem(row("0.5.0/90001", "[activated enabled]", team="OTHERTEAM1"), "90002"), "another team")

    def test_the_registry_names_both_ga_evidence_instances(self) -> None:
        instances = release_driver_acceptance.evidence_instances(release_driver.REPOSITORY)
        self.assertEqual([item.name for item in instances], list(release_driver_acceptance.GA_INSTANCES))
        self.assertTrue(all(item.project and item.zone and item.address for item in instances))

    def test_collect_stops_the_instances_when_they_never_become_reachable(self) -> None:
        self.prepare_collect()
        self.machine.answer(("/usr/bin/dig",), stdout="")
        with patch.object(release_driver_acceptance, "REACHABILITY_ATTEMPTS", 2), \
                patch.object(release_driver_acceptance.time, "sleep"), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(DriverError, "UDP 53"):
            release_driver_acceptance._collect(self.context())
        actions = [argv[3] for argv in self.gcloud_calls()]
        self.assertEqual(actions.count("start"), 2)
        self.assertEqual(actions.count("stop"), 2)
        self.assertEqual(self.machine.executed, [])

    def test_a_failed_stop_is_reported_without_hiding_the_collect_failure(self) -> None:
        self.prepare_collect()
        self.machine.answer(("/usr/bin/dig",), stdout="")
        for instance in release_driver_acceptance.evidence_instances(release_driver.REPOSITORY):
            self.machine.answer((release_driver_acceptance.GCLOUD, "compute", "instances", "stop", instance.name), status=1)
        with patch.object(release_driver_acceptance, "REACHABILITY_ATTEMPTS", 1), \
                patch.object(release_driver_acceptance.time, "sleep"), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as errors, \
                self.assertRaisesRegex(DriverError, "UDP 53"):
            release_driver_acceptance._collect(self.context())
        self.assertIn("Stop the evidence instances yourself", errors.getvalue())

    def test_a_gcloud_refusal_names_its_reason_and_still_stops_the_instances(self) -> None:
        self.prepare_collect()
        first = release_driver_acceptance.evidence_instances(release_driver.REPOSITORY)[0]
        self.machine.answer((release_driver_acceptance.GCLOUD, "compute", "instances", "start", first.name), status=1,
                            stderr="ERROR: (gcloud.compute.instances.start) Reauthentication failed.\n")
        with contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(DriverError, f"could not start {first.name}: ERROR: .*Reauthentication failed"):
            release_driver_acceptance._collect(self.context())
        self.assertEqual([argv[3] for argv in self.gcloud_calls()].count("stop"), 2)

    def test_every_instance_gets_its_own_stop_attempt(self) -> None:
        self.prepare_collect()
        first, second = release_driver_acceptance.evidence_instances(release_driver.REPOSITORY)
        self.machine.answer((release_driver_acceptance.GCLOUD, "compute", "instances", "stop", first.name),
                            status=1, stderr="ERROR: (gcloud.compute.instances.stop) quota exceeded\n")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as errors, \
                self.assertRaisesRegex(DriverError, f"not all stopped: .*{first.name}.*quota exceeded"):
            release_driver_acceptance._stop_instances(
                self.context(), (first, second), report_only=False
            )
        self.assertEqual([argv[4] for argv in self.gcloud_calls() if argv[3] == "stop"], [first.name, second.name])
        self.assertIn(f"gcloud compute instances stop {first.name}", errors.getvalue())
        self.assertNotIn(f"gcloud compute instances stop {second.name}", errors.getvalue())

    def prepare_collect(self) -> None:
        (self.release.acceptance / "migration-journals").mkdir(parents=True)
        self.machine.answer(("/bin/ps",), stdout="/usr/sbin/cfprefsd\n")
        self.machine.answer(("/usr/sbin/scutil", "--nc", "list"), stdout="")
        self.machine.answer(("/usr/sbin/scutil", "--proxy"), stdout="<dictionary> {\n}\n")
        self.machine.answer(("/usr/bin/systemextensionsctl", "list"), stdout="")
        self.machine.answer(("/usr/bin/pmset",), stdout="Now drawing from 'AC Power'\n")
        self.machine.answer(("/sbin/route",), stdout="   interface: en0\n")
        self.machine.answer((release_driver_acceptance.GCLOUD, "compute", "instances", "start"))
        self.machine.answer((release_driver_acceptance.GCLOUD, "compute", "instances", "stop"))
        for instance in release_driver_acceptance.evidence_instances(release_driver.REPOSITORY):
            self.machine.answer(
                (release_driver_acceptance.GCLOUD, "compute", "instances", "describe", instance.name),
                stdout=instance.address + "\n",
            )
        patcher = patch.object(release_driver_acceptance, "installed_build", return_value="90002")
        patcher.start()
        self.addCleanup(patcher.stop)

    def gcloud_calls(self) -> list[tuple[str, ...]]:
        return [call for call in self._calls if call[0] == release_driver_acceptance.GCLOUD]

    def setUp(self) -> None:
        super().setUp()
        self._calls: list[tuple[str, ...]] = []
        original = self.machine.read

        def recording(argv, *, timeout=60, cwd=None):
            self._calls.append(tuple(argv))
            return original(argv, timeout=timeout, cwd=cwd)

        self.machine.read = recording  # type: ignore[method-assign]
        self.enroll()


class PreflightTests(unittest.TestCase):
    # Steps that assert the hosted runner's own environment; they have no local
    # equivalent and check no repository content.
    HOSTED_ENVIRONMENT_STEPS = {
        "Assert exact CI source and workflow identity",
        "Select latest available Xcode",
        "Record Apple validation toolchain",
        "Assert Apple Silicon host",
        "Assert selected Apple validation toolchain",
        # Runs the unsigned candidate build that the gate lanes also cover.
        "Build and verify unsigned 0.5.0 validation skeleton (50000)",
    }

    def test_every_inline_workflow_step_is_classified(self) -> None:
        workflow = (release_driver.REPOSITORY / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        inline = set()
        for step in re.split(r"\n      - ", workflow)[1:]:
            name = re.match(r"name: (.*)", step)
            if name and re.search(r"^\s*run:", step, re.M) and "run_release_ci_gate.sh" not in step:
                inline.add(re.sub(r" \$\{\{.*$", "", name.group(1)).strip())
        self.assertEqual(inline, self.HOSTED_ENVIRONMENT_STEPS | set(release_driver.INLINE_CONTENT_STEPS))

    def test_preflight_runs_the_pinned_shellcheck_exactly_as_the_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            machine = FakeMachine(Path(directory))
            machine.answer(("/bin/bash", "-n"))
            machine.answer(("/bin/zsh", "-n"))
            machine.answer((release_driver.SHELLCHECK, "--version"), stdout="ShellCheck\nversion: 0.11.0\n")
            machine.answer((release_driver.SHELLCHECK, "-x"), status=1, stdout="SC2031 (info): CFW_GA_BUILD was modified")
            context = Context(Release("0.5.0", "90002", Path(directory), "v1.14.2"), release_driver.REPOSITORY,
                              {"SHELLCHECK_VERSION": "0.11.0"}, machine)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(release_driver.command_preflight(context), 1)
            self.assertIn("SC2031", output.getvalue())
            machine.answer((release_driver.SHELLCHECK, "--version"), stdout="ShellCheck\nversion: 0.10.0\n")
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(DriverError, "pins ShellCheck 0.11.0"):
                release_driver.command_preflight(context)

    def test_preflight_reports_the_syntax_error_the_shell_printed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            machine = FakeMachine(Path(directory))
            machine.answer(("/bin/bash", "-n"), status=2, stderr="line 3: syntax error near unexpected token `fi'\n")
            machine.answer(("/bin/zsh", "-n"))
            machine.answer((release_driver.SHELLCHECK, "--version"), stdout="ShellCheck\nversion: 0.11.0\n")
            machine.answer((release_driver.SHELLCHECK, "-x"))
            context = Context(Release("0.5.0", "90002", Path(directory), "v1.14.2"), release_driver.REPOSITORY,
                              {"SHELLCHECK_VERSION": "0.11.0"}, machine)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(release_driver.command_preflight(context), 1)
        self.assertIn("syntax error near unexpected token", output.getvalue())


class EntryPointTests(unittest.TestCase):
    """The driver as the operator starts it: run as __main__ by the release launcher."""

    def run_driver(self, home: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", "-p", "-c",
             'set -euo pipefail; source "$1/scripts/release_python_launcher.sh"; '
             'cfw_run_release_python_script "$1" "$1/scripts/release_driver.py" "${@:2}"',
             "release-driver-test", str(release_driver.REPOSITORY), *arguments],
            cwd=release_driver.REPOSITORY,
            env={"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C",
                 "CFW_RELEASE_PYTHON_EXECUTABLE": sys.executable},
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def test_a_refusal_raised_in_a_stage_module_is_one_line_with_its_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            ledger = home / ".cfm-release-tooling/releases/shipped.json"
            ledger.parent.mkdir(parents=True)
            ledger.write_text("{}\n", encoding="utf-8")
            completed = self.run_driver(home, "status")
        self.assertEqual(completed.stderr, f"refusing: {ledger} is not the shipped-release ledger\n")
        self.assertEqual(completed.returncode, PREREQUISITE)
        self.assertEqual(completed.stdout, "")

    def test_no_driver_module_imports_the_entry_point(self) -> None:
        # The launcher runs scripts/release_driver.py as __main__; a module that
        # imported it by name would load a second copy with its own DriverError.
        modules = sorted((release_driver.REPOSITORY / "scripts").glob("release_driver*.py"))
        self.assertEqual([path.name for path in modules], [
            "release_driver.py", "release_driver_acceptance.py", "release_driver_context.py",
            "release_driver_review.py"])
        for path in modules:
            imported: set[str] = set()
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
                    imported.update(f"{node.module}.{alias.name}" for alias in node.names)
                elif isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
            with self.subTest(module=path.name):
                self.assertNotIn("scripts.release_driver", imported)


class HostedRunSelectionTests(unittest.TestCase):
    def run_listing(self, *runs: dict) -> list:
        from scripts import github_hosted_ci_receipt as receipt

        listing = {"total_count": len(runs), "workflow_runs": list(runs)}
        with patch.object(receipt, "_fetch_api_json", return_value=listing) as fetched:
            try:
                return [receipt.latest_commit_run(COMMIT)]
            finally:
                path = fetched.call_args.args[0]
                self.assertRegex(path, receipt.API_PATH_RE)

    def candidate(self, identifier: int, status: str = "completed", conclusion: str = "success") -> dict:
        from scripts import github_hosted_ci_receipt as receipt

        return {"id": identifier, "head_sha": COMMIT, "event": "pull_request", "workflow_id": receipt.WORKFLOW_ID,
                "status": status, "conclusion": conclusion}

    def test_the_newest_successful_run_of_the_commit_is_selected(self) -> None:
        self.assertEqual(self.run_listing(self.candidate(11), self.candidate(12)), [12])

    def test_a_newest_run_in_progress_or_failed_is_never_skipped(self) -> None:
        from scripts.publication.common import PublicationError

        with self.assertRaisesRegex(PublicationError, "still in_progress"):
            self.run_listing(self.candidate(11), self.candidate(12, status="in_progress", conclusion=None))
        with self.assertRaisesRegex(PublicationError, "concluded failure"):
            self.run_listing(self.candidate(11), self.candidate(12, conclusion="failure"))
        with self.assertRaisesRegex(PublicationError, "no pull_request run"):
            self.run_listing(dict(self.candidate(11), head_sha="b" * 40))

    def test_preflight_refuses_a_run_that_tested_another_commit(self) -> None:
        from scripts import github_hosted_ci_receipt as receipt
        from scripts.publication.common import PublicationError

        identity = {"repositoryCommit": COMMIT, "releaseSourceSha256": "1" * 64}
        live = {"tested_source": {"repository_commit": "b" * 40}, "run": {"id": 3, "run_attempt": 1}}
        with patch.object(receipt, "current_identity", return_value=identity), \
                patch.object(receipt, "_workflow_source_bytes", return_value=b"workflow"), \
                patch.object(receipt, "_live_receipt", return_value=live), \
                self.assertRaisesRegex(PublicationError, "tested another commit"):
            receipt.preflight_run(Path("/repository"), 3)

    def test_the_preflight_result_line_is_the_one_the_ci_stage_parses(self) -> None:
        from scripts import github_hosted_ci_receipt as receipt

        passed = {"run": {"id": 4242, "run_attempt": 2, "head_sha": COMMIT}, "jobs": [{}, {}, {}]}
        with patch.object(receipt, "preflight_run", return_value=passed), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            receipt._preflight_main(receipt._arguments(["preflight"]))
        self.assertEqual(release_driver.PREFLIGHT_RESULT_RE.findall(output.getvalue()), [("4242", COMMIT)])


if __name__ == "__main__":
    unittest.main()
