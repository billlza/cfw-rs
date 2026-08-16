from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts.dormant_app_install import (
    AppIdentity,
    CandidateIdentity,
    CommandResult,
    DormantInstallTransaction,
    InstallError,
    InstallPaths,
    InstallRuntime,
    JOURNAL_NAME,
    JOURNAL_PENDING_NAME,
    LOCK_NAME,
    JournalStore,
    PARTIAL_PAYLOAD_NAME,
    PAYLOAD_NAME,
    STAGING_PREFIX,
    TARGET_NAME,
    capture_cfw_guard,
    _parse_btm_values,
    _normalize_routes,
    _parse_processes,
    _require_fixed_command,
    _run_bounded_process,
    production_command_runner,
    require_cfm_dormant,
    swap_names,
    validate_journal,
    _require_journal_successor,
)


OLD = AppIdentity("0.4.0", "40006", "a" * 64)
NEW = AppIdentity("0.4.0", "40009", "b" * 64)
CANDIDATE = CandidateIdentity(
    app=NEW,
    manifest_sha256="c" * 64,
    repository_commit="d" * 40,
    release_source_sha256="e" * 64,
)


def btm_fixture(
    *, identifier: str = "16.example.unrelated", include_gui_uid: bool = True
) -> str:
    sections = [
        (-2, "FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE"),
        (0, "FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000"),
    ]
    if include_gui_uid:
        sections.append((501, "61C4D840-8827-4F43-ADE6-BCBA90A9229D"))
    rendered = []
    for position, (uid, section_uuid) in enumerate(sections, start=1):
        item_identifier = identifier if uid == -2 else f"16.example.user-{uid}"
        item_uuid = f"00000000-0000-4000-8000-{position:012d}"
        rendered.append(
            "\n".join(
                (
                    "========================",
                    f" Records for UID {uid} : {section_uuid}",
                    "========================",
                    "",
                    " ServiceManagement migrated: false",
                    " LaunchServices registered: false",
                    "",
                    " Items:",
                    "",
                    " #1:",
                    f"                 UUID: {item_uuid}",
                    "                 Name: Fixture",
                    "       Developer Name: Fixture Developer",
                    "                 Type: daemon (0x10)",
                    "                Flags: [  ] (0)",
                    "          Disposition: [disabled, allowed, not notified] (0x2)",
                    f"           Identifier: {item_identifier}",
                    "                  URL: (null)",
                    "           Generation: 1",
                )
            )
        )
    return "\n\n".join(rendered) + "\n\n\n\n"


def guard(*, proxy: str = "1" * 64) -> dict[str, object]:
    return {
        "cfw_processes": [
            {
                "binary_sha256": "2" * 64,
                "path": (
                    "/Applications/Clash for Windows.app/Contents/MacOS/"
                    "Clash for Windows"
                ),
                "pid": 100,
                "started_at": "Thu Jul 23 15:20:55 2026",
                "uid": 501,
            },
            {
                "binary_sha256": "3" * 64,
                "path": (
                    "/Applications/Clash for Windows.app/Contents/Resources/"
                    "static/files/darwin/x64/clash-darwin"
                ),
                "pid": 101,
                "started_at": "Thu Jul 23 15:21:03 2026",
                "uid": 0,
            },
        ],
        "dns_sha256": "4" * 64,
        "proxy_sha256": proxy,
        "routes_ipv4_sha256": "5" * 64,
        "routes_ipv6_sha256": "6" * 64,
        "tun_sha256": "7" * 64,
    }


class GuardSequence:
    def __init__(self, values: list[dict[str, object]]) -> None:
        self.values = values
        self.index = 0

    def __call__(self) -> dict[str, object]:
        if self.index >= len(self.values):
            return self.values[-1]
        value = self.values[self.index]
        self.index += 1
        return value


class SimulatedCrash(BaseException):
    pass


class DormantInstallFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.candidate = self.repository / "target/candidates/0.4.0/signed" / TARGET_NAME
        self.parent = self.root / "Applications"
        self.target = self.parent / TARGET_NAME
        self.candidate.mkdir(parents=True)
        self.parent.mkdir()
        self.target.mkdir()
        self._write_identity(self.candidate, NEW)
        self._write_identity(self.target, OLD)
        (self.candidate / "candidate.txt").write_text("new\n", encoding="utf-8")
        (self.target / "installed.txt").write_text("old\n", encoding="utf-8")
        self.paths = InstallPaths(
            repository=self.repository,
            candidate_app=self.candidate,
            candidate_manifest=self.candidate.parent / f"{TARGET_NAME}.manifest.json",
            target_parent=self.parent,
        )
        self.admit_count = 0
        self.copy_count = 0
        self.swap_count = 0

    def cleanup(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_identity(path: Path, identity: AppIdentity) -> None:
        (path / "identity.json").write_text(
            json.dumps(identity.document(), sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def read_identity(path: Path) -> AppIdentity:
        try:
            value = json.loads((path / "identity.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise InstallError("fixture_identity_invalid", "fixture identity is incomplete") from error
        return AppIdentity(value["version"], value["build_number"], value["tree_sha256"])

    def copy(self, source: Path, destination: Path) -> None:
        self.copy_count += 1
        shutil.copytree(source, destination, symlinks=True)

    def admit(self, _paths: InstallPaths) -> CandidateIdentity:
        self.admit_count += 1
        return CANDIDATE

    def swap(self, first_fd: int, first_name: str, second_fd: int, second_name: str) -> None:
        self.swap_count += 1
        swap_names(first_fd, first_name, second_fd, second_name)

    def runtime(
        self,
        *,
        captures: list[dict[str, object]] | None = None,
        dormant=None,
        quick=None,
        swap=None,
    ) -> InstallRuntime:
        return InstallRuntime(
            capture_guard=GuardSequence(captures or [guard()]),
            require_cfm_dormant=dormant or (lambda _guard: None),
            require_cfm_process_absent=quick or (lambda: []),
            admit_candidate=self.admit,
            read_identity=self.read_identity,
            copy_candidate=self.copy,
            sync_tree=lambda _path: None,
            swap=swap or self.swap,
            verify_bundle=lambda _path, _identity: None,
        )

    def transaction(self, **runtime_arguments) -> DormantInstallTransaction:
        return DormantInstallTransaction(self.paths, self.runtime(**runtime_arguments))

    def journal(self) -> dict[str, object]:
        return json.loads((self.parent / JOURNAL_NAME).read_text(encoding="utf-8"))

    def write_pending(self, document: dict[str, object]) -> None:
        path = self.parent / JOURNAL_PENDING_NAME
        path.write_text(
            json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def staging_payload(self) -> Path:
        document = self.journal()
        return self.parent / document["staging_name"] / PAYLOAD_NAME

    def partial_payload(self) -> Path:
        document = self.journal()
        return self.parent / document["staging_name"] / PARTIAL_PAYLOAD_NAME


@unittest.skipUnless(os.uname().sysname == "Darwin", "RENAME_SWAP is macOS-only")
class DormantInstallTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = DormantInstallFixture()
        self.addCleanup(self.fixture.cleanup)

    def test_install_atomically_preserves_old_bundle_and_closes_guard(self) -> None:
        result = self.fixture.transaction().install()

        self.assertEqual(result["phase"], "installed")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), OLD)
        self.assertEqual(self.fixture.swap_count, 1)
        self.assertEqual(result["guards"][0]["before"], result["guards"][0]["after"])
        journal = self.fixture.parent / JOURNAL_NAME
        self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
        self.assertEqual(journal.parent, self.fixture.parent)
        self.assertNotIn(self.fixture.target, journal.parents)

    def test_registered_or_running_cfm_blocks_before_any_journal_or_copy(self) -> None:
        def blocked(_guard) -> None:
            raise InstallError("cfm_service_registered", "fixture service")

        with self.assertRaisesRegex(InstallError, "fixture service"):
            self.fixture.transaction(dormant=blocked).install()

        self.assertFalse((self.fixture.parent / JOURNAL_NAME).exists())
        self.assertFalse((self.fixture.parent / JOURNAL_PENDING_NAME).exists())
        self.assertFalse((self.fixture.parent / LOCK_NAME).exists())
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.admit_count, 0)
        self.assertEqual(self.fixture.copy_count, 0)
        self.assertEqual(self.fixture.swap_count, 0)

    def test_crash_before_swap_recovers_from_staged_candidate(self) -> None:
        def crash_before_swap(*_arguments) -> None:
            raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            self.fixture.transaction(swap=crash_before_swap).install()
        self.assertEqual(self.fixture.journal()["phase"], "staged")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), NEW)

        result = self.fixture.transaction().recover()
        self.assertEqual(result["phase"], "installed")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), OLD)
        self.assertTrue(all(item["before"] == item["after"] for item in result["guards"]))

    def test_mid_copy_partial_payload_is_discarded_and_rebuilt_on_recovery(self) -> None:
        def partial_copy(_source: Path, destination: Path) -> None:
            destination.mkdir()
            (destination / "partial.txt").write_text("incomplete\n", encoding="utf-8")
            raise SimulatedCrash()

        runtime = self.fixture.runtime()
        runtime = replace(runtime, copy_candidate=partial_copy)
        with self.assertRaises(SimulatedCrash):
            DormantInstallTransaction(self.fixture.paths, runtime).install()

        self.assertEqual(self.fixture.journal()["phase"], "prepared")
        self.assertTrue(self.fixture.partial_payload().is_dir())
        self.assertFalse(self.fixture.staging_payload().exists())
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)

        result = self.fixture.transaction().recover()
        self.assertEqual(result["phase"], "installed")
        self.assertFalse(self.fixture.partial_payload().exists())
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), OLD)

    def test_crash_after_atomic_swap_is_identified_without_second_swap(self) -> None:
        def swap_then_crash(first_fd: int, first_name: str, second_fd: int, second_name: str) -> None:
            self.fixture.swap(first_fd, first_name, second_fd, second_name)
            raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            self.fixture.transaction(swap=swap_then_crash).install()
        self.assertEqual(self.fixture.journal()["phase"], "staged")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), OLD)
        self.assertEqual(self.fixture.swap_count, 1)

        result = self.fixture.transaction().recover()
        self.assertEqual(result["phase"], "installed")
        self.assertEqual(self.fixture.swap_count, 1)
        self.assertTrue(all(item["before"] == item["after"] for item in result["guards"]))

    def test_guard_drift_during_heavy_check_blocks_before_swap(self) -> None:
        changed = guard(proxy="8" * 64)
        current = guard()
        checks = 0

        def capture() -> dict[str, object]:
            return current

        def drift_during_dormancy(_guard) -> None:
            nonlocal checks, current
            checks += 1
            if checks == 6:
                current = changed

        runtime = replace(
            self.fixture.runtime(dormant=drift_during_dormancy),
            capture_guard=capture,
        )
        with self.assertRaisesRegex(InstallError, "Clash for Windows identity"):
            DormantInstallTransaction(self.fixture.paths, runtime).install()

        self.assertEqual(checks, 6)
        self.assertEqual(self.fixture.journal()["phase"], "staged")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), NEW)
        self.assertEqual(self.fixture.swap_count, 0)

    def test_cfm_process_appearing_during_final_capture_blocks_before_swap(self) -> None:
        captures = 0
        cfm_active = False

        def capture() -> dict[str, object]:
            nonlocal captures, cfm_active
            captures += 1
            if captures == 12:
                cfm_active = True
            return guard()

        def quick_process_check() -> list[dict[str, object]]:
            if cfm_active:
                raise InstallError("cfm_process_running", "fixture CFM appeared")
            return []

        runtime = replace(
            self.fixture.runtime(quick=quick_process_check),
            capture_guard=capture,
        )
        with self.assertRaisesRegex(InstallError, "fixture CFM appeared"):
            DormantInstallTransaction(self.fixture.paths, runtime).install()

        self.assertEqual(captures, 12)
        self.assertEqual(self.fixture.journal()["phase"], "staged")
        self.assertEqual(self.fixture.swap_count, 0)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), NEW)

    def test_cfm_process_appearing_during_terminal_check_is_not_sealed(self) -> None:
        checks = 0
        cfm_active = False

        def becomes_active(_guard) -> None:
            nonlocal checks, cfm_active
            checks += 1
            if checks == 7:
                cfm_active = True

        def quick_process_check() -> list[dict[str, object]]:
            if cfm_active:
                raise InstallError("cfm_process_running", "fixture CFM appeared")
            return []

        with self.assertRaisesRegex(InstallError, "fixture CFM appeared"):
            self.fixture.transaction(
                dormant=becomes_active, quick=quick_process_check
            ).install()

        self.assertEqual(checks, 7)
        self.assertEqual(self.fixture.journal()["phase"], "swapped")
        self.assertIsNone(self.fixture.journal()["guards"][-1]["after"])
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), OLD)

    def test_staged_bundle_tamper_during_heavy_check_blocks_before_swap(self) -> None:
        checks = 0
        tampered = replace(NEW, tree_sha256="9" * 64)

        def tamper_staged(_guard) -> None:
            nonlocal checks
            checks += 1
            if checks == 6:
                self.fixture._write_identity(self.fixture.staging_payload(), tampered)

        with self.assertRaisesRegex(InstallError, "bundle layout differs"):
            self.fixture.transaction(dormant=tamper_staged).install()

        self.assertEqual(checks, 6)
        self.assertEqual(self.fixture.journal()["phase"], "staged")
        self.assertEqual(self.fixture.swap_count, 0)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), tampered)

    def test_target_tamper_during_terminal_check_is_not_sealed(self) -> None:
        checks = 0
        tampered = replace(NEW, tree_sha256="9" * 64)

        def tamper_target(_guard) -> None:
            nonlocal checks
            checks += 1
            if checks == 7:
                self.fixture._write_identity(self.fixture.target, tampered)

        with self.assertRaisesRegex(InstallError, "bundle layout differs"):
            self.fixture.transaction(dormant=tamper_target).install()

        journal = self.fixture.journal()
        self.assertEqual(checks, 7)
        self.assertEqual(journal["phase"], "swapped")
        self.assertIsNone(journal["guards"][-1]["after"])
        self.assertEqual(self.fixture.swap_count, 1)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), tampered)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), OLD)

    def test_unknown_staging_identity_blocks_recovery_without_swap(self) -> None:
        def crash_before_swap(*_arguments) -> None:
            raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            self.fixture.transaction(swap=crash_before_swap).install()
        self.fixture._write_identity(
            self.fixture.staging_payload(),
            replace(NEW, tree_sha256="9" * 64),
        )

        with self.assertRaisesRegex(InstallError, "unknown bundle identities"):
            self.fixture.transaction().recover()
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.swap_count, 0)

    def test_rollback_is_atomic_and_itself_crash_recoverable(self) -> None:
        installed = self.fixture.transaction().install()
        self.assertEqual(installed["phase"], "installed")

        def swap_then_crash(first_fd: int, first_name: str, second_fd: int, second_name: str) -> None:
            self.fixture.swap(first_fd, first_name, second_fd, second_name)
            raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            self.fixture.transaction(swap=swap_then_crash).rollback()
        self.assertEqual(self.fixture.journal()["phase"], "rollback-prepared")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), NEW)

        result = self.fixture.transaction().recover()
        self.assertEqual(result["phase"], "rolled-back")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), NEW)
        self.assertTrue(all(item["before"] == item["after"] for item in result["guards"]))

    def test_guard_drift_during_rollback_check_blocks_before_swap(self) -> None:
        self.fixture.transaction().install()
        current = guard()
        changed = guard(proxy="8" * 64)
        checks = 0

        def capture() -> dict[str, object]:
            return current

        def drift_during_dormancy(_guard) -> None:
            nonlocal checks, current
            checks += 1
            if checks == 3:
                current = changed

        runtime = replace(
            self.fixture.runtime(dormant=drift_during_dormancy),
            capture_guard=capture,
        )
        with self.assertRaisesRegex(InstallError, "Clash for Windows identity"):
            DormantInstallTransaction(self.fixture.paths, runtime).rollback()

        self.assertEqual(checks, 3)
        self.assertEqual(self.fixture.journal()["phase"], "rollback-prepared")
        self.assertEqual(self.fixture.swap_count, 1)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), OLD)

    def test_cfm_process_appearing_during_rollback_terminal_is_not_sealed(self) -> None:
        self.fixture.transaction().install()

        def swap_then_crash(
            first_fd: int, first_name: str, second_fd: int, second_name: str
        ) -> None:
            self.fixture.swap(first_fd, first_name, second_fd, second_name)
            raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            self.fixture.transaction(swap=swap_then_crash).rollback()
        self.assertEqual(self.fixture.journal()["phase"], "rollback-prepared")

        checks = 0
        cfm_active = False

        def becomes_active(_guard) -> None:
            nonlocal checks, cfm_active
            checks += 1
            if checks == 3:
                cfm_active = True

        def quick_process_check() -> list[dict[str, object]]:
            if cfm_active:
                raise InstallError("cfm_process_running", "fixture CFM appeared")
            return []

        with self.assertRaisesRegex(InstallError, "fixture CFM appeared"):
            self.fixture.transaction(
                dormant=becomes_active, quick=quick_process_check
            ).recover()

        journal = self.fixture.journal()
        self.assertEqual(checks, 3)
        self.assertEqual(journal["phase"], "rollback-swapped")
        self.assertIsNone(journal["guards"][-1]["after"])
        self.assertEqual(self.fixture.swap_count, 2)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), NEW)

    def test_rollback_bundle_tamper_during_heavy_check_blocks_before_swap(self) -> None:
        self.fixture.transaction().install()
        checks = 0
        tampered = replace(OLD, tree_sha256="9" * 64)

        def tamper_staged(_guard) -> None:
            nonlocal checks
            checks += 1
            if checks == 3:
                self.fixture._write_identity(self.fixture.staging_payload(), tampered)

        with self.assertRaisesRegex(InstallError, "bundle layout differs"):
            self.fixture.transaction(dormant=tamper_staged).rollback()

        self.assertEqual(checks, 3)
        self.assertEqual(self.fixture.journal()["phase"], "rollback-prepared")
        self.assertEqual(self.fixture.swap_count, 1)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), tampered)

    def test_rollback_target_tamper_during_terminal_check_is_not_sealed(self) -> None:
        self.fixture.transaction().install()

        def swap_then_crash(
            first_fd: int, first_name: str, second_fd: int, second_name: str
        ) -> None:
            self.fixture.swap(first_fd, first_name, second_fd, second_name)
            raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            self.fixture.transaction(swap=swap_then_crash).rollback()

        checks = 0
        tampered = replace(OLD, tree_sha256="9" * 64)

        def tamper_target(_guard) -> None:
            nonlocal checks
            checks += 1
            if checks == 3:
                self.fixture._write_identity(self.fixture.target, tampered)

        with self.assertRaisesRegex(InstallError, "bundle layout differs"):
            self.fixture.transaction(dormant=tamper_target).recover()

        journal = self.fixture.journal()
        self.assertEqual(checks, 3)
        self.assertEqual(journal["phase"], "rollback-swapped")
        self.assertIsNone(journal["guards"][-1]["after"])
        self.assertEqual(self.fixture.swap_count, 2)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), tampered)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), NEW)

    def test_second_install_cannot_overwrite_recovery_journal_or_backup(self) -> None:
        self.fixture.transaction().install()
        backup = self.fixture.staging_payload()
        with self.assertRaisesRegex(InstallError, "not newer than installed"):
            self.fixture.transaction().install()
        self.assertEqual(self.fixture.read_identity(backup), OLD)
        self.assertEqual(self.fixture.swap_count, 1)

    def test_journal_publish_reply_loss_recovers_from_durable_prepared_record(self) -> None:
        publish = JournalStore._rename_pending
        calls = 0

        def publish_then_crash(store: JournalStore) -> None:
            nonlocal calls
            calls += 1
            publish(store)
            if calls == 1:
                raise SimulatedCrash()

        with patch.object(JournalStore, "_rename_pending", publish_then_crash):
            with self.assertRaises(SimulatedCrash):
                self.fixture.transaction().install()

        self.assertEqual(self.fixture.journal()["phase"], "prepared")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        result = self.fixture.transaction().recover()
        self.assertEqual(result["phase"], "installed")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)

    def test_fsynced_pending_next_generation_is_promoted_during_recovery(self) -> None:
        installed = self.fixture.transaction().install()
        pending = json.loads(json.dumps(installed))
        pending["sequence"] += 1
        pending["phase"] = "rollback-prepared"
        pending["guards"].append(
            {"after": None, "before": guard(), "operation": "rollback"}
        )
        self.fixture.write_pending(pending)

        with JournalStore(self.fixture.paths) as store:
            with store.locked():
                result = store.load()
        self.assertIsNotNone(result)
        self.assertEqual(result["sequence"], pending["sequence"])
        self.assertEqual(result["phase"], "rollback-prepared")
        self.assertEqual(self.fixture.journal()["sequence"], pending["sequence"])
        self.assertFalse((self.fixture.parent / JOURNAL_PENDING_NAME).exists())
        self.assertEqual(self.fixture.swap_count, 1)

    def test_pending_generation_with_broken_lineage_fails_without_swap(self) -> None:
        installed = self.fixture.transaction().install()
        pending = json.loads(json.dumps(installed))
        pending["sequence"] += 2
        self.fixture.write_pending(pending)

        with self.assertRaisesRegex(InstallError, "pending journal lineage"):
            self.fixture.transaction().recover()
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.swap_count, 1)

    def test_malformed_pending_generation_fails_without_touching_bundles(self) -> None:
        self.fixture.transaction().install()
        pending = self.fixture.parent / JOURNAL_PENDING_NAME
        pending.write_text("{}\n", encoding="utf-8")
        pending.chmod(0o600)

        with self.assertRaisesRegex(InstallError, "unexpected field set"):
            self.fixture.transaction().recover()
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.swap_count, 1)

    def test_active_cfm_blocks_recovery_before_lock_or_pending_mutation(self) -> None:
        self.fixture.transaction().install()
        journal = self.fixture.parent / JOURNAL_NAME
        lock = self.fixture.parent / LOCK_NAME
        pending = self.fixture.parent / JOURNAL_PENDING_NAME
        pending.write_text("{}\n", encoding="utf-8")
        pending.chmod(0o600)
        before = {
            "journal": journal.read_bytes(),
            "lock_inode": lock.stat().st_ino,
            "pending": pending.read_bytes(),
            "target": self.fixture.read_identity(self.fixture.target),
            "backup": self.fixture.read_identity(self.fixture.staging_payload()),
        }

        def blocked(_guard) -> None:
            raise InstallError("cfm_process_running", "fixture active CFM")

        transaction = self.fixture.transaction(dormant=blocked)
        with self.assertRaisesRegex(InstallError, "fixture active CFM"):
            transaction.recover()
        self.assertEqual(journal.read_bytes(), before["journal"])
        self.assertEqual(lock.stat().st_ino, before["lock_inode"])
        self.assertEqual(pending.read_bytes(), before["pending"])
        self.assertEqual(self.fixture.read_identity(self.fixture.target), before["target"])
        self.assertEqual(
            self.fixture.read_identity(self.fixture.staging_payload()), before["backup"]
        )

    def test_active_cfm_blocks_rollback_before_transaction_mutation(self) -> None:
        self.fixture.transaction().install()
        journal = self.fixture.parent / JOURNAL_NAME
        lock = self.fixture.parent / LOCK_NAME
        before_journal = journal.read_bytes()
        before_lock_inode = lock.stat().st_ino

        def blocked(_guard) -> None:
            raise InstallError("cfm_service_registered", "fixture registered CFM")

        with self.assertRaisesRegex(InstallError, "fixture registered CFM"):
            self.fixture.transaction(dormant=blocked).rollback()
        self.assertEqual(journal.read_bytes(), before_journal)
        self.assertEqual(lock.stat().st_ino, before_lock_inode)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), OLD)

    def test_cfm_race_after_lock_blocks_before_pending_promotion(self) -> None:
        self.fixture.transaction().install()
        journal = self.fixture.parent / JOURNAL_NAME
        pending = self.fixture.parent / JOURNAL_PENDING_NAME
        pending.write_text("{}\n", encoding="utf-8")
        pending.chmod(0o600)
        before_journal = journal.read_bytes()
        before_pending = pending.read_bytes()
        checks = 0

        def races(_guard) -> None:
            nonlocal checks
            checks += 1
            if checks == 2:
                raise InstallError("cfm_service_registered", "fixture CFM raced")

        with self.assertRaisesRegex(InstallError, "fixture CFM raced"):
            self.fixture.transaction(dormant=races).recover()
        self.assertEqual(checks, 2)
        self.assertEqual(journal.read_bytes(), before_journal)
        self.assertEqual(pending.read_bytes(), before_pending)
        self.assertEqual(self.fixture.swap_count, 1)


class DormantInstallValidationTests(unittest.TestCase):
    def test_terminal_install_pending_is_a_precise_guard_closure(self) -> None:
        transaction_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        installed = {
            "candidate": CANDIDATE.document(),
            "document": "cfw-dormant-app-install-v1",
            "guards": [{"after": guard(), "before": guard(), "operation": "install"}],
            "phase": "installed",
            "previous": OLD.document(),
            "schema_version": 1,
            "sequence": 4,
            "staging_name": f"{STAGING_PREFIX}{transaction_id}",
            "transaction_id": transaction_id,
        }
        swapped = json.loads(json.dumps(installed))
        swapped["phase"] = "swapped"
        swapped["sequence"] = 3
        swapped["guards"][-1]["after"] = None
        validate_journal(swapped)
        validate_journal(installed)
        _require_journal_successor(swapped, installed)

    def test_terminal_rollback_pending_is_a_precise_guard_closure(self) -> None:
        transaction_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        rolled_back = {
            "candidate": CANDIDATE.document(),
            "document": "cfw-dormant-app-install-v1",
            "guards": [
                {"after": guard(), "before": guard(), "operation": "install"},
                {"after": guard(), "before": guard(), "operation": "rollback"},
            ],
            "phase": "rolled-back",
            "previous": OLD.document(),
            "schema_version": 1,
            "sequence": 7,
            "staging_name": f"{STAGING_PREFIX}{transaction_id}",
            "transaction_id": transaction_id,
        }
        rollback_swapped = json.loads(json.dumps(rolled_back))
        rollback_swapped["phase"] = "rollback-swapped"
        rollback_swapped["sequence"] = 6
        rollback_swapped["guards"][-1]["after"] = None
        validate_journal(rollback_swapped)
        validate_journal(rolled_back)
        _require_journal_successor(rollback_swapped, rolled_back)

    def test_journal_rejects_caller_chosen_staging_name(self) -> None:
        document = {
            "candidate": CANDIDATE.document(),
            "document": "cfw-dormant-app-install-v1",
            "guards": [{"after": guard(), "before": guard(), "operation": "install"}],
            "phase": "installed",
            "previous": OLD.document(),
            "schema_version": 1,
            "sequence": 4,
            "staging_name": "../../arbitrary",
            "transaction_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        }
        with self.assertRaisesRegex(InstallError, "staging directory"):
            validate_journal(document)

    def test_staging_name_is_uuid_bound_not_a_public_path_api(self) -> None:
        transaction_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        self.assertEqual(
            f"{STAGING_PREFIX}{transaction_id}",
            ".com.bill.clashformac.dormant-install.aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        )

    def test_production_candidate_is_fixed_to_40009_validation_worktree(self) -> None:
        paths = InstallPaths.production()
        self.assertTrue(
            paths.candidate_app.as_posix().endswith(
                "/target/release-worktrees/40009/target/candidates/0.4.0/"
                "validation/40009/signed/Clash for Mac.app"
            )
        )

    def test_inactive_but_registered_cfm_job_still_blocks(self) -> None:
        def runner(arguments: tuple[str, ...]) -> CommandResult:
            if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                return CommandResult(0, "1 0 Thu Jul 23 15:20:55 2026 /sbin/launchd\n", "")
            if arguments[:2] == ("/bin/launchctl", "print"):
                return CommandResult(0, "state = not running\n", "")
            raise AssertionError(arguments)

        with self.assertRaises(InstallError) as captured:
            require_cfm_dormant(guard(), runner)
        self.assertEqual(captured.exception.code, "cfm_service_registered")

    def test_unobservable_cfm_job_state_is_not_treated_as_absent(self) -> None:
        def runner(arguments: tuple[str, ...]) -> CommandResult:
            if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                return CommandResult(0, "1 0 Thu Jul 23 15:20:55 2026 /sbin/launchd\n", "")
            if arguments[:2] == ("/bin/launchctl", "print"):
                return CommandResult(1, "", "permission denied\n")
            raise AssertionError(arguments)

        with self.assertRaises(InstallError) as captured:
            require_cfm_dormant(guard(), runner)
        self.assertEqual(captured.exception.code, "cfm_service_observation_failed")

    def test_backup_bundle_host_process_is_not_mistaken_for_dormancy(self) -> None:
        def runner(arguments: tuple[str, ...]) -> CommandResult:
            if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                return CommandResult(
                    0,
                    "42 501 Thu Jul 23 15:20:55 2026 "
                    "/Applications/.Clash for Mac.backup-40006/Contents/"
                    "MacOS/clash-for-mac\n",
                    "",
                )
            raise AssertionError(arguments)

        with self.assertRaises(InstallError) as captured:
            require_cfm_dormant(guard(), runner)
        self.assertEqual(captured.exception.code, "cfm_process_running")

    def test_registered_packet_tunnel_extension_blocks_dormancy(self) -> None:
        def runner(arguments: tuple[str, ...]) -> CommandResult:
            if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                return CommandResult(0, "1 0 Thu Jul 23 15:20:55 2026 /sbin/launchd\n", "")
            if arguments[:2] == ("/bin/launchctl", "print"):
                return CommandResult(
                    113,
                    "",
                    'Could not find service "fixture" in domain\n',
                )
            if arguments == ("/usr/bin/sfltool", "dumpbtm"):
                return CommandResult(0, btm_fixture(), "")
            if arguments == ("/usr/bin/systemextensionsctl", "list"):
                return CommandResult(
                    0,
                    "* * YKUPL7Z869 com.bill.clashformac.packet-tunnel enabled\n",
                    "",
                )
            raise AssertionError(arguments)

        with patch(
            "scripts.dormant_app_install._required_btm_uids",
            return_value={-2, 0, 501},
        ), self.assertRaises(InstallError) as captured:
            require_cfm_dormant(guard(), runner)
        self.assertEqual(captured.exception.code, "cfm_system_extension_registered")

    def test_all_known_cfm_runtime_surfaces_absent_passes_read_only_gate(self) -> None:
        observed: list[tuple[str, ...]] = []

        def runner(arguments: tuple[str, ...]) -> CommandResult:
            observed.append(arguments)
            if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                return CommandResult(0, "1 0 Thu Jul 23 15:20:55 2026 /sbin/launchd\n", "")
            if arguments[:2] == ("/bin/launchctl", "print"):
                return CommandResult(
                    113,
                    "",
                    'Could not find service "fixture" in domain\n',
                )
            if arguments == ("/usr/bin/sfltool", "dumpbtm"):
                return CommandResult(0, btm_fixture(), "")
            if arguments == ("/usr/bin/systemextensionsctl", "list"):
                return CommandResult(0, "0 extension(s)\n", "")
            raise AssertionError(arguments)

        with patch(
            "scripts.dormant_app_install._required_btm_uids",
            return_value={-2, 0, 501},
        ):
            require_cfm_dormant(guard(), runner)
        self.assertEqual(sum(command[0] == "/bin/launchctl" for command in observed), 3)
        self.assertIn(("/usr/bin/sfltool", "dumpbtm"), observed)
        self.assertIn(("/usr/bin/systemextensionsctl", "list"), observed)

    def test_registered_btm_identity_and_near_match_are_distinguished(self) -> None:
        def run_with(output: str) -> None:
            def runner(arguments: tuple[str, ...]) -> CommandResult:
                if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                    return CommandResult(
                        0, "1 0 Thu Jul 23 15:20:55 2026 /sbin/launchd\n", ""
                    )
                if arguments[:2] == ("/bin/launchctl", "print"):
                    return CommandResult(
                        113, "", 'Could not find service "fixture" in domain\n'
                    )
                if arguments == ("/usr/bin/sfltool", "dumpbtm"):
                    return CommandResult(0, output, "")
                if arguments == ("/usr/bin/systemextensionsctl", "list"):
                    return CommandResult(0, "0 extension(s)\n", "")
                raise AssertionError(arguments)

            with patch(
                "scripts.dormant_app_install._required_btm_uids",
                return_value={-2, 0, 501},
            ):
                require_cfm_dormant(guard(), runner)

        run_with(btm_fixture(identifier="16.com.bill.clashformacx.helper"))
        registered = (
            btm_fixture(identifier="2.com.bill.clashformac"),
            btm_fixture().replace(
                "           Generation: 1",
                "    Parent Identifier: 2.com.bill.clashformac\n"
                "           Generation: 1",
                1,
            ),
            btm_fixture().replace(
                "           Generation: 1",
                "    Bundle Identifier: com.bill.clashformac\n"
                "           Generation: 1",
                1,
            ),
            btm_fixture().replace(
                "           Generation: 1",
                "    Assoc. Bundle IDs: [com.bill.clashformac]\n"
                "           Generation: 1",
                1,
            ),
            btm_fixture().replace(
                "           Generation: 1",
                "           Generation: 1\n"
                "  Embedded Item Identifiers:\n"
                "    #1: 8192.com.bill.clashformac",
                1,
            ),
        )
        for output in registered:
            with self.subTest(output=output[:80]), self.assertRaises(
                InstallError
            ) as captured:
                run_with(output)
            self.assertEqual(
                captured.exception.code, "cfm_background_item_registered"
            )


class BtmParserTests(unittest.TestCase):
    def test_complete_multi_uid_output_is_accepted(self) -> None:
        values = _parse_btm_values(btm_fixture(), {-2, 0, 501})
        self.assertIn("16.example.unrelated", values)

    def test_empty_truncated_unknown_gap_and_missing_uid_fail_closed(self) -> None:
        complete = btm_fixture()
        malformed = {
            "empty": "",
            "truncated": complete.rstrip("\n") + "\n\n",
            "unknown": complete.replace(
                "           Generation: 1",
                "           Mystery Field: value\n           Generation: 1",
                1,
            ),
            "gap": complete.replace(" #1:", " #2:", 1),
            "missing_uid": btm_fixture(include_gui_uid=False),
        }
        for label, output in malformed.items():
            with self.subTest(label=label), self.assertRaises(InstallError) as captured:
                _parse_btm_values(output, {-2, 0, 501})
            self.assertEqual(
                captured.exception.code, "cfm_background_item_observation_invalid"
            )


class CfwProductionGuardTests(unittest.TestCase):
    PS = (
        "36650 501 Thu Jul 23 15:20:55 2026 "
        "/Applications/Clash for Windows.app/Contents/MacOS/Clash for Windows\n"
        "36751 0 Thu Jul 23 15:21:03 2026 "
        "/Applications/Clash for Windows.app/Contents/Resources/static/files/"
        "darwin/x64/clash-darwin\n"
    )
    PROXY = """<dictionary> {
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
  SOCKSEnable : 1
  SOCKSPort : 7890
  SOCKSProxy : 127.0.0.1
}
"""
    DNS = """DNS configuration
resolver #1
  nameserver[0] : 8.8.8.8
  reach : 0x00000002 (Reachable)
"""
    ROUTES4 = """Routing tables
Internet:
Destination Gateway Flags Netif Expire
1 198.18.0.1 UGSc utun6
2/7 198.18.0.1 UGSc utun6
172.16.160.1 aa:bb UHLWI en0 1200
"""
    ROUTES6 = """Routing tables
Internet6:
Destination Gateway Flags Netif Expire
"""
    IFCONFIG = """utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000
\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xffff0000
\tnd6 options=201<PERFORMNUD,DAD>
en0: flags=8863<UP> mtu 1500
"""

    def runner(self, overrides: dict[tuple[str, ...], str] | None = None):
        outputs = {
            ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="): self.PS,
            ("/usr/sbin/scutil", "--proxy"): self.PROXY,
            ("/usr/sbin/scutil", "--dns"): self.DNS,
            ("/usr/sbin/netstat", "-rn", "-f", "inet"): self.ROUTES4,
            ("/usr/sbin/netstat", "-rn", "-f", "inet6"): self.ROUTES6,
            ("/sbin/ifconfig",): self.IFCONFIG,
        }
        outputs.update(overrides or {})

        def run(arguments: tuple[str, ...]) -> CommandResult:
            if arguments not in outputs:
                raise AssertionError(arguments)
            return CommandResult(0, outputs[arguments], "")

        return run

    def test_exact_current_cfw_lifeline_is_captured_with_start_times(self) -> None:
        with patch(
            "scripts.dormant_app_install._hash_regular", return_value="a" * 64
        ):
            snapshot = capture_cfw_guard(self.runner())
        self.assertEqual(
            [process["started_at"] for process in snapshot["cfw_processes"]],
            ["Thu Jul 23 15:20:55 2026", "Thu Jul 23 15:21:03 2026"],
        )
        self.assertRegex(snapshot["proxy_sha256"], r"^[0-9a-f]{64}$")

    def test_missing_or_duplicate_fixed_process_is_rejected(self) -> None:
        missing = self.PS.splitlines()[0] + "\n"
        duplicate = self.PS + self.PS.splitlines()[0].replace("36650", "36651", 1) + "\n"
        for observed in (missing, duplicate):
            with self.subTest(observed=observed):
                with patch(
                    "scripts.dormant_app_install._hash_regular", return_value="a" * 64
                ):
                    with self.assertRaises(InstallError) as captured:
                        capture_cfw_guard(
                            self.runner(
                                {("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="): observed}
                            )
                        )
                self.assertEqual(captured.exception.code, "cfw_process_identity_invalid")

    def test_wrong_proxy_dns_tunnel_or_route_is_rejected(self) -> None:
        cases = {
            "proxy": {
                ("/usr/sbin/scutil", "--proxy"): self.PROXY.replace("7890", "7891")
            },
            "dns": {
                ("/usr/sbin/scutil", "--dns"): self.DNS.replace("8.8.8.8", "1.1.1.1")
            },
            "tun": {
                ("/sbin/ifconfig",): self.IFCONFIG.replace("198.18.0.1", "198.19.0.1")
            },
            "route": {
                ("/usr/sbin/netstat", "-rn", "-f", "inet"): self.ROUTES4.replace(
                    "utun6", "utun9"
                )
            },
        }
        for label, overrides in cases.items():
            with self.subTest(label=label):
                with patch(
                    "scripts.dormant_app_install._hash_regular", return_value="a" * 64
                ):
                    with self.assertRaises(InstallError):
                        capture_cfw_guard(self.runner(overrides))

    def test_route_projection_has_a_real_empty_state_and_ignores_expiry(self) -> None:
        self.assertEqual(_normalize_routes("", "utun6"), "")
        self.assertEqual(_normalize_routes("1 198.18.0.1 UGSc utun9 12\n", "utun6"), "")
        self.assertEqual(
            _normalize_routes("1 198.18.0.1 UGSc utun6 12\n", "utun6"),
            "1 198.18.0.1 UGSc utun6\n",
        )

    def test_process_parser_rejects_missing_start_time(self) -> None:
        with self.assertRaises(InstallError):
            _parse_processes("36650 501 /Applications/example\n")


class BoundedCommandRunnerTests(unittest.TestCase):
    def test_sfltool_dumpbtm_has_a_dedicated_slow_success_bound(self) -> None:
        command = ("/usr/bin/sfltool", "dumpbtm")

        def slow_success(arguments: tuple[str, ...], *, timeout: float) -> CommandResult:
            self.assertEqual(arguments, command)
            self.assertEqual(timeout, 120.0)
            time.sleep(0.02)
            return CommandResult(0, btm_fixture(), "")

        with patch(
            "scripts.dormant_app_install._run_bounded_process",
            side_effect=slow_success,
        ):
            result = production_command_runner(command)
        self.assertEqual(result.returncode, 0)

    def test_sfltool_dumpbtm_timeout_is_not_converted_to_success(self) -> None:
        command = ("/usr/bin/sfltool", "dumpbtm")
        timeout = InstallError("command_timeout", "fixture timeout")
        with patch(
            "scripts.dormant_app_install._run_bounded_process",
            side_effect=timeout,
        ) as bounded, self.assertRaises(InstallError) as captured:
            production_command_runner(command)
        bounded.assert_called_once_with(command, timeout=120.0)
        self.assertIs(captured.exception, timeout)

    def test_immediate_exit_has_a_result_and_only_uses_its_spawned_group(self) -> None:
        observed_groups: list[int] = []
        spawned_pids: list[int] = []
        real_killpg = os.killpg
        real_popen = subprocess.Popen

        def observe(group: int, requested_signal: int) -> None:
            observed_groups.append(group)
            real_killpg(group, requested_signal)

        def spawn(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            spawned_pids.append(process.pid)
            return process

        with patch("scripts.dormant_app_install.os.killpg", side_effect=observe), patch(
            "scripts.dormant_app_install.subprocess.Popen", side_effect=spawn
        ):
            result = _run_bounded_process((sys.executable, "-c", "raise SystemExit(0)"), timeout=2)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(spawned_pids, list(set(spawned_pids)))
        self.assertTrue(observed_groups)
        self.assertEqual(set(observed_groups), set(spawned_pids))
        self.assertNotIn(100, observed_groups)
        self.assertNotIn(101, observed_groups)

    def test_timeout_is_typed_and_bounded(self) -> None:
        started = time.monotonic()
        with self.assertRaises(InstallError) as captured:
            _run_bounded_process(
                (sys.executable, "-c", "import time; time.sleep(30)"),
                timeout=0.1,
            )
        self.assertEqual(captured.exception.code, "command_timeout")
        self.assertLess(time.monotonic() - started, 5)

    def test_fast_oversized_output_is_killed_at_the_pipe_bound(self) -> None:
        with self.assertRaises(InstallError) as captured:
            _run_bounded_process(
                (
                    sys.executable,
                    "-c",
                    "import os; data=b'x'*65536; "
                    "[(os.write(1,data)) for _ in range(145)]",
                ),
                timeout=5,
            )
        self.assertEqual(captured.exception.code, "command_output_oversized")

    def test_descendant_pipe_writer_is_cleaned_when_leader_exits(self) -> None:
        code = (
            "import subprocess,sys; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "print(child.pid, flush=True)"
        )
        result = _run_bounded_process((sys.executable, "-c", code), timeout=5)
        child = int(result.stdout.strip())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            self.fail("spawned descendant remained alive after command completion")

    def test_closed_pipes_do_not_shorten_the_command_timeout(self) -> None:
        code = "import os,time; os.close(1); os.close(2); time.sleep(30)"
        with self.assertRaises(InstallError) as captured:
            _run_bounded_process((sys.executable, "-c", code), timeout=0.1)
        self.assertEqual(captured.exception.code, "command_timeout")

    def test_keyboard_interrupt_still_cleans_the_spawned_process_group(self) -> None:
        spawned_pids: list[int] = []
        real_popen = subprocess.Popen

        def spawn(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            spawned_pids.append(process.pid)
            return process

        with patch(
            "scripts.dormant_app_install.subprocess.Popen", side_effect=spawn
        ), patch.object(selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                _run_bounded_process(
                    (sys.executable, "-c", "import time; time.sleep(30)"),
                    timeout=5,
                )
        self.assertEqual(len(spawned_pids), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(spawned_pids[0], 0)

    def test_fixed_command_shapes_reject_every_mutating_variant(self) -> None:
        rejected = (
            ("/bin/launchctl", "bootout", "system/com.bill.clashformac.helper"),
            ("/usr/bin/sfltool", "resetbtm"),
            ("/usr/bin/systemextensionsctl", "reset"),
            ("/sbin/ifconfig", "utun10", "down"),
            ("/usr/bin/codesign", "--sign", "-", "/Applications/Clash for Mac.app"),
            ("/usr/bin/ditto", "/tmp/source", "/Applications/Clash for Mac.app"),
            ("/usr/bin/xcrun", "notarytool", "submit", "/tmp/file"),
        )
        for command in rejected:
            with self.subTest(command=command):
                with self.assertRaises(InstallError):
                    _require_fixed_command(command)

if __name__ == "__main__":
    unittest.main()
