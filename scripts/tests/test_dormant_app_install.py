from __future__ import annotations

from dataclasses import replace
import errno
import io
import json
import os
from pathlib import Path
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, call, patch

from scripts.candidate_artifact_binding import ArtifactToolchainError, CandidateBindingError
from scripts import dormant_app_install as install
from scripts import ga_acceptance_environment as ga_environment

from scripts.dormant_app_install import (
    AppIdentity,
    CandidateIdentity,
    CommandResult,
    DormantInstallTransaction,
    GA_INSTALL_PROFILE,
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
    admit_fixed_candidate,
    _assert_guard_unchanged,
    _normalize_routes,
    _clean_profile_sources,
    _parse_processes,
    _parse_system_extension_identities,
    _require_fixed_command,
    _run_bounded_process,
    production_command_runner,
    parse_service_maintenance_receipt,
    require_cfm_dormant,
    require_single_interactive_local_user,
    swap_names,
    validate_journal,
    _require_journal_successor,
    exclusive_release_maintenance_lock,
)
from scripts.dormant_app_install import (
    INSTALLED_40019_PREDECESSOR,
    INSTALLED_40041_PREDECESSOR,
    SUPPORTED_PREDECESSORS,
    bind_journal_predecessor,
    require_target_application_present,
    resolve_predecessor,
)


# The predecessor fixture carries the real frozen 40019 tree identity: the
# install admits a predecessor only against its exact recorded tree digest,
# so an invented digest would be rejected as a tampered bundle, not admitted.
OLD = AppIdentity("0.4.0", "40019", INSTALLED_40019_PREDECESSOR.tree_sha256)
NEW = AppIdentity("0.4.0", "40042", "b" * 64)
# The installed 40041 with its real frozen tree identity: the production
# predecessor of this build.
INSTALLED = AppIdentity("0.4.0", "40041", INSTALLED_40041_PREDECESSOR.tree_sha256)
CANDIDATE = CandidateIdentity(
    app=NEW,
    manifest_sha256="c" * 64,
    repository_commit="d" * 40,
    release_source_sha256="e" * 64,
)
GA_ENVIRONMENT = {
    "architecture": "arm64",
    "boot_environment_sha256": "9" * 64,
    "document": ga_environment.DOCUMENT,
    "hardware_model": "Mac16,1",
    "machine_sha256": "8" * 64,
    "macos_build_version": "26A5388g",
    "macos_product_version": "27.0",
    "physical_nonvirtualized": True,
    "schema_version": ga_environment.SCHEMA_VERSION,
}


def service_status_fixture(
    *, proxy: str = "not_registered", authority: str = "not_registered"
) -> str:
    return json.dumps(
        {
            "action": "status",
            "document": "cfw-current-service-maintenance-v2",
            "engine_status": None,
            "global_authority": authority,
            "off_proof_profile": None,
            "proxy_agent": proxy,
        },
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def inactive_tombstone_fixture() -> str:
    return "\n".join(
        (
            "system/com.bill.clashformac.helper = {",
            "\tactive count = 0",
            "\tmanaged_by = com.apple.xpc.ServiceManagement",
            "\tstate = not running",
            "\tprogram identifier = Contents/Library/HelperTools/cfw-helper-tombstone (mode: 2)",
            "\tparent bundle identifier = com.bill.clashformac",
            "\tLWCR = {",
            '\t\t"team-identifier" => "YKUPL7Z869"',
            "\t}",
            "\tdomain = system",
            "}",
            "",
        )
    )


def local_users_fixture(*, extra_authenticated_uid: int | None = None) -> str:
    records = [
        "\n".join(
            (
                "AuthenticationAuthority: ;ShadowHash;",
                f"NFSHomeDirectory: /Users/test-{os.geteuid()}",
                "RecordName: test-user",
                f"UniqueID: {os.geteuid()}",
                "UserShell: /bin/zsh",
            )
        )
    ]
    if extra_authenticated_uid is not None:
        records.append(
            "\n".join(
                (
                    "AuthenticationAuthority: ;ShadowHash;",
                    f"NFSHomeDirectory: /Users/test-{extra_authenticated_uid}",
                    "RecordName: other-user",
                    f"UniqueID: {extra_authenticated_uid}",
                    "UserShell: /bin/zsh",
                )
            )
        )
    return "\n-\n".join(records) + "\n"


def is_local_user_inventory_command(arguments: tuple[str, ...]) -> bool:
    return arguments == (
        "/usr/bin/dscl",
        ".",
        "-readall",
        "/Users",
        "UniqueID",
        "NFSHomeDirectory",
        "UserShell",
        "AuthenticationAuthority",
    )


def system_extensions_fixture(
    *identities: tuple[str, str],
    category: str = "com.apple.system_extension.network_extension",
) -> str:
    if not identities:
        return "0 extension(s)\n"
    lines = [
        f"{len(identities)} extension(s)",
        f"--- {category}",
        "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]",
    ]
    lines.extend(
        f"*\t*\t{team_id}\t{bundle_id} (1.2.3/123)\t{bundle_id}\t[activated enabled]"
        for team_id, bundle_id in identities
    )
    return "\n".join(lines) + "\n"


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
        self.service_baseline = guard()

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
        environment: dict[str, object] | None = None,
        quick=None,
        swap=None,
    ) -> InstallRuntime:
        guard_values = captures or [guard()]

        def require_service_decommissioned(
            _paths, _candidate, _previous, expected_guard
        ):
            _assert_guard_unchanged(self.service_baseline, expected_guard)
            return dict(GA_ENVIRONMENT)

        return InstallRuntime(
            capture_guard=GuardSequence(guard_values),
            observe_environment=lambda: dict(environment or GA_ENVIRONMENT),
            require_cfm_dormant=dormant or (lambda _guard: None),
            require_cfm_process_absent=quick or (lambda: []),
            admit_candidate=self.admit,
            read_identity=self.read_identity,
            copy_candidate=self.copy,
            sync_tree=lambda _path: None,
            swap=swap or self.swap,
            verify_bundle=lambda _path, _identity: None,
            require_service_decommissioned=require_service_decommissioned,
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
        self.assertEqual(
            result["ga_environment_sha256"],
            ga_environment.environment_sha256(GA_ENVIRONMENT),
        )
        journal = self.fixture.parent / JOURNAL_NAME
        self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
        self.assertEqual(journal.parent, self.fixture.parent)
        self.assertNotIn(self.fixture.target, journal.parents)

    def test_environment_drift_blocks_before_journal_copy_or_swap(self) -> None:
        changed = dict(GA_ENVIRONMENT)
        changed["machine_sha256"] = "7" * 64
        with self.assertRaises(InstallError) as captured:
            self.fixture.transaction(environment=changed).install()
        self.assertEqual(captured.exception.code, "install_environment_drift")
        self.assertFalse((self.fixture.parent / JOURNAL_NAME).exists())
        self.assertFalse((self.fixture.parent / JOURNAL_PENDING_NAME).exists())
        self.assertEqual(self.fixture.copy_count, 0)
        self.assertEqual(self.fixture.swap_count, 0)

    def test_install_admits_only_a_supported_newer_installed_application(self) -> None:
        cases = (
            (AppIdentity("0.4.0", "40030", "a" * 64), "predecessor_unsupported"),
            (AppIdentity("0.4.0", "40019", "f" * 64), "predecessor_identity_mismatch"),
            # The GA build itself is never a predecessor.
            (NEW, "predecessor_unsupported"),
            (AppIdentity("0.3.5", "40019", OLD.tree_sha256), "install_identity_mismatch"),
        )
        for installed, code in cases:
            with self.subTest(code=code):
                self.fixture._write_identity(self.fixture.target, installed)
                with self.assertRaises(InstallError) as captured:
                    self.fixture.transaction().install()
                self.assertEqual(captured.exception.code, code)
                self.assertFalse((self.fixture.parent / JOURNAL_NAME).exists())
                self.assertFalse((self.fixture.parent / JOURNAL_PENDING_NAME).exists())
                self.assertEqual(self.fixture.copy_count, 0)
                self.assertEqual(self.fixture.swap_count, 0)
        shutil.rmtree(self.fixture.target)
        with self.assertRaises(InstallError) as captured:
            self.fixture.transaction().install()
        self.assertEqual(captured.exception.code, "previous_app_absent")
        self.assertFalse((self.fixture.parent / JOURNAL_NAME).exists())
        self.assertEqual(self.fixture.copy_count, 0)
        self.assertEqual(self.fixture.swap_count, 0)

    def test_install_over_the_installed_40041_records_that_predecessor(self) -> None:
        self.fixture._write_identity(self.fixture.target, INSTALLED)
        result = self.fixture.transaction().install()

        self.assertEqual(result["phase"], "installed")
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), INSTALLED)
        self.assertEqual(self.fixture.swap_count, 1)
        journal = self.fixture.journal()
        self.assertEqual(journal["previous"], INSTALLED.document())
        validate_journal(journal, GA_INSTALL_PROFILE)

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

    def test_shared_maintenance_lock_blocks_before_journal_copy_or_swap(self) -> None:
        with exclusive_release_maintenance_lock(self.fixture.parent):
            with self.assertRaises(InstallError) as captured:
                self.fixture.transaction().install()

        self.assertEqual(captured.exception.code, "maintenance_busy")
        self.assertFalse((self.fixture.parent / JOURNAL_NAME).exists())
        self.assertEqual(self.fixture.copy_count, 0)
        self.assertEqual(self.fixture.swap_count, 0)

    def test_shared_maintenance_lock_path_rebinding_is_detected(self) -> None:
        lock_path = self.fixture.parent / ".com.bill.clashformac.release-maintenance-v1.lock"
        with self.assertRaises(InstallError) as captured:
            with exclusive_release_maintenance_lock(self.fixture.parent):
                lock_path.unlink()
                lock_path.write_bytes(b"")
                lock_path.chmod(0o600)

        self.assertEqual(
            captured.exception.code,
            "maintenance_lock_identity_drift",
        )

    def test_service_guard_drift_blocks_before_install_journal_copy_or_swap(self) -> None:
        changed = guard(proxy="8" * 64)
        captures = [guard(), guard(), guard(), guard(), changed, changed]

        with self.assertRaises(InstallError) as captured:
            self.fixture.transaction(captures=captures).install()

        self.assertEqual(captured.exception.code, "cfw_guard_changed")
        self.assertFalse((self.fixture.parent / JOURNAL_NAME).exists())
        self.assertFalse((self.fixture.parent / JOURNAL_PENDING_NAME).exists())
        self.assertFalse(
            any(
                path.is_dir() and path.name.startswith(STAGING_PREFIX)
                for path in self.fixture.parent.iterdir()
            )
        )
        self.assertEqual(self.fixture.copy_count, 0)
        self.assertEqual(self.fixture.swap_count, 0)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)

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

    def test_recovery_rejects_service_guard_drift_before_resume_or_swap(self) -> None:
        def crash_before_swap(*_arguments) -> None:
            raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            self.fixture.transaction(swap=crash_before_swap).install()
        journal_path = self.fixture.parent / JOURNAL_NAME
        before_journal = journal_path.read_bytes()
        before_copy_count = self.fixture.copy_count
        before_swap_count = self.fixture.swap_count
        changed = guard(proxy="8" * 64)

        with self.assertRaises(InstallError) as captured:
            self.fixture.transaction(captures=[changed]).recover()

        self.assertEqual(captured.exception.code, "cfw_guard_changed")
        self.assertEqual(journal_path.read_bytes(), before_journal)
        self.assertEqual(self.fixture.copy_count, before_copy_count)
        self.assertEqual(self.fixture.swap_count, before_swap_count)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), NEW)

    def test_recovery_authorizes_service_guard_before_pending_publication(self) -> None:
        def stop_before_publish(_store: JournalStore) -> None:
            raise SimulatedCrash()

        with patch.object(JournalStore, "_rename_pending", stop_before_publish):
            with self.assertRaises(SimulatedCrash):
                self.fixture.transaction().install()

        journal_path = self.fixture.parent / JOURNAL_NAME
        pending_path = self.fixture.parent / JOURNAL_PENDING_NAME
        self.assertFalse(journal_path.exists())
        before_pending = pending_path.read_bytes()
        before_pending_inode = pending_path.stat().st_ino
        changed = guard(proxy="8" * 64)

        with self.assertRaises(InstallError) as captured:
            self.fixture.transaction(captures=[changed]).recover()

        self.assertEqual(captured.exception.code, "cfw_guard_changed")
        self.assertFalse(journal_path.exists())
        self.assertEqual(pending_path.read_bytes(), before_pending)
        self.assertEqual(pending_path.stat().st_ino, before_pending_inode)
        self.assertEqual(self.fixture.copy_count, 0)
        self.assertEqual(self.fixture.swap_count, 0)
        self.assertEqual(self.fixture.read_identity(self.fixture.target), OLD)

    def test_transaction_exposes_no_rollback_surface(self) -> None:
        self.assertFalse(hasattr(self.fixture.transaction(), "rollback"))

    def test_second_install_cannot_overwrite_recovery_journal_or_backup(self) -> None:
        self.fixture.transaction().install()
        backup = self.fixture.staging_payload()
        # The installed application is now this GA build itself, which is never
        # a supported predecessor; admission fails before any mutation.
        with self.assertRaisesRegex(InstallError, "not a supported install predecessor"):
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

    def test_fsynced_rollback_revision_is_rejected_without_promotion(self) -> None:
        installed = self.fixture.transaction().install()
        journal = self.fixture.parent / JOURNAL_NAME
        before_journal = journal.read_bytes()
        pending = json.loads(json.dumps(installed))
        pending["sequence"] += 1
        pending["phase"] = "rollback-prepared"
        pending["guards"].append(
            {"after": None, "before": guard(), "operation": "rollback"}
        )
        self.fixture.write_pending(pending)

        with self.assertRaises(InstallError) as captured:
            with JournalStore(self.fixture.paths) as store:
                with store.locked():
                    store.load(lambda _document: None)
        self.assertEqual(captured.exception.code, "journal_invalid")
        self.assertEqual(journal.read_bytes(), before_journal)
        self.assertTrue((self.fixture.parent / JOURNAL_PENDING_NAME).exists())
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.read_identity(self.fixture.staging_payload()), OLD)
        self.assertEqual(self.fixture.swap_count, 1)

    def test_pending_revision_with_broken_lineage_fails_without_swap(self) -> None:
        installed = self.fixture.transaction().install()
        pending = json.loads(json.dumps(installed))
        pending["sequence"] += 2
        self.fixture.write_pending(pending)

        with self.assertRaisesRegex(InstallError, "pending journal lineage"):
            self.fixture.transaction().recover()
        self.assertEqual(self.fixture.read_identity(self.fixture.target), NEW)
        self.assertEqual(self.fixture.swap_count, 1)

    def test_malformed_pending_revision_fails_without_touching_bundles(self) -> None:
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
    def test_install_journal_json_recursion_is_a_stable_domain_error(self) -> None:
        deeply_nested = (
            "{\"nested\":" * 10_000 + "0" + "}" * 10_000
        ).encode("ascii")
        with self.assertRaises(InstallError) as captured:
            install.validate_journal_bytes(deeply_nested)
        self.assertEqual(captured.exception.code, "journal_invalid")

        with patch.object(
            install,
            "_canonical_json",
            side_effect=RecursionError("fixture canonical recursion"),
        ), self.assertRaises(InstallError) as captured:
            install.validate_journal_bytes(b"{}\n")
        self.assertEqual(captured.exception.code, "journal_invalid")

        for token in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(token=token), self.assertRaises(
                InstallError
            ) as captured:
                install.validate_journal_bytes(
                    b'{"value":' + token + b"}\n"
                )
            self.assertEqual(captured.exception.code, "journal_invalid")

    def test_service_evidence_json_recursion_is_a_stable_domain_error(self) -> None:
        deeply_nested = (
            "{\"nested\":" * 10_000 + "0" + "}" * 10_000
        ).encode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "service.json"
            path.write_bytes(deeply_nested)
            path.chmod(0o600)
            descriptor = os.open(root, os.O_RDONLY)
            try:
                with self.assertRaises(InstallError) as captured:
                    install._read_private_service_document(
                        descriptor,
                        path.name,
                        "deep service fixture",
                    )
                self.assertEqual(
                    captured.exception.code,
                    "service_decommission_evidence_invalid",
                )

                path.write_bytes(b'{"value":NaN}\n')
                path.chmod(0o600)
                with self.assertRaises(InstallError) as captured:
                    install._read_private_service_document(
                        descriptor,
                        path.name,
                        "non-finite service fixture",
                    )
                self.assertEqual(
                    captured.exception.code,
                    "service_decommission_evidence_invalid",
                )

                path.write_bytes(b"{}\n")
                path.chmod(0o600)
                with patch.object(
                    install.os,
                    "stat",
                    side_effect=FileNotFoundError("fixture path rebind"),
                ), self.assertRaises(InstallError) as captured:
                    install._read_private_service_document(
                        descriptor,
                        path.name,
                        "rebound service fixture",
                    )
                self.assertEqual(
                    captured.exception.code,
                    "service_decommission_evidence_invalid",
                )

                path.write_bytes(b"{}\n")
                path.chmod(0o600)
                with patch.object(
                    install,
                    "_canonical_json",
                    side_effect=RecursionError("fixture canonical recursion"),
                ), self.assertRaises(InstallError) as captured:
                    install._read_private_service_document(
                        descriptor,
                        path.name,
                        "deep service fixture",
                    )
                self.assertEqual(
                    captured.exception.code,
                    "service_decommission_evidence_invalid",
                )
            finally:
                os.close(descriptor)

    def test_service_receipt_deep_json_is_a_stable_domain_error(self) -> None:
        deeply_nested = "{\"nested\":" * 10_000 + "0" + "}" * 10_000
        with self.assertRaises(InstallError) as captured:
            parse_service_maintenance_receipt(
                CommandResult(0, deeply_nested + "\n", ""),
                "status",
            )
        self.assertEqual(captured.exception.code, "cfm_service_status_invalid")

        with self.assertRaises(InstallError) as captured:
            parse_service_maintenance_receipt(
                CommandResult(0, '{"value":NaN}\n', ""),
                "status",
            )
        self.assertEqual(captured.exception.code, "cfm_service_status_invalid")

        receipt = {
            "action": "status",
            "document": install.SERVICE_MAINTENANCE_DOCUMENT,
            "engine_status": None,
            "global_authority": "not_registered",
            "off_proof_profile": None,
            "proxy_agent": "not_registered",
        }
        stdout = json.dumps(
            receipt,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        with patch.object(
            install,
            "_canonical_json",
            side_effect=RecursionError("fixture canonical recursion"),
        ), self.assertRaises(InstallError) as captured:
            parse_service_maintenance_receipt(
                CommandResult(0, stdout, ""),
                "status",
            )
        self.assertEqual(captured.exception.code, "cfm_service_status_invalid")

    def test_existing_install_lock_path_failure_is_typed_without_recreation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = InstallPaths(
                repository=root,
                candidate_app=root / TARGET_NAME,
                candidate_manifest=root / f"{TARGET_NAME}.manifest.json",
                target_parent=root,
            )
            lock_path = root / LOCK_NAME
            lock_path.write_bytes(b"")
            lock_path.chmod(0o600)
            with JournalStore(paths) as store, patch.object(
                install.os,
                "stat",
                side_effect=FileNotFoundError("fixture lock rebind"),
            ), self.assertRaises(InstallError) as captured:
                with store.locked(require_existing=True):
                    self.fail("rebound installation lock was accepted")
            self.assertEqual(captured.exception.code, "install_lock_unsafe")
            self.assertTrue(lock_path.is_file())

    def test_service_maintenance_receipt_engine_status_contract(self) -> None:
        actions = (
            "status",
            "prove-off",
            "prove-installed-40019-off",
            "unregister-proxy-agent",
            "unregister-installed-40019-proxy-agent",
            "unregister-global-authority",
            "unregister-installed-40019-global-authority",
            install.INSTALLED_40019_RECOVERY_ACTION,
            "register-global-authority",
            "register-proxy-agent",
        )
        for action in actions:
            expected_engine_status = None if action == "status" else "off"
            receipt = {
                "action": action.replace("-", "_"),
                "document": "cfw-current-service-maintenance-v2",
                "engine_status": expected_engine_status,
                "global_authority": "not_registered",
                "off_proof_profile": (
                    None
                    if action == "status"
                    else (
                        install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
                        if action == install.INSTALLED_40019_RECOVERY_ACTION
                        else (
                            install.INSTALLED_40019_OFF_PROOF_PROFILE
                            if "installed-40019" in action
                            else install.CURRENT_OFF_PROOF_PROFILE
                        )
                    )
                ),
                "proxy_agent": "not_registered",
            }
            stdout = json.dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
            with self.subTest(action=action):
                self.assertEqual(
                    parse_service_maintenance_receipt(
                        CommandResult(0, stdout, ""),
                        action,
                    ),
                    receipt,
                )

                invalid_receipt = {
                    **receipt,
                    "engine_status": (
                        "off" if expected_engine_status is None else None
                    ),
                }
                invalid_stdout = json.dumps(
                    invalid_receipt,
                    sort_keys=True,
                    separators=(",", ":"),
                ) + "\n"
                with self.assertRaises(InstallError) as captured:
                    parse_service_maintenance_receipt(
                        CommandResult(0, invalid_stdout, ""),
                        action,
                    )
                self.assertEqual(
                    captured.exception.code,
                    "cfm_service_status_invalid",
                )

                if action != "status":
                    wrong_profile = {
                        **receipt,
                        "off_proof_profile": (
                            install.CURRENT_OFF_PROOF_PROFILE
                            if receipt["off_proof_profile"]
                            == install.INSTALLED_40019_OFF_PROOF_PROFILE
                            else install.INSTALLED_40019_OFF_PROOF_PROFILE
                        ),
                    }
                    with self.assertRaises(InstallError) as profile_error:
                        parse_service_maintenance_receipt(
                            CommandResult(
                                0,
                                json.dumps(
                                    wrong_profile,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                )
                                + "\n",
                                "",
                            ),
                            action,
                        )
                    self.assertEqual(
                        profile_error.exception.code,
                        "cfm_service_status_invalid",
                    )

        recovery_receipt = {
            "action": "recover_installed_40019_global_authority",
            "document": "cfw-current-service-maintenance-v2",
            "engine_status": "off",
            "global_authority": "not_registered",
            "off_proof_profile": (
                install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
            ),
            "proxy_agent": "not_registered",
        }
        recovery_stdout = json.dumps(
            recovery_receipt,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        self.assertEqual(
            parse_service_maintenance_receipt(
                CommandResult(0, recovery_stdout, ""),
                install.INSTALLED_40019_RECOVERY_ACTION,
            ),
            recovery_receipt,
        )
        wrong_profile_for_proxy = {
            **recovery_receipt,
            "action": "unregister_installed_40019_proxy_agent",
            "global_authority": "enabled",
        }
        wrong_profile_stdout = json.dumps(
            wrong_profile_for_proxy,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        with self.assertRaises(InstallError) as wrong_action:
            parse_service_maintenance_receipt(
                CommandResult(0, wrong_profile_stdout, ""),
                "unregister-installed-40019-proxy-agent",
            )
        self.assertEqual(wrong_action.exception.code, "cfm_service_status_invalid")

        malformed_profile = {
            **recovery_receipt,
            "off_proof_profile": [
                install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
            ],
        }
        with self.assertRaises(InstallError) as malformed_error:
            parse_service_maintenance_receipt(
                CommandResult(
                    0,
                    json.dumps(
                        malformed_profile,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    "",
                ),
                install.INSTALLED_40019_RECOVERY_ACTION,
            )
        self.assertEqual(
            malformed_error.exception.code,
            "cfm_service_status_invalid",
        )

        legacy_mislabel = {
            **recovery_receipt,
            "action": "unregister_installed_40019_global_authority",
        }
        with self.assertRaises(InstallError) as legacy_error:
            parse_service_maintenance_receipt(
                CommandResult(
                    0,
                    json.dumps(
                        legacy_mislabel,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    "",
                ),
                "unregister-installed-40019-global-authority",
            )
        self.assertEqual(
            legacy_error.exception.code,
            "cfm_service_status_invalid",
        )

    def test_candidate_admission_rejects_toolchain_environment_override(self) -> None:
        with patch.dict(
            os.environ,
            {"CFW_TOOLCHAIN_ROOT": "/tmp/caller-selected-toolchain"},
        ):
            with self.assertRaises(InstallError) as captured:
                admit_fixed_candidate(
                    InstallPaths.production(),
                    lambda arguments: (_ for _ in ()).throw(
                        AssertionError(arguments)
                    ),
                )
        self.assertEqual(captured.exception.code, "candidate_toolchain_override")

    def test_ga_profile_has_one_fixed_40042_path_and_journal(self) -> None:
        paths = InstallPaths.production()

        self.assertEqual(paths.profile, GA_INSTALL_PROFILE)
        self.assertEqual(paths.profile.build_number, "40042")
        # An unbound profile cannot express a predecessor claim at all; the
        # predecessor is observed on the machine and bound separately.
        self.assertFalse(hasattr(paths.profile, "previous_build_number"))
        self.assertEqual(
            paths.repository,
            paths.operator_repository / "target/release-worktrees/40042",
        )
        self.assertTrue(
            str(paths.candidate_app).endswith(
                "/target/candidates/0.4.0/ga/40042/signed/Clash for Mac.app"
            )
        )
        self.assertEqual(
            paths.profile.native_products_relative,
            Path(
                "target/candidates/0.4.0/ga/40042/signing-output/signed-native-products"
            ),
        )
        self.assertEqual(paths.journal_name, JOURNAL_NAME)
        self.assertEqual(paths.profile.staging_prefix, STAGING_PREFIX)

    def test_ga_journal_rejects_a_retired_or_misidentified_predecessor(self) -> None:
        transaction_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        document = {
            "candidate": CANDIDATE.document(),
            "document": install.DOCUMENT,
            "ga_environment_sha256": ga_environment.environment_sha256(
                GA_ENVIRONMENT
            ),
            "guards": [
                {"after": None, "before": guard(), "operation": "install"}
            ],
            "phase": "prepared",
            "previous": OLD.document(),
            "schema_version": install.SCHEMA_VERSION,
            "sequence": 1,
            "staging_name": f"{STAGING_PREFIX}{transaction_id}",
            "transaction_id": transaction_id,
        }
        validate_journal(document, GA_INSTALL_PROFILE)

        document["previous"]["build_number"] = "40030"
        with self.assertRaises(InstallError) as captured:
            validate_journal(document, GA_INSTALL_PROFILE)
        # A retired build was never a supported predecessor, so the journal
        # cannot even be read with a vocabulary; that is the precise reason.
        self.assertEqual(captured.exception.code, "predecessor_unsupported")

        # The recorded build number alone is not trusted either.
        document["previous"] = {**OLD.document(), "tree_sha256": "f" * 64}
        with self.assertRaises(InstallError) as captured:
            validate_journal(document, GA_INSTALL_PROFILE)
        self.assertEqual(captured.exception.code, "predecessor_identity_mismatch")

    def test_pre_environment_install_schema_is_rejected(self) -> None:
        transaction_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        legacy = {
            "candidate": CANDIDATE.document(),
            "document": "cfw-dormant-app-install-v1",
            "guards": [
                {"after": None, "before": guard(), "operation": "install"}
            ],
            "phase": "prepared",
            "previous": OLD.document(),
            "schema_version": 1,
            "sequence": 1,
            "staging_name": f"{STAGING_PREFIX}{transaction_id}",
            "transaction_id": transaction_id,
        }
        with self.assertRaises(InstallError) as captured:
            validate_journal(legacy, GA_INSTALL_PROFILE)
        self.assertEqual(captured.exception.code, "journal_invalid")

        current = {
            "candidate": CANDIDATE.document(),
            "document": install.DOCUMENT,
            "ga_environment_sha256": ga_environment.environment_sha256(
                GA_ENVIRONMENT
            ),
            "guards": [
                {"after": None, "before": guard(), "operation": "install"}
            ],
            "phase": "prepared",
            "previous": OLD.document(),
            "schema_version": True,
            "sequence": 1,
            "staging_name": f"{STAGING_PREFIX}{transaction_id}",
            "transaction_id": transaction_id,
        }
        with self.assertRaises(InstallError) as captured:
            validate_journal(current, GA_INSTALL_PROFILE)
        self.assertEqual(captured.exception.code, "journal_invalid")

    def test_retired_final_cli_and_wrapper_are_explicitly_rejected(self) -> None:
        with (
            patch.object(
                sys,
                "argv",
                ["dormant_app_install.py", "--preflight", "--final"],
            ),
            patch("sys.stderr", new_callable=io.StringIO) as stderr,
            patch.object(install, "_transaction") as transaction,
            self.assertRaises(SystemExit) as captured,
        ):
            install.main()
        self.assertEqual(captured.exception.code, 2)
        self.assertIn("--final is retired", stderr.getvalue())
        transaction.assert_not_called()

        repository = Path(__file__).resolve().parents[2]
        completed = subprocess.run(
            (
                "/bin/bash",
                str(repository / "scripts/run_dormant_app_install.sh"),
                "--preflight",
                "--final",
            ),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("--final is retired", completed.stderr)

    def test_terminal_install_pending_is_a_precise_guard_closure(self) -> None:
        transaction_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        installed = {
            "candidate": CANDIDATE.document(),
            "document": install.DOCUMENT,
            "ga_environment_sha256": ga_environment.environment_sha256(
                GA_ENVIRONMENT
            ),
            "guards": [{"after": guard(), "before": guard(), "operation": "install"}],
            "phase": "installed",
            "previous": OLD.document(),
            "schema_version": install.SCHEMA_VERSION,
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

    def test_forward_only_journal_rejects_legacy_rollback_shapes(self) -> None:
        transaction_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        document = {
            "candidate": CANDIDATE.document(),
            "document": install.DOCUMENT,
            "ga_environment_sha256": ga_environment.environment_sha256(
                GA_ENVIRONMENT
            ),
            "guards": [
                {"after": guard(), "before": guard(), "operation": "install"},
                {"after": guard(), "before": guard(), "operation": "rollback"},
            ],
            "phase": "installed",
            "previous": OLD.document(),
            "schema_version": install.SCHEMA_VERSION,
            "sequence": 5,
            "staging_name": f"{STAGING_PREFIX}{transaction_id}",
            "transaction_id": transaction_id,
        }
        for phase in (
            "installed",
            "rollback-prepared",
            "rollback-swapped",
            "rolled-back",
        ):
            shaped = json.loads(json.dumps(document))
            shaped["phase"] = phase
            with self.subTest(phase=phase):
                with self.assertRaises(InstallError) as captured:
                    validate_journal(shaped)
                self.assertEqual(captured.exception.code, "journal_invalid")

    def test_journal_rejects_caller_chosen_staging_name(self) -> None:
        document = {
            "candidate": CANDIDATE.document(),
            "document": install.DOCUMENT,
            "ga_environment_sha256": ga_environment.environment_sha256(
                GA_ENVIRONMENT
            ),
            "guards": [{"after": guard(), "before": guard(), "operation": "install"}],
            "phase": "installed",
            "previous": OLD.document(),
            "schema_version": install.SCHEMA_VERSION,
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

    def test_production_candidate_is_fixed_to_40042_ga_root(self) -> None:
        paths = InstallPaths.production()
        self.assertTrue(
            paths.candidate_app.as_posix().endswith(
                "/target/candidates/0.4.0/ga/40042/signed/Clash for Mac.app"
            )
        )

    def test_operator_and_frozen_artifact_keep_distinct_checked_sources(self) -> None:
        from scripts.release_executor_source import ExecutorSource, FrozenReleaseSources

        operator = Path("/operator")
        artifact = operator / "target/release-worktrees/40042"
        sources = FrozenReleaseSources(
            executor=ExecutorSource(operator, "a" * 40, "b" * 64),
            artifact=ExecutorSource(artifact, "c" * 40, "d" * 64),
        )
        with patch(
            "scripts.dormant_app_install.capture_frozen_release_sources",
            return_value=sources,
        ) as capture:
            self.assertIs(
                _clean_profile_sources(operator, artifact), sources
            )
        capture.assert_called_once_with(operator)
        with patch(
            "scripts.dormant_app_install.capture_frozen_release_sources",
            return_value=sources,
        ), self.assertRaises(CandidateBindingError):
            _clean_profile_sources(operator, Path("/other-worktree"))

    def test_artifact_toolchain_failure_stops_admission_before_app_or_service_actions(self) -> None:
        from scripts.release_executor_source import ExecutorSource, FrozenReleaseSources

        with tempfile.TemporaryDirectory() as temporary:
            operator = Path(temporary).resolve()
            with patch.object(install, "__file__", str(operator / "scripts/dormant_app_install.py")):
                paths = InstallPaths.production()
                paths.release_toolchain_root.mkdir(parents=True)
                paths.candidate_manifest.parent.mkdir(parents=True)
                paths.candidate_manifest.write_text(
                    '{"metadata":{"buildNumber":"40042"}}\n', encoding="utf-8"
                )
                sources = FrozenReleaseSources(
                    executor=ExecutorSource(operator, "a" * 40, "b" * 64),
                    artifact=ExecutorSource(paths.repository, "c" * 40, "d" * 64),
                )
                failure = ArtifactToolchainError(
                    "artifact_toolchain_verification_failed", "frozen toolchain rejected"
                )
                runner = Mock(side_effect=AssertionError("no application or service command"))
                with (
                    patch.object(install, "_clean_profile_sources", return_value=sources),
                    patch.object(
                        install, "derive_artifact_toolchain_metadata", side_effect=failure
                    ) as reader,
                    patch.object(install, "validate_candidate_app_manifest") as validate_app,
                    self.assertRaises(InstallError) as captured,
                ):
                    admit_fixed_candidate(paths, runner)
                self.assertEqual(captured.exception.code, "candidate_binding_invalid")
                self.assertIs(captured.exception.__cause__, failure)
                reader.assert_called_once_with(paths.repository)
                validate_app.assert_not_called()
                runner.assert_not_called()

    def test_local_user_inventory_blocks_logged_out_authenticated_users(self) -> None:
        def runner(output: str):
            def run(arguments: tuple[str, ...]) -> CommandResult:
                if is_local_user_inventory_command(arguments):
                    return CommandResult(0, output, "")
                raise AssertionError(arguments)

            return run

        require_single_interactive_local_user(
            runner(local_users_fixture()), os.geteuid()
        )
        with self.assertRaises(InstallError) as captured:
            require_single_interactive_local_user(
                runner(local_users_fixture(extra_authenticated_uid=os.geteuid() + 1)),
                os.geteuid(),
            )
        self.assertEqual(
            captured.exception.code, "cfm_multi_user_registration_unproven"
        )

    def test_noninteractive_service_account_does_not_create_a_false_user_gate(self) -> None:
        output = local_users_fixture().rstrip("\n") + "\n-\n" + "\n".join(
            (
                "NFSHomeDirectory: /Library/PostgreSQL/18",
                "RecordName: postgres",
                f"UniqueID: {os.geteuid() + 1}",
                "UserShell: /bin/bash",
                "",
            )
        )

        def runner(arguments: tuple[str, ...]) -> CommandResult:
            if is_local_user_inventory_command(arguments):
                return CommandResult(0, output, "")
            raise AssertionError(arguments)

        require_single_interactive_local_user(runner, os.geteuid())

    def test_inactive_but_registered_cfm_job_still_blocks(self) -> None:
        def runner(arguments: tuple[str, ...]) -> CommandResult:
            if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                return CommandResult(0, "1 0 Thu Jul 23 15:20:55 2026 /sbin/launchd\n", "")
            if is_local_user_inventory_command(arguments):
                return CommandResult(0, local_users_fixture(), "")
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
            if is_local_user_inventory_command(arguments):
                return CommandResult(0, local_users_fixture(), "")
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
            if is_local_user_inventory_command(arguments):
                return CommandResult(0, local_users_fixture(), "")
            if arguments[:2] == ("/bin/launchctl", "print"):
                if arguments[2] == "system/com.bill.clashformac.helper":
                    return CommandResult(0, inactive_tombstone_fixture(), "")
                return CommandResult(
                    113,
                    "",
                    'Could not find service "fixture" in domain\n',
                )
            if arguments[1:] == ("--service-maintenance-v2", "status"):
                return CommandResult(0, service_status_fixture(), "")
            if arguments == ("/usr/bin/systemextensionsctl", "list"):
                return CommandResult(
                    0,
                    system_extensions_fixture(
                        ("YKUPL7Z869", "com.bill.clashformac.packet-tunnel")
                    ),
                    "",
                )
            raise AssertionError(arguments)

        with self.assertRaises(InstallError) as captured:
            require_cfm_dormant(guard(), runner)
        self.assertEqual(captured.exception.code, "cfm_system_extension_registered")

    def test_all_known_cfm_runtime_surfaces_absent_passes_read_only_gate(self) -> None:
        observed: list[tuple[str, ...]] = []

        def runner(arguments: tuple[str, ...]) -> CommandResult:
            observed.append(arguments)
            if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                return CommandResult(0, "1 0 Thu Jul 23 15:20:55 2026 /sbin/launchd\n", "")
            if is_local_user_inventory_command(arguments):
                return CommandResult(0, local_users_fixture(), "")
            if arguments[:2] == ("/bin/launchctl", "print"):
                if arguments[2] == "system/com.bill.clashformac.helper":
                    return CommandResult(0, inactive_tombstone_fixture(), "")
                return CommandResult(
                    113,
                    "",
                    'Could not find service "fixture" in domain\n',
                )
            if arguments[1:] == ("--service-maintenance-v2", "status"):
                return CommandResult(0, service_status_fixture(), "")
            if arguments == ("/usr/bin/systemextensionsctl", "list"):
                return CommandResult(0, "0 extension(s)\n", "")
            raise AssertionError(arguments)

        require_cfm_dormant(guard(), runner)
        self.assertEqual(sum(command[0] == "/bin/launchctl" for command in observed), 3)
        self.assertTrue(
            any(command[1:] == ("--service-maintenance-v2", "status") for command in observed)
        )
        self.assertIn(("/usr/bin/systemextensionsctl", "list"), observed)

    def test_unrelated_system_extensions_do_not_block_dormancy(self) -> None:
        def runner(arguments: tuple[str, ...]) -> CommandResult:
            if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                return CommandResult(0, "1 0 Thu Jul 23 15:20:55 2026 /sbin/launchd\n", "")
            if is_local_user_inventory_command(arguments):
                return CommandResult(0, local_users_fixture(), "")
            if arguments[:2] == ("/bin/launchctl", "print"):
                if arguments[2] == "system/com.bill.clashformac.helper":
                    return CommandResult(0, inactive_tombstone_fixture(), "")
                return CommandResult(
                    113,
                    "",
                    'Could not find service "fixture" in domain\n',
                )
            if arguments[1:] == ("--service-maintenance-v2", "status"):
                return CommandResult(0, service_status_fixture(), "")
            if arguments == ("/usr/bin/systemextensionsctl", "list"):
                return CommandResult(
                    0,
                    system_extensions_fixture(
                        ("EZ5B6482X4", "com.devguru.DriverKit.SamsungMTP")
                    ),
                    "",
                )
            raise AssertionError(arguments)

        require_cfm_dormant(guard(), runner)

    def test_signed_service_status_and_inactive_tombstone_are_both_required(self) -> None:
        def run_with(*, service_status: str, tombstone: str) -> None:
            def runner(arguments: tuple[str, ...]) -> CommandResult:
                if arguments[:3] == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                    return CommandResult(
                        0, "1 0 Thu Jul 23 15:20:55 2026 /sbin/launchd\n", ""
                    )
                if is_local_user_inventory_command(arguments):
                    return CommandResult(0, local_users_fixture(), "")
                if arguments[:2] == ("/bin/launchctl", "print"):
                    if arguments[2] == "system/com.bill.clashformac.helper":
                        return CommandResult(0, tombstone, "")
                    return CommandResult(
                        113, "", 'Could not find service "fixture" in domain\n'
                    )
                if arguments[1:] == ("--service-maintenance-v2", "status"):
                    return CommandResult(0, service_status, "")
                if arguments == ("/usr/bin/systemextensionsctl", "list"):
                    return CommandResult(0, "0 extension(s)\n", "")
                raise AssertionError(arguments)

            require_cfm_dormant(guard(), runner)

        run_with(
            service_status=service_status_fixture(),
            tombstone=inactive_tombstone_fixture(),
        )
        with self.assertRaises(InstallError) as service_error:
            run_with(
                service_status=service_status_fixture(proxy="enabled"),
                tombstone=inactive_tombstone_fixture(),
            )
        self.assertEqual(service_error.exception.code, "cfm_service_status_invalid")
        with self.assertRaises(InstallError) as tombstone_error:
            run_with(
                service_status=service_status_fixture(),
                tombstone=inactive_tombstone_fixture().replace(
                    "active count = 0", "active count = 1"
                ),
            )
        self.assertEqual(tombstone_error.exception.code, "cfm_legacy_tombstone_invalid")


class InstallPredecessorTests(unittest.TestCase):
    """The install predecessor is observed, not pre-declared, and fails closed."""

    def test_current_schema_predecessor_selects_the_current_vocabulary(self) -> None:
        # 40041 speaks engine v6 / Authority v1.1, so a 40041 -> 40042 install
        # needs none of the 40019 compatibility actions.
        predecessor = resolve_predecessor(
            AppIdentity("0.4.0", "40041", INSTALLED_40041_PREDECESSOR.tree_sha256),
            "40042",
        )
        self.assertEqual(predecessor, INSTALLED_40041_PREDECESSOR)
        self.assertEqual(predecessor.off_proof_profile, "current_engine_v6_authority_v1_1")
        self.assertEqual(predecessor.unregister_proxy_action, "unregister-proxy-agent")
        self.assertEqual(
            predecessor.unregister_authority_action, "unregister-global-authority"
        )
        self.assertFalse(predecessor.supports_authority_recovery_intent)

    def test_legacy_predecessor_still_selects_the_compatibility_vocabulary(self) -> None:
        predecessor = resolve_predecessor(
            AppIdentity("0.4.0", "40019", INSTALLED_40019_PREDECESSOR.tree_sha256),
            "40042",
        )
        self.assertEqual(predecessor, INSTALLED_40019_PREDECESSOR)
        self.assertEqual(
            predecessor.off_proof_profile, "installed_40019_engine_v5_authority_v1_0"
        )
        self.assertEqual(
            predecessor.unregister_authority_action,
            "unregister-installed-40019-global-authority",
        )
        self.assertTrue(predecessor.supports_authority_recovery_intent)

    def test_unrecognised_predecessor_is_rejected_rather_than_guessed(self) -> None:
        # No admissible wire protocol exists for an unknown installed build.
        with self.assertRaises(InstallError) as raised:
            resolve_predecessor(AppIdentity("0.4.0", "40040", "a" * 64), "40042")
        self.assertEqual(raised.exception.code, "predecessor_unsupported")

    def test_predecessor_build_number_alone_is_not_trusted(self) -> None:
        # CFBundleVersion is an unauthenticated bundle string; the exact frozen
        # tree identity must agree with it.
        with self.assertRaises(InstallError) as raised:
            resolve_predecessor(AppIdentity("0.4.0", "40041", "f" * 64), "40042")
        self.assertEqual(raised.exception.code, "predecessor_identity_mismatch")

    def test_downgrade_and_reinstall_are_rejected(self) -> None:
        observed = AppIdentity("0.4.0", "40041", INSTALLED_40041_PREDECESSOR.tree_sha256)
        for candidate in ("40041", "40019"):
            with self.assertRaises(InstallError) as raised:
                resolve_predecessor(observed, candidate)
            self.assertEqual(raised.exception.code, "candidate_not_newer")

    def test_foreign_product_version_is_rejected(self) -> None:
        with self.assertRaises(InstallError) as raised:
            resolve_predecessor(
                AppIdentity("0.3.5", "40041", INSTALLED_40041_PREDECESSOR.tree_sha256),
                "40042",
            )
        self.assertEqual(raised.exception.code, "install_identity_mismatch")

    def test_absent_application_is_its_own_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "Clash for Mac.app"
            with self.assertRaises(InstallError) as raised:
                require_target_application_present(missing)
            self.assertEqual(raised.exception.code, "previous_app_absent")

    def test_a_symlinked_application_is_not_a_readable_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").mkdir()
            link = root / "Clash for Mac.app"
            link.symlink_to(root / "real")
            with self.assertRaises(InstallError) as raised:
                require_target_application_present(link)
            self.assertEqual(raised.exception.code, "app_identity_invalid")

    def test_an_old_journal_keeps_validating_against_its_own_vocabulary(self) -> None:
        # The 40019 -> 40041 migration journal is immutable evidence. It is read
        # with the vocabulary its own recorded predecessor implies.
        predecessor = bind_journal_predecessor(
            AppIdentity("0.4.0", "40019", INSTALLED_40019_PREDECESSOR.tree_sha256)
        )
        self.assertEqual(
            predecessor.unregister_proxy_action,
            "unregister-installed-40019-proxy-agent",
        )

    def test_the_supported_predecessor_table_is_an_exact_frozen_contract(self) -> None:
        self.assertEqual(
            dict(SUPPORTED_PREDECESSORS),
            {
                "40019": INSTALLED_40019_PREDECESSOR,
                "40041": INSTALLED_40041_PREDECESSOR,
            },
        )
        with self.assertRaises(TypeError):
            SUPPORTED_PREDECESSORS["40042"] = INSTALLED_40041_PREDECESSOR  # type: ignore[index]

    def test_current_predecessor_event_contract_never_admits_recovery(self) -> None:
        # A current-schema predecessor speaks the plain vocabulary at every
        # event and can never be asked to recover a 40019-era Authority.
        # Exercised on the bound contract directly: a full 40041 -> 40042
        # transaction round-trip needs the 40042 profile.
        bound = install.BoundInstallProfile(GA_INSTALL_PROFILE, INSTALLED_40041_PREDECESSOR)
        self.assertEqual(
            bound.service_actions,
            (
                "prepare",
                "unregister-proxy-agent",
                "unregister-global-authority",
                "verify-dormant",
                "register-global-authority",
                "register-proxy-agent",
                "prove-off",
            ),
        )
        self.assertEqual(
            bound.service_event_proof_profiles,
            (install.CURRENT_OFF_PROOF_PROFILE,) * len(bound.service_actions),
        )
        for sequence in range(len(bound.service_actions)):
            actions, profiles = bound.service_event_contract(
                sequence, authority_recovery_prepared=False
            )
            self.assertEqual(actions, frozenset({bound.service_actions[sequence]}))
            self.assertEqual(profiles, frozenset({install.CURRENT_OFF_PROOF_PROFILE}))
            with self.assertRaises(InstallError) as raised:
                bound.service_event_contract(sequence, authority_recovery_prepared=True)
            self.assertEqual(raised.exception.code, "service_journal_invalid")

    def test_legacy_predecessor_event_contract_widens_only_the_authority_step(self) -> None:
        bound = install.BoundInstallProfile(GA_INSTALL_PROFILE, INSTALLED_40019_PREDECESSOR)
        authority = bound.service_actions.index(
            "unregister-installed-40019-global-authority"
        )
        actions, profiles = bound.service_event_contract(
            authority, authority_recovery_prepared=True
        )
        self.assertEqual(actions, frozenset({install.INSTALLED_40019_RECOVERY_ACTION}))
        self.assertEqual(
            profiles, frozenset({install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE})
        )
        actions, profiles = bound.service_event_contract(
            authority, authority_recovery_prepared=False
        )
        self.assertEqual(
            actions, frozenset({"unregister-installed-40019-global-authority"})
        )
        self.assertEqual(profiles, frozenset({install.INSTALLED_40019_OFF_PROOF_PROFILE}))
        # The step after the Authority unregister only changes its proof
        # profile; every other step is identical whether or not a recovery
        # intent exists.
        for sequence in range(len(bound.service_actions)):
            if sequence == authority:
                continue
            plain = bound.service_event_contract(
                sequence, authority_recovery_prepared=False
            )
            recovering = bound.service_event_contract(
                sequence, authority_recovery_prepared=True
            )
            self.assertEqual(plain[0], recovering[0])
            if sequence == authority + 1:
                self.assertEqual(
                    plain[1], frozenset({install.INSTALLED_40019_OFF_PROOF_PROFILE})
                )
                self.assertEqual(
                    recovering[1],
                    frozenset({install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE}),
                )
            else:
                self.assertEqual(plain[1], recovering[1])

    def test_a_binding_is_reached_only_through_observation_or_the_record(self) -> None:
        observed = install.BoundInstallProfile.observed(
            GA_INSTALL_PROFILE,
            AppIdentity("0.4.0", "40019", INSTALLED_40019_PREDECESSOR.tree_sha256),
        )
        recorded = install.BoundInstallProfile.recorded(
            GA_INSTALL_PROFILE,
            AppIdentity("0.4.0", "40019", INSTALLED_40019_PREDECESSOR.tree_sha256),
        )
        self.assertEqual(observed, recorded)
        self.assertEqual(observed.predecessor, INSTALLED_40019_PREDECESSOR)
        self.assertEqual(observed.profile.build_number, GA_INSTALL_PROFILE.build_number)
        # The installed 40041 is the production observation for this build.
        self.assertEqual(
            install.BoundInstallProfile.observed(GA_INSTALL_PROFILE, INSTALLED).predecessor,
            INSTALLED_40041_PREDECESSOR,
        )
        # Observation demands a supported predecessor strictly older than this
        # build; the GA build itself is neither.
        with self.assertRaises(InstallError) as raised:
            install.BoundInstallProfile.observed(GA_INSTALL_PROFILE, NEW)
        self.assertEqual(raised.exception.code, "predecessor_unsupported")
        # The record carries the same identity proof, so it stays readable as
        # evidence of any supported predecessor.
        self.assertEqual(
            install.BoundInstallProfile.recorded(GA_INSTALL_PROFILE, INSTALLED).predecessor,
            INSTALLED_40041_PREDECESSOR,
        )
        with self.assertRaises(InstallError) as raised:
            install.BoundInstallProfile.recorded(
                GA_INSTALL_PROFILE, AppIdentity("0.4.0", "40041", "f" * 64)
            )
        self.assertEqual(raised.exception.code, "predecessor_identity_mismatch")


class SystemExtensionParserTests(unittest.TestCase):
    def test_unrelated_and_near_match_identities_are_accepted(self) -> None:
        identities = _parse_system_extension_identities(
            system_extensions_fixture(
                ("EZ5B6482X4", "com.devguru.DriverKit.SamsungMTP"),
                ("YKUPL7Z869", "com.bill.clashformac.packet-tunnelx"),
            )
        )
        self.assertEqual(
            identities,
            {
                ("EZ5B6482X4", "com.devguru.DriverKit.SamsungMTP"),
                ("YKUPL7Z869", "com.bill.clashformac.packet-tunnelx"),
            },
        )

    def test_empty_output_is_the_only_zero_count_shape(self) -> None:
        self.assertEqual(_parse_system_extension_identities("0 extension(s)\n"), set())
        with self.assertRaises(InstallError) as captured:
            _parse_system_extension_identities(
                "0 extension(s)\n--- com.apple.system_extension.network_extension\n"
            )
        self.assertEqual(
            captured.exception.code, "cfm_system_extension_observation_invalid"
        )

    def test_malformed_count_header_duplicate_and_row_fail_closed(self) -> None:
        valid = system_extensions_fixture(("EZ5B6482X4", "com.example.extension"))
        malformed = {
            "count": valid.replace("1 extension(s)", "2 extension(s)", 1),
            "header": valid.replace("teamID", "team", 1),
            "duplicate": valid.replace("1 extension(s)", "2 extension(s)", 1)
            + valid.split("\n", 3)[3],
            "row": valid.replace("EZ5B6482X4", "invalid-team", 1),
            "diagnostic": valid + "warning: partial output\n",
        }
        for label, output in malformed.items():
            with self.subTest(label=label), self.assertRaises(InstallError) as captured:
                _parse_system_extension_identities(output)
            self.assertEqual(
                captured.exception.code, "cfm_system_extension_observation_invalid"
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
    class _FakePipe:
        def __init__(
            self,
            *,
            descriptor: int = 11,
            close_error: bool = False,
            close_exception: BaseException | None = None,
        ) -> None:
            self.descriptor = descriptor
            self.close_error = close_error
            self.close_exception = close_exception
            self.closed = False

        def fileno(self) -> int:
            return self.descriptor

        def close(self) -> None:
            self.closed = True
            if self.close_exception is not None:
                raise self.close_exception
            if self.close_error:
                raise OSError("fixture pipe close failure")

    class _FakeProcess:
        def __init__(
            self,
            stdout: "BoundedCommandRunnerTests._FakePipe",
            stderr: "BoundedCommandRunnerTests._FakePipe",
        ) -> None:
            self.pid = 424_242
            self.stdout = stdout
            self.stderr = stderr

    @staticmethod
    def _unreaped_process() -> Mock:
        process = Mock()
        process.pid = 424_242
        process.returncode = None

        def reap(*, timeout: float) -> int:
            if timeout <= 0:
                raise AssertionError("fixture received a nonpositive wait timeout")
            process.returncode = 0
            return 0

        process.wait.side_effect = reap
        return process

    def test_leader_exit_observation_is_nonreaping_and_fail_closed(self) -> None:
        process = self._unreaped_process()
        with patch(
            "scripts.dormant_app_install.os.waitid",
            return_value=object(),
        ) as waitid:
            self.assertTrue(install._leader_exited_without_reaping(process))
        waitid.assert_called_once_with(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
        self.assertIsNone(process.returncode)

        for error, expected_code in (
            (ChildProcessError("fixture ECHILD"), "command_wait_failed"),
            (OSError("fixture waitid"), "command_wait_failed"),
            (KeyboardInterrupt(), "command_cleanup_interrupted"),
        ):
            with (
                self.subTest(error=type(error).__name__),
                patch(
                    "scripts.dormant_app_install.os.waitid",
                    side_effect=error,
                ),
                self.assertRaises(InstallError) as captured,
            ):
                install._leader_exited_without_reaping(process)
            self.assertEqual(captured.exception.code, expected_code)
            self.assertIs(captured.exception.__cause__, error)

    def test_unreaped_leader_fallback_preserves_signal_failures(self) -> None:
        process = self._unreaped_process()
        missing_error = ProcessLookupError("fixture leader signal race")
        process.kill.side_effect = missing_error
        with patch(
            "scripts.dormant_app_install._leader_exited_without_reaping",
            return_value=False,
        ):
            failure = install._kill_unreaped_leader(process)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_termination_failed")
        self.assertIs(failure.__cause__, missing_error)

        for signal_error, expected_code in (
            (
                OSError(errno.EPERM, "fixture leader signal denied"),
                "command_termination_failed",
            ),
            (KeyboardInterrupt(), "command_cleanup_interrupted"),
        ):
            with self.subTest(signal_error=type(signal_error).__name__):
                process = self._unreaped_process()
                process.kill.side_effect = signal_error
                failure = install._kill_unreaped_leader(process)
                self.assertIsNotNone(failure)
                self.assertEqual(failure.code, expected_code)
                self.assertIs(failure.__cause__, signal_error)

    def test_group_cleanup_sends_one_signal_then_only_observes(self) -> None:
        process = self._unreaped_process()
        outcomes: list[BaseException | None] = [
            None,
            None,
            PermissionError("fixture transient EPERM"),
            ProcessLookupError("fixture group absent"),
        ]

        def killpg(_group: int, _requested_signal: int) -> None:
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome

        with patch(
            "scripts.dormant_app_install.os.killpg",
            side_effect=killpg,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            return_value=0,
        ), patch("scripts.dormant_app_install.time.sleep"):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNone(failure)
        self.assertEqual(
            signal_group.call_args_list,
            [
                call(process.pid, signal.SIGKILL),
                call(process.pid, 0),
                call(process.pid, 0),
                call(process.pid, 0),
            ],
        )
        self.assertFalse(outcomes)

    def test_initial_group_signal_interruption_uses_safe_leader_fallback(
        self,
    ) -> None:
        process = self._unreaped_process()
        signal_interruption = KeyboardInterrupt()
        outcomes: list[BaseException | None] = [
            signal_interruption,
            ProcessLookupError("fixture group absent"),
        ]

        def killpg(_group: int, _requested_signal: int) -> None:
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome

        with patch(
            "scripts.dormant_app_install.os.killpg",
            side_effect=killpg,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            return_value=0,
        ):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_cleanup_interrupted")
        self.assertIs(failure.__cause__, signal_interruption)
        process.kill.assert_called_once_with()
        self.assertEqual(
            signal_group.call_args_list,
            [call(process.pid, signal.SIGKILL), call(process.pid, 0)],
        )
        self.assertFalse(outcomes)

    def test_group_cleanup_never_signals_a_persistently_visible_reused_id(
        self,
    ) -> None:
        process = self._unreaped_process()
        with patch(
            "scripts.dormant_app_install.os.killpg",
            return_value=None,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            side_effect=(0, 0, 6),
        ), patch("scripts.dormant_app_install.time.sleep"):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_termination_failed")
        self.assertEqual(
            str(failure),
            "spawned command group did not disappear after SIGKILL",
        )
        self.assertEqual(
            signal_group.call_args_list,
            [call(process.pid, signal.SIGKILL), call(process.pid, 0)],
        )

    def test_group_cleanup_requires_absence_after_permission_limited_probe(
        self,
    ) -> None:
        process = self._unreaped_process()
        outcomes: list[BaseException | None] = [
            None,
            PermissionError("fixture persistent EPERM"),
        ]

        def killpg(_group: int, _requested_signal: int) -> None:
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome

        with patch(
            "scripts.dormant_app_install.os.killpg",
            side_effect=killpg,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            side_effect=(0, 0, 6),
        ), patch("scripts.dormant_app_install.time.sleep"):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_termination_failed")
        self.assertEqual(
            str(failure),
            "spawned command group absence could not be observed",
        )
        self.assertEqual(
            signal_group.call_args_list,
            [call(process.pid, signal.SIGKILL), call(process.pid, 0)],
        )

    def test_initial_group_failure_distinguishes_running_and_exited_leader(
        self,
    ) -> None:
        for signal_error in (PermissionError, ProcessLookupError):
            for leader_exited, expected_failure in ((False, True), (True, False)):
                with self.subTest(
                    signal_error=signal_error.__name__,
                    leader_exited=leader_exited,
                ):
                    process = self._unreaped_process()
                    outcomes: list[BaseException | None] = [
                        signal_error("fixture initial group failure"),
                        ProcessLookupError("fixture group absent"),
                    ]

                    def killpg(_group: int, _requested_signal: int) -> None:
                        outcome = outcomes.pop(0)
                        if outcome is not None:
                            raise outcome

                    with patch(
                        "scripts.dormant_app_install.os.killpg",
                        side_effect=killpg,
                    ) as signal_group, patch(
                        "scripts.dormant_app_install._leader_exited_without_reaping",
                        return_value=leader_exited,
                    ), patch(
                        "scripts.dormant_app_install.time.monotonic",
                        return_value=0,
                    ):
                        failure = install._terminate_process_group(process, process.pid)
                    self.assertEqual(failure is not None, expected_failure)
                    self.assertEqual(
                        signal_group.call_args_list,
                        [
                            call(process.pid, signal.SIGKILL),
                            call(process.pid, 0),
                        ],
                    )
                    self.assertFalse(outcomes)
                    self.assertEqual(process.kill.call_count, int(not leader_exited))

    def test_initial_group_and_leader_observation_failure_kills_leader(self) -> None:
        for signal_error in (PermissionError, ProcessLookupError):
            with self.subTest(signal_error=signal_error.__name__):
                process = self._unreaped_process()
                observation_cause = ChildProcessError("fixture waitid failure")
                observation_failure = InstallError(
                    "command_wait_failed",
                    "fixture leader observation failure",
                )
                observation_failure.__cause__ = observation_cause
                outcomes: list[BaseException | None] = [
                    signal_error("fixture initial group failure"),
                    ProcessLookupError("fixture group absent"),
                ]

                def killpg(_group: int, _requested_signal: int) -> None:
                    outcome = outcomes.pop(0)
                    if outcome is not None:
                        raise outcome

                with patch(
                    "scripts.dormant_app_install.os.killpg",
                    side_effect=killpg,
                ) as signal_group, patch(
                    "scripts.dormant_app_install._leader_exited_without_reaping",
                    side_effect=observation_failure,
                ), patch(
                    "scripts.dormant_app_install.time.monotonic",
                    return_value=0,
                ):
                    failure = install._terminate_process_group(process, process.pid)
                self.assertIs(failure, observation_failure)
                self.assertIs(failure.__cause__, observation_cause)
                process.kill.assert_called_once_with()
                self.assertEqual(
                    signal_group.call_args_list,
                    [
                        call(process.pid, signal.SIGKILL),
                        call(process.pid, 0),
                    ],
                )
                self.assertFalse(outcomes)

    def test_interrupted_group_wait_uses_one_signal_and_the_same_deadline(
        self,
    ) -> None:
        process = self._unreaped_process()
        attempts = 0

        def wait(*, timeout: float) -> int:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise KeyboardInterrupt
            process.returncode = 0
            return 0

        process.wait.side_effect = wait
        outcomes: list[BaseException | None] = [
            None,
            ProcessLookupError("fixture group absent"),
        ]

        def killpg(_group: int, _requested_signal: int) -> None:
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome

        with patch(
            "scripts.dormant_app_install.os.killpg",
            side_effect=killpg,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            side_effect=(10, 11, 12),
        ):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_cleanup_interrupted")
        self.assertIsInstance(failure.__cause__, KeyboardInterrupt)
        self.assertEqual(
            [entry.args[1] for entry in signal_group.call_args_list],
            [signal.SIGKILL, 0],
        )
        self.assertFalse(outcomes)
        self.assertEqual(
            [entry.kwargs["timeout"] for entry in process.wait.call_args_list],
            [4, 3],
        )

    def test_group_wait_timeout_fails_without_resignalling(self) -> None:
        process = self._unreaped_process()
        process.wait.side_effect = subprocess.TimeoutExpired(
            cmd=("fixture",),
            timeout=5,
        )
        with patch(
            "scripts.dormant_app_install.os.killpg",
            return_value=None,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            side_effect=(0, 0),
        ):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_termination_failed")
        self.assertIsInstance(failure.__cause__, subprocess.TimeoutExpired)
        self.assertEqual(
            signal_group.call_args_list,
            [call(process.pid, signal.SIGKILL)],
        )

    def test_absence_observation_interruption_continues_without_resignalling(
        self,
    ) -> None:
        process = self._unreaped_process()
        outcomes: list[BaseException | None] = [
            None,
            None,
            ProcessLookupError("fixture group absent"),
        ]

        def killpg(_group: int, _requested_signal: int) -> None:
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome

        with patch(
            "scripts.dormant_app_install.os.killpg",
            side_effect=killpg,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            return_value=0,
        ), patch(
            "scripts.dormant_app_install.time.sleep",
            side_effect=KeyboardInterrupt,
        ):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_cleanup_interrupted")
        self.assertIsInstance(failure.__cause__, KeyboardInterrupt)
        self.assertEqual(
            [entry.args[1] for entry in signal_group.call_args_list],
            [signal.SIGKILL, 0, 0],
        )
        self.assertFalse(outcomes)

    def test_generic_absence_probe_error_is_preserved(self) -> None:
        process = self._unreaped_process()
        probe_error = OSError(errno.EIO, "fixture probe failure")
        outcomes: list[BaseException | None] = [None, probe_error]

        def killpg(_group: int, _requested_signal: int) -> None:
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome

        with patch(
            "scripts.dormant_app_install.os.killpg",
            side_effect=killpg,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            return_value=0,
        ):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_termination_failed")
        self.assertIs(failure.__cause__, probe_error)
        self.assertEqual(
            signal_group.call_args_list,
            [call(process.pid, signal.SIGKILL), call(process.pid, 0)],
        )
        self.assertFalse(outcomes)

    def test_absence_probe_interruption_is_typed_and_retried(self) -> None:
        process = self._unreaped_process()
        probe_interruption = KeyboardInterrupt()
        outcomes: list[BaseException | None] = [
            None,
            probe_interruption,
            ProcessLookupError("fixture group absent"),
        ]

        def killpg(_group: int, _requested_signal: int) -> None:
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome

        with patch(
            "scripts.dormant_app_install.os.killpg",
            side_effect=killpg,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            return_value=0,
        ), patch(
            "scripts.dormant_app_install.time.sleep",
        ):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_cleanup_interrupted")
        self.assertIs(failure.__cause__, probe_interruption)
        self.assertEqual(
            [entry.args[1] for entry in signal_group.call_args_list],
            [signal.SIGKILL, 0, 0],
        )
        self.assertFalse(outcomes)

    def test_secondary_cleanup_errors_are_retained_as_notes(self) -> None:
        process = self._unreaped_process()
        group_error = OSError(errno.EIO, "fixture group signal failure")
        probe_error = OSError(errno.EBUSY, "fixture group probe failure")
        outcomes: list[BaseException | None] = [group_error, probe_error]

        def killpg(_group: int, _requested_signal: int) -> None:
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome

        with patch(
            "scripts.dormant_app_install.os.killpg",
            side_effect=killpg,
        ) as signal_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            return_value=0,
        ):
            failure = install._terminate_process_group(process, process.pid)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.code, "command_termination_failed")
        self.assertIs(failure.__cause__, group_error)
        self.assertIn(
            "secondary cleanup failure: spawned command group absence could "
            "not be observed (OSError errno=16)",
            failure.__notes__,
        )
        self.assertEqual(
            signal_group.call_args_list,
            [call(process.pid, signal.SIGKILL), call(process.pid, 0)],
        )
        process.kill.assert_called_once_with()
        self.assertFalse(outcomes)

    def test_primary_and_cleanup_causes_are_both_retained(self) -> None:
        stdout = self._FakePipe()
        stderr = self._FakePipe()
        process = self._FakeProcess(stdout, stderr)
        cleanup_cause = KeyboardInterrupt()
        cleanup_failure = InstallError(
            "command_cleanup_interrupted",
            "fixture cleanup interruption",
        )
        cleanup_failure.__cause__ = cleanup_cause
        with patch(
            "scripts.dormant_app_install.subprocess.Popen",
            return_value=process,
        ), patch(
            "scripts.dormant_app_install.selectors.DefaultSelector",
            side_effect=OSError("fixture selector exhaustion"),
        ), patch(
            "scripts.dormant_app_install._terminate_process_group",
            return_value=cleanup_failure,
        ), self.assertRaises(InstallError) as captured:
            _run_bounded_process(("/usr/bin/true",), timeout=1)
        self.assertIs(captured.exception, cleanup_failure)
        self.assertIsInstance(captured.exception.__cause__, InstallError)
        self.assertEqual(captured.exception.__cause__.code, "command_io_unavailable")
        self.assertIn(
            "cleanup failure cause before primary failure chaining "
            "(KeyboardInterrupt)",
            captured.exception.__notes__,
        )

    def test_cleanup_failure_stops_pipe_drain_without_command_deadline_delay(
        self,
    ) -> None:
        stdout = self._FakePipe(descriptor=11)
        stderr = self._FakePipe(descriptor=12)
        process = self._FakeProcess(stdout, stderr)
        process.returncode = None
        selector = Mock()
        selector.get_map.return_value = {11: object(), 12: object()}
        selector.select.return_value = []
        cleanup_failure = InstallError(
            "command_termination_failed",
            "fixture cleanup failure",
        )

        def terminate(_process: object, _group: int) -> InstallError:
            process.returncode = 0
            return cleanup_failure

        with patch(
            "scripts.dormant_app_install.subprocess.Popen",
            return_value=process,
        ), patch(
            "scripts.dormant_app_install.selectors.DefaultSelector",
            return_value=selector,
        ), patch(
            "scripts.dormant_app_install.os.set_blocking",
        ), patch(
            "scripts.dormant_app_install._leader_exited_without_reaping",
            return_value=True,
        ), patch(
            "scripts.dormant_app_install._terminate_process_group",
            side_effect=terminate,
        ) as terminate_group, patch(
            "scripts.dormant_app_install.time.monotonic",
            side_effect=(0, 0),
        ) as monotonic, self.assertRaises(InstallError) as captured:
            _run_bounded_process(("/usr/bin/true",), timeout=600)
        self.assertIs(captured.exception, cleanup_failure)
        terminate_group.assert_called_once_with(process, process.pid)
        selector.select.assert_called_once()
        self.assertEqual(monotonic.call_count, 2)
        self.assertTrue(stdout.closed)
        self.assertTrue(stderr.closed)

    def test_selector_initialization_failure_cleans_process_and_both_pipes(
        self,
    ) -> None:
        for stdout_close_error in (False, True):
            with self.subTest(stdout_close_error=stdout_close_error):
                stdout = self._FakePipe(close_error=stdout_close_error)
                stderr = self._FakePipe()
                process = self._FakeProcess(stdout, stderr)
                with patch(
                    "scripts.dormant_app_install.subprocess.Popen",
                    return_value=process,
                ), patch(
                    "scripts.dormant_app_install.selectors.DefaultSelector",
                    side_effect=OSError("fixture selector exhaustion"),
                ), patch(
                    "scripts.dormant_app_install._terminate_process_group",
                    return_value=None,
                ) as terminate, self.assertRaises(InstallError) as captured:
                    _run_bounded_process(("/usr/bin/true",), timeout=1)
                self.assertEqual(
                    captured.exception.code,
                    (
                        "command_cleanup_failed"
                        if stdout_close_error
                        else "command_io_unavailable"
                    ),
                )
                terminate.assert_called_once_with(process, process.pid)
                self.assertTrue(stdout.closed)
                self.assertTrue(stderr.closed)

    def test_post_selector_io_failure_is_typed_and_cleans_every_resource(
        self,
    ) -> None:
        stdout = self._FakePipe(descriptor=11)
        stderr = self._FakePipe(descriptor=12)
        process = self._FakeProcess(stdout, stderr)
        with patch(
            "scripts.dormant_app_install.subprocess.Popen",
            return_value=process,
        ), patch(
            "scripts.dormant_app_install.os.set_blocking",
            side_effect=OSError("fixture descriptor exhaustion"),
        ), patch(
            "scripts.dormant_app_install._terminate_process_group",
            return_value=None,
        ) as terminate, self.assertRaises(InstallError) as captured:
            _run_bounded_process(("/usr/bin/true",), timeout=1)
        self.assertEqual(captured.exception.code, "command_io_unavailable")
        self.assertIsInstance(captured.exception.__cause__, OSError)
        terminate.assert_called_once_with(process, process.pid)
        self.assertTrue(stdout.closed)
        self.assertTrue(stderr.closed)

    def test_close_interruptions_do_not_skip_remaining_cleanup(self) -> None:
        for interrupted_resource in ("selector", "stdout"):
            with self.subTest(interrupted_resource=interrupted_resource):
                close_interruption = KeyboardInterrupt()
                stdout = self._FakePipe(
                    descriptor=11,
                    close_exception=(
                        close_interruption
                        if interrupted_resource == "stdout"
                        else None
                    ),
                )
                stderr = self._FakePipe(descriptor=12)
                process = self._FakeProcess(stdout, stderr)
                selector = Mock()
                if interrupted_resource == "selector":
                    selector.close.side_effect = close_interruption
                with patch(
                    "scripts.dormant_app_install.subprocess.Popen",
                    return_value=process,
                ), patch(
                    "scripts.dormant_app_install.selectors.DefaultSelector",
                    return_value=selector,
                ), patch(
                    "scripts.dormant_app_install.os.set_blocking",
                    side_effect=OSError("fixture descriptor exhaustion"),
                ), patch(
                    "scripts.dormant_app_install._terminate_process_group",
                    return_value=None,
                ) as terminate, self.assertRaises(InstallError) as captured:
                    _run_bounded_process(("/usr/bin/true",), timeout=1)
                self.assertEqual(
                    captured.exception.code,
                    "command_cleanup_interrupted",
                )
                self.assertIsInstance(captured.exception.__cause__, InstallError)
                self.assertEqual(
                    captured.exception.__cause__.code,
                    "command_io_unavailable",
                )
                self.assertIn(
                    "cleanup failure cause before primary failure chaining "
                    "(KeyboardInterrupt)",
                    captured.exception.__notes__,
                )
                terminate.assert_called_once_with(process, process.pid)
                self.assertTrue(stdout.closed)
                self.assertTrue(stderr.closed)

    def test_immediate_exit_has_a_result_and_only_uses_its_spawned_group(self) -> None:
        observed_groups: list[int] = []
        cleanup_events: list[tuple[str, int]] = []
        spawned_pids: list[int] = []
        real_killpg = os.killpg
        real_waitid = os.waitid
        real_popen = subprocess.Popen

        def observe(group: int, requested_signal: int) -> None:
            observed_groups.append(group)
            cleanup_events.append((f"signal-{requested_signal}", group))
            real_killpg(group, requested_signal)

        def observe_leader(idtype: int, pid: int, options: int):
            observation = real_waitid(idtype, pid, options)
            if observation is not None:
                cleanup_events.append(("leader-exited-unreaped", pid))
            return observation

        def spawn(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            spawned_pids.append(process.pid)
            return process

        with patch("scripts.dormant_app_install.os.killpg", side_effect=observe), patch(
            "scripts.dormant_app_install.subprocess.Popen", side_effect=spawn
        ), patch(
            "scripts.dormant_app_install.os.waitid", side_effect=observe_leader
        ):
            result = _run_bounded_process((sys.executable, "-c", "raise SystemExit(0)"), timeout=2)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(spawned_pids, list(set(spawned_pids)))
        self.assertTrue(observed_groups)
        self.assertEqual(set(observed_groups), set(spawned_pids))
        self.assertEqual(
            cleanup_events[0],
            ("leader-exited-unreaped", spawned_pids[0]),
        )
        self.assertEqual(
            [
                event
                for event in cleanup_events
                if event[0] == f"signal-{signal.SIGKILL}"
            ],
            [(f"signal-{signal.SIGKILL}", spawned_pids[0])],
        )
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

    def test_signed_host_maintenance_commands_are_exact_and_closed(self) -> None:
        executables = (str(InstallPaths.production().candidate_executable),)
        for executable in executables:
            for action in (
                "prove-off",
                "prove-installed-40019-off",
                "status",
                "unregister-proxy-agent",
                "unregister-installed-40019-proxy-agent",
                "unregister-global-authority",
                "unregister-installed-40019-global-authority",
                install.INSTALLED_40019_RECOVERY_ACTION,
                "register-global-authority",
                "register-proxy-agent",
            ):
                _require_fixed_command(
                    (executable, "--service-maintenance-v2", action)
                )
        executable = executables[0]
        for command in (
            (executable, "--service-maintenance-v2", "unknown"),
            (executable, "--service-maintenance-v2", "status", "extra"),
            ("/tmp/clash-for-mac", "--service-maintenance-v2", "status"),
        ):
            with self.subTest(command=command), self.assertRaises(InstallError):
                _require_fixed_command(command)

    def test_launchctl_observation_allows_only_fixed_current_and_tombstone_jobs(self) -> None:
        for domain in (
            "system/com.bill.clashformac.global-authority",
            "system/com.bill.clashformac.helper",
            "gui/501/com.bill.clashformac.proxy-agent",
        ):
            _require_fixed_command(("/bin/launchctl", "print", domain))
        for domain in (
            "system/com.bill.clashformac.unreviewed",
            "gui/0/com.bill.clashformac.proxy-agent",
            "gui/501/com.bill.clashformac.helper",
        ):
            with self.subTest(domain=domain), self.assertRaises(InstallError):
                _require_fixed_command(("/bin/launchctl", "print", domain))

if __name__ == "__main__":
    unittest.main()
