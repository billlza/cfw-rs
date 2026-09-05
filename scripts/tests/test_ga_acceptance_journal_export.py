from __future__ import annotations

import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts import current_service_transaction as service
from scripts import dormant_app_install as install
from scripts import ga_acceptance_environment as ga_environment
from scripts import ga_acceptance_journal_export as journal_export
from scripts.publication.common import PublicationError, canonical_json
from scripts.publication.durable_file import (
    DurabilityOutcomeUnknown,
    RootedDirectoryChanged,
)


# The recorded predecessor is the installed 40041 with its real frozen tree
# identity; the install journal is only readable against the exact predecessor
# it names, and that predecessor selects the current service vocabulary.
PREVIOUS = install.AppIdentity(
    "0.4.0", "40041", install.INSTALLED_40041_PREDECESSOR.tree_sha256
)
BOUND = install.BoundInstallProfile.recorded(install.GA_INSTALL_PROFILE, PREVIOUS)
CANDIDATE = install.CandidateIdentity(
    app=install.AppIdentity("0.4.0", "40043", "b" * 64),
    manifest_sha256="c" * 64,
    repository_commit="d" * 40,
    release_source_sha256="e" * 64,
)
ENVIRONMENT = {
    "architecture": "arm64",
    "boot_environment_sha256": "7" * 64,
    "document": ga_environment.DOCUMENT,
    "hardware_model": "Mac16,1",
    "machine_sha256": "8" * 64,
    "macos_build_version": "26A5388g",
    "macos_product_version": "27.0",
    "physical_nonvirtualized": True,
    "schema_version": ga_environment.SCHEMA_VERSION,
}
TRANSACTION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def guard() -> dict[str, object]:
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
                "uid": os.geteuid(),
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
        "proxy_sha256": "1" * 64,
        "routes_ipv4_sha256": "5" * 64,
        "routes_ipv6_sha256": "6" * 64,
        "tun_sha256": "9" * 64,
    }


class JournalExportFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name).resolve(strict=True)
        self.repository = root / "repository"
        self.source_parent = root / "Applications"
        self.repository.mkdir()
        self.source_parent.mkdir()
        stage_input_root = self.repository.joinpath(
            *journal_export.STAGE_INPUT_ROOT_RELATIVE.parts
        )
        stage_input_root.mkdir(parents=True)
        stage_input_root.chmod(0o700)
        profile = install.GA_INSTALL_PROFILE
        candidate_root = self.repository / "candidate"
        self.install_paths = install.InstallPaths(
            repository=self.repository,
            candidate_app=candidate_root / install.TARGET_NAME,
            candidate_manifest=candidate_root / f"{install.TARGET_NAME}.manifest.json",
            target_parent=self.source_parent,
            operator_repository=self.repository,
            profile=profile,
        )
        self.service_paths = service.ServicePaths(
            install_paths=self.install_paths,
            transaction_parent=self.source_parent,
        )
        self.paths = journal_export.JournalExportPaths(
            repository=self.repository,
            install_paths=self.install_paths,
            service_paths=self.service_paths,
        )
        self._write_service_journal()
        self._write_install_journal()

    def cleanup(self) -> None:
        self.temporary.cleanup()

    def _write_service_journal(self) -> None:
        with service.ServiceEventStore(self.service_paths) as store:
            with store.locked():
                intent, events = store.create(
                    CANDIDATE,
                    PREVIOUS,
                    guard(),
                    ENVIRONMENT,
                )
                for sequence in range(1, len(service.PHASES)):
                    events.append(
                        store.append(
                            events,
                            intent=intent,
                            phase=service.PHASES[sequence],
                            action=BOUND.service_actions[sequence],
                            guard=guard(),
                        )
                    )

    def install_document(self) -> dict[str, object]:
        return {
            "candidate": CANDIDATE.document(),
            "document": install.DOCUMENT,
            "ga_environment_sha256": ga_environment.environment_sha256(
                ENVIRONMENT
            ),
            "guards": [
                {"after": guard(), "before": guard(), "operation": "install"}
            ],
            "phase": "installed",
            "previous": PREVIOUS.document(),
            "schema_version": install.SCHEMA_VERSION,
            "sequence": 4,
            "staging_name": f"{install.STAGING_PREFIX}{TRANSACTION_ID}",
            "transaction_id": TRANSACTION_ID,
        }

    def _write_install_journal(self) -> None:
        with install.JournalStore(self.install_paths) as store:
            with store.locked():
                store.write(self.install_document())

    def export(self) -> dict[str, object]:
        return journal_export.export_ga_acceptance_journals(
            self.paths,
            observer=lambda: dict(ENVIRONMENT),
            transaction_id=TRANSACTION_ID,
        )

    def recover(self) -> dict[str, object]:
        return journal_export.recover_ga_acceptance_journal_export(
            self.paths,
            observer=lambda: dict(ENVIRONMENT),
        )

    def verify(self) -> dict[str, object]:
        with patch.object(
            journal_export.JournalExportPaths,
            "verification",
            return_value=self.paths,
        ):
            return journal_export.verify_ga_acceptance_journal_export(
                self.repository
            )


@unittest.skipUnless(os.uname().sysname == "Darwin", "durable rename is macOS-only")
class GAAcceptanceJournalExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = JournalExportFixture()
        self.addCleanup(self.fixture.cleanup)

    def test_real_producer_journals_export_as_one_private_container(self) -> None:
        exported = self.fixture.export()
        verified = self.fixture.verify()
        self.assertEqual(exported, verified)
        self.assertEqual(exported["candidate"], CANDIDATE.document())
        self.assertEqual(exported["previous"], PREVIOUS.document())
        self.assertEqual(
            exported["environment"]["sha256"],
            ga_environment.environment_sha256(ENVIRONMENT),
        )
        root = self.fixture.paths.migration_root
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        self.assertEqual(
            set(os.listdir(root)),
            {
                journal_export.INSTALL_NAME,
                journal_export.SERVICE_NAME,
                journal_export.INTERNAL_INTENT_NAME,
                journal_export.RECEIPT_NAME,
            },
        )
        self.assertFalse((root / "environment.json").exists())
        environment_path = root.joinpath(
            journal_export.SERVICE_NAME,
            service.ENVIRONMENT_NAME,
        )
        self.assertEqual(environment_path.read_bytes(), canonical_json(ENVIRONMENT))
        for current, directories, files in os.walk(root):
            for directory in directories:
                self.assertEqual(
                    stat.S_IMODE((Path(current) / directory).stat().st_mode),
                    0o700,
                )
            for name in files:
                self.assertEqual(
                    stat.S_IMODE((Path(current) / name).stat().st_mode),
                    0o600,
                )
        corpus = b"".join(
            path.read_bytes() for path in root.rglob("*") if path.is_file()
        ).lower()
        self.assertNotIn(b"io_platform_uuid", corpus)
        self.assertNotIn(b"volume_group_uuid", corpus)
        self.assertNotIn(b"boot_session", corpus)

    def test_boolean_schema_aliases_are_rejected_end_to_end(self) -> None:
        self.fixture.export()
        external_path = self.fixture.paths.external_intent
        internal_path = (
            self.fixture.paths.migration_root / journal_export.INTERNAL_INTENT_NAME
        )
        receipt_path = self.fixture.paths.migration_root / journal_export.RECEIPT_NAME
        intent = json.loads(external_path.read_text())
        boolean_receipt = journal_export._receipt(intent)
        boolean_receipt["schema_version"] = True
        with self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "receipt does not bind",
        ):
            journal_export._validate_receipt(boolean_receipt, intent)
        intent["schema_version"] = True
        intent_data = canonical_json(intent)
        external_path.write_bytes(intent_data)
        internal_path.write_bytes(intent_data)
        receipt = json.loads(receipt_path.read_text())
        receipt["intent_sha256"] = journal_export.sha256_bytes(intent_data)
        receipt["schema_version"] = True
        receipt_path.write_bytes(canonical_json(receipt))
        with self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "identity is invalid",
        ):
            self.fixture.verify()

    def test_deep_json_is_a_domain_error(self) -> None:
        deeply_nested = (
            "{\"nested\":" * 10_000 + "0" + "}" * 10_000
        ).encode("ascii")
        with self.assertRaises(journal_export.GAAcceptanceJournalExportError):
            journal_export._strict_json(deeply_nested, "deep fixture")

        with patch.object(
            journal_export.json,
            "loads",
            side_effect=RecursionError("fixture decoder recursion"),
        ), self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "not strict JSON",
        ):
            journal_export._strict_json(b"{}\n", "deep fixture")

        for token in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(token=token), self.assertRaisesRegex(
                journal_export.GAAcceptanceJournalExportError,
                "not strict JSON",
            ):
                journal_export._strict_json(
                    b'{"value":' + token + b"}\n",
                    "non-finite fixture",
                )

        with patch.object(
            journal_export,
            "canonical_json",
            side_effect=RecursionError("fixture canonical recursion"),
        ), self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "not canonical JSON",
        ):
            journal_export._strict_json(b"{}\n", "deep fixture")

        with self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "not canonical JSON",
        ):
            journal_export._strict_json(
                b'{"value":"\\ud800"}\n',
                "surrogate fixture",
            )

    def test_symlinked_stage_input_ancestor_is_rejected(self) -> None:
        self.fixture.export()
        stage_input_root = self.fixture.paths.stage_input_root
        relocated = self.fixture.repository.parent / "relocated-stage-inputs"
        stage_input_root.rename(relocated)
        stage_input_root.symlink_to(relocated, target_is_directory=True)
        with self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "fixed paths could not be reopened safely",
        ):
            self.fixture.verify()

    def test_stage_root_rebind_during_verification_is_rejected(self) -> None:
        self.fixture.export()
        stage_input_root = self.fixture.paths.stage_input_root
        replacement = self.fixture.repository.parent / "replacement-stage-inputs"
        displaced = self.fixture.repository.parent / "displaced-stage-inputs"
        shutil.copytree(stage_input_root, replacement)
        replacement.chmod(0o700)
        replacement_intent = replacement / journal_export.EXTERNAL_INTENT_NAME
        replacement_intent.write_bytes(b"{}\n")
        replacement_intent.chmod(0o600)
        real_lock = journal_export.exclusive_rooted_directory_lock
        rebound = False

        @contextmanager
        def rebinding_lock(root: Path, directory: Path, **keywords):
            nonlocal rebound
            if directory == self.fixture.paths.acceptance_root and not rebound:
                rebound = True
                stage_input_root.rename(displaced)
                replacement.rename(stage_input_root)
            with real_lock(root, directory, **keywords) as descriptor:
                yield descriptor

        with patch.object(
            journal_export,
            "exclusive_rooted_directory_lock",
            side_effect=rebinding_lock,
        ), self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "fixed paths could not be reopened safely",
        ):
            self.fixture.verify()
        self.assertTrue(rebound)

    def test_missing_producer_locks_fail_without_recreating_them(self) -> None:
        lock_names = (
            install.MAINTENANCE_LOCK_NAME,
            self.fixture.service_paths.lock_name,
            self.fixture.install_paths.lock_name,
        )
        for lock_name in lock_names:
            with self.subTest(lock_name=lock_name):
                fixture = JournalExportFixture()
                self.addCleanup(fixture.cleanup)
                lock_path = fixture.source_parent / lock_name
                self.assertTrue(lock_path.is_file())
                lock_path.unlink()
                with self.assertRaisesRegex(
                    journal_export.GAAcceptanceJournalExportError,
                    "admission failed closed",
                ):
                    fixture.export()
                self.assertFalse(lock_path.exists())
                self.assertFalse(fixture.paths.external_intent.exists())
                self.assertFalse(fixture.paths.external_pending_intent.exists())

    def test_busy_maintenance_lock_fails_before_export_side_effects(self) -> None:
        with install.exclusive_release_maintenance_lock(
            self.fixture.source_parent,
            require_existing=True,
        ), self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "admission failed closed",
        ):
            self.fixture.export()

        self.assertFalse(self.fixture.paths.acceptance_root.exists())
        self.assertFalse(self.fixture.paths.external_intent.exists())
        self.assertFalse(self.fixture.paths.external_pending_intent.exists())

    def test_invalid_acceptance_root_after_durable_intent_requires_recovery(
        self,
    ) -> None:
        self.fixture.paths.acceptance_root.mkdir(mode=0o755)
        self.fixture.paths.acceptance_root.chmod(0o755)
        with self.assertRaises(
            journal_export.GAAcceptanceJournalExportRecoveryRequired
        ) as captured:
            self.fixture.export()
        self.assertIs(
            type(captured.exception),
            journal_export.GAAcceptanceJournalExportRecoveryRequired,
        )
        self.assertTrue(self.fixture.paths.external_intent.is_file())
        self.assertFalse(self.fixture.paths.external_pending_intent.exists())
        self.assertFalse(self.fixture.paths.migration_root.exists())

        self.fixture.paths.acceptance_root.chmod(0o700)
        self.assertEqual(self.fixture.recover(), self.fixture.verify())

    def test_post_publish_source_reread_failure_requires_exact_recovery_type(
        self,
    ) -> None:
        real_snapshot = service.ServiceEventStore.terminal_snapshot
        calls = 0

        def fail_second_snapshot(
            store: service.ServiceEventStore,
        ) -> service.TerminalServiceJournalSnapshot:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise install.InstallError(
                    "fixture_source_reread_failed",
                    "fixture producer reread failure",
                )
            return real_snapshot(store)

        with patch.object(
            service.ServiceEventStore,
            "terminal_snapshot",
            autospec=True,
            side_effect=fail_second_snapshot,
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportRecoveryRequired
        ) as captured:
            self.fixture.export()
        self.assertIs(
            type(captured.exception),
            journal_export.GAAcceptanceJournalExportRecoveryRequired,
        )
        self.assertTrue(self.fixture.paths.external_intent.is_file())
        self.assertTrue(self.fixture.paths.migration_root.is_dir())
        self.assertEqual(self.fixture.recover(), self.fixture.verify())

    def test_export_reply_loss_recovers_without_replacing_intent(self) -> None:
        real_promote = journal_export.promote_private_pending
        calls = 0

        def promote_then_lose_reply(pending: Path, destination: Path) -> None:
            nonlocal calls
            calls += 1
            real_promote(pending, destination)
            if calls == 1:
                raise DurabilityOutcomeUnknown("fixture reply loss")

        with patch.object(
            journal_export,
            "promote_private_pending",
            side_effect=promote_then_lose_reply,
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportOutcomeUnknown
        ):
            self.fixture.export()
        intent_bytes = self.fixture.paths.external_intent.read_bytes()
        recovered = self.fixture.recover()
        self.assertEqual(recovered, self.fixture.verify())
        self.assertEqual(self.fixture.paths.external_intent.read_bytes(), intent_bytes)

    def test_container_rename_reply_loss_recovers_published_bytes(self) -> None:
        real_publish = journal_export.publish_private_directory_exclusive

        def publish_then_lose_reply(source: Path, destination: Path) -> None:
            real_publish(source, destination)
            raise DurabilityOutcomeUnknown("fixture directory reply loss")

        with patch.object(
            journal_export,
            "publish_private_directory_exclusive",
            side_effect=publish_then_lose_reply,
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportOutcomeUnknown
        ):
            self.fixture.export()
        self.assertTrue(self.fixture.paths.migration_root.exists())
        self.assertFalse(
            any(
                name.startswith(".migration-journals-")
                for name in os.listdir(self.fixture.paths.acceptance_root)
            )
        )
        self.assertEqual(self.fixture.recover(), self.fixture.verify())

    def test_post_publish_reopen_failure_requires_fixed_recovery(self) -> None:
        for failure in (
            journal_export.GAAcceptanceJournalExportError("fixture reopen drift"),
            OSError("fixture reopen I/O failure"),
        ):
            with self.subTest(failure=type(failure).__name__):
                fixture = JournalExportFixture()
                self.addCleanup(fixture.cleanup)
                with patch.object(
                    journal_export,
                    "_verify_published_export",
                    side_effect=failure,
                ), self.assertRaises(
                    journal_export.GAAcceptanceJournalExportRecoveryRequired
                ):
                    fixture.export()
                self.assertTrue(fixture.paths.migration_root.exists())
                self.assertFalse(
                    any(
                        name.startswith(".migration-journals-")
                        for name in os.listdir(fixture.paths.acceptance_root)
                    )
                )
                self.assertEqual(fixture.recover(), fixture.verify())

    def test_final_container_lstat_failure_is_a_domain_error(self) -> None:
        self.fixture.export()
        real_lstat = Path.lstat
        root_reads = 0

        def fail_final_root_lstat(path: Path):
            nonlocal root_reads
            if path == self.fixture.paths.migration_root:
                root_reads += 1
                if root_reads == 2:
                    raise OSError("fixture final root lstat failure")
            return real_lstat(path)

        with patch.object(
            Path,
            "lstat",
            autospec=True,
            side_effect=fail_final_root_lstat,
        ), self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "changed while reopening",
        ):
            self.fixture.verify()

    def test_rooted_lock_exit_drift_after_each_export_mutation_requires_recovery(
        self,
    ) -> None:
        real_lock = journal_export.exclusive_rooted_directory_lock
        for fail_on_call in (1, 2, 3):
            with self.subTest(fail_on_call=fail_on_call):
                fixture = JournalExportFixture()
                self.addCleanup(fixture.cleanup)
                calls = 0

                @contextmanager
                def drifting_lock(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    current_call = calls
                    with real_lock(*args, **kwargs) as descriptor:
                        yield descriptor
                    if current_call == fail_on_call:
                        raise RootedDirectoryChanged("fixture rooted-lock exit drift")

                with patch.object(
                    journal_export,
                    "exclusive_rooted_directory_lock",
                    side_effect=drifting_lock,
                ), self.assertRaises(
                    journal_export.GAAcceptanceJournalExportOutcomeUnknown
                ):
                    fixture.export()
                self.assertTrue(fixture.paths.external_intent.exists())
                self.assertEqual(fixture.recover(), fixture.verify())

    def test_pending_directory_parent_fsync_failure_is_typed_and_preserved(
        self,
    ) -> None:
        real_fsync = journal_export.fsync_locked_directory
        calls = 0

        def fail_second_fsync(descriptor: int, path: Path) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise PublicationError("fixture parent full-fsync failure")
            real_fsync(descriptor, path)

        with patch.object(
            journal_export,
            "fsync_locked_directory",
            side_effect=fail_second_fsync,
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportOutcomeUnknown
        ):
            self.fixture.export()
        intent = json.loads(self.fixture.paths.external_intent.read_text())
        pending = self.fixture.paths.acceptance_root / intent["pending_name"]
        self.assertTrue(pending.is_dir())
        before = tuple(os.listdir(pending))
        with self.assertRaises(
            journal_export.GAAcceptanceJournalExportError
        ) as captured:
            self.fixture.recover()
        self.assertIs(
            type(captured.exception),
            journal_export.GAAcceptanceJournalExportError,
        )
        self.assertEqual(tuple(os.listdir(pending)), before)
        self.assertFalse(self.fixture.paths.migration_root.exists())

    def test_recovery_intent_promotion_exit_drift_is_typed_and_retryable(self) -> None:
        with patch.object(
            journal_export,
            "promote_private_pending",
            side_effect=PublicationError("fixture pre-rename failure"),
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportRecoveryRequired
        ):
            self.fixture.export()
        self.assertTrue(self.fixture.paths.external_pending_intent.exists())
        self.assertFalse(self.fixture.paths.external_intent.exists())

        real_lock = journal_export.exclusive_rooted_directory_lock
        calls = 0

        @contextmanager
        def drifting_lock(*args, **kwargs):
            nonlocal calls
            calls += 1
            with real_lock(*args, **kwargs) as descriptor:
                yield descriptor
            if calls == 1:
                raise RootedDirectoryChanged("fixture recovery lock exit drift")

        with patch.object(
            journal_export,
            "exclusive_rooted_directory_lock",
            side_effect=drifting_lock,
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportOutcomeUnknown
        ):
            self.fixture.recover()
        self.assertTrue(self.fixture.paths.external_intent.exists())
        self.assertFalse(self.fixture.paths.external_pending_intent.exists())
        self.assertEqual(self.fixture.recover(), self.fixture.verify())

    def test_recovered_intent_reopen_failure_requires_exact_recovery_type(
        self,
    ) -> None:
        with patch.object(
            journal_export,
            "promote_private_pending",
            side_effect=PublicationError("fixture pre-rename failure"),
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportRecoveryRequired
        ):
            self.fixture.export()
        real_read = journal_export._read_private_file

        def fail_promoted_intent_read(path: Path, label: str) -> bytes:
            if path == self.fixture.paths.external_intent:
                raise journal_export.GAAcceptanceJournalExportError(
                    "fixture promoted intent reopen failure"
                )
            return real_read(path, label)

        with patch.object(
            journal_export,
            "_read_private_file",
            side_effect=fail_promoted_intent_read,
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportRecoveryRequired
        ) as captured:
            self.fixture.recover()
        self.assertIs(
            type(captured.exception),
            journal_export.GAAcceptanceJournalExportRecoveryRequired,
        )
        self.assertTrue(self.fixture.paths.external_intent.is_file())
        self.assertFalse(self.fixture.paths.external_pending_intent.exists())
        self.assertEqual(self.fixture.recover(), self.fixture.verify())

    def test_recovery_publish_reopen_failure_requires_exact_recovery_type(
        self,
    ) -> None:
        with patch.object(
            journal_export,
            "publish_private_directory_exclusive",
            side_effect=PublicationError("fixture pre-publish failure"),
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportRecoveryRequired
        ):
            self.fixture.export()
        with patch.object(
            journal_export,
            "_verify_published_export",
            side_effect=journal_export.GAAcceptanceJournalExportError(
                "fixture published container reopen failure"
            ),
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportRecoveryRequired
        ) as captured:
            self.fixture.recover()
        self.assertIs(
            type(captured.exception),
            journal_export.GAAcceptanceJournalExportRecoveryRequired,
        )
        self.assertTrue(self.fixture.paths.migration_root.is_dir())
        self.assertEqual(self.fixture.recover(), self.fixture.verify())

    def test_partial_pending_container_is_preserved_and_rejected(self) -> None:
        real_write = journal_export.write_private_pending
        calls = 0

        def fail_after_first_file(path: Path, data: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls > 1:
                raise OSError("fixture interrupted write")
            real_write(path, data)

        with patch.object(
            journal_export,
            "write_private_pending",
            side_effect=fail_after_first_file,
        ), self.assertRaises(
            journal_export.GAAcceptanceJournalExportRecoveryRequired
        ):
            self.fixture.export()
        external = json.loads(self.fixture.paths.external_intent.read_text())
        pending = self.fixture.paths.acceptance_root / external["pending_name"]
        self.assertTrue(pending.exists())
        before = sorted(path.relative_to(pending) for path in pending.rglob("*"))
        with self.assertRaises(
            journal_export.GAAcceptanceJournalExportError
        ) as captured:
            self.fixture.recover()
        self.assertIs(
            type(captured.exception),
            journal_export.GAAcceptanceJournalExportError,
        )
        self.assertEqual(
            sorted(path.relative_to(pending) for path in pending.rglob("*")),
            before,
        )
        self.assertFalse(self.fixture.paths.migration_root.exists())

    def test_environment_drift_fails_before_any_export_intent(self) -> None:
        changed = dict(ENVIRONMENT)
        changed["machine_sha256"] = "f" * 64
        with self.assertRaises(journal_export.GAAcceptanceJournalExportError):
            journal_export.export_ga_acceptance_journals(
                self.fixture.paths,
                observer=lambda: changed,
                transaction_id=TRANSACTION_ID,
            )
        self.assertFalse(self.fixture.paths.external_intent.exists())
        self.assertFalse(self.fixture.paths.external_pending_intent.exists())
        self.assertFalse(self.fixture.paths.acceptance_root.exists())

    def test_legacy_install_schema_is_rejected_without_source_mutation(self) -> None:
        journal = self.fixture.install_paths.journal
        original_service = sorted(
            path.read_bytes()
            for path in self.fixture.service_paths.transaction_directory.iterdir()
        )
        legacy = self.fixture.install_document()
        legacy.pop("ga_environment_sha256")
        legacy["document"] = "cfw-dormant-app-install-v1"
        legacy["schema_version"] = 1
        journal.write_bytes(canonical_json(legacy))
        journal.chmod(0o600)
        before = journal.read_bytes()
        with self.assertRaises(journal_export.GAAcceptanceJournalExportError):
            self.fixture.export()
        self.assertEqual(journal.read_bytes(), before)
        self.assertEqual(
            sorted(
                path.read_bytes()
                for path in self.fixture.service_paths.transaction_directory.iterdir()
            ),
            original_service,
        )
        self.assertFalse(self.fixture.paths.external_intent.exists())

    def test_source_hardlink_is_rejected_before_export_intent(self) -> None:
        linked = self.fixture.repository / "linked-source-journal.json"
        os.link(self.fixture.install_paths.journal, linked)
        before = self.fixture.install_paths.journal.read_bytes()
        with self.assertRaises(journal_export.GAAcceptanceJournalExportError):
            self.fixture.export()
        self.assertEqual(self.fixture.install_paths.journal.read_bytes(), before)
        self.assertEqual(self.fixture.install_paths.journal.stat().st_nlink, 2)
        self.assertFalse(self.fixture.paths.external_intent.exists())

    def test_hardlink_symlink_and_mode_tamper_are_rejected(self) -> None:
        self.fixture.export()
        install_path = self.fixture.paths.migration_root / journal_export.INSTALL_NAME
        hardlink = self.fixture.repository / "linked-install.json"
        os.link(install_path, hardlink)
        with self.assertRaises(journal_export.GAAcceptanceJournalExportError):
            self.fixture.verify()
        hardlink.unlink()
        self.assertEqual(install_path.stat().st_nlink, 1)
        install_path.chmod(0o644)
        with self.assertRaises(journal_export.GAAcceptanceJournalExportError):
            self.fixture.verify()
        install_path.chmod(0o600)
        environment_path = self.fixture.paths.migration_root.joinpath(
            journal_export.SERVICE_NAME,
            service.ENVIRONMENT_NAME,
        )
        original = self.fixture.paths.acceptance_root / "environment-original.json"
        environment_path.rename(original)
        environment_path.symlink_to(Path("..") / original.name)
        with self.assertRaises(journal_export.GAAcceptanceJournalExportError):
            self.fixture.verify()

    def test_unsafe_exported_service_name_is_a_domain_error(self) -> None:
        self.fixture.export()
        unsafe = self.fixture.paths.migration_root / journal_export.SERVICE_NAME / "bad\nname"
        unsafe.write_bytes(b"{}\n")
        unsafe.chmod(0o600)
        with self.assertRaisesRegex(
            journal_export.GAAcceptanceJournalExportError,
            "name is unsafe",
        ):
            self.fixture.verify()

    def test_published_container_and_pending_container_cannot_coexist(self) -> None:
        self.fixture.export()
        intent = json.loads(self.fixture.paths.external_intent.read_text())
        pending = self.fixture.paths.acceptance_root / intent["pending_name"]
        pending.mkdir(mode=0o700)
        with self.assertRaises(journal_export.GAAcceptanceJournalExportError):
            self.fixture.recover()
        self.assertTrue(self.fixture.paths.migration_root.exists())
        self.assertTrue(pending.exists())


class JournalExportSourceContractTests(unittest.TestCase):
    def test_source_contract_and_fixed_layout(self) -> None:
        journal_export.self_check()
        self.assertEqual(
            journal_export.ENVIRONMENT_RELATIVE,
            journal_export.SERVICE_RELATIVE / service.ENVIRONMENT_NAME,
        )
        self.assertNotEqual(
            journal_export.ENVIRONMENT_RELATIVE,
            journal_export.MIGRATION_RELATIVE / "environment.json",
        )


if __name__ == "__main__":
    unittest.main()
