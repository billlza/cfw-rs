from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import archive_install_history as archive
from scripts import dormant_app_install as install
from scripts.tests import test_ga_acceptance_journal_export as fixture_module


class InstallHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        # Construct a completed historical upgrade, then validate it through
        # today's operator whose active build is newer.
        profile = replace(install.GA_INSTALL_PROFILE, product_version="0.4.0", build_number="40069")
        self.expected = replace(fixture_module.CANDIDATE.app, version="0.4.0", build_number="40069")
        candidate = replace(fixture_module.CANDIDATE, app=self.expected)
        previous = install.AppIdentity(
            "0.4.0", "40067", install.INSTALLED_40067_PREDECESSOR.tree_sha256)
        with patch.object(install, "GA_INSTALL_PROFILE", profile), patch.object(
            fixture_module, "CANDIDATE", candidate
        ):
            self.fixture = fixture_module.JournalExportFixture(previous=previous)
        self.addCleanup(self.fixture.cleanup)
        self.paths = self.fixture.install_paths
        self.destination = self.paths.target_parent / archive.HISTORY_NAME / "40069"
        self.executor = {"repositoryCommit": "a" * 40, "releaseSourceSha256": "b" * 64}
        # The retained preview that replaced the archived build on this Mac.
        self.installed = install.AppIdentity(
            "0.5.0", "50025", install.INSTALLED_50025_PREDECESSOR.tree_sha256)

    def retain(self, **options: object) -> Path:
        return archive.archive_completed_history(
            self.paths, self.expected, self.executor,
            lambda: self.expected, lambda: None, **options)

    def assert_originals_present(self) -> None:
        self.assertTrue(self.paths.journal.exists())
        self.assertTrue(self.fixture.service_paths.transaction_directory.exists())

    def test_terminal_history_retains_exact_bytes_and_is_idempotent(self) -> None:
        journal = self.paths.journal.read_bytes()
        service_directory = self.fixture.service_paths.transaction_directory
        files = {p.name: p.read_bytes() for p in service_directory.iterdir()}
        destination = self.retain()
        self.assertEqual(destination, self.destination)
        self.assertFalse(self.paths.journal.exists())
        self.assertFalse(service_directory.exists())
        self.assertEqual((destination / self.paths.journal_name).read_bytes(), journal)
        self.assertEqual(
            {p.name: p.read_bytes() for p in (destination / service_directory.name).iterdir()}, files)
        self.assertTrue((destination / archive.COMPLETE_NAME).is_file())
        self.assertEqual(self.retain(), destination)

    def test_interruption_between_the_two_renames_resumes_without_overwrite(self) -> None:
        calls = 0

        def interrupted(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected interruption after retaining the service tree")
            os.rename(*args, **kwargs)

        with self.assertRaisesRegex(OSError, "injected interruption"):
            self.retain(move=interrupted)
        self.assertTrue((self.destination / archive.INTENT_NAME).exists())
        self.assertFalse((self.destination / archive.COMPLETE_NAME).exists())
        self.assertTrue(self.paths.journal.exists())
        self.assertFalse(self.fixture.service_paths.transaction_directory.exists())
        self.assertEqual(self.retain(), self.destination)

    def test_pending_service_transaction_is_not_archived(self) -> None:
        self.fixture.service_paths.pending_directory.mkdir(mode=0o700)
        with self.assertRaises(install.InstallError):
            self.retain()
        self.assert_originals_present()

    def test_pending_installation_is_not_archived(self) -> None:
        pending = self.paths.target_parent / self.paths.journal_pending_name
        pending.write_bytes(self.paths.journal.read_bytes())
        pending.chmod(0o600)
        with self.assertRaises(install.InstallError):
            self.retain()
        self.assert_originals_present()

    def test_current_application_identity_must_match_the_terminal_records(self) -> None:
        with self.assertRaisesRegex(install.InstallError, "installed application changed"):
            archive.archive_completed_history(
                self.paths, self.expected, self.executor,
                lambda: replace(self.expected, tree_sha256="f" * 64), lambda: None)
        self.assert_originals_present()

    def test_unsafe_history_directory_is_not_repaired_or_used(self) -> None:
        history = self.destination.parent
        history.mkdir(mode=0o755)
        with self.assertRaisesRegex(install.InstallError, "unsafe ownership or permissions"):
            self.retain()
        self.assertEqual(history.stat().st_mode & 0o777, 0o755)
        self.assert_originals_present()

    def test_conflicting_destination_is_preserved(self) -> None:
        self.destination.parent.mkdir(mode=0o700)
        self.destination.mkdir(mode=0o700)
        conflicting = self.destination / self.paths.journal_name
        conflicting.write_bytes(b"unrelated record")
        with self.assertRaisesRegex(install.InstallError, "exactly one recorded location"):
            self.retain()
        self.assertEqual(conflicting.read_bytes(), b"unrelated record")
        self.assert_originals_present()

    def test_complete_receipt_binds_the_original_intent(self) -> None:
        self.retain()
        path = self.destination / archive.INTENT_NAME
        intent = json.loads(path.read_bytes())
        intent["executor"]["repositoryCommit"] = "c" * 40
        path.write_bytes(install._canonical_json(intent))
        with self.assertRaisesRegex(install.InstallError, "completed installation history changed"):
            self.retain()

    def test_extra_history_files_are_not_silently_accepted(self) -> None:
        self.retain()
        (self.destination / "unknown.json").write_bytes(b"{}")
        with self.assertRaisesRegex(install.InstallError, "inventory changed"):
            self.retain()

    def test_receipts_of_a_still_installed_build_carry_no_superseding_identity(self) -> None:
        self.retain()
        for name in (archive.INTENT_NAME, archive.COMPLETE_NAME):
            receipt = json.loads((self.destination / name).read_bytes())
            self.assertEqual(receipt["candidate"]["version"], "0.4.0")
            self.assertNotIn("superseded_by_installed", receipt)

    def test_superseded_records_are_retained_for_the_declared_installed_build(self) -> None:
        destination = archive.archive_completed_history(
            self.paths, self.expected, self.executor,
            lambda: self.installed, lambda: None, installed=self.installed)
        self.assertEqual(destination, self.destination)
        self.assertFalse(self.paths.journal.exists())
        for name in (archive.INTENT_NAME, archive.COMPLETE_NAME):
            receipt = json.loads((destination / name).read_bytes())
            self.assertEqual(receipt["candidate"]["build_number"], "40069")
            self.assertEqual(receipt["superseded_by_installed"], self.installed.document())
        # Repeating the retention requires the same declaration and the same
        # installed application; the archived build itself never satisfies it.
        self.assertEqual(archive.archive_completed_history(
            self.paths, self.expected, self.executor,
            lambda: self.installed, lambda: None, installed=self.installed), destination)
        with self.assertRaisesRegex(install.InstallError, "history intent changed"):
            archive.archive_completed_history(
                self.paths, self.expected, self.executor, lambda: self.expected, lambda: None)

    def test_superseded_retention_requires_the_declared_build_to_be_installed(self) -> None:
        for observed in (self.expected, replace(self.installed, tree_sha256="f" * 64)):
            with self.subTest(observed=observed), self.assertRaisesRegex(
                install.InstallError, "not the declared superseding build"
            ):
                archive.archive_completed_history(
                    self.paths, self.expected, self.executor,
                    lambda: observed, lambda: None, installed=self.installed)
            self.assert_originals_present()

    def test_superseded_retention_requires_a_newer_declared_build(self) -> None:
        older = install.AppIdentity(
            "0.4.0", "40067", install.INSTALLED_40067_PREDECESSOR.tree_sha256)
        for declared in (older, self.expected):
            with self.subTest(declared=declared.build_number), self.assertRaisesRegex(
                install.InstallError, "must be newer than the archived build"
            ):
                archive.archive_completed_history(
                    self.paths, self.expected, self.executor,
                    lambda: declared, lambda: None, installed=declared)
            self.assert_originals_present()

    def test_retention_plan_binds_each_lineage_entry_to_its_own_identity(self) -> None:
        retained = install.INSTALLED_40073_PREDECESSOR
        expected, installed, profile = archive._retention_plan("40073", None)
        self.assertEqual(expected, install.AppIdentity("0.4.0", "40073", retained.tree_sha256))
        self.assertEqual(installed, expected)
        self.assertEqual((profile.product_version, profile.build_number), ("0.4.0", "40073"))
        self.assertEqual(
            replace(profile, product_version=install.VERSION, build_number=install.BUILD_NUMBER),
            install.GA_INSTALL_PROFILE,
        )
        expected, installed, _ = archive._retention_plan("40073", "50025")
        self.assertEqual(expected.build_number, "40073")
        self.assertEqual(installed, self.installed)
        for previous, declared, message in (
            ("50028", None, "not an explicitly supported predecessor"),
            ("40073", "50028", "declared installed build is not an explicitly supported"),
            ("40073", "40072", "must be newer than the archived build"),
            ("40073", "40073", "must be newer than the archived build"),
        ):
            with self.subTest(previous=previous, declared=declared), self.assertRaisesRegex(
                install.InstallError, message
            ):
                archive._retention_plan(previous, declared)


if __name__ == "__main__":
    unittest.main()
