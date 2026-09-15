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
        profile = replace(install.GA_INSTALL_PROFILE, build_number="40068")
        self.expected = replace(fixture_module.CANDIDATE.app, build_number="40068")
        candidate = replace(fixture_module.CANDIDATE, app=self.expected)
        previous = install.AppIdentity(
            "0.4.0", "40067", install.INSTALLED_40067_PREDECESSOR.tree_sha256)
        with patch.object(install, "GA_INSTALL_PROFILE", profile), patch.object(
            fixture_module, "CANDIDATE", candidate
        ):
            self.fixture = fixture_module.JournalExportFixture(previous=previous)
        self.addCleanup(self.fixture.cleanup)
        self.paths = self.fixture.install_paths
        self.destination = self.paths.target_parent / archive.HISTORY_NAME / "40068"
        self.executor = {"repositoryCommit": "a" * 40, "releaseSourceSha256": "b" * 64}

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


if __name__ == "__main__":
    unittest.main()
