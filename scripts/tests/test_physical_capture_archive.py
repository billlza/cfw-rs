from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest

from scripts.physical_capture.archive import (
    PRIVATE_DIRECTORY_MODE,
    PRIVATE_FILE_MODE,
    PhysicalCaptureArchiveError,
    SecureArchive,
)


class SecureArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        self.target = self.repository / "target"
        self.target.mkdir(mode=0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_archive(self) -> SecureArchive:
        return SecureArchive.create(
            self.repository, "physical-capture/run-40003-macos15"
        )

    def test_archive_creates_private_directories_and_files(self) -> None:
        with self.create_archive() as archive:
            record = archive.write_bytes("reports/lifecycle.json", b"evidence\n")
            self.assertEqual(record.relative_path, "reports/lifecycle.json")
            self.assertEqual(record.size, len(b"evidence\n"))
            self.assertEqual(record.sha256, hashlib.sha256(b"evidence\n").hexdigest())
            self.assertEqual(archive.read_bytes(record.relative_path), b"evidence\n")

        for directory in (
            self.target / "physical-capture",
            self.target / "physical-capture/run-40003-macos15",
            self.target / "physical-capture/run-40003-macos15/reports",
        ):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), PRIVATE_DIRECTORY_MODE)
            self.assertEqual(directory.stat().st_uid, os.geteuid())
        report = self.target / "physical-capture/run-40003-macos15/reports/lifecycle.json"
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), PRIVATE_FILE_MODE)
        self.assertEqual(report.stat().st_nlink, 1)
        self.assertEqual(report.stat().st_uid, os.geteuid())

    def test_copy_reopens_source_and_publishes_exact_descriptor(self) -> None:
        source = self.repository / "capture.pcap"
        source.write_bytes(b"pcap-bytes")
        with self.create_archive() as archive:
            record = archive.copy_file(
                source.absolute(), "raw/packet/tcp-ipv4.pcap", maximum=1024
            )
            self.assertEqual(record.size, len(b"pcap-bytes"))
            self.assertEqual(record.sha256, hashlib.sha256(b"pcap-bytes").hexdigest())
            self.assertEqual(
                record.descriptor("packet-pcap"),
                {
                    "kind": "packet-pcap",
                    "path": "raw/packet/tcp-ipv4.pcap",
                    "size": len(b"pcap-bytes"),
                    "sha256": hashlib.sha256(b"pcap-bytes").hexdigest(),
                },
            )

    def test_archive_root_must_be_canonical_and_below_target(self) -> None:
        for relative in (
            "../escape",
            "/absolute",
            "physical//run",
            "physical/./run",
            "physical/../../run",
            "physical/run with spaces",
            "physical\\run",
        ):
            with self.subTest(relative=relative), self.assertRaises(
                PhysicalCaptureArchiveError
            ):
                SecureArchive.create(self.repository, relative)
        self.assertFalse((self.repository / "escape").exists())

    def test_existing_destination_is_never_replaced(self) -> None:
        with self.create_archive() as archive:
            archive.write_bytes("report.json", b"first")
            with self.assertRaisesRegex(
                PhysicalCaptureArchiveError, "exclusively publish"
            ) as raised:
                archive.write_bytes("report.json", b"second")
            self.assertEqual(raised.exception.code, "archive_destination_exists")
            self.assertEqual(archive.read_bytes("report.json"), b"first")
            root = self.target / "physical-capture/run-40003-macos15"
            self.assertEqual(list(root.glob(".*.pending-*")), [])

    def test_symlink_destination_is_not_followed_or_replaced(self) -> None:
        outside = self.repository / "outside"
        outside.write_bytes(b"outside")
        with self.create_archive() as archive:
            root = self.target / "physical-capture/run-40003-macos15"
            os.symlink(outside, root / "report.json")
            with self.assertRaises(PhysicalCaptureArchiveError):
                archive.write_bytes("report.json", b"attacker replacement")
            self.assertEqual(outside.read_bytes(), b"outside")
            self.assertTrue((root / "report.json").is_symlink())

    def test_copy_rejects_symlink_hardlink_and_relative_source(self) -> None:
        source = self.repository / "source.bin"
        source.write_bytes(b"source")
        symlink = self.repository / "source-link.bin"
        symlink.symlink_to(source)
        hardlink = self.repository / "source-hardlink.bin"
        os.link(source, hardlink)
        with self.create_archive() as archive:
            with self.assertRaisesRegex(PhysicalCaptureArchiveError, "absolute"):
                archive.copy_file(Path("source.bin"), "raw/relative.bin")
            with self.assertRaises(PhysicalCaptureArchiveError):
                archive.copy_file(symlink.absolute(), "raw/symlink.bin")
            with self.assertRaisesRegex(PhysicalCaptureArchiveError, "single-link"):
                archive.copy_file(source.absolute(), "raw/hardlink.bin")

    def test_existing_archive_with_broad_mode_is_rejected(self) -> None:
        archive = self.create_archive()
        archive.close()
        root = self.target / "physical-capture/run-40003-macos15"
        root.chmod(0o755)
        with self.assertRaisesRegex(PhysicalCaptureArchiveError, "0700"):
            SecureArchive.open(
                self.repository, "physical-capture/run-40003-macos15"
            )

    def test_open_archive_detects_root_path_replacement(self) -> None:
        with self.create_archive() as archive:
            parent = self.target / "physical-capture"
            original = parent / "run-40003-macos15"
            moved = parent / "run-moved"
            original.rename(moved)
            original.mkdir(mode=PRIVATE_DIRECTORY_MODE)
            with self.assertRaisesRegex(PhysicalCaptureArchiveError, "root path changed"):
                archive.write_bytes("report.json", b"evidence")

    def test_complete_pending_file_can_be_published_or_discarded(self) -> None:
        with self.create_archive() as archive:
            archive.ensure_directory("journal")
            journal = self.target / "physical-capture/run-40003-macos15/journal"
            pending_path = journal / (".00000001.json.pending-" + "a" * 32)
            pending_path.write_bytes(b"pending-event\n")
            pending_path.chmod(PRIVATE_FILE_MODE)
            pending = archive.pending_files("journal")
            self.assertEqual(len(pending), 1)
            self.assertEqual(archive.read_pending(pending[0]), b"pending-event\n")
            archive.publish_pending(pending[0])
            self.assertEqual(archive.read_bytes("journal/00000001.json"), b"pending-event\n")

            discard_path = journal / (".00000002.json.pending-" + "b" * 32)
            discard_path.write_bytes(b"discard-event\n")
            discard_path.chmod(PRIVATE_FILE_MODE)
            pending = archive.pending_files("journal")
            self.assertEqual(len(pending), 1)
            archive.discard_pending(pending[0])
            self.assertFalse(discard_path.exists())

    def test_exact_reopen_recovers_only_expected_pending_prefixes(self) -> None:
        expected = b'{"request":"exact"}\n'
        with self.create_archive() as archive:
            archive.ensure_directory("cloud")
            cloud = self.target / "physical-capture/run-40003-macos15/cloud"
            prefix = cloud / (".request.json.pending-" + "c" * 32)
            prefix.write_bytes(expected[:9])
            prefix.chmod(PRIVATE_FILE_MODE)
            archived = archive.write_or_reopen_exact(
                "cloud/request.json", expected, maximum=1024
            )
            self.assertEqual(archived.sha256, hashlib.sha256(expected).hexdigest())
            self.assertFalse(prefix.exists())

            archive.write_bytes("cloud/response.json", expected)
            leftover = cloud / (".response.json.pending-" + "d" * 32)
            leftover.write_bytes(expected[:5])
            leftover.chmod(PRIVATE_FILE_MODE)
            archive.write_or_reopen_exact(
                "cloud/response.json", expected, maximum=1024
            )
            self.assertFalse(leftover.exists())

            mismatch = cloud / (".mismatch.json.pending-" + "e" * 32)
            mismatch.write_bytes(b"not-a-prefix")
            mismatch.chmod(PRIVATE_FILE_MODE)
            with self.assertRaises(PhysicalCaptureArchiveError) as raised:
                archive.write_or_reopen_exact(
                    "cloud/mismatch.json", expected, maximum=1024
                )
            self.assertEqual(raised.exception.code, "pending_archive_mismatch")
            self.assertTrue(mismatch.exists())

    def test_exact_reopen_rejects_unrelated_pending_file(self) -> None:
        with self.create_archive() as archive:
            archive.ensure_directory("derived")
            directory = (
                self.target
                / "physical-capture/run-40003-macos15/derived"
            )
            unrelated = directory / (".other.json.pending-" + "f" * 32)
            unrelated.write_bytes(b"{}\n")
            unrelated.chmod(PRIVATE_FILE_MODE)
            with self.assertRaises(PhysicalCaptureArchiveError) as raised:
                archive.write_or_reopen_exact(
                    "derived/run.json", b"{}\n", maximum=1024
                )
            self.assertEqual(
                raised.exception.code, "ambiguous_pending_archive_file"
            )

    def test_unsafe_target_directory_is_rejected(self) -> None:
        self.target.chmod(0o777)
        with self.assertRaisesRegex(PhysicalCaptureArchiveError, "group/world"):
            self.create_archive()


if __name__ == "__main__":
    unittest.main()
