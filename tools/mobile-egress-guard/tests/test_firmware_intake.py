"""Archive intake regressions; synthetic archives only, no extraction."""
import hashlib
from io import BytesIO, StringIO
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import firmware_intake


class FirmwareIntakeTests(unittest.TestCase):
    def make_archive(self, path, filenames):
        with tarfile.open(path, "w:gz") as archive:
            for name in filenames:
                payload = b"# synthetic build input\n"
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                archive.addfile(member, BytesIO(payload))
            link = tarfile.TarInfo("src/vendor-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            archive.addfile(link)

    def test_scans_without_extracting_or_following_links(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            archive = root / "vendor-oss.tgz"
            self.make_archive(archive, ["src/Makefile", "src/Kconfig"])
            inventory = firmware_intake.inspect(archive)
            self.assertEqual(inventory["members"], 3)
            self.assertEqual(inventory["regular_files"], 2)
            self.assertEqual(inventory["links_not_followed"], 1)
            self.assertEqual(inventory["archive_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertIn("src/Makefile", inventory["sample_source_paths"])
            self.assertFalse((root / "src").exists())
            self.assertIn("not a recovery image", inventory["note"])

    def test_rejects_traversal_and_absolute_paths_without_writing(self):
        for bad in ["../outside", "/etc/passwd", "dir/../outside"]:
            with self.subTest(name=bad), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                archive = root / "bad.tgz"
                self.make_archive(archive, [bad])
                with self.assertRaises(firmware_intake.IntakeError):
                    firmware_intake.inspect(archive)
                self.assertEqual(sorted(x.name for x in root.iterdir()), ["bad.tgz"])

    def test_rejects_nontar_and_input_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            invalid = root / "invalid.tgz"
            invalid.write_bytes(b"not an archive")
            with self.assertRaises(firmware_intake.IntakeError):
                firmware_intake.inspect(invalid)
            link = root / "linked.tgz"
            link.symlink_to(invalid)
            with self.assertRaises(firmware_intake.IntakeError):
                firmware_intake.inspect(link)

    def test_duplicate_members_are_reported_not_silently_rewritten(self):
        with tempfile.TemporaryDirectory() as root:
            archive = Path(root) / "duplicated.tgz"
            self.make_archive(archive, ["src/Makefile", "src/Makefile"])
            self.assertEqual(firmware_intake.inspect(archive)["duplicate_paths"], 1)

    def test_json_cli_has_no_filesystem_side_effects(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            archive = root / "vendor-oss.tgz"
            self.make_archive(archive, ["source/Makefile"])
            out = StringIO()
            with redirect_stdout(out):
                self.assertEqual(firmware_intake.main([str(archive)]), 0)
            report = json.loads(out.getvalue())
            self.assertEqual(report["regular_files"], 1)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["vendor-oss.tgz"])


if __name__ == "__main__":
    unittest.main()
