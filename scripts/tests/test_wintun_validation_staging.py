"""Synthetic archive boundary tests; these never load a driver or prove its ABI."""
import hashlib
import importlib.util
import sys
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("stage_wintun_validation", SCRIPTS / "stage_wintun_validation.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class WintunStagingTests(unittest.TestCase):
    def fixture(self, root, extra=None):
        dll = b"synthetic DLL bytes, not executable"
        license_text = b"synthetic license\r\noriginal bytes\r\n"
        (root / "LICENSE.txt").write_bytes(license_text)
        archive = root / "distribution.zip"
        with zipfile.ZipFile(archive, "x") as bundle:
            bundle.writestr("wintun/bin/amd64/wintun.dll", dll)
            bundle.writestr("wintun/LICENSE.txt", license_text)
            if extra is not None:
                bundle.writestr(extra, b"unexpected")
        pins = {"WINTUN_VERSION": "0.14.1", "WINTUN_ARCHIVE_SHA256": stage.sha256(archive),
                "WINTUN_WINDOWS_AMD64_SHA256": hashlib.sha256(dll).hexdigest(),
                "WINTUN_BINARY_LICENSE_PATH": "LICENSE.txt", "WINTUN_BINARY_LICENSE_SHA256": hashlib.sha256(license_text).hexdigest()}
        return archive, pins

    def test_original_bytes_are_preserved_without_runtime_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); archive, pins = self.fixture(root)
            receipt = stage.stage_archive(root, archive, root / "out", pins)
            self.assertEqual((root / "out/LICENSE.txt").read_bytes(), (root / "LICENSE.txt").read_bytes())
            self.assertEqual(stage.sha256(root / "out/wintun.dll"), pins["WINTUN_WINDOWS_AMD64_SHA256"])
            self.assertFalse(receipt["loaded_or_installed"])
            self.assertFalse(receipt["release_accepted"])

    def test_archive_dll_and_license_pins_are_independent(self):
        for key in ["WINTUN_ARCHIVE_SHA256", "WINTUN_WINDOWS_AMD64_SHA256", "WINTUN_BINARY_LICENSE_SHA256"]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); archive, pins = self.fixture(root)
                pins[key] = "0" * 64
                with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                    stage.stage_archive(root, archive, root / "out", pins)
                self.assertFalse((root / "out").exists())

    def test_unsafe_and_case_colliding_members_are_rejected(self):
        for member in ["../escaped", "WINTUN/LICENSE.TXT", "C:/escaped", "wintun\\escaped"]:
            with self.subTest(member=member), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); archive, pins = self.fixture(root, member)
                with self.assertRaises(RuntimeError):
                    stage.stage_archive(root, archive, root / "out", pins)
                self.assertFalse((root / "out").exists())

    def test_existing_output_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); archive, pins = self.fixture(root)
            output = root / "out"; output.mkdir(); (output / "keep").write_bytes(b"keep")
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                stage.stage_archive(root, archive, output, pins)
            self.assertEqual((output / "keep").read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
