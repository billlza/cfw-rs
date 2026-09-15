"""Exercise the isolated dependency patch boundary with a real Git checkout."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
CONTRACT = REPOSITORY / "scripts/xcodegen_dependency_contract.sh"


class XcodeGenDependencyPatchTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.checkout = self.root / "checkouts/AEXML"
        self.checkout.mkdir(parents=True)
        self.manifest = self.checkout / "Package.swift"
        self.before = b"// fixture manifest\nlet platform = 4\n"
        self.after = b"// fixture manifest\nlet platform = 9\n"
        self.manifest.write_bytes(self.before)
        self._git("init", "--quiet")
        self._git("add", "Package.swift")
        self._git(
            "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "Fixture",
        )
        self.revision = self._git("rev-parse", "HEAD").stdout.decode().strip()
        self.manifest.write_bytes(self.after)
        self.patch_file = self.root / "manifest.patch"
        self.patch_file.write_bytes(self._git("diff", "--", "Package.swift").stdout)
        self.manifest.write_bytes(self.before)
        digest = lambda data: hashlib.sha256(data).hexdigest()
        self.environment = {
            **os.environ,
            "XCODEGEN_AEXML_COMMIT": self.revision,
            "XCODEGEN_AEXML_UPSTREAM_MANIFEST_SHA256": digest(self.before),
            "XCODEGEN_AEXML_PATCH_PATH": self.patch_file.name,
            "XCODEGEN_AEXML_PATCH_SHA256": digest(self.patch_file.read_bytes()),
            "XCODEGEN_AEXML_PATCHED_MANIFEST_SHA256": digest(self.after),
        }

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(self.checkout), *arguments],
            check=True, capture_output=True,
        )

    def _apply(self) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "/bin/bash", "-p", "-c",
                'set -euo pipefail; source "$1"; cfw_patch_xcodegen_aexml "$2" "$3"',
                "xcodegen-patch-test", str(CONTRACT), str(self.root),
                str(self.checkout.parent),
            ],
            env=self.environment, capture_output=True, check=False,
        )

    def test_locked_pristine_checkout_accepts_only_the_bound_manifest_update(self) -> None:
        result = self._apply()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self.manifest.read_bytes(), self.after)
        self.assertEqual(self._git("rev-parse", "HEAD").stdout.decode().strip(), self.revision)
        self.assertEqual(self._git("diff", "--name-only").stdout, b"Package.swift\n")
        repeated = self._apply()
        self.assertNotEqual(repeated.returncode, 0)
        self.assertIn(b"pristine locked revision", repeated.stderr)

    def test_wrong_revision_is_rejected_before_editing(self) -> None:
        self.environment["XCODEGEN_AEXML_COMMIT"] = "0" * 40
        result = self._apply()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.manifest.read_bytes(), self.before)

    def test_untracked_checkout_content_is_preserved_and_rejected(self) -> None:
        unrelated = self.checkout / "unrelated.swift"
        unrelated.write_bytes(b"unrelated content")
        result = self._apply()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.manifest.read_bytes(), self.before)
        self.assertEqual(unrelated.read_bytes(), b"unrelated content")

    def test_replaced_patch_bytes_are_rejected_before_editing(self) -> None:
        self.patch_file.write_bytes(self.patch_file.read_bytes().replace(b"= 9", b"= 8"))
        result = self._apply()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.manifest.read_bytes(), self.before)

    def test_manifest_symlink_cannot_modify_an_outside_file(self) -> None:
        outside = self.root / "outside.swift"
        outside.write_bytes(self.before)
        self.manifest.unlink()
        self.manifest.symlink_to(outside)
        result = self._apply()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outside.read_bytes(), self.before)


if __name__ == "__main__":
    unittest.main()
