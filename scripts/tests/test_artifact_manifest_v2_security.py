#!/usr/bin/env python3
"""Security invariants for the release artifact-tree v2 contract."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent.parent
HASH = SCRIPTS / "hash_artifact.py"
VERIFY = SCRIPTS / "verify_artifact_manifest.py"


class ArtifactManifestV2SecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "tree"
        (self.root / "bin").mkdir(parents=True)
        (self.root / "bin/tool").write_text("tool\n", encoding="utf-8")
        self.manifest = self.base / "tree.manifest.json"

    def hash(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(HASH),
                str(self.root),
                "--output",
                str(self.manifest),
                "--algorithm",
                "sha256-tree-v2",
                "--metadata",
                "kind=test",
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_internal_relative_symlink_is_accepted(self) -> None:
        (self.root / "current").symlink_to("bin/tool")
        completed = self.hash()
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_absolute_symlink_is_rejected_even_when_target_is_inside_root(self) -> None:
        (self.root / "current").symlink_to((self.root / "bin/tool").resolve())
        completed = self.hash()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("must be relative", completed.stderr)

    def test_parent_and_chained_symlink_escapes_are_rejected(self) -> None:
        outside = self.base / "outside"
        outside.write_text("outside\n", encoding="utf-8")

        for setup in (
            lambda: (self.root / "current").symlink_to("../outside"),
            lambda: (
                (self.root / "hop").symlink_to("../outside"),
                (self.root / "current").symlink_to("hop"),
            ),
        ):
            with self.subTest(setup=setup):
                setup()
                completed = self.hash()
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("within the artifact root", completed.stderr)
                for name in ("current", "hop"):
                    path = self.root / name
                    if path.is_symlink():
                        path.unlink()

    def test_dangling_symlink_is_rejected(self) -> None:
        (self.root / "current").symlink_to("missing")
        completed = self.hash()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("within the artifact root", completed.stderr)

    def test_verifier_returns_digest_from_successful_verification(self) -> None:
        self.assertEqual(self.hash().returncode, 0)
        expected = json.loads(self.manifest.read_text(encoding="utf-8"))["sha256"]
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(VERIFY),
                str(self.root),
                str(self.manifest),
                "--algorithm",
                "sha256-tree-v2",
                "--exact-metadata",
                "--metadata",
                "kind=test",
                "--print-tree-sha256",
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, f"{expected}\n")


if __name__ == "__main__":
    unittest.main()
