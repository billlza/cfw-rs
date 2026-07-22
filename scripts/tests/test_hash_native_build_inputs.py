from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.hash_native_build_inputs import INPUTS, build_digest


class NativeBuildInputHashTests(unittest.TestCase):
    def make_repository(self, root: Path) -> None:
        for relative in INPUTS:
            path = root / relative
            if Path(relative).suffix:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative, encoding="utf-8")
            else:
                path.mkdir(parents=True, exist_ok=True)
                (path / "input.txt").write_text(relative, encoding="utf-8")

    def test_digest_is_stable_and_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.make_repository(repository)
            first = build_digest(repository)
            self.assertEqual(first, build_digest(repository))
            (repository / "native/macos/Sources/input.txt").write_text(
                "changed", encoding="utf-8"
            )
            self.assertNotEqual(first, build_digest(repository))

    def test_symlink_input_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.make_repository(repository)
            target = repository / "native/macos/Sources/input.txt"
            target.unlink()
            target.symlink_to("../Headers/input.txt")
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                build_digest(repository)


if __name__ == "__main__":
    unittest.main()
