from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from scripts.hash_native_build_inputs import INPUTS, build_digest

REPOSITORY = Path(__file__).resolve().parents[2]


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

    def test_host_build_script_hashes_the_same_inputs(self) -> None:
        # build.rs recomputes this digest to admit the native products, so both
        # sides must list the same native build inputs.
        source = (REPOSITORY / "apps/cfw-tauri-shell/build.rs").read_text(
            encoding="utf-8"
        )
        function = source[source.index("fn native_build_inputs_digest(") :]
        block = function[function.index("for relative in [") : function.index("] {")]
        self.assertEqual(tuple(re.findall(r'"([^"]+)"', block)), INPUTS)

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
