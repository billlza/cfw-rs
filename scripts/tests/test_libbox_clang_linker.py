"""Clang receives all original input and failures, with one Objective-C runtime."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


LINKER = Path(__file__).resolve().parents[1] / "libbox_clang_linker.sh"


class LibboxClangLinkerTests(unittest.TestCase):
    def test_preserves_argument_boundaries_diagnostics_and_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linker space ") as temporary:
            developer = Path(temporary) / "Xcode.app/Contents/Developer"
            clang = developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
            clang.parent.mkdir(parents=True)
            clang.write_text(
                "#!/bin/bash\n"
                "printf '%s\\0' \"$@\"\n"
                "printf '%s\\n' 'real linker diagnostic' >&2\n"
                "exit 42\n",
                encoding="utf-8",
            )
            clang.chmod(0o755)
            original = ["input with space.o", "-lobjc", "-lssl", "-lobjc", "-lssl", "-o", "output file"]
            completed = subprocess.run(
                [str(LINKER), *original],
                env={**os.environ, "DEVELOPER_DIR": str(developer)},
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 42)
            self.assertEqual(completed.stderr, b"real linker diagnostic\n")
            self.assertEqual(
                completed.stdout.decode().split("\0")[:-1],
                ["input with space.o", "-lobjc", "-lssl", "-lssl", "-o", "output file"],
            )

    def test_missing_xcode_fails_before_linking(self) -> None:
        completed = subprocess.run(
            [str(LINKER), "-lobjc"], env={}, capture_output=True, check=False
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"selected Xcode Clang linker is unavailable", completed.stderr)


if __name__ == "__main__":
    unittest.main()
