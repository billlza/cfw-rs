from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

CONTRACT = Path(__file__).resolve().parents[1] / "native_ui_development_checks.sh"


class NativeUiDevelopmentDispatchTests(unittest.TestCase):
    def run_helper(self, repository: Path, *, operation="test", prepare_exit=0):
        # Real shell helper; only expensive compiler/runtime boundaries are
        # replaced by recorders. This does not claim a native UI build.
        script = '''
set -euo pipefail
source "$1"
export CFW_RELEASE_CARGO_EXECUTABLE=/fixture/cargo
export PREPARE_EXIT="$4"
export RECORD="$2/record"
cfw_run_release_python_script() {
  printf 'prepare:%s\\n' "$*" >> "$RECORD"
  if [[ "$PREPARE_EXIT" != 0 ]]; then return "$PREPARE_EXIT"; fi
  printf '%s/products\\n' "$4"
}
cfw_run_with_release_cargo_runtime() {
  printf 'cargo:%s\\ntarget:%s\\nproducts:%s\\n' "$*" "$CARGO_TARGET_DIR" "$CFW_DEVELOPMENT_NATIVE_UI_PRODUCTS" >> "$RECORD"
}
cfw_run_native_ui_development_check "$2" "$3"
'''
        return subprocess.run(["/bin/bash", "-p", "-c", script, "ci-native-test", str(CONTRACT), str(repository), operation, str(prepare_exit)],
                              env=dict(os.environ), capture_output=True, text=True, check=False)

    def test_prepare_precedes_cargo_and_each_invocation_binds_a_distinct_fresh_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            paths = []
            for operation in ("test", "clippy"):
                result = self.run_helper(repository, operation=operation)
                self.assertEqual(result.returncode, 0, result.stderr)
            records = (repository / "record").read_text().splitlines()
            for start in (0, 4):
                self.assertTrue(records[start].startswith("prepare:"))
                self.assertTrue(records[start + 1].startswith("cargo:"))
                self.assertIn("--locked --workspace --all-targets --all-features", records[start + 1])
                path = Path(records[start + 2].removeprefix("target:"))
                self.assertTrue(path.is_relative_to(repository / "target/development"))
                self.assertTrue(path.is_dir())
                self.assertEqual(records[start + 3], f"products:{path}/products")
                paths.append(path)
            self.assertNotEqual(paths[0], paths[1])
            self.assertIn("-- -D warnings", records[5])

    def test_failed_preparation_prevents_cargo_without_deleting_failed_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            result = self.run_helper(repository, prepare_exit=17)
            self.assertEqual(result.returncode, 17)
            record = (repository / "record").read_text()
            self.assertNotIn("cargo:", record)
            self.assertEqual(len(list((repository / "target/development").iterdir())), 1)

    def test_alias_parent_is_refused_before_preparation_or_external_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            outside = repository / "outside"
            outside.mkdir()
            (repository / "target").symlink_to(outside, target_is_directory=True)
            result = self.run_helper(repository)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((repository / "record").exists())
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
