from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.verify_ci_no_masking import (
    CiPolicyError,
    DEFAULT_PINS,
    DEFAULT_WORKFLOW,
    audit_workflow,
)


PINS = "\n".join(
    [
        "RUST_VERSION=1.97.1",
        "NODE_VERSION=24.18.0",
        "XCODE_VERSION=26.6",
        "XCODE_BUILD_VERSION=17F113",
    ]
)

GOOD_WORKFLOW = """name: CI

env:
  DEVELOPER_DIR: /Applications/Xcode_26.6.app/Contents/Developer

jobs:
  build:
    runs-on: macos-26
    timeout-minutes: 60
    steps:
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: "1.97.1"
      - uses: actions/setup-node@v5
        with:
          node-version: "24.18.0"
      - name: Assert toolchain
        run: test "$(xcodebuild -version)" = $'Xcode 26.6\\nBuild version 17F113'
      - name: Check formatting
        run: cargo fmt --all -- --check
      - name: Lint
        run: cargo clippy --locked --workspace -- -D warnings
      - name: Swift lint
        run: swift format lint --recursive --strict native/macos/Sources
"""


class VerifyCiNoMaskingTests(unittest.TestCase):
    def _write(self, directory: Path, workflow: str, pins: str = PINS) -> tuple[Path, Path]:
        workflow_path = directory / "ci.yml"
        pins_path = directory / "pins.env"
        workflow_path.write_text(workflow, encoding="utf-8")
        pins_path.write_text(pins, encoding="utf-8")
        return workflow_path, pins_path

    def test_repository_workflow_passes(self) -> None:
        # The real, checked-in workflow must satisfy the policy.
        audit_workflow(DEFAULT_WORKFLOW, DEFAULT_PINS)

    def test_good_synthetic_workflow_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workflow_path, pins_path = self._write(Path(tmp), GOOD_WORKFLOW)
            audit_workflow(workflow_path, pins_path)

    def test_or_true_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "run: cargo fmt --all -- --check",
                "run: cargo fmt --all -- --check || true",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, r"\|\| true"):
                audit_workflow(workflow_path, pins_path)

    def test_continue_on_error_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "      - name: Lint",
                "      - name: Lint\n        continue-on-error: true",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "continue-on-error"):
                audit_workflow(workflow_path, pins_path)

    def test_unconditional_skip_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "      - name: Lint",
                "      - name: Lint\n        if: false",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "if: false"):
                audit_workflow(workflow_path, pins_path)

    def test_set_plus_e_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "run: cargo clippy --locked --workspace -- -D warnings",
                "run: |\n          set +e\n          cargo clippy --locked --workspace -- -D warnings",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, r"set \+e"):
                audit_workflow(workflow_path, pins_path)

    def test_missing_timeout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace("    timeout-minutes: 60\n", "")
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "timeout-minutes"):
                audit_workflow(workflow_path, pins_path)

    def test_drifted_rust_toolchain_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace('toolchain: "1.97.1"', 'toolchain: "1.98.0"')
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "Rust toolchain"):
                audit_workflow(workflow_path, pins_path)

    def test_multiple_node_toolchains_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                '        with:\n          node-version: "24.18.0"',
                '        with:\n          node-version: "24.18.0"\n'
                "      - name: Second node\n"
                "        run: use node-20.0.0/bin/npm",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "multiple Node.js toolchains"):
                audit_workflow(workflow_path, pins_path)

    def test_dropped_clippy_gate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "cargo clippy --locked --workspace -- -D warnings",
                "cargo clippy --locked --workspace",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "-D warnings"):
                audit_workflow(workflow_path, pins_path)

    def test_missing_workflow_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pins_path = Path(tmp) / "pins.env"
            pins_path.write_text(PINS, encoding="utf-8")
            with self.assertRaisesRegex(CiPolicyError, "workflow is missing"):
                audit_workflow(Path(tmp) / "absent.yml", pins_path)


if __name__ == "__main__":
    unittest.main()
