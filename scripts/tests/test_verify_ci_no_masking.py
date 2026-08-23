from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.verify_ci_no_masking import (
    CiPolicyError,
    DEFAULT_PINS,
    DEFAULT_WORKFLOW,
    audit_shell_test_python_isolation,
    audit_workflow,
)


PINS = "\n".join(
    [
        "RUST_VERSION=1.97.1",
        "NODE_VERSION=24.18.0",
        "PYTHON_VERSION=3.14.6",
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
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405
        id: validation-python
        with:
          python-version: "3.14.6"
          architecture: arm64
          update-environment: false
      - name: Bootstrap Node
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' bootstrap-node-toolchain
      - name: Assert toolchain
        run: test "$(/usr/bin/xcodebuild -version)" = $'Xcode 26.6\\nBuild version 17F113'
      - name: Verify policy
        run: PYTHONDONTWRITEBYTECODE=1 python3 -S -B scripts/verify_policy.py
      - name: Prepare Cargo workspace inputs
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' prepare-cargo-workspace-inputs
      - name: Bootstrap policy tools
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' bootstrap-policy-tools
      - name: Check formatting
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-fmt
      - name: Metadata
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-metadata
      - name: Lint
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy
      - name: Rust test
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-test
      - name: Rust target audit
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-target-audit
      - name: Cargo deny
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' cargo-deny
      - name: Swift lint
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' swift-format-lint
      - name: Swift test
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' swift-package-test
      - name: Xcode test
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' xcode-unsigned-test
      - name: Xcode analyze
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' xcode-analyze
      - name: Prepare UI
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' prepare-ui-dependencies
      - name: Test UI
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' ui-test
      - name: Build UI
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' ui-build
      - name: Audit UI
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' ui-audit
      - name: Build boundaries
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' build-script-boundary
      - name: CI policy
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' ci-no-masking
      - name: Evidence lane
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' evidence-manifest-lane
      - name: Version contract
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' version-contract
      - name: Release tool tests
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' release-tool-tests
      - name: Bootstrap release tools
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' bootstrap-release-toolchain
      - name: Verify Xcode project
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' verify-xcode-project
      - name: Materialize libbox
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' fetch-libbox-upstream /tmp/upstream
      - name: Patch libbox
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' materialize-libbox-source /tmp/upstream /tmp/patched
      - name: Test libbox
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' libbox-source-tests /tmp/patched
      - name: Scan libbox
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' libbox-vulnerability-scan /tmp/patched
      - name: Build libbox
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' build-libbox /tmp/patched
      - name: Install Tauri
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' install-tauri-cli
      - name: Signer integration
        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' updater-signer-integration
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

    def test_rust_test_gate_cannot_drop_all_features(self) -> None:
        source_gate = Path(__file__).resolve().parents[1] / "run_release_ci_gate.sh"
        source = source_gate.read_text(encoding="utf-8")
        required = (
            '"$CFW_RELEASE_CARGO_EXECUTABLE" test '
            "\\"
            "\n"
            "      --locked --workspace --all-targets --all-features"
        )
        self.assertIn(required, source)
        with tempfile.TemporaryDirectory() as temporary:
            drifted_gate = Path(temporary) / "run_release_ci_gate.sh"
            drifted_gate.write_text(
                source.replace(
                    required,
                    required.removesuffix(" --all-features"),
                    1,
                ),
                encoding="utf-8",
            )
            with patch(
                "scripts.verify_ci_no_masking.RELEASE_CI_GATE", drifted_gate
            ), self.assertRaisesRegex(
                CiPolicyError, "omits required Cargo command"
            ):
                audit_workflow(DEFAULT_WORKFLOW, DEFAULT_PINS)

    def test_fetch_gate_does_not_read_account_git_state(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[1] / "run_release_ci_gate.sh"
        ).read_text(encoding="utf-8")
        for fragment in (
            '"HOME=/var/empty"',
            '"GIT_ATTR_NOSYSTEM=1"',
            '"GIT_CONFIG_GLOBAL=/dev/null"',
            '"GIT_CONFIG_NOSYSTEM=1"',
            '"GIT_TERMINAL_PROMPT=0"',
            "-c core.attributesFile=/dev/null",
        ):
            self.assertIn(fragment, wrapper)
        self.assertNotIn('"HOME=$HOME"', wrapper)

    def test_good_synthetic_workflow_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workflow_path, pins_path = self._write(Path(tmp), GOOD_WORKFLOW)
            audit_workflow(workflow_path, pins_path)

    def test_or_true_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-fmt",
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-fmt || true",
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
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy",
                "run: |\n          set +e\n          ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy",
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
                "      - name: Bootstrap Node",
                "      - name: Second node\n"
                "        run: use node-20.0.0/bin/npm\n"
                "      - name: Bootstrap Node",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "multiple Node.js toolchains"):
                audit_workflow(workflow_path, pins_path)

    def test_dropped_clippy_gate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "' rust-clippy",
                "' rust-test",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "-D warnings"):
                audit_workflow(workflow_path, pins_path)

    def test_commented_out_required_gate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy",
                "        # run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "-D warnings"):
                audit_workflow(workflow_path, pins_path)

    def test_gate_name_outside_run_command_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "      - name: Lint\n"
                "        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy",
                "      - name: rust-clippy\n        run: /bin/false",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "-D warnings"):
                audit_workflow(workflow_path, pins_path)

    def test_early_success_before_gate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy",
                "run: exit 0; ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "-D warnings"):
                audit_workflow(workflow_path, pins_path)

    def test_unreachable_conditional_gate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy",
                "run: |\n"
                "          if false; then\n"
                "            ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy\n"
                "          fi",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "-D warnings"):
                audit_workflow(workflow_path, pins_path)

    def test_redirected_gate_command_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy",
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-clippy >/dev/null",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "-D warnings"):
                audit_workflow(workflow_path, pins_path)

    def test_commented_out_gate_implementation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            workflow_path, pins_path = self._write(directory, GOOD_WORKFLOW)
            real_gate = Path(__file__).resolve().parents[1] / "run_release_ci_gate.sh"
            gate_source = real_gate.read_text(encoding="utf-8")
            active_line = "  cfw_run_warning_free_policy_install \\\n"
            self.assertIn(active_line, gate_source)
            gate_path = directory / "run_release_ci_gate.sh"
            gate_path.write_text(
                gate_source.replace(
                    active_line,
                    "  # cfw_run_warning_free_policy_install \\\n",
                ),
                encoding="utf-8",
            )
            with patch(
                "scripts.verify_ci_no_masking.RELEASE_CI_GATE",
                gate_path,
            ):
                with self.assertRaisesRegex(
                    CiPolicyError,
                    "cfw_run_warning_free_policy_install",
                ):
                    audit_workflow(workflow_path, pins_path)

    def test_dropped_swift_warnings_as_errors_gate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' swift-package-test",
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' swift-format-lint",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "warnings-as-errors"):
                audit_workflow(workflow_path, pins_path)

    def test_ambient_swift_driver_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' swift-format-lint",
                "run: /usr/bin/swift format lint --recursive --strict native/macos/Sources",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "closed Apple driver"):
                audit_workflow(workflow_path, pins_path)

    def test_python_site_initialization_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace("python3 -S -B", "python3 -B")
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "site initialization"):
                audit_workflow(workflow_path, pins_path)

    def test_release_tool_tests_require_pinned_identity_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "      - name: Bootstrap policy tools\n"
                "        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' bootstrap-policy-tools\n",
                "",
            ).replace(
                "      - name: Verify policy",
                "      - name: Release tooling\n"
                "        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' release-tool-tests\n"
                "      - name: Verify policy",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "pinned identity tool"):
                audit_workflow(workflow_path, pins_path)

    def test_policy_bootstrap_requires_workspace_cargo_input_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "      - name: Prepare Cargo workspace inputs\n"
                "        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' prepare-cargo-workspace-inputs\n",
                "",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "prepare-cargo-workspace-inputs"):
                audit_workflow(workflow_path, pins_path)

    def test_workspace_cargo_inputs_must_precede_policy_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            preparation = (
                "      - name: Prepare Cargo workspace inputs\n"
                "        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' prepare-cargo-workspace-inputs\n"
            )
            bootstrap = (
                "      - name: Bootstrap policy tools\n"
                "        run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' bootstrap-policy-tools\n"
            )
            bad = GOOD_WORKFLOW.replace(preparation + bootstrap, bootstrap + preparation)
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "after policy bootstrap"):
                audit_workflow(workflow_path, pins_path)

    def test_shell_test_python_must_disable_site_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp)
            (tests / "bad_test.sh").write_text(
                "#!/bin/bash\npython3 - script.py\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CiPolicyError, "closed Python"):
                audit_shell_test_python_isolation(tests)

            (tests / "bad_test.sh").write_text(
                "#!/bin/bash\npython3 -S -B - script.py\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CiPolicyError, "closed Python"):
                audit_shell_test_python_isolation(tests)

            (tests / "bad_test.sh").write_text(
                "#!/bin/bash\n"
                'PYTHONDONTWRITEBYTECODE=1 "$CFW_RELEASE_PYTHON_EXECUTABLE" '
                "-I -S -B -W error - <<'PY'\n"
                "raise SystemExit(0)\n"
                "PY\n",
                encoding="utf-8",
            )
            audit_shell_test_python_isolation(tests)

    def test_raw_npm_install_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = GOOD_WORKFLOW.replace(
                "run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' prepare-ui-dependencies",
                "run: npm ci",
            )
            workflow_path, pins_path = self._write(Path(tmp), bad)
            with self.assertRaisesRegex(CiPolicyError, "raw npm command"):
                audit_workflow(workflow_path, pins_path)

    def test_missing_workflow_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pins_path = Path(tmp) / "pins.env"
            pins_path.write_text(PINS, encoding="utf-8")
            with self.assertRaisesRegex(CiPolicyError, "workflow is missing"):
                audit_workflow(Path(tmp) / "absent.yml", pins_path)


if __name__ == "__main__":
    unittest.main()
