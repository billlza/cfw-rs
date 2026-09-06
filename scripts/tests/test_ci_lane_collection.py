#!/usr/bin/env python3
"""Fail-closed tests for the unsigned-CI lane collector (Task 12.3 input).

Collector tests inject the process runner; bounded subprocess tests also exercise
the real lane launcher and standalone CI wrapper with fixture tools. They verify
the recording, journal, dispatch, and assembly rules that keep
the unsigned-CI gate honest - a nonzero exit can never be recorded as a pass, a
wall-clock overrun is recorded as ``timeout``, a stale or hand-edited journal
record is refused, and the assembled document is validated by the gate's own
validator.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from publication import ci_lanes  # noqa: E402
from publication.common import PublicationError, canonical_json  # noqa: E402
from publication.sealed_manifest import REQUIRED_CI_LANES  # noqa: E402

COMMIT = "a" * 40
SOURCE = "c" * 64
TOOLCHAIN_TREES = {"managed": "e" * 64}
IDENTITY = {
    "document": ci_lanes.TOOLCHAIN_BINDING_KIND,
    "fixture": True,
    "release_tree_sha256": TOOLCHAIN_TREES,
}
TOOLCHAIN = ci_lanes.toolchain_sha256(IDENTITY)


def _current_release_environment(
    repository: Path,
    pins: dict[str, str],
    source: dict[str, str] | None = None,
) -> dict[str, str]:
    selected = dict(os.environ if source is None else source)
    role = (
        "unsigned-validation"
        if "CFW_UNSIGNED_VALIDATION_PYTHON" in selected
        else "production"
    )
    return ci_lanes.release_tool_environment(
        repository, pins, selected, role=role
    )


def _runner(results):
    """Return a runner that replays scripted (exit_code, timed_out) outcomes."""

    def run(_repository, lane, _environment):
        exit_code, timed_out = results.get(lane.identifier, (0, False))
        return (
            f"output for {lane.identifier}".encode(),
            exit_code,
            timed_out,
            1.5,
        )

    return run


class CiLaneTableTests(unittest.TestCase):
    def test_standalone_gate_fixes_child_modes_and_preserves_parent_log_and_exit(self) -> None:
        wrapper_source = (
            Path(__file__).resolve().parents[1] / "run_release_ci_gate.sh"
        ).read_bytes()
        for child_exit in (0, 17):
            with self.subTest(child_exit=child_exit), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary).resolve() / "standalone gate"
                scripts = repository / "scripts"
                scripts.mkdir(parents=True)
                wrapper = scripts / "run_release_ci_gate.sh"
                wrapper.write_bytes(wrapper_source)
                wrapper.chmod(0o755)
                (scripts / "dependency_pins.env").write_text(
                    "MACOS_DEPLOYMENT_TARGET=15.0\n", encoding="utf-8"
                )
                # Substitute only external tool admission and the leaf driver;
                # the reviewed wrapper's shell, dispatch, and umask run intact.
                (scripts / "release_tool_environment.sh").write_text(
                    'cfw_seal_release_tool_environment() { [[ "$1" == production ]]; }\n'
                    'cfw_select_release_apple_toolchain() { :; }\n'
                    'cfw_run_release_python_script() {\n'
                    '  [[ $# -eq 2 && "$2" == "$1/scripts/release_apple_toolchain.py" ]] || return 97\n'
                    f'  {shlex.quote(sys.executable)} -I -S -B -W error "$2"\n'
                    '}\n',
                    encoding="utf-8",
                )
                (scripts / "release_policy_tool_directory.sh").write_text(
                    "", encoding="utf-8"
                )
                (scripts / "release_apple_toolchain.py").write_text(
                    "from pathlib import Path\n"
                    "Path('ordinary.txt').write_text('public artifact\\n')\n"
                    "Path('ordinary-directory').mkdir()\n"
                    "print('gate probe completed')\n"
                    f"raise SystemExit({child_exit})\n",
                    encoding="utf-8",
                )
                private_log = repository / "private.log"
                previous_umask = os.umask(0o077)
                try:
                    with private_log.open("xb") as output:
                        result = subprocess.run(
                            ["/bin/bash", "-p", str(wrapper), "apple-toolchain"],
                            cwd=repository,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                            stdout=output,
                            stderr=subprocess.PIPE,
                            timeout=5,
                            check=False,
                        )
                    observed_parent_umask = os.umask(0o077)
                    self.assertEqual(result.returncode, child_exit, result.stderr)
                    self.assertEqual(result.stderr, b"")
                    self.assertEqual(observed_parent_umask, 0o077)
                    self.assertEqual(private_log.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(private_log.read_bytes(), b"gate probe completed\n")
                    self.assertEqual(
                        (
                            (repository / "ordinary.txt").stat().st_mode & 0o777,
                            (repository / "ordinary-directory").stat().st_mode & 0o777,
                        ),
                        (0o644, 0o755),
                    )
                finally:
                    os.umask(previous_umask)

    def test_lane_umask_is_deterministic_without_changing_the_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            previous = os.umask(0o077)
            try:
                output, exit_code, timed_out, _duration = ci_lanes.execute_lane(
                    repository,
                    ci_lanes.Lane("file-modes", "/usr/bin/touch ordinary.txt", timeout=5),
                    {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
                observed_parent = os.umask(0o077)
                self.assertEqual((output, exit_code, timed_out), (b"", 0, False))
                self.assertEqual((repository / "ordinary.txt").stat().st_mode & 0o777, 0o644)
                self.assertEqual(observed_parent, 0o077)
            finally:
                os.umask(previous)

    def test_lane_table_matches_the_gate(self) -> None:
        ci_lanes.self_check()
        self.assertEqual(
            sorted(lane.identifier for lane in ci_lanes.LANES), sorted(REQUIRED_CI_LANES)
        )

    def test_every_lane_is_bounded(self) -> None:
        for lane in ci_lanes.LANES:
            self.assertGreater(lane.timeout, 0, lane.identifier)
            self.assertLessEqual(len(lane.command), 1024, lane.identifier)
            self.assertEqual(lane.command.strip(), lane.command, lane.identifier)

    def test_packet_lan_peer_lane_uses_full_verifier(self) -> None:
        lane = ci_lanes.LANE_INDEX["packet-lan-peer"]
        self.assertEqual(
            lane.command,
            "./scripts/run_release_ci_gate.sh packet-lan-peer",
        )
        wrapper = (
            Path(__file__).resolve().parents[1] / "run_release_ci_gate.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '/bin/bash -p "$repo_root/scripts/verify_packet_lan_peer.sh"',
            wrapper,
        )
        self.assertIn(
            '"$repo_root" "$repo_root/scripts/verify_pinned_build_inputs.py"',
            wrapper,
        )

    def test_python_lanes_disable_site_initialization(self) -> None:
        for lane in ci_lanes.LANES:
            if "python3 " in lane.command:
                with self.subTest(lane=lane.identifier):
                    self.assertIn("python3 -S -B", lane.command)

    def test_unsigned_candidate_build_python_disables_site_initialization(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        for relative in (
            "scripts/build_unsigned_candidate.sh",
            "scripts/build_native_products.sh",
        ):
            with self.subTest(script=relative):
                for number, line in enumerate(
                    (repository / relative).read_text(encoding="utf-8").splitlines(),
                    start=1,
                ):
                    if "python3 " in line:
                        self.assertIn("python3 -S -B", line, f"{relative}:{number}")

    def test_apple_lanes_use_fixed_system_drivers(self) -> None:
        expected_gates = {
            "swift-format-lint": "swift-format-lint",
            "swift-package-test": "swift-package-test",
            "xcode-unsigned-test": "xcode-unsigned-test",
            "xcode-analyze": "xcode-analyze",
        }
        for identifier, gate in expected_gates.items():
            with self.subTest(lane=identifier):
                self.assertEqual(
                    ci_lanes.LANE_INDEX[identifier].command,
                    f"./scripts/run_release_ci_gate.sh {gate}",
                )
        wrapper = (
            Path(__file__).resolve().parents[1] / "run_release_ci_gate.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("/usr/bin/swift format lint --recursive --strict", wrapper)
        self.assertIn("/usr/bin/swift test --package-path native/macos", wrapper)
        self.assertIn("-Xswiftc -warnings-as-errors", wrapper)
        self.assertIn("/usr/bin/xcodebuild test", wrapper)
        self.assertIn("/usr/bin/xcodebuild analyze", wrapper)

    def test_evidence_manifest_lane_uses_the_release_gate(self) -> None:
        self.assertEqual(
            ci_lanes.LANE_INDEX["evidence-manifest-lane"].command,
            "./scripts/run_release_ci_gate.sh evidence-manifest-lane",
        )

    def test_lane_runner_uses_fixed_privileged_bash(self) -> None:
        source = Path(ci_lanes.__file__).read_text(encoding="utf-8")
        self.assertIn(
            '["/bin/bash", "-p", "-euo", "pipefail", "-c", lane.command]',
            source,
        )

    def test_real_lane_output_is_killed_at_the_streaming_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            environment = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
            started = time.monotonic()
            with patch.object(ci_lanes, "MAX_LOG_BYTES", 4096):
                with self.assertRaisesRegex(PublicationError, "output exceeded 4096"):
                    ci_lanes.execute_lane(
                        repository,
                        ci_lanes.Lane(
                            "streaming-output-limit",
                            "/usr/bin/yes bounded-output",
                            timeout=5,
                        ),
                        environment,
                    )
            self.assertLess(time.monotonic() - started, 5)

    def test_real_lane_timeout_kills_the_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            environment = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
            started = time.monotonic()
            output, exit_code, timed_out, duration = ci_lanes.execute_lane(
                repository,
                ci_lanes.Lane(
                    "streaming-timeout",
                    "/bin/sleep 10",
                    timeout=1,
                ),
                environment,
            )
            self.assertEqual(output, b"")
            self.assertIsNone(exit_code)
            self.assertTrue(timed_out)
            self.assertGreaterEqual(duration, 1)
            self.assertLess(time.monotonic() - started, 5)

    def test_zero_exit_with_background_descendant_is_rejected_and_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            pid_path = repository / "descendant.pid"
            environment = {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "PID_PATH": str(pid_path),
            }
            command = (
                "/bin/sleep 30 >/dev/null 2>&1 & child=$!; "
                "printf '%s\\n' \"$child\" > \"$PID_PATH\"; exit 0"
            )
            started = time.monotonic()
            with self.assertRaisesRegex(PublicationError, "left a descendant"):
                ci_lanes.execute_lane(
                    repository,
                    ci_lanes.Lane("background-descendant", command, timeout=5),
                    environment,
                )
            child = int(pid_path.read_text(encoding="utf-8").strip())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail(f"lane descendant remained alive: {child}")
            self.assertLess(time.monotonic() - started, 5)

    def test_lane_selector_setup_failure_terminates_the_owned_process(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryFile() as output,
        ):
            process = Mock(pid=12345, stdout=output)
            process.poll.return_value = None
            lane = ci_lanes.Lane(
                "selector-failure", "/bin/sleep 30", timeout=2
            )
            with (
                patch.object(ci_lanes.subprocess, "Popen", return_value=process),
                patch.object(
                    ci_lanes.selectors,
                    "DefaultSelector",
                    side_effect=OSError("selector unavailable"),
                ),
                patch.object(
                    ci_lanes, "_terminate_lane_process_group"
                ) as terminate,
                self.assertRaisesRegex(OSError, "selector unavailable"),
            ):
                ci_lanes.execute_lane(
                    Path(temporary).resolve(),
                    lane,
                    {"PATH": "/usr/bin:/bin"},
                )
            terminate.assert_called_once_with(process, lane.identifier)
            self.assertTrue(output.closed)


class ReleaseToolEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = Path(__file__).resolve().parents[2]
        self.pins = ci_lanes._pins(self.repository)

    def test_ambient_tool_shadows_and_injection_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            marker = Path(temporary) / "ambient-tool-ran"
            for tool in ("swift", "xcodebuild", "xcrun", "rustc", "cargo"):
                executable = fake_bin / tool
                executable.write_text(
                    f"#!/bin/sh\ntouch '{marker}'\nexit 99\n", encoding="utf-8"
                )
                executable.chmod(0o755)
            source = dict(os.environ)
            source.update(
                {
                    "PATH": f"{fake_bin}:{source['PATH']}",
                    "TOOLCHAINS": "malicious",
                    "SDKROOT": str(Path(temporary) / "sdk"),
                    "SWIFT_EXEC": str(fake_bin / "swift"),
                    "BASH_ENV": str(Path(temporary) / "bash-env"),
                    "PYTHONPATH": str(Path(temporary) / "python"),
                    "RUSTUP_HOME": str(Path(temporary) / "untrusted-rustup"),
                    "RUSTUP_TOOLCHAIN": "untrusted-channel",
                    "RUSTC": str(fake_bin / "rustc"),
                    "RUSTC_WRAPPER": str(fake_bin / "rustc"),
                    "RUSTFLAGS": "--cfg injected",
                    "DYLD_INSERT_LIBRARIES": str(Path(temporary) / "inject.dylib"),
                }
            )
            environment = _current_release_environment(
                self.repository, self.pins, source
            )
            self.assertFalse(marker.exists())

        release_home = Path(environment["HOME"]).resolve()
        python_series = self.pins["PYTHON_VERSION"].rsplit(".", 1)[0]
        validation_launcher = environment.get("CFW_UNSIGNED_VALIDATION_PYTHON")
        python_bin = (
            Path(validation_launcher).parent
            if validation_launcher is not None
            else Path("/opt/homebrew/Cellar")
            / f"python@{python_series}"
            / self.pins["PYTHON_VERSION"]
            / "Frameworks/Python.framework/Versions"
            / python_series
            / "bin"
        )
        expected_path = ":".join(
            (
                *ci_lanes.SYSTEM_PATH,
                str(
                    release_home
                    / {
                        "global": ".rustup/toolchains",
                        "private": ".cfm-release-tooling/rust-toolchains",
                    }[environment["CFW_RELEASE_RUST_TOOLCHAIN"]]
                    / f"{self.pins['RUST_VERSION']}-aarch64-apple-darwin/bin"
                ),
                str(
                    release_home
                    / ".cfm-release-tooling"
                    / (
                        f"policy-{self.pins['CARGO_AUDIT_VERSION']}-"
                        f"{self.pins['CARGO_DENY_VERSION']}"
                    )
                    / "bin"
                ),
            )
        )
        self.assertEqual(environment["PATH"], expected_path)
        self.assertEqual(
            environment["CFW_RELEASE_RUST_TOOLCHAIN"],
            source.get("CFW_RELEASE_RUST_TOOLCHAIN", "global"),
        )
        rust_bin = Path(expected_path.split(":")[4])
        self.assertEqual(environment["CFW_RELEASE_RUSTC_EXECUTABLE"], str(rust_bin / "rustc"))
        self.assertEqual(environment["CFW_RELEASE_CARGO_EXECUTABLE"], str(rust_bin / "cargo"))
        self.assertEqual(
            Path(environment["CFW_RELEASE_PYTHON_EXECUTABLE"]),
            (python_bin / f"python{python_series}").resolve(strict=True),
        )
        self.assertEqual(
            Path(environment["CFW_RELEASE_PYTHON_RUNTIME"]),
            python_bin.parent / "Python",
        )
        self.assertEqual(
            Path(environment["CFW_RELEASE_PYTHON_STDLIB"]),
            python_bin.parent / "lib" / f"python{python_series}",
        )
        for name in (
            "TOOLCHAINS",
            "SDKROOT",
            "SWIFT_EXEC",
            "BASH_ENV",
            "PYTHONPATH",
            "RUSTC_WRAPPER",
            "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
            "RUSTC",
            "RUSTFLAGS",
            "DYLD_INSERT_LIBRARIES",
        ):
            self.assertNotIn(name, environment)

    def test_poisoned_ambient_environment_does_not_change_resolved_identity(self) -> None:
        baseline_source = dict(os.environ)
        poisoned_source = dict(baseline_source)
        poisoned_source.update(
            {
                "PATH": "/tmp/untrusted-bin:" + baseline_source["PATH"],
                "TOOLCHAINS": "untrusted",
                "SDKROOT": "/tmp/untrusted-sdk",
                "SWIFT_EXEC": "/tmp/untrusted-swift",
                "RUSTFLAGS": "--cfg untrusted",
                "RUSTUP_HOME": "/tmp/untrusted-rustup",
                "RUSTUP_TOOLCHAIN": "untrusted-channel",
                "DYLD_LIBRARY_PATH": "/tmp/untrusted-library",
                "HOME": "/tmp/untrusted-home",
                "XCODE_XCCONFIG_FILE": "/tmp/untrusted.xcconfig",
                "CPATH": "/tmp/untrusted-headers",
                "GIT_DIR": "/tmp/untrusted-git-dir",
                "NODE_PATH": "/tmp/untrusted-node-modules",
            }
        )
        baseline = _current_release_environment(
            self.repository, self.pins, baseline_source
        )
        poisoned = _current_release_environment(
            self.repository, self.pins, poisoned_source
        )
        self.assertEqual(baseline, poisoned)

    def test_explicit_rust_selection_and_executables_survive_lane_execution(self) -> None:
        for selection in ("global", "private"):
            for pinned_node in (False, True):
                with self.subTest(selection=selection, pinned_node=pinned_node):
                    with tempfile.TemporaryDirectory() as temporary:
                        repository = Path(temporary).resolve()
                        rust_parent = {
                            "global": ".rustup/toolchains",
                            "private": ".cfm-release-tooling/rust-toolchains",
                        }[selection]
                        rust_bin = (
                            repository / rust_parent
                            / f"{self.pins['RUST_VERSION']}-aarch64-apple-darwin/bin"
                        )
                        rust_bin.mkdir(parents=True)
                        for name in ("rustc", "cargo"):
                            executable = rust_bin / name
                            executable.write_text(
                                f"#!/bin/sh\nprintf '%s\\n' '{selection}-{name}'\n",
                                encoding="utf-8",
                            )
                            executable.chmod(0o755)
                        # This fixture explicitly owns its selection; a private
                        # test runner must not alter the global fixture case.
                        sealed = {
                            "PATH": f"{rust_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
                            "LANG": "C", "LC_ALL": "C",
                            "CFW_RELEASE_RUST_TOOLCHAIN": selection,
                            "CFW_RELEASE_RUSTC_EXECUTABLE": str(rust_bin / "rustc"),
                            "CFW_RELEASE_CARGO_EXECUTABLE": str(rust_bin / "cargo"),
                        }
                        snapshot = dict(sealed)
                        lane = ci_lanes.Lane(
                            "rust-location-fixture",
                            'printf "%s\\n" "$CFW_RELEASE_RUST_TOOLCHAIN" '
                            '"$(command -v rustc)" "$(command -v cargo)"; '
                            '"$CFW_RELEASE_RUSTC_EXECUTABLE" --version; '
                            '"$CFW_RELEASE_CARGO_EXECUTABLE" --version',
                            pinned_node=pinned_node, timeout=5,
                        )
                        with patch.dict(os.environ, {
                            "CFW_RELEASE_RUST_TOOLCHAIN": "private",
                            "RUSTUP_HOME": "/tmp/untrusted-rustup",
                            "RUSTUP_TOOLCHAIN": "untrusted-channel",
                        }):
                            environment = ci_lanes.lane_environment(
                                repository, lane, self.pins,
                                repository / "source", repository / "output",
                                repository / "runner", repository / "toolchains",
                                release_environment=sealed,
                            )
                            output, exit_code, timed_out, _duration = ci_lanes.execute_lane(
                                repository, lane, environment,
                            )
                        self.assertEqual(sealed, snapshot)
                        self.assertEqual((exit_code, timed_out), (0, False), output)
                        self.assertEqual(output.decode().splitlines(), [
                            selection, str(rust_bin / "rustc"), str(rust_bin / "cargo"),
                            f"{selection}-rustc", f"{selection}-cargo",
                        ])
                        self.assertNotIn("RUSTUP_HOME", environment)
                        self.assertNotIn("RUSTUP_TOOLCHAIN", environment)

    def test_unsigned_validation_python_is_explicit_and_production_rejects_it(
        self,
    ) -> None:
        current = _current_release_environment(self.repository, self.pins)
        validation_python = os.environ.get("CFW_UNSIGNED_VALIDATION_PYTHON")
        if validation_python is None:
            validation_python = str(
                Path(current["CFW_RELEASE_PYTHON_EXECUTABLE"]).parent / "python3"
            )
        source = dict(os.environ)
        source["CFW_UNSIGNED_VALIDATION_PYTHON"] = validation_python

        with self.assertRaisesRegex(
            PublicationError, "refuses an unsigned-validation Python"
        ):
            ci_lanes.release_tool_environment(
                self.repository, self.pins, source
            )

        unsigned = ci_lanes.release_tool_environment(
            self.repository,
            self.pins,
            source,
            role="unsigned-validation",
        )
        self.assertEqual(
            Path(unsigned["CFW_UNSIGNED_VALIDATION_PYTHON"]).resolve(strict=True),
            Path(unsigned["CFW_RELEASE_PYTHON_EXECUTABLE"]),
        )
        self.assertEqual(
            unsigned["CFW_RELEASE_PYTHON_EXECUTABLE"],
            current["CFW_RELEASE_PYTHON_EXECUTABLE"],
        )
        for name in (
            "CFW_RELEASE_RUST_TOOLCHAIN", "CFW_RELEASE_RUSTC_EXECUTABLE",
            "CFW_RELEASE_CARGO_EXECUTABLE", "PATH",
        ):
            self.assertEqual(unsigned[name], current[name])

    def test_invalid_explicit_developer_dir_fails_without_fallback(self) -> None:
        source = dict(os.environ)
        source["DEVELOPER_DIR"] = "/definitely/missing/Xcode.app/Contents/Developer"
        with self.assertRaisesRegex(
            PublicationError, "selected Xcode Developer directory"
        ):
            _current_release_environment(self.repository, self.pins, source)

    def test_exported_shell_function_is_rejected_before_lane_execution(self) -> None:
        source = dict(os.environ)
        source["BASH_FUNC_swift%%"] = "() { touch /tmp/forbidden; }"
        with self.assertRaisesRegex(PublicationError, "exported shell functions"):
            _current_release_environment(self.repository, self.pins, source)

    def test_identity_resolution_uses_absolute_rust_and_apple_tools(self) -> None:
        environment = _current_release_environment(self.repository, self.pins)
        rustc_bin = Path(environment["CFW_RELEASE_RUSTC_EXECUTABLE"])
        cargo_bin = Path(environment["CFW_RELEASE_CARGO_EXECUTABLE"])
        calls: list[list[str]] = []
        swift_identity = Mock(canonical="Apple Swift fixture")

        def identity(argv, _repository, _label, _environment, maximum=512):
            del maximum
            calls.append(argv)
            if argv == [str(rustc_bin), "--version"]:
                return f"rustc {self.pins['RUST_VERSION']} fixture"
            if argv == [str(cargo_bin), "--version"]:
                return f"cargo {self.pins['RUST_VERSION']} fixture"
            if argv[0].endswith("/cargo-audit"):
                return f"cargo-audit {self.pins['CARGO_AUDIT_VERSION']}"
            if argv[0].endswith("/cargo-deny"):
                return f"cargo-deny {self.pins['CARGO_DENY_VERSION']}"
            if argv[0].endswith(f"/python{self.pins['PYTHON_VERSION'].rsplit('.', 1)[0]}"):
                return f"Python {self.pins['PYTHON_VERSION']}"
            if argv[0] == "/usr/bin/git":
                return "git version fixture"
            if argv[0] == "/bin/bash":
                return "GNU bash fixture"
            if argv[0] == "/bin/zsh":
                return "zsh fixture"
            if argv[0].endswith("cargo-tauri"):
                return f"tauri-cli {self.pins['TAURI_CLI_VERSION']}"
            if argv[0].endswith("xcodegen"):
                return f"Version: {self.pins['XCODEGEN_VERSION']}"
            if argv == [ci_lanes.APPLE_XCODEBUILD, "-version"]:
                return (
                    f"Xcode {self.pins['XCODE_VERSION']}; "
                    f"Build version {self.pins['XCODE_BUILD_VERSION']}"
                )
            if argv[0].endswith("/node"):
                return f"v{self.pins['NODE_VERSION']}"
            if argv[0].endswith("/npm"):
                return "fixture npm"
            if argv[0].endswith("/go"):
                return f"go version go{self.pins['GO_VERSION']} darwin/arm64"
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(
                ci_lanes, "identity_output", side_effect=identity
            ), patch.object(
                ci_lanes,
                "swift_toolchain_identity",
                return_value=swift_identity,
            ) as resolve_swift, patch.object(
                ci_lanes,
                "_go_module_identity",
                return_value="fixture module",
            ):
                resolved = ci_lanes._resolved_toolchain(
                    self.repository,
                    self.pins,
                    Path(temporary),
                    release_environment=environment,
                )
        self.assertIn([str(rustc_bin), "--version"], calls)
        self.assertIn([str(cargo_bin), "--version"], calls)
        self.assertTrue(any(call[0].endswith("/cargo-audit") for call in calls))
        self.assertTrue(any(call[0].endswith("/cargo-deny") for call in calls))
        self.assertTrue(any("/python" in call[0] for call in calls))
        self.assertIn(["/usr/bin/git", "--version"], calls)
        self.assertIn(["/bin/bash", "--version"], calls)
        self.assertIn(["/bin/zsh", "--version"], calls)
        self.assertIn([ci_lanes.APPLE_XCODEBUILD, "-version"], calls)
        resolve_swift.assert_called_once_with(
            self.repository,
            environment,
            self.pins["MACOS_DEPLOYMENT_TARGET"],
        )
        self.assertEqual(resolved["swift"], swift_identity.canonical)
        for name in (
            "rustc",
            "cargo",
            "cargo-audit",
            "cargo-deny",
            "python3",
            "git",
            "bash",
            "zsh",
        ):
            with self.subTest(bound_executable=name):
                self.assertIn("path=", resolved[name])
                self.assertIn("sha256=", resolved[name])
                self.assertIn("identity=", resolved[name])
        self.assertIn("stdlib_algorithm=sha256-tree-v1", resolved["python3"])
        self.assertIn("stdlib_sha256=", resolved["python3"])

    def test_python_standard_library_bytes_change_its_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stdlib = Path(temporary).resolve() / "python3.14"
            stdlib.mkdir()
            module = stdlib / "json.py"
            module.write_text("VALUE = 1\n", encoding="utf-8")
            before = ci_lanes._python_stdlib_binding(stdlib)
            module.write_text("VALUE = 2\n", encoding="utf-8")
            after = ci_lanes._python_stdlib_binding(stdlib)

        self.assertNotEqual(before, after)


class RecordingTests(unittest.TestCase):
    def lane(self) -> ci_lanes.Lane:
        return ci_lanes.LANE_INDEX["rust-fmt"]

    def record(self, exit_code, timed_out) -> dict:
        return ci_lanes.record_lane(
            self.lane(),
            COMMIT,
            SOURCE,
            TOOLCHAIN,
            b"log",
            exit_code,
            timed_out,
            2.0,
            1700000000,
        )

    def test_zero_exit_is_the_only_pass(self) -> None:
        self.assertEqual(self.record(0, False)["status"], "passed")

    def test_nonzero_exit_is_failed(self) -> None:
        record = self.record(3, False)
        self.assertEqual((record["status"], record["exit_code"]), ("failed", 3))

    def test_timeout_is_recorded_as_timeout(self) -> None:
        record = self.record(None, True)
        self.assertEqual((record["status"], record["exit_code"]), ("timeout", 124))

    def test_signal_death_is_failed_with_shell_convention(self) -> None:
        record = self.record(-9, False)
        self.assertEqual((record["status"], record["exit_code"]), ("failed", 137))

    def test_missing_exit_status_fails_closed(self) -> None:
        with self.assertRaises(PublicationError):
            self.record(None, False)

    def test_log_digest_is_the_combined_output_digest(self) -> None:
        record = self.record(0, False)
        self.assertEqual(record["log_sha256"], hashlib.sha256(b"log").hexdigest())

    def test_unbounded_lane_output_is_rejected(self) -> None:
        with patch.object(ci_lanes, "MAX_LOG_BYTES", 3):
            with self.assertRaisesRegex(PublicationError, "output exceeded"):
                ci_lanes.record_lane(
                    self.lane(),
                    COMMIT,
                    SOURCE,
                    TOOLCHAIN,
                    b"four",
                    0,
                    False,
                    1.0,
                    1,
                )


class LibboxReproductionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repository = Path(self.directory.name).resolve()
        self.authoritative = (
            self.repository / ci_lanes.AUTHORITATIVE_LIBBOX_OUTPUT
        )
        self.rebuilt = self.repository / ci_lanes.DEFAULT_LIBBOX_OUTPUT
        for artifact in (self.authoritative, self.rebuilt):
            artifact.mkdir(parents=True)
            (artifact / "Libbox").write_bytes(b"reproducible-libbox")
        source_repository = Path(__file__).resolve().parents[2]
        self.pins = ci_lanes._pins(source_repository)
        self.toolchain_trees = {
            "go": "a" * 64,
            "go-release-tools": "b" * 64,
            "go-module-cache": "c" * 64,
        }
        self.write_manifest(self.authoritative)
        self.write_manifest(self.rebuilt)

    def write_manifest(self, artifact: Path) -> None:
        document = ci_lanes.build_manifest(
            artifact, algorithm="sha256-tree-v1"
        )
        document["metadata"] = ci_lanes._libbox_manifest_metadata(
            self.pins, self.toolchain_trees
        )
        manifest = artifact.parent / (artifact.name + ".manifest.json")
        manifest.write_text(
            json.dumps(
                document,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def verify(self) -> str:
        return ci_lanes.verify_libbox_reproduction(
            self.repository,
            self.rebuilt,
            self.pins,
            self.toolchain_trees,
        )

    def test_exact_rebuild_is_accepted(self) -> None:
        expected = ci_lanes.build_manifest(
            self.authoritative, algorithm="sha256-tree-v1"
        )["sha256"]
        self.assertEqual(self.verify(), expected)

    def test_individually_valid_tree_drift_is_rejected(self) -> None:
        (self.rebuilt / "Libbox").write_bytes(b"different-valid-libbox")
        self.write_manifest(self.rebuilt)
        with self.assertRaisesRegex(PublicationError, "not byte-identical"):
            self.verify()

    def test_matching_but_foreign_metadata_is_rejected(self) -> None:
        for artifact in (self.authoritative, self.rebuilt):
            manifest = artifact.parent / (artifact.name + ".manifest.json")
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["metadata"]["sourceCommit"] = "f" * 40
            manifest.write_text(
                json.dumps(
                    document,
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        with self.assertRaisesRegex(PublicationError, "metadata drifted"):
            self.verify()

    def test_semantically_equal_but_reencoded_manifest_is_rejected(self) -> None:
        manifest = self.rebuilt.parent / (self.rebuilt.name + ".manifest.json")
        document = json.loads(manifest.read_text(encoding="utf-8"))
        manifest.write_text(
            json.dumps(document, ensure_ascii=True, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PublicationError, "not byte-identical"):
            self.verify()

    def test_duplicate_manifest_field_is_rejected(self) -> None:
        manifest = self.rebuilt.parent / (self.rebuilt.name + ".manifest.json")
        encoded = manifest.read_text(encoding="utf-8")
        manifest.write_text(
            encoded.replace(
                '  "algorithm": "sha256-tree-v1",',
                '  "algorithm": "sha256-tree-v1",\n  "algorithm": "sha256-tree-v1",',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PublicationError, "manifest is invalid"):
            self.verify()

    def test_authoritative_tree_cannot_substitute_for_a_rebuild(self) -> None:
        with self.assertRaisesRegex(PublicationError, "independent canonical path"):
            ci_lanes.verify_libbox_reproduction(
                self.repository,
                self.authoritative,
                self.pins,
                self.toolchain_trees,
            )


class CollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.addCleanup(self.directory.cleanup)
        (self.root / "evidence").mkdir()
        (self.root / "target/toolchains").mkdir(parents=True)
        # The collector still reads the real pin schema. Toolchain identity and
        # lane execution are injected through their explicit collaborators,
        # never through ambient process state.
        (self.root / "scripts").mkdir()
        (self.root / "scripts/dependency_pins.env").write_bytes(
            (Path(__file__).resolve().parent.parent / "dependency_pins.env").read_bytes()
        )

    def collect(self, results=None, **overrides):
        injected_toolchain = overrides.pop("toolchain", (TOOLCHAIN, IDENTITY))
        source_identities = overrides.pop(
            "source_identities",
            [
                {"repositoryCommit": COMMIT, "releaseSourceSha256": SOURCE},
                {"repositoryCommit": COMMIT, "releaseSourceSha256": SOURCE},
                {"repositoryCommit": COMMIT, "releaseSourceSha256": SOURCE},
                {"repositoryCommit": COMMIT, "releaseSourceSha256": SOURCE},
            ],
        )
        arguments = {
            "commit": COMMIT,
            "release_source_sha256": SOURCE,
            "output": self.root / "evidence" / "unsigned-ci-lanes.json",
            "journal": self.root / "evidence" / "journal",
            "runner": _runner(results or {}),
            "reproduction_verifier": overrides.pop(
                "reproduction_verifier",
                lambda _repository, _artifact, _pins, _trees: "f" * 64,
            ),
            "report": lambda _message: None,
        }
        arguments.update(overrides)
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    ci_lanes,
                    "current_identity",
                    side_effect=source_identities,
                )
            )
            if injected_toolchain is not None:
                digest, identity = injected_toolchain
                execution_environment = {
                    "HOME": "/Users/release",
                    "PATH": "/usr/bin:/bin",
                    "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
                }
                stack.enter_context(
                    patch.object(
                        ci_lanes,
                        "release_tool_environment",
                        return_value=execution_environment,
                    )
                )
                stack.enter_context(
                    patch.object(
                        ci_lanes,
                        "derive_toolchain_binding",
                        side_effect=((digest, identity), (digest, identity), (digest, identity)),
                    )
                )
                stack.enter_context(
                    patch.object(
                        ci_lanes,
                        "verified_release_toolchain_trees",
                        side_effect=(
                            (self.root / "target/toolchains", TOOLCHAIN_TREES),
                            (self.root / "target/toolchains", TOOLCHAIN_TREES),
                            (self.root / "target/toolchains", TOOLCHAIN_TREES),
                        ),
                    )
                )
                stack.enter_context(
                    patch.object(
                        ci_lanes,
                        "lane_environment",
                        return_value=execution_environment,
                    )
                )
            return ci_lanes.collect_ci_lanes(self.root, **arguments)

    def test_all_lanes_pass(self) -> None:
        result = self.collect()
        document = result["document"]
        self.assertEqual(result["failures"], [])
        self.assertEqual(document["schema_version"], 2)
        self.assertEqual(document["document"], ci_lanes.LANE_DOCUMENT_KIND)
        self.assertEqual(document["toolchain_sha256"], TOOLCHAIN)
        self.assertEqual(document["release_source_sha256"], SOURCE)
        self.assertEqual(len(document["lanes"]), len(REQUIRED_CI_LANES))
        for lane in document["lanes"]:
            self.assertEqual(set(lane), set(ci_lanes.DOCUMENT_LANE_FIELDS))
            self.assertEqual(lane["commit"], COMMIT)
            self.assertEqual(lane["release_source_sha256"], SOURCE)
            self.assertEqual(lane["toolchain_sha256"], TOOLCHAIN)
            self.assertEqual(lane["status"], "passed")

    def test_all_passing_lanes_reverify_the_libbox_reproduction(self) -> None:
        calls = []

        def verify(repository, artifact, pins, toolchain_trees):
            calls.append((repository, artifact, pins, toolchain_trees))
            return "f" * 64

        self.collect(reproduction_verifier=verify)

        self.assertEqual(len(calls), 2)
        repository, artifact, _pins, toolchain_trees = calls[0]
        self.assertEqual(repository, self.root)
        self.assertEqual(artifact, self.root / ci_lanes.DEFAULT_LIBBOX_OUTPUT)
        self.assertEqual(toolchain_trees, TOOLCHAIN_TREES)
        self.assertEqual(calls[1], calls[0])

    def test_reproduction_failure_does_not_publish_lane_records_or_output(self) -> None:
        def reject(*_arguments):
            raise PublicationError("Libbox reproduction failed")

        with self.assertRaisesRegex(PublicationError, "reproduction failed"):
            self.collect(reproduction_verifier=reject)

        journal = self.root / "evidence" / "journal"
        self.assertEqual(list(journal.glob("*.json")), [])
        self.assertFalse(
            (self.root / "evidence" / "unsigned-ci-lanes.json").exists()
        )
        retained = journal / "attempt-0001"
        result = json.loads((retained / "result.json").read_bytes())
        self.assertEqual(result["outcome"], "verification-failed")
        self.assertEqual(result["phase"], "reproduction")
        self.assertEqual(set(result["records"]), set(REQUIRED_CI_LANES))
        self.assertTrue((retained / "rust-test.log").is_file())

    def test_reproduction_drift_blocks_the_final_document(self) -> None:
        digests = iter(("f" * 64, "e" * 64))

        def drift(*_arguments):
            return next(digests)

        with self.assertRaisesRegex(
            PublicationError, "changed while CI evidence"
        ):
            self.collect(reproduction_verifier=drift)

        self.assertFalse(
            (self.root / "evidence" / "unsigned-ci-lanes.json").exists()
        )
        attempt = self.root / "evidence/journal/attempt-0001"
        retained = json.loads((attempt / "result.json").read_bytes())
        self.assertEqual(retained["outcome"], "verification-failed")
        self.assertEqual(retained["observed_reproduction_sha256s"], ["f" * 64, "e" * 64])
        self.assertIsNone(retained["reproduction_sha256"])
        ran = []

        def run(_repository, lane, _environment):
            ran.append(lane.identifier)
            return b"fresh verification", 0, False, 0.5

        self.collect(runner=run)
        self.assertEqual(ran, [lane.identifier for lane in ci_lanes.LANES])

    def test_failed_lane_does_not_claim_a_libbox_reproduction(self) -> None:
        def reject(*_arguments):
            raise AssertionError("failed lane set must not claim reproduction")

        result = self.collect(
            {"libbox-build": (1, False)}, reproduction_verifier=reject
        )
        self.assertEqual(result["failures"], ["libbox-build"])

    def test_a_failing_lane_is_reported_not_masked(self) -> None:
        result = self.collect({"rust-test": (101, False), "node-audit": (1, False)})
        self.assertEqual(result["failures"], ["node-audit", "rust-test"])
        statuses = {lane["id"]: (lane["status"], lane["exit_code"]) for lane in result["document"]["lanes"]}
        self.assertEqual(statuses["rust-test"], ("failed", 101))
        self.assertEqual(statuses["node-audit"], ("failed", 1))
        self.assertIsNone(result["output"])
        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())
        self.assertTrue((Path(result["attempt"]) / "document.json").is_file())

    def test_a_timed_out_lane_is_reported_as_timeout(self) -> None:
        result = self.collect({"xcode-analyze": (None, True)})
        self.assertEqual(result["failures"], ["xcode-analyze"])
        statuses = {lane["id"]: (lane["status"], lane["exit_code"]) for lane in result["document"]["lanes"]}
        self.assertEqual(statuses["xcode-analyze"], ("timeout", 124))

    def test_an_incomplete_lane_set_is_refused(self) -> None:
        with self.assertRaisesRegex(PublicationError, "missing"):
            self.collect(only=frozenset({"rust-fmt"}))
        self.assertFalse((self.root / "evidence" / "unsigned-ci-lanes.json").exists())
        attempt = self.root / "evidence/journal/attempt-0001"
        result = json.loads((attempt / "result.json").read_bytes())
        self.assertEqual(result["outcome"], "partial")
        self.assertEqual(set(result["records"]), {"rust-fmt"})
        ran = []

        def run(_repository, lane, _environment):
            ran.append(lane.identifier)
            return b"remaining lane", 0, False, 0.5

        completed = self.collect(runner=run)
        self.assertEqual(completed["failures"], [])
        self.assertEqual(set(ran), set(REQUIRED_CI_LANES) - {"rust-fmt"})

    def test_rerun_retains_failed_attempt_and_promotes_only_passing_document(self) -> None:
        first = self.collect({"rust-fmt": (2, False)})
        self.assertEqual(first["failures"], ["rust-fmt"])
        self.assertIsNone(first["output"])
        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())
        first_attempt = Path(first["attempt"])
        before = {path.name: path.read_bytes() for path in first_attempt.iterdir()}
        ran = []

        def run(_repository, lane, _environment):
            ran.append(lane.identifier)
            return b"passing retry", 0, False, 0.5

        second = self.collect(rerun=frozenset({"rust-fmt"}), runner=run)
        self.assertEqual(second["failures"], [])
        self.assertEqual(ran, ["rust-fmt"])
        self.assertEqual(second["records"]["rust-fmt"]["exit_code"], 0)
        self.assertEqual({path.name: path.read_bytes() for path in first_attempt.iterdir()}, before)
        second_attempt = Path(second["attempt"])
        result = json.loads((second_attempt / "result.json").read_bytes())
        self.assertEqual(result["selected"]["rust-fmt"]["attempt_number"], 2)
        self.assertEqual(result["selected"]["rust-test"]["attempt_number"], 1)
        self.assertEqual(Path(second["output"]).read_bytes(), (second_attempt / "document.json").read_bytes())

    def test_an_existing_record_is_never_replaced(self) -> None:
        self.collect()
        with self.assertRaisesRegex(PublicationError, "refusing to replace"):
            self.collect()

    def test_production_toolchain_drift_is_rejected_before_document_write(self) -> None:
        execution_environment = {
            "HOME": "/Users/release",
            "PATH": "/fixed/rust:/usr/bin:/bin",
            "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
        }
        trees = {"managed": "e" * 64}
        initial_identity = {
            "document": ci_lanes.TOOLCHAIN_BINDING_KIND,
            "fixture": True,
            "release_tree_sha256": trees,
        }
        ending_identity = {**initial_identity, "resolved": {"rustc": "drifted"}}
        with (
            patch.object(
                ci_lanes,
                "release_tool_environment",
                return_value=execution_environment,
            ),
            patch.object(
                ci_lanes,
                "derive_toolchain_binding",
                side_effect=(
                    (TOOLCHAIN, initial_identity),
                    ("d" * 64, ending_identity),
                ),
            ) as derive,
            patch.object(
                ci_lanes,
                "verified_release_toolchain_trees",
                return_value=(self.root / "target/toolchains", trees),
            ) as verify,
            patch.object(
                ci_lanes,
                "lane_environment",
                return_value=execution_environment,
            ) as lane_environment,
        ):
            with self.assertRaisesRegex(
                PublicationError, "changed while CI lanes were executing"
            ):
                self.collect(toolchain=None)

        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())
        journal = self.root / "evidence/journal"
        self.assertFalse((journal / "toolchain-binding.json").exists())
        self.assertEqual(list(journal.glob(".ci-lane-attempt.*")), [])
        for lane in ci_lanes.LANES:
            self.assertFalse((journal / f"{lane.identifier}.json").exists())
            self.assertFalse((journal / f"{lane.identifier}.log").exists())
        self.assertEqual(derive.call_count, 2)
        for call in derive.call_args_list:
            self.assertIs(call.kwargs["release_environment"], execution_environment)
        self.assertEqual(verify.call_count, 2)
        for call in verify.call_args_list:
            self.assertIs(call.kwargs["environment"], execution_environment)
        self.assertTrue(lane_environment.called)
        for call in lane_environment.call_args_list:
            self.assertIs(call.kwargs["release_environment"], execution_environment)

        recovered_runs: list[str] = []

        def recovered_runner(_repository, lane, _environment):
            recovered_runs.append(lane.identifier)
            return (f"recovered {lane.identifier}".encode(), 0, False, 0.5)

        with (
            patch.object(
                ci_lanes,
                "release_tool_environment",
                return_value=execution_environment,
            ),
            patch.object(
                ci_lanes,
                "derive_toolchain_binding",
                return_value=(TOOLCHAIN, initial_identity),
            ),
            patch.object(
                ci_lanes,
                "verified_release_toolchain_trees",
                return_value=(self.root / "target/toolchains", trees),
            ),
            patch.object(
                ci_lanes,
                "lane_environment",
                return_value=execution_environment,
            ),
        ):
            recovered = self.collect(toolchain=None, runner=recovered_runner)

        self.assertEqual(recovered["failures"], [])
        self.assertEqual(recovered_runs, [lane.identifier for lane in ci_lanes.LANES])

    def test_policy_tool_mode_drift_is_revalidated_before_publication(self) -> None:
        execution_environment = {
            "HOME": "/Users/release",
            "PATH": "/fixed/rust:/usr/bin:/bin",
            "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
        }
        identity = {
            "document": ci_lanes.TOOLCHAIN_BINDING_KIND,
            "fixture": True,
            "release_tree_sha256": TOOLCHAIN_TREES,
        }
        policy_tool = self.root / "policy-tool"
        policy_tool.write_text("fixture", encoding="utf-8")
        policy_tool.chmod(0o700)
        environment_calls = 0

        def revalidate_environment(_repository, _pins, source_environment=None):
            nonlocal environment_calls
            environment_calls += 1
            if source_environment is not None and policy_tool.stat().st_mode & 0o777 != 0o700:
                raise PublicationError("release policy-tool mode is unsafe")
            return execution_environment

        def drifting_runner(_repository, lane, _environment):
            if lane.identifier == ci_lanes.LANES[0].identifier:
                policy_tool.chmod(0o755)
            return (f"output for {lane.identifier}".encode(), 0, False, 0.5)

        with (
            patch.object(
                ci_lanes,
                "release_tool_environment",
                side_effect=revalidate_environment,
            ),
            patch.object(
                ci_lanes,
                "derive_toolchain_binding",
                return_value=(TOOLCHAIN, identity),
            ),
            patch.object(
                ci_lanes,
                "verified_release_toolchain_trees",
                return_value=(self.root / "target/toolchains", TOOLCHAIN_TREES),
            ),
            patch.object(
                ci_lanes,
                "lane_environment",
                return_value=execution_environment,
            ),
            self.assertRaisesRegex(
                PublicationError,
                "release tool environment changed while CI lanes were executing",
            ),
        ):
            self.collect(toolchain=None, runner=drifting_runner)

        self.assertEqual(environment_calls, 2)
        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())
        self.assertFalse((self.root / "evidence/journal/toolchain-binding.json").exists())

    def test_source_drift_retains_attempt_and_recovery_reruns_every_lane(self) -> None:
        changed = {
            "repositoryCommit": COMMIT,
            "releaseSourceSha256": "d" * 64,
        }
        first_runs: list[str] = []

        def drifting_runner(_repository, lane, _environment):
            first_runs.append(lane.identifier)
            return (f"first {lane.identifier}".encode(), 0, False, 0.5)

        with self.assertRaisesRegex(PublicationError, "release source changed"):
            self.collect(
                runner=drifting_runner,
                source_identities=[
                    {"repositoryCommit": COMMIT, "releaseSourceSha256": SOURCE},
                    changed,
                ],
            )

        self.assertEqual(first_runs, [lane.identifier for lane in ci_lanes.LANES])
        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())
        journal = self.root / "evidence/journal"
        self.assertFalse((journal / "toolchain-binding.json").exists())
        for lane in ci_lanes.LANES:
            self.assertFalse((journal / f"{lane.identifier}.json").exists())
            self.assertFalse((journal / f"{lane.identifier}.log").exists())
        attempt = journal / "attempt-0001"
        before = {path.name: path.read_bytes() for path in attempt.iterdir()}
        terminal = json.loads(before["result.json"])
        self.assertEqual((terminal["outcome"], terminal["phase"]), ("verification-failed", "source"))
        self.assertEqual(set(terminal["records"]), set(REQUIRED_CI_LANES))

        recovered_runs: list[str] = []

        def recovered_runner(_repository, lane, _environment):
            recovered_runs.append(lane.identifier)
            return (f"recovered {lane.identifier}".encode(), 0, False, 0.5)

        result = self.collect(runner=recovered_runner)
        self.assertEqual(result["failures"], [])
        self.assertEqual(recovered_runs, [lane.identifier for lane in ci_lanes.LANES])
        self.assertEqual({path.name: path.read_bytes() for path in attempt.iterdir()}, before)

    def test_production_toolchain_binding_passes_when_start_and_end_match(self) -> None:
        execution_environment = {
            "HOME": "/Users/release",
            "PATH": "/fixed/rust:/usr/bin:/bin",
            "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
        }
        trees = {"managed": "e" * 64}
        identity = {
            "document": ci_lanes.TOOLCHAIN_BINDING_KIND,
            "fixture": True,
            "release_tree_sha256": trees,
        }
        with (
            patch.object(
                ci_lanes,
                "release_tool_environment",
                return_value=execution_environment,
            ),
            patch.object(
                ci_lanes,
                "derive_toolchain_binding",
                return_value=(TOOLCHAIN, identity),
            ) as derive,
            patch.object(
                ci_lanes,
                "verified_release_toolchain_trees",
                return_value=(self.root / "target/toolchains", trees),
            ),
            patch.object(
                ci_lanes,
                "lane_environment",
                return_value=execution_environment,
            ),
        ):
            result = self.collect(toolchain=None)

        self.assertEqual(result["failures"], [])
        self.assertEqual(derive.call_count, 3)
        self.assertTrue((self.root / "evidence/unsigned-ci-lanes.json").is_file())

    def test_execution_toolchain_tree_drift_is_rejected(self) -> None:
        execution_environment = {
            "HOME": "/Users/release",
            "PATH": "/fixed/rust:/usr/bin:/bin",
            "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
        }
        initial_trees = {"managed": "e" * 64}
        changed_trees = {"managed": "f" * 64}
        identity = {
            "document": ci_lanes.TOOLCHAIN_BINDING_KIND,
            "fixture": True,
            "release_tree_sha256": initial_trees,
        }
        with (
            patch.object(
                ci_lanes,
                "release_tool_environment",
                return_value=execution_environment,
            ),
            patch.object(
                ci_lanes,
                "derive_toolchain_binding",
                return_value=(TOOLCHAIN, identity),
            ),
            patch.object(
                ci_lanes,
                "verified_release_toolchain_trees",
                side_effect=(
                    (self.root / "target/toolchains", initial_trees),
                    (self.root / "target/toolchains", changed_trees),
                ),
            ),
            patch.object(
                ci_lanes,
                "lane_environment",
                return_value=execution_environment,
            ),
        ):
            with self.assertRaisesRegex(
                PublicationError, "changed while CI lanes were executing"
            ):
                self.collect(toolchain=None)

        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())

    def test_a_stale_journal_record_is_not_replayed(self) -> None:
        self.collect()
        (self.root / "evidence" / "unsigned-ci-lanes.json").unlink()
        journal = self.root / "evidence/journal/attempt-0001"
        record = json.loads((journal / "rust-fmt.json").read_text(encoding="utf-8"))
        record["commit"] = "c" * 40
        (journal / "rust-fmt.json").write_text(
            canonical_json(record).decode("utf-8"), encoding="utf-8"
        )
        with self.assertRaisesRegex(PublicationError, "differs from its bound result"):
            self.collect(assemble_only=True)

    def test_a_foreign_release_source_journal_record_is_not_replayed(self) -> None:
        self.collect()
        (self.root / "evidence" / "unsigned-ci-lanes.json").unlink()
        journal = self.root / "evidence/journal/attempt-0001"
        record = json.loads((journal / "rust-fmt.json").read_text(encoding="utf-8"))
        record["release_source_sha256"] = "d" * 64
        (journal / "rust-fmt.json").write_text(
            canonical_json(record).decode("utf-8"), encoding="utf-8"
        )
        with self.assertRaisesRegex(PublicationError, "differs from its bound result"):
            self.collect(assemble_only=True)

    def test_a_hand_edited_journal_status_is_rejected(self) -> None:
        self.collect({"rust-fmt": (7, False)})
        journal = self.root / "evidence/journal/attempt-0001"
        record = json.loads((journal / "rust-fmt.json").read_text(encoding="utf-8"))
        record["status"] = "passed"
        (journal / "rust-fmt.json").write_text(
            canonical_json(record).decode("utf-8"), encoding="utf-8"
        )
        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())
        with self.assertRaisesRegex(PublicationError, "does not match its exit code"):
            self.collect(assemble_only=True)

    def test_a_tampered_journal_log_is_rejected(self) -> None:
        self.collect()
        journal = self.root / "evidence/journal/attempt-0001"
        (journal / "rust-fmt.log").write_bytes(b"rewritten")
        (self.root / "evidence" / "unsigned-ci-lanes.json").unlink()
        with self.assertRaisesRegex(PublicationError, "log digest changed"):
            self.collect(assemble_only=True)

    def test_assemble_only_reuses_records_without_running(self) -> None:
        self.collect()
        (self.root / "evidence" / "unsigned-ci-lanes.json").unlink()

        def refuse(*_arguments):
            raise AssertionError("assemble-only must not run a lane")

        reproduction_calls = []

        def verify(*arguments):
            reproduction_calls.append(arguments)
            return "f" * 64

        result = self.collect(
            runner=refuse,
            assemble_only=True,
            reproduction_verifier=verify,
        )
        self.assertEqual(result["failures"], [])
        self.assertEqual(len(reproduction_calls), 2)

    def test_unknown_lane_selection_is_refused(self) -> None:
        with self.assertRaisesRegex(PublicationError, "unknown unsigned CI lane"):
            self.collect(only=frozenset({"not-a-lane"}))

    def test_runner_failure_retains_prior_output_and_cannot_seed_a_retry(self) -> None:
        ran = []

        def interrupted(_repository, lane, _environment):
            ran.append(lane.identifier)
            if lane.identifier == "rust-fmt":
                raise PublicationError("lane process boundary failed")
            return b"retained process output", 0, False, 0.5

        with self.assertRaisesRegex(PublicationError, "process boundary failed"):
            self.collect(runner=interrupted)
        attempt = self.root / "evidence/journal/attempt-0001"
        before = {path.name: path.read_bytes() for path in attempt.iterdir()}
        result = json.loads(before["result.json"])
        self.assertEqual((result["outcome"], result["phase"]), ("verification-failed", "lanes"))
        self.assertEqual(set(result["records"]), set(ran) - {"rust-fmt"})
        self.assertEqual(before["build-script-boundary.log"], b"retained process output")
        repeated = []

        def retry(_repository, lane, _environment):
            repeated.append(lane.identifier)
            return b"retry output", 0, False, 0.5

        self.collect(runner=retry)
        self.assertEqual(repeated, [lane.identifier for lane in ci_lanes.LANES])
        self.assertEqual({path.name: path.read_bytes() for path in attempt.iterdir()}, before)

    def test_incomplete_attempt_is_rejected_without_starting_another(self) -> None:
        first = self.collect({"rust-fmt": (1, False)})
        attempt = Path(first["attempt"])
        (attempt / "result.json").unlink()
        before = {path.name: path.read_bytes() for path in attempt.iterdir()}
        runner = Mock(side_effect=AssertionError("incomplete evidence must block execution"))
        with self.assertRaisesRegex(PublicationError, "is incomplete"):
            self.collect(runner=runner)
        runner.assert_not_called()
        self.assertFalse((attempt.parent / "attempt-0002").exists())
        self.assertEqual({path.name: path.read_bytes() for path in attempt.iterdir()}, before)

    def test_unknown_journal_entry_is_rejected_before_execution(self) -> None:
        journal = self.root / "evidence/journal"
        journal.mkdir()
        (journal / "unclassified.json").write_text("{}\n", encoding="utf-8")
        runner = Mock()
        with self.assertRaisesRegex(PublicationError, "unknown entry"):
            self.collect(runner=runner)
        runner.assert_not_called()
        self.assertFalse((journal / "attempt-0001").exists())

    def test_a_malformed_attempt_outcome_raises_a_domain_error(self) -> None:
        first = self.collect({"rust-fmt": (1, False)})
        path = Path(first["attempt"]) / "result.json"
        result = json.loads(path.read_bytes())
        result["outcome"] = []
        path.write_bytes(canonical_json(result))
        with self.assertRaisesRegex(PublicationError, "unexpected shape"):
            self.collect()

    def test_a_tampered_attempt_toolchain_binding_is_rejected(self) -> None:
        first = self.collect({"rust-fmt": (1, False)})
        path = Path(first["attempt"]) / "toolchain-binding.json"
        path.write_bytes(canonical_json({"changed": True}))
        with self.assertRaisesRegex(PublicationError, "toolchain binding changed"):
            self.collect()

    def test_verification_failed_records_cannot_be_selected_by_a_later_intent(self) -> None:
        with self.assertRaisesRegex(PublicationError, "reproduction failed"):
            self.collect(reproduction_verifier=Mock(side_effect=PublicationError("reproduction failed")))
        with self.assertRaisesRegex(PublicationError, "records are missing"):
            self.collect(only=frozenset({"rust-fmt"}))
        journal = self.root / "evidence/journal"
        failed = json.loads((journal / "attempt-0001/result.json").read_bytes())
        path = journal / "attempt-0002/intent.json"
        intent = json.loads(path.read_bytes())
        intent["selected"]["rust-test"] = {
            "attempt_number": 1,
            "record_sha256": failed["records"]["rust-test"],
        }
        path.write_bytes(canonical_json(intent))
        with self.assertRaisesRegex(PublicationError, "does not match an immutable record"):
            self.collect()

    def test_legacy_records_seed_forward_attempts_without_any_rewrite(self) -> None:
        legacy = self.root / "evidence/legacy-journal"
        legacy.mkdir()
        binding = canonical_json(IDENTITY)
        (legacy / "toolchain-binding.json").write_bytes(binding)
        for lane in ci_lanes.LANES:
            record = ci_lanes.record_lane(lane, COMMIT, SOURCE, TOOLCHAIN, b"legacy output", 0, False, 0.5, 1)
            ci_lanes.write_journal_record(legacy, lane, record, b"legacy output")
        before = {path.name: path.read_bytes() for path in legacy.iterdir()}
        runner = Mock(side_effect=AssertionError("legacy replay must not execute lanes"))
        result = self.collect(journal=legacy, runner=runner, assemble_only=True)
        runner.assert_not_called()
        self.assertEqual(result["failures"], [])
        self.assertEqual({name: (legacy / name).read_bytes() for name in before}, before)
        intent = json.loads((Path(result["attempt"]) / "intent.json").read_bytes())
        self.assertEqual({item["attempt_number"] for item in intent["selected"].values()}, {0})
        self.assertFalse((Path(result["attempt"]) / "rust-test.log").exists())

    def test_foreign_legacy_records_are_preserved_but_never_replayed(self) -> None:
        legacy = self.root / "evidence/legacy-journal"
        legacy.mkdir()
        (legacy / "toolchain-binding.json").write_bytes(canonical_json(IDENTITY))
        lane = ci_lanes.LANE_INDEX["rust-fmt"]
        record = ci_lanes.record_lane(lane, "e" * 40, SOURCE, TOOLCHAIN, b"legacy", 0, False, 0.5, 1)
        ci_lanes.write_journal_record(legacy, lane, record, b"legacy")
        before = (legacy / "rust-fmt.json").read_bytes()
        with self.assertRaisesRegex(PublicationError, "records are missing"):
            self.collect(journal=legacy, assemble_only=True)
        self.assertEqual((legacy / "rust-fmt.json").read_bytes(), before)
        result = json.loads((legacy / "attempt-0001/result.json").read_bytes())
        self.assertEqual(result["selected"], {})

    def test_promotion_interruption_recovers_the_same_pending_document(self) -> None:
        output = self.root / "evidence/unsigned-ci-lanes.json"
        promote = ci_lanes.promote_private_pending

        def interrupt(pending, destination):
            if destination == output:
                raise PublicationError("canonical publication interrupted")
            promote(pending, destination)

        with patch.object(ci_lanes, "promote_private_pending", side_effect=interrupt):
            with self.assertRaisesRegex(PublicationError, "publication interrupted"):
                self.collect()
        pending = output.with_name(f".{output.name}.pending")
        original = pending.read_bytes()
        first = self.root / "evidence/journal/attempt-0001"
        before = {path.name: path.read_bytes() for path in first.iterdir()}
        runner = Mock(side_effect=AssertionError("publication recovery must replay existing records"))
        result = self.collect(runner=runner)
        runner.assert_not_called()
        self.assertEqual(output.read_bytes(), original)
        self.assertEqual(result["failures"], [])
        self.assertFalse(pending.exists())
        self.assertEqual({path.name: path.read_bytes() for path in first.iterdir()}, before)

    def test_final_source_drift_retains_observations_without_publishing(self) -> None:
        original = {"repositoryCommit": COMMIT, "releaseSourceSha256": SOURCE}
        changed = {**original, "releaseSourceSha256": "d" * 64}
        with self.assertRaisesRegex(PublicationError, "source changed before"):
            self.collect(source_identities=[original, original, changed])
        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())
        result = json.loads((self.root / "evidence/journal/attempt-0001/result.json").read_bytes())
        self.assertEqual((result["outcome"], result["phase"]), ("verification-failed", "source"))
        self.assertEqual(result["observed_reproduction_sha256s"], ["f" * 64, "f" * 64])
        self.assertIsNone(result["reproduction_sha256"])

    def test_executor_source_drift_is_recorded_before_canonical_publication(self) -> None:
        executor = {"repositoryCommit": "d" * 40, "releaseSourceSha256": "e" * 64}
        check = Mock(side_effect=[None, PublicationError("executor source changed")])
        with self.assertRaisesRegex(PublicationError, "executor source changed"):
            self.collect(executor_source=executor, source_recheck=check)
        attempt = self.root / "evidence/journal/attempt-0001"
        result = json.loads((attempt / "result.json").read_bytes())
        self.assertEqual((result["outcome"], result["phase"]), ("verification-failed", "source"))
        self.assertEqual(json.loads((attempt / "intent.json").read_bytes())["executor_source"], executor)
        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())

    def test_an_existing_journal_file_and_binding_cannot_be_overwritten(self) -> None:
        first = self.collect({"rust-fmt": (1, False)})
        attempt = Path(first["attempt"])
        before = {path.name: path.read_bytes() for path in attempt.iterdir()}
        with self.assertRaisesRegex(PublicationError, "refusing to replace"):
            ci_lanes.write_journal_record(attempt, ci_lanes.LANE_INDEX["rust-fmt"], first["records"]["rust-fmt"], b"changed")
        with self.assertRaisesRegex(PublicationError, "immutable record"):
            ci_lanes._publish_toolchain_binding(attempt, {"changed": True})
        self.assertEqual({path.name: path.read_bytes() for path in attempt.iterdir()}, before)

    def test_canonical_output_cannot_enter_the_journal_namespace(self) -> None:
        with self.assertRaisesRegex(PublicationError, "outside its attempt journal"):
            self.collect(output=self.root / "evidence/journal/canonical.json")

    def test_source_drift_during_final_history_read_blocks_canonical_publication(self) -> None:
        read_history = ci_lanes._read_ci_history
        drifted = False
        completed_payload = None

        def source(*_arguments, **_keywords):
            return {"repositoryCommit": COMMIT, "releaseSourceSha256": "d" * 64 if drifted else SOURCE}

        def history(*arguments, **keywords):
            nonlocal drifted, completed_payload
            result = read_history(*arguments, **keywords)
            if keywords.get("active_attempt") is None and result.count == 1:
                completed_payload = (self.root / "evidence/journal/attempt-0001/result.json").read_bytes()
                drifted = True
            return result

        with patch.object(ci_lanes, "_read_ci_history", side_effect=history):
            with self.assertRaisesRegex(PublicationError, "source changed before canonical"):
                self.collect(source_identities=source)
        attempt = self.root / "evidence/journal/attempt-0001"
        self.assertEqual((attempt / "result.json").read_bytes(), completed_payload)
        failure = json.loads((attempt / "admission-failure.json").read_bytes())
        self.assertEqual(failure["code"], "source_admission_failed")
        self.assertEqual(failure["document_sha256"], hashlib.sha256((attempt / "document.json").read_bytes()).hexdigest())
        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())
        self.assertFalse((self.root / "evidence/.unsigned-ci-lanes.json.pending").exists())
        self.assertEqual(read_history(attempt.parent, COMMIT, SOURCE, TOOLCHAIN).selected, {})

    def test_toolchain_drift_during_final_history_read_blocks_canonical_publication(self) -> None:
        read_history = ci_lanes._read_ci_history

        def history(*arguments, **keywords):
            result = read_history(*arguments, **keywords)
            if keywords.get("active_attempt") is None and result.count == 1:
                changed = {**IDENTITY, "resolved": {"rustc": "changed"}}
                ci_lanes.derive_toolchain_binding.side_effect = [(ci_lanes.toolchain_sha256(changed), changed)]
            return result

        with patch.object(ci_lanes, "_read_ci_history", side_effect=history):
            with self.assertRaisesRegex(PublicationError, "toolchain changed before canonical"):
                self.collect()
        attempt = self.root / "evidence/journal/attempt-0001"
        failure = json.loads((attempt / "admission-failure.json").read_bytes())
        self.assertEqual(failure["code"], "toolchain_admission_failed")
        self.assertFalse((self.root / "evidence/unsigned-ci-lanes.json").exists())

    def test_symlink_ancestor_cannot_redirect_output_or_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary).resolve()
            (outside / "nested").mkdir()
            linked = self.root / "linked"
            linked.symlink_to(outside, target_is_directory=True)
            for override in (
                {"output": linked / "nested/lanes.json"},
                {"journal": linked / "nested/journal"},
            ):
                with self.subTest(override=override):
                    with self.assertRaisesRegex(PublicationError, "symlink ancestors"):
                        self.collect(**override)
            self.assertEqual(list((outside / "nested").iterdir()), [])

    def test_changed_command_cwd_and_timeout_keep_history_but_require_a_fresh_lane(self) -> None:
        first = self.collect()
        attempt = Path(first["attempt"])
        before = {path.name: path.read_bytes() for path in attempt.iterdir()}
        original = ci_lanes.LANE_INDEX["rust-fmt"]
        updates = (
            {"command": "./scripts/run_release_ci_gate.sh rust-fmt-updated"},
            {"cwd": "crates"},
            {"timeout": original.timeout + 1},
        )
        for number, updates_for_lane in enumerate(updates, start=2):
            with self.subTest(updates=updates_for_lane):
                changed = ci_lanes.Lane(
                    original.identifier,
                    updates_for_lane.get("command", original.command),
                    cwd=updates_for_lane.get("cwd", original.cwd),
                    timeout=updates_for_lane.get("timeout", original.timeout),
                )
                lanes = tuple(changed if lane.identifier == original.identifier else lane for lane in ci_lanes.LANES)
                ran = []

                def run(_repository, lane, _environment):
                    ran.append(lane)
                    return b"updated contract", 0, False, 0.5

                with (
                    patch.object(ci_lanes, "LANES", lanes),
                    patch.object(ci_lanes, "LANE_INDEX", {lane.identifier: lane for lane in lanes}),
                ):
                    self.collect(output=self.root / f"evidence/lanes-{number}.json", runner=run)
                self.assertEqual(ran, [changed])
        self.assertEqual({path.name: path.read_bytes() for path in attempt.iterdir()}, before)

    def test_binding_document_cannot_claim_an_unrelated_toolchain_digest(self) -> None:
        first = self.collect({"rust-fmt": (1, False)})
        attempt = Path(first["attempt"])
        unrelated = canonical_json({"document": ci_lanes.TOOLCHAIN_BINDING_KIND, "unrelated": True})
        (attempt / "toolchain-binding.json").write_bytes(unrelated)
        intent_path = attempt / "intent.json"
        intent = json.loads(intent_path.read_bytes())
        intent["toolchain_binding_sha256"] = hashlib.sha256(unrelated).hexdigest()
        intent_path.write_bytes(canonical_json(intent))
        with self.assertRaisesRegex(PublicationError, "toolchain binding changed"):
            self.collect()

    def test_injected_artifact_binding_is_used_at_every_admission_boundary(self) -> None:
        artifact_identity = {**IDENTITY, "resolved": {"node": "artifact-policy-1"}}
        artifact_digest = ci_lanes.toolchain_sha256(artifact_identity)
        self.assertNotEqual(artifact_digest, TOOLCHAIN)
        reader = Mock(return_value=(artifact_digest, artifact_identity))
        result = self.collect(binding_reader=reader)
        self.assertEqual(reader.call_count, 3)
        self.assertEqual(result["toolchain_sha256"], artifact_digest)
        self.assertEqual(result["toolchain_identity"], artifact_identity)
        for call in reader.call_args_list:
            self.assertEqual(call.args, (self.root,))
            self.assertEqual(call.kwargs["release_environment"]["PATH"], "/usr/bin:/bin")


class CiLaneCliTests(unittest.TestCase):
    def test_plain_collection_remains_independent_of_frozen_source_admission(self) -> None:
        from scripts import sealed_evidence_manifest as cli
        from scripts import release_executor_source as sources

        arguments = cli.parser().parse_args(["collect-ci-lanes", "--output", "result.json"])
        observed = {"repositoryCommit": COMMIT, "releaseSourceSha256": SOURCE}
        result = {"document": {"lanes": []}, "attempt": "attempt-0001", "toolchain_sha256": TOOLCHAIN, "failures": []}
        with (
            patch.object(cli, "_repository", return_value=Path("/source")),
            patch.object(cli, "current_identity", return_value=observed),
            patch.object(cli, "collect_ci_lanes", return_value=result) as collect,
            patch.object(sources, "capture_frozen_release_sources") as capture,
            redirect_stdout(io.StringIO()),
        ):
            cli.command_collect_ci_lanes(arguments)
        capture.assert_not_called()
        self.assertEqual(collect.call_args.args, (Path("/source"),))
        self.assertEqual(collect.call_args.kwargs["commit"], COMMIT)
        self.assertIsNone(collect.call_args.kwargs["executor_source"])
        self.assertIsNone(collect.call_args.kwargs["binding_reader"])

    def test_frozen_collection_keeps_artifact_commands_and_allows_owned_external_journal(self) -> None:
        from scripts import sealed_evidence_manifest as cli
        from scripts import release_executor_source as sources

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifact = root / "artifact"
            (artifact / "stage-inputs").mkdir(parents=True)
            external = root / "external-journal"
            binding = sources.FrozenReleaseSources(
                executor=sources.ExecutorSource(root, "d" * 40, "e" * 64),
                artifact=sources.ExecutorSource(artifact, COMMIT, SOURCE),
            )
            arguments = cli.parser().parse_args([
                "collect-ci-lanes", "--artifact-repository", str(artifact),
                "--output", "stage-inputs/lanes.json", "--journal", str(external),
            ])
            result = {"document": {"lanes": []}, "attempt": "attempt-0001", "toolchain_sha256": TOOLCHAIN, "failures": []}
            with (
                patch.object(cli, "_repository", return_value=root),
                patch.object(sources, "capture_frozen_release_sources", return_value=binding),
                patch.object(sources, "require_frozen_sources_unchanged") as check,
                patch.object(cli, "collect_ci_lanes", return_value=result) as collect,
                redirect_stdout(io.StringIO()),
            ):
                cli.command_collect_ci_lanes(arguments)
                collect.call_args.kwargs["source_recheck"]()
            self.assertEqual(collect.call_args.args, (artifact,))
            self.assertEqual(collect.call_args.kwargs["commit"], COMMIT)
            self.assertEqual(collect.call_args.kwargs["executor_source"], binding.executor.identity)
            self.assertEqual(collect.call_args.kwargs["output"], artifact / "stage-inputs/lanes.json")
            self.assertEqual(collect.call_args.kwargs["journal"], external)
            self.assertIs(collect.call_args.kwargs["binding_reader"], cli._read_artifact_ci_toolchain_binding)
            check.assert_called_once_with(binding)

    def test_artifact_query_error_is_translated_with_its_typed_cause(self) -> None:
        from scripts import sealed_evidence_manifest as cli

        cause = cli.ArtifactToolchainError("artifact_toolchain_verification_failed", "fixed policy failed", exit_code=7)
        with (
            patch.object(cli, "derive_artifact_ci_toolchain_binding", side_effect=cause),
            self.assertRaisesRegex(cli.PublicationError, "artifact_toolchain_verification_failed, exit=7") as raised,
        ):
            cli._read_artifact_ci_toolchain_binding(Path("/artifact"), {"PATH": "/usr/bin:/bin"})
        self.assertIs(raised.exception.__cause__, cause)

    def test_frozen_output_rejects_an_ancestor_link_before_collection(self) -> None:
        from scripts import sealed_evidence_manifest as cli
        from scripts import release_executor_source as sources

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifact = root / "artifact"
            artifact.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (artifact / "linked").symlink_to(outside, target_is_directory=True)
            binding = sources.FrozenReleaseSources(
                executor=sources.ExecutorSource(root, "d" * 40, "e" * 64),
                artifact=sources.ExecutorSource(artifact, COMMIT, SOURCE),
            )
            arguments = cli.parser().parse_args([
                "collect-ci-lanes", "--artifact-repository", str(artifact),
                "--output", "linked/lanes.json",
            ])
            with (
                patch.object(cli, "_repository", return_value=root),
                patch.object(sources, "capture_frozen_release_sources", return_value=binding),
                patch.object(cli, "collect_ci_lanes") as collect,
                self.assertRaisesRegex(cli.PublicationError, "not a real directory"),
            ):
                cli.command_collect_ci_lanes(arguments)
            collect.assert_not_called()
            self.assertEqual(list(outside.iterdir()), [])


class AssemblyTests(unittest.TestCase):
    def records(self) -> dict:
        return {
            lane: {
                "id": lane,
                "command": ci_lanes.LANE_INDEX[lane].command,
                "status": "passed",
                "exit_code": 0,
                "log_sha256": hashlib.sha256(lane.encode()).hexdigest(),
                "commit": COMMIT,
                "release_source_sha256": SOURCE,
                "toolchain_sha256": TOOLCHAIN,
            }
            for lane in REQUIRED_CI_LANES
        }

    def test_masked_pass_is_rejected_by_the_gate_validator(self) -> None:
        records = self.records()
        records["rust-test"]["exit_code"] = 1
        with self.assertRaisesRegex(PublicationError, "masks a nonzero exit status"):
            ci_lanes.assemble_document(records, COMMIT, SOURCE, TOOLCHAIN)

    def test_foreign_commit_is_rejected(self) -> None:
        records = self.records()
        records["rust-test"]["commit"] = "d" * 40
        with self.assertRaisesRegex(PublicationError, "different commit"):
            ci_lanes.assemble_document(records, COMMIT, SOURCE, TOOLCHAIN)

    def test_foreign_toolchain_is_rejected(self) -> None:
        records = self.records()
        records["rust-test"]["toolchain_sha256"] = "e" * 64
        with self.assertRaisesRegex(PublicationError, "different toolchain"):
            ci_lanes.assemble_document(records, COMMIT, SOURCE, TOOLCHAIN)

    def test_foreign_release_source_is_rejected(self) -> None:
        records = self.records()
        records["rust-test"]["release_source_sha256"] = "e" * 64
        with self.assertRaisesRegex(PublicationError, "release source"):
            ci_lanes.assemble_document(records, COMMIT, SOURCE, TOOLCHAIN)

    def test_missing_lane_is_rejected(self) -> None:
        records = self.records()
        del records["shellcheck"]
        with self.assertRaisesRegex(PublicationError, "missing"):
            ci_lanes.assemble_document(records, COMMIT, SOURCE, TOOLCHAIN)


if __name__ == "__main__":
    unittest.main()
