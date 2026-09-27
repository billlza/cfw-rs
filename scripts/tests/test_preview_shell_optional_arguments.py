from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.release_build_identity import SIGNED_PREVIEW_IDENTITY

REPOSITORY = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get("CFW_SHELL_DISPATCH_SOURCE_ROOT", str(REPOSITORY))).resolve()
EVIDENCE = os.environ.get("CFW_SHELL_DISPATCH_EVIDENCE")

RECORDER = '''import json, os, pathlib, sys
kind, *arguments = sys.argv[1:]
root = pathlib.Path(os.environ["CFW_FIXTURE_ROOT"])
with (root / "events.jsonl").open("a") as output:
    output.write(json.dumps({"kind": kind, "argv": arguments}) + "\\n")
if kind == "python":
    name = pathlib.Path(arguments[1]).name
    if name == "repository_source_identity.py":
        print("a" * 40, "b" * 64)
    elif name == "candidate_artifact_binding.py":
        print(" ".join(["d" * 64] * 9))
    elif name == "hash_artifact.py":
        output = pathlib.Path(arguments[arguments.index("--output") + 1])
        if not output.is_relative_to(root):
            raise SystemExit("fixture write escaped temporary repository")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text('{"fixture": "argv recording only, not an application manifest"}\\n')
    elif name not in {"verify_version_contract.py", "verify_artifact_manifest.py", "native_ui_artifact.py"}:
        raise SystemExit("unexpected Python boundary: " + name)
    if name == os.environ.get("CFW_FIXTURE_FAIL_SCRIPT"):
        raise SystemExit(37)
'''

HELPERS = '''cfw_fixture_record() {
  "$CFW_FIXTURE_PYTHON" "$CFW_FIXTURE_ROOT/record.py" "$@"
}
cfw_seal_release_tool_environment() {
  cfw_fixture_record seal "$@" "flags=$-"
  export CFW_RELEASE_PYTHON_EXECUTABLE="$CFW_FIXTURE_PYTHON"
}
cfw_select_release_apple_toolchain() { cfw_fixture_record select-apple; }
cfw_require_supported_python() { cfw_fixture_record supported-python "$@"; }
cfw_verify_node_toolchain_tree() { cfw_fixture_record node-tree "$@"; }
cfw_verify_tauri_toolchain_tree() { cfw_fixture_record tauri-tree "$@"; }
cfw_verify_ui_dependencies_tree() { printf '%s\\n' "$CFW_FIXTURE_DIGEST"; }
cfw_run_release_python_script() { cfw_fixture_record python "$@"; }
cfw_create_release_cargo_runtime() { printf '%s/fixture-cargo-home\\n' "$CFW_FIXTURE_ROOT"; }
cfw_verify_release_cargo_runtime() { cfw_fixture_record cargo-verify "$@"; }
cfw_remove_release_cargo_runtime() { cfw_fixture_record cargo-remove "$@"; }
cfw_build_tauri_host_skeleton() { cfw_fixture_record tauri "$@"; }
libbox_verify_xcframework_artifact() { cfw_fixture_record libbox "$@"; }
rustc() { printf 'rustc 1.98.1 (fixture)\\n'; }
function /usr/bin/xcodebuild { printf 'Xcode 27.0\\nBuild version 27A266a\\n'; }
'''


class PreviewShellOptionalArgumentsTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="cfm-shell-argv-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        scripts = root / "scripts"
        scripts.mkdir()
        for name in ("build_native_ui.sh", "build_unsigned_candidate.sh"):
            shutil.copy2(SOURCE / "scripts" / name, scripts / name)
        (root / "record.py").write_text(RECORDER)
        (scripts / "release_tool_environment.sh").write_text(HELPERS)
        for name in ("release_toolchain_contract.sh", "libbox_source_contract.sh", "ui_dependency_contract.sh", "tauri_host_skeleton.sh"):
            (scripts / name).write_text("# Fixture functions are supplied by release_tool_environment.sh.\n")
        (scripts / "dependency_pins.env").write_text(
            "XCODE_VERSION=27.0\nXCODE_BUILD_VERSION=27A266a\nRUST_VERSION=1.98.1\n"
            "NODE_VERSION=26.8.2\nTAURI_CLI_VERSION=2.11.4\nMACOS_DEPLOYMENT_TARGET=15.0\n"
        )
        for name in ("build_native_products.sh", "build_legacy_tombstone.sh", "build_ui_with_pinned_node.sh",
                     "verify_candidate_bundle.sh", "verify_xcode_project.sh"):
            path = scripts / name
            path.write_text('#!/bin/bash -p\nset -euo pipefail\nexec "$CFW_FIXTURE_PYTHON" "$CFW_FIXTURE_ROOT/record.py" external "$0" "$@"\n')
            path.chmod(0o755)
        for relative, version in (("node-26.8.2/bin/node", "v26.8.2"), ("tauri-cli-2.11.4/bin/cargo-tauri", "tauri-cli 2.11.4")):
            path = root / "target/toolchains" / relative
            path.parent.mkdir(parents=True)
            path.write_text('#!/bin/bash -p\nset -euo pipefail\n[[ "$#" == 1 && "$1" == --version ]] || exit 97\nprintf \'%s\\n\' ' + repr(version) + '\n')
            path.chmod(0o755)
        (root / "apps/cfw-tauri-shell/node_modules").mkdir(parents=True)
        return root

    def run_script(self, case: str, root: Path, script: str, arguments=(), *, unsigned=False, fail_script=None):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("CFW_") and key not in {"BASH_ENV", "ENV"}}
        environment.update({
            "CFW_FIXTURE_ROOT": str(root), "CFW_FIXTURE_PYTHON": sys.executable,
            "CFW_FIXTURE_DIGEST": "d" * 64,
            "CFW_NATIVE_PRODUCTS_OUTPUT": str(root / "fixture-native-products"),
            "CFW_BUILD_NUMBER": "50000" if unsigned else SIGNED_PREVIEW_IDENTITY.build_number,
        })
        if unsigned:
            environment["CFW_UNSIGNED_VALIDATION_PYTHON"] = sys.executable
        if fail_script:
            environment["CFW_FIXTURE_FAIL_SCRIPT"] = fail_script
        result = subprocess.run(["/bin/bash", "-p", "-e", "-u", "-o", "pipefail", str(root / "scripts" / script), *arguments],
                                env=environment, capture_output=True, text=True, check=False, timeout=30)
        events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()] if (root / "events.jsonl").exists() else []
        if EVIDENCE:
            destination = Path(EVIDENCE)
            destination.mkdir(parents=True, exist_ok=True)
            with (destination / (case + ".json")).open("x") as output:
                json.dump({"scope": "temporary shell dispatch fixture; external build and verification tools replaced by argv recorders",
                           "root": str(root), "argv": result.args, "exit": result.returncode,
                           "stdout": result.stdout, "stderr": result.stderr, "events": events}, output, indent=2)
                output.write("\n")
        return result, events

    def assert_strict_shell(self, events):
        for event in events:
            if event["kind"] == "seal":
                flags = event["argv"][-1].removeprefix("flags=")
                self.assertIn("e", flags)
                self.assertIn("u", flags)
                self.assertIn("p", flags)

    def test_native_ui_build_and_verify_keep_exact_optional_flag_argv(self):
        for operation in ("build", "verify"):
            for unsigned in (False, True):
                with self.subTest(operation=operation, unsigned=unsigned):
                    root = self.fixture()
                    arguments = (["--verify"] if operation == "verify" else []) + (["--unsigned-preview-validation"] if unsigned else [])
                    result, events = self.run_script(f"producer-{operation}-{unsigned}", root, "build_native_ui.sh", arguments, unsigned=unsigned)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assert_strict_shell(events)
                    expected = [str(root), str(root / "scripts/native_ui_artifact.py"), operation,
                                "--repository", str(root), "--products", str(root / "fixture-native-products"),
                                "--build-number", "50000" if unsigned else SIGNED_PREVIEW_IDENTITY.build_number]
                    if unsigned:
                        expected.append("--unsigned-preview-validation")
                    self.assertEqual([event["argv"] for event in events if event["kind"] == "python"], [expected])
                    self.assertEqual(events[0]["argv"][0], "unsigned-validation" if unsigned else "production")

    def test_unsigned_builder_modes_preserve_all_three_optional_argument_groups(self):
        for preview, validation_python in ((False, False), (False, True), (True, True)):
            with self.subTest(preview=preview, validation_python=validation_python):
                root = self.fixture()
                arguments = (["--preview-validation"] if preview else []) + (["--validation-python-executable", sys.executable] if validation_python else [])
                result, events = self.run_script(f"builder-{preview}-{validation_python}", root, "build_unsigned_candidate.sh", arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_strict_shell(events)
                python = [event["argv"] for event in events if event["kind"] == "python"]
                calls = lambda name: [call for call in python if Path(call[1]).name == name]
                self.assertEqual(calls("verify_version_contract.py"), [[str(root), str(root / "scripts/verify_version_contract.py"), *(["--preview"] if preview else [])]])
                tauri = [event["argv"] for event in events if event["kind"] == "tauri"]
                self.assertEqual(len(tauri), 1)
                self.assertEqual(len(tauri[0]), 4 if preview else 3)
                self.assertEqual(tauri[0][:2], [str(root / "apps/cfw-tauri-shell"), str(root / "target/toolchains/tauri-cli-2.11.4/bin/cargo-tauri")])
                self.assertEqual(tauri[0][3:], ["--native-ui-unsigned-preview"] if preview else [])
                version, build = ("0.5.0", "50000") if preview else ("0.4.0", "40000")
                native = root / ("target/candidates/0.5.0/unsigned/50000/native-products" if preview else "target/candidates/0.4.0/unsigned/native-products")
                config = json.loads(tauri[0][2])["bundle"]["macOS"]
                self.assertEqual(config["bundleVersion"], build)
                self.assertEqual(len(config["files"]), 7 if preview else 5)
                if preview:
                    self.assertEqual(config["files"]["Frameworks/libCFMNativeDashboard.dylib"], str(native / "libCFMNativeDashboard.dylib"))
                kind = "unsigned-preview-application-validation-v1" if preview else "unsigned-application-validation-v1"
                metadata_groups = [("hash_artifact.py", 1), ("verify_artifact_manifest.py", 2)]
                for name, count in metadata_groups:
                    self.assertEqual(len(calls(name)), count)
                    for call in calls(name):
                        self.assertNotIn("", call)
                        metadata = [call[index + 1] for index, value in enumerate(call[:-1]) if value == "--metadata"]
                        self.assertEqual(metadata.count("version=" + version), 1)
                        self.assertEqual(metadata.count("artifactKind=" + kind), 1)
                        self.assertEqual(metadata.count("buildNumber=" + build), 1)
                        self.assertEqual([item for item in metadata if item.startswith("signingMode=")], ["signingMode=unsigned-validation"] if preview else [])
                        version_index = metadata.index("version=" + version)
                        if preview:
                            self.assertEqual(metadata[version_index + 1], "signingMode=unsigned-validation")
                identity_metadata = ["artifactKind=" + kind, "version=" + version]
                if preview:
                    identity_metadata.append("signingMode=unsigned-validation")
                shared_metadata = [
                    "buildNumber=" + build,
                    "cargoWorkspaceSourcesTreeSha256=" + "d" * 64,
                    "goModuleCacheTreeSha256=" + "d" * 64,
                    "goToolchainTreeSha256=" + "d" * 64,
                    "goToolsTreeSha256=" + "d" * 64,
                    "nodeToolchainTreeSha256=" + "d" * 64,
                    "releaseSourceSha256=" + "b" * 64,
                    "repositoryCommit=" + "a" * 40,
                    "tauriToolchainTreeSha256=" + "d" * 64,
                    "toolchainSha256=" + "d" * 64,
                    "uiDependenciesTreeSha256=" + "d" * 64,
                    "xcodegenToolchainTreeSha256=" + "d" * 64,
                ]
                metadata_argv = lambda items: [part for item in items for part in ("--metadata", item)]
                candidate = native.parent
                app = candidate / "cargo/release/bundle/macos/Clash for Mac.app"
                manifest = candidate / "Clash for Mac.app.manifest.json"
                bundle_calls = [event["argv"] for event in events
                                if event["kind"] == "external"
                                and Path(event["argv"][0]).name == "verify_candidate_bundle.sh"]
                expected_context = "unsigned-preview-host" if preview else "unsigned-host"
                self.assertEqual(bundle_calls, [[str(root / "scripts/verify_candidate_bundle.sh"),
                                                str(app), str(native), "--context", expected_context]] * 2)
                expected_hash_metadata = [identity_metadata[0], "architecture=arm64", shared_metadata[0],
                                          "deploymentTarget=15.0", *shared_metadata[1:], *identity_metadata[1:]]
                self.assertEqual(calls("hash_artifact.py"), [[str(root), str(root / "scripts/hash_artifact.py"), str(app),
                                                             "--output", str(manifest), *metadata_argv(expected_hash_metadata)]])
                verify_prefix = [str(root), str(root / "scripts/verify_artifact_manifest.py"), str(app), str(manifest)]
                self.assertEqual(calls("verify_artifact_manifest.py"), [
                    [*verify_prefix, *metadata_argv(identity_metadata + shared_metadata)],
                    [*verify_prefix, *metadata_argv(identity_metadata + [shared_metadata[0], "releaseSourceSha256=" + "b" * 64,
                                                                       "repositoryCommit=" + "a" * 40])],
                ])
                binding = [str(root), str(root / "scripts/candidate_artifact_binding.py"), "--repository", str(root)]
                if validation_python:
                    binding.append("--unsigned-validation-toolchain")
                self.assertEqual(calls("candidate_artifact_binding.py"), [binding, binding])

    def test_dispatched_failure_remains_fatal_and_does_not_run_later_stages(self):
        for script, failure in (("build_native_ui.sh", "native_ui_artifact.py"), ("build_unsigned_candidate.sh", "verify_version_contract.py")):
            with self.subTest(script=script):
                root = self.fixture()
                result, events = self.run_script("failure-" + script, root, script, fail_script=failure)
                self.assertEqual(result.returncode, 37, result.stderr)
                self.assertFalse(any(event["kind"] == "tauri" for event in events))
                self.assert_strict_shell(events)


if __name__ == "__main__":
    unittest.main()
