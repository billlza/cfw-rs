#!/usr/bin/env python3
"""Fail-closed tests for release-managed toolchain trees."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.publication.common import PublicationError
from scripts.publication.ci_lanes import Lane, lane_environment, release_tool_environment
from scripts.publication.release_toolchains import verified_release_toolchain_trees


SCRIPTS = Path(__file__).resolve().parent.parent
REPOSITORY = SCRIPTS.parent
HASH = SCRIPTS / "hash_artifact.py"
VERIFY = SCRIPTS / "verify_artifact_manifest.py"
PINS = SCRIPTS / "dependency_pins.env"
CONTRACT = SCRIPTS / "release_toolchain_contract.sh"


def _pins() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in PINS.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value
    return result


class TreeManifestV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "tool"
        (self.root / "bin").mkdir(parents=True)
        self.binary = self.root / "bin/tool"
        self.binary.write_text("original\n", encoding="utf-8")
        self.binary.chmod(0o755)
        (self.root / "share").mkdir()
        (self.root / "share/data").write_text("payload\n", encoding="utf-8")
        (self.root / "current").symlink_to("share/data")
        self.manifest = Path(self.temporary.name) / "tool.manifest.json"
        self.generate()

    def generate(self) -> None:
        subprocess.run(
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
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def verify(self, *extra: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
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
                *extra,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def assert_rejected(self) -> None:
        self.assertNotEqual(self.verify().returncode, 0)

    def test_unchanged_tree_is_accepted(self) -> None:
        self.assertEqual(self.verify().returncode, 0)

    def test_verified_entry_is_printed_as_canonical_json(self) -> None:
        completed = self.verify("--print-entry", "bin/tool")
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        entry = next(
            item for item in manifest["entries"] if item["path"] == "bin/tool"
        )
        expected = (
            json.dumps(
                entry,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
        self.assertEqual(completed.stdout, expected)
        self.assertEqual(completed.stderr, b"")

    def test_print_entry_rejects_missing_noncanonical_and_competing_output(self) -> None:
        for arguments in (
            ("--print-entry", "bin/missing"),
            ("--print-entry", "bin/../bin/tool"),
            ("--print-entry", "/bin/tool"),
            ("--print-entry", "bin/tool", "--print-tree-sha256"),
        ):
            with self.subTest(arguments=arguments):
                self.assertNotEqual(self.verify(*arguments).returncode, 0)

    def test_content_addition_deletion_and_mode_changes_are_rejected(self) -> None:
        mutations = (
            (
                lambda: self.binary.write_text("changed\n", encoding="utf-8"),
                lambda: self.binary.write_text("original\n", encoding="utf-8"),
            ),
            (
                lambda: (self.root / "extra").write_text("extra\n", encoding="utf-8"),
                lambda: (self.root / "extra").unlink(),
            ),
            (
                lambda: (self.root / "share/data").unlink(),
                lambda: (self.root / "share/data").write_text("payload\n", encoding="utf-8"),
            ),
            (lambda: self.binary.chmod(0o700), lambda: self.binary.chmod(0o755)),
            (
                lambda: (self.root / "share").chmod(0o700),
                lambda: (self.root / "share").chmod(0o755),
            ),
            (lambda: self.root.chmod(0o700), lambda: self.root.chmod(0o755)),
        )
        for mutation, restore in mutations:
            with self.subTest(mutation=mutation):
                mutation()
                self.assert_rejected()
                restore()
                self.assertEqual(self.verify().returncode, 0)

    def test_symlink_target_and_root_symlink_are_rejected(self) -> None:
        (self.root / "current").unlink()
        (self.root / "current").symlink_to("bin/tool")
        self.assert_rejected()

        link = Path(self.temporary.name) / "linked-root"
        link.symlink_to(self.root, target_is_directory=True)
        completed = subprocess.run(
            [sys.executable, "-B", str(HASH), str(link), "--algorithm", "sha256-tree-v2"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(completed.returncode, 0)

    def test_hardlinked_member_is_rejected(self) -> None:
        linked = self.root / "share/linked"
        os.link(self.binary, linked)
        self.assert_rejected()

    def test_root_rename_is_rejected(self) -> None:
        renamed = self.root.with_name("renamed-tool")
        self.root.rename(renamed)
        original_root = self.root
        self.root = renamed
        try:
            self.assert_rejected()
        finally:
            renamed.rename(original_root)
            self.root = original_root

    def test_duplicate_and_unknown_fields_are_rejected(self) -> None:
        text = self.manifest.read_text(encoding="utf-8")
        self.manifest.write_text(text.replace("{", '{"algorithm":"sha256-tree-v2",', 1))
        self.assert_rejected()

        self.manifest.unlink()
        self.generate()
        payload = json.loads(self.manifest.read_text(encoding="utf-8"))
        payload["unexpected"] = True
        self.manifest.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_rejected()

        self.manifest.unlink()
        self.generate()
        payload = json.loads(self.manifest.read_text(encoding="utf-8"))
        payload["entries"][0]["unexpected"] = True
        self.manifest.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_rejected()

    def test_algorithm_downgrade_and_extra_metadata_are_rejected(self) -> None:
        payload = json.loads(self.manifest.read_text(encoding="utf-8"))
        payload["algorithm"] = "sha256-tree-v1"
        payload.pop("rootMode")
        for entry in payload["entries"]:
            entry.pop("mode")
        self.manifest.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_rejected()

        self.manifest.unlink()
        self.generate()
        payload = json.loads(self.manifest.read_text(encoding="utf-8"))
        payload["metadata"]["unreviewed"] = "value"
        self.manifest.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_rejected()


class AddedFileTransformTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.app = Path(self.temporary.name) / "Clash for Mac.app"
        (self.app / "Contents").mkdir(parents=True)
        (self.app / "Contents/Info.plist").write_text("base\n", encoding="utf-8")
        self.manifest = Path(self.temporary.name) / "pre-sign.json"
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(HASH),
                str(self.app),
                "--output",
                str(self.manifest),
                "--metadata",
                "kind=pre-sign",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.profile = Path(self.temporary.name) / "Host.provisionprofile"
        self.profile.write_bytes(b"profile-bytes")
        self.embedded = self.app / "Contents/embedded.provisionprofile"
        self.embedded.write_bytes(self.profile.read_bytes())

    def added_file(self) -> str:
        digest = hashlib.sha256(self.profile.read_bytes()).hexdigest()
        return f"Contents/embedded.provisionprofile={digest}:{self.profile.stat().st_size}"

    def verify(self, specification: str | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(VERIFY),
                str(self.app),
                str(self.manifest),
                "--metadata",
                "kind=pre-sign",
                "--added-file",
                self.added_file() if specification is None else specification,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_exact_profile_addition_is_accepted(self) -> None:
        self.assertEqual(self.verify().returncode, 0)

    def test_base_profile_and_extra_file_drift_are_rejected(self) -> None:
        mutations = (
            lambda: (self.app / "Contents/Info.plist").write_text(
                "changed\n", encoding="utf-8"
            ),
            lambda: self.embedded.write_bytes(b"changed-profile"),
            lambda: (self.app / "Contents/unexpected").write_text(
                "unexpected\n", encoding="utf-8"
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                original_base = (self.app / "Contents/Info.plist").read_bytes()
                original_profile = self.embedded.read_bytes()
                mutation()
                self.assertNotEqual(self.verify().returncode, 0)
                (self.app / "Contents/Info.plist").write_bytes(original_base)
                self.embedded.write_bytes(original_profile)
                unexpected = self.app / "Contents/unexpected"
                if unexpected.exists():
                    unexpected.unlink()

    def test_malformed_duplicate_and_existing_added_paths_are_rejected(self) -> None:
        digest = hashlib.sha256(self.profile.read_bytes()).hexdigest()
        bad = (
            f"../embedded={digest}:1",
            f"Contents//embedded.provisionprofile={digest}:1",
            f"Missing/embedded.provisionprofile={digest}:1",
            f"Contents/Info.plist={digest}:1",
            "Contents/other=not-a-digest:1",
            f"Contents/other={digest}:01",
        )
        for specification in bad:
            with self.subTest(specification=specification):
                self.assertNotEqual(self.verify(specification).returncode, 0)

        command = [
            sys.executable,
            "-B",
            str(VERIFY),
            str(self.app),
            str(self.manifest),
            "--metadata",
            "kind=pre-sign",
            "--added-file",
            self.added_file(),
            "--added-file",
            self.added_file(),
        ]
        self.assertNotEqual(
            subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).returncode,
            0,
        )


class ExecutionBeforeVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.toolchain_root = Path(self.temporary.name) / "toolchains"
        self.toolchain_root.mkdir()
        self.pins = _pins()

    def _component(self, name: str) -> tuple[Path, Path, list[str], str]:
        if name == "node":
            root = self.toolchain_root / f"node-{self.pins['NODE_VERSION']}"
            binary = root / "bin/node"
            metadata = [
                "artifactKind=pinned-node-toolchain-v1",
                "platform=darwin-arm64",
                f"sourceArchiveSha256={self.pins['NODE_DARWIN_ARM64_SHA256']}",
                f"version={self.pins['NODE_VERSION']}",
            ]
            function = "cfw_verify_node_toolchain_tree"
        elif name == "go":
            root = self.toolchain_root / f"go-{self.pins['GO_VERSION']}"
            binary = root / "bin/go"
            metadata = [
                "artifactKind=pinned-go-toolchain-v1",
                "platform=darwin-arm64",
                f"sourceArchiveSha256={self.pins['GO_DARWIN_ARM64_SHA256']}",
                f"version={self.pins['GO_VERSION']}",
            ]
            function = "cfw_verify_go_toolchain_tree"
        elif name == "xcodegen":
            root = self.toolchain_root / f"xcodegen-{self.pins['XCODEGEN_VERSION']}"
            binary = root / "bin/xcodegen"
            metadata = [
                "artifactKind=pinned-xcodegen-toolchain-v2",
                "buildPolicy=isolated-resolved-swiftpm-v1",
                f"macosDeploymentTarget={self.pins['MACOS_DEPLOYMENT_TARGET']}",
                f"packageResolvedSha256={self.pins['XCODEGEN_PACKAGE_RESOLVED_SHA256']}",
                f"patchSha256={self.pins['XCODEGEN_PATCH_SHA256']}",
                f"patchedSettingsBuilderSha256={self.pins['XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256']}",
                "platform=darwin-arm64",
                f"sourceArchiveSha256={self.pins['XCODEGEN_SOURCE_SHA256']}",
                f"sourceCommit={self.pins['XCODEGEN_COMMIT']}",
                f"version={self.pins['XCODEGEN_VERSION']}",
                f"xcodeBuild={self.pins['XCODE_BUILD_VERSION']}",
                f"xcodeVersion={self.pins['XCODE_VERSION']}",
            ]
            function = "cfw_verify_xcodegen_toolchain_tree"
        elif name == "tauri":
            root = self.toolchain_root / f"tauri-cli-{self.pins['TAURI_CLI_VERSION']}"
            binary = root / "bin/cargo-tauri"
            metadata = [
                "artifactKind=pinned-tauri-cli-v2",
                f"cacheContractSha256={self.pins['TAURI_CARGO_CACHE_CONTRACT_SHA256']}",
                "cacheNormalization=cargo-runtime-metadata-v1",
                f"crateSha256={self.pins['TAURI_CLI_CRATE_SHA256']}",
                "dependencyMode=isolated-fetch-offline-locked-v1",
                f"lockPatchSha256={self.pins['TAURI_CLI_LOCK_PATCH_SHA256']}",
                f"macosDeploymentTarget={self.pins['MACOS_DEPLOYMENT_TARGET']}",
                f"patchedCargoLockSha256={self.pins['TAURI_CLI_PATCHED_CARGO_LOCK_SHA256']}",
                "payloadLayout=bin-and-patched-source-v1",
                "platform=darwin-arm64",
                f"rustToolchain={self.pins['RUST_VERSION']}-aarch64-apple-darwin",
                f"spinCrateSha256={self.pins['TAURI_CLI_SPIN_CRATE_SHA256']}",
                f"spinVersion={self.pins['TAURI_CLI_SPIN_VERSION']}",
                f"upstreamCargoLockSha256={self.pins['TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256']}",
                f"version={self.pins['TAURI_CLI_VERSION']}",
                f"xcodeBuild={self.pins['XCODE_BUILD_VERSION']}",
                f"xcodeVersion={self.pins['XCODE_VERSION']}",
            ]
            function = "cfw_verify_tauri_toolchain_tree"
        else:
            raise AssertionError(f"unsupported fixture component: {name}")
        manifest = self.toolchain_root / f"{root.name}.manifest.json"
        return binary, manifest, metadata, function

    def test_correct_version_wrapper_is_rejected_before_execution(self) -> None:
        for name in ("node", "go", "xcodegen", "tauri"):
            with self.subTest(name=name):
                binary, manifest, metadata, function = self._component(name)
                binary.parent.mkdir(parents=True)
                binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                binary.chmod(0o755)
                command = [
                    sys.executable,
                    "-B",
                    str(HASH),
                    str(binary.parent.parent),
                    "--output",
                    str(manifest),
                    "--algorithm",
                    "sha256-tree-v2",
                ]
                for item in metadata:
                    command.extend(("--metadata", item))
                subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                sentinel = Path(self.temporary.name) / f"{name}.executed"
                binary.write_text(
                    f"#!/bin/sh\ntouch {sentinel!s}\nprintf '%s\\n' correct-version\n",
                    encoding="utf-8",
                )
                binary.chmod(0o755)
                shell = (
                    'set -euo pipefail; source "$1"; source "$2"; '
                    f'{function} "$3" "$4"; "$5" --version'
                )
                completed = subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        shell,
                        "toolchain-test",
                        str(PINS),
                        str(CONTRACT),
                        str(REPOSITORY),
                        str(self.toolchain_root),
                        str(binary),
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"manifest", completed.stderr)
                self.assertFalse(sentinel.exists())

    def test_verify_xcode_project_rejects_wrapper_before_execution(self) -> None:
        binary, manifest, metadata, _function = self._component("xcodegen")
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\nprintf 'Version: test\\n'\n", encoding="utf-8")
        binary.chmod(0o755)
        command = [
            sys.executable,
            "-B",
            str(HASH),
            str(binary.parent.parent),
            "--output",
            str(manifest),
            "--algorithm",
            "sha256-tree-v2",
        ]
        for item in metadata:
            command.extend(("--metadata", item))
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        sentinel = Path(self.temporary.name) / "xcodegen-consumer-executed"
        binary.write_text(
            f'#!/bin/sh\ntouch "{sentinel!s}"\nprintf "Version: {self.pins["XCODEGEN_VERSION"]}\\n"\n',
            encoding="utf-8",
        )
        binary.chmod(0o755)
        environment = dict(os.environ)
        environment["CFW_TOOLCHAIN_ROOT"] = str(self.toolchain_root)
        completed = subprocess.run(
            [str(SCRIPTS / "verify_xcode_project.sh")],
            cwd=REPOSITORY,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(sentinel.exists())


class ReleaseConsumerContractTests(unittest.TestCase):
    def test_release_consumers_share_the_closed_apple_tool_environment(self) -> None:
        for relative in (
            "build_signed_candidate.sh",
            "build_unsigned_candidate.sh",
            "build_native_products.sh",
            "verify_release_environment.sh",
        ):
            with self.subTest(script=relative):
                text = (SCRIPTS / relative).read_text(encoding="utf-8")
                self.assertTrue(text.startswith("#!/bin/bash -p\n"))
                self.assertIn(
                    'source "$repo_root/scripts/release_tool_environment.sh"', text
                )
                self.assertIn("cfw_seal_release_tool_environment", text)
                self.assertIn("cfw_select_release_apple_toolchain", text)
                self.assertNotRegex(text, r"(?m)(?<!/)\bxcodebuild\s+(?:build|-version)")
                self.assertLess(text.index("unset CDPATH"), text.index('repo_root="$(cd '))
                self.assertLess(
                    text.index('source "$repo_root/scripts/dependency_pins.env"'),
                    text.index("cfw_seal_release_tool_environment"),
                )

        contract = (SCRIPTS / "release_tool_environment.sh").read_text(
            encoding="utf-8"
        )
        for fragment in (
            'rust_toolchain_root="$release_home/.rustup/toolchains/$RUST_VERSION-aarch64-apple-darwin"',
            'policy_tool_root="$release_home/.cfm-release-tooling/policy-$CARGO_AUDIT_VERSION-$CARGO_DENY_VERSION"',
            'cargo_aux_bin="$policy_tool_root/bin"',
            'python_root="/opt/homebrew/Cellar/python@$python_series/$PYTHON_VERSION/',
            '/usr/bin:/bin:/usr/sbin:/sbin:$rust_bin:$cargo_aux_bin',
            "/usr/bin/dscacheutil -q user -a uid",
            "/usr/bin/xcode-select -p",
            "/usr/bin/xcodebuild -version",
            "/usr/bin/xcrun --find swift",
            "SDKROOT",
            "SWIFT_EXEC",
            "TOOLCHAINS",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, contract)

        signed = (SCRIPTS / "build_signed_candidate.sh").read_text(encoding="utf-8")
        unsigned = (SCRIPTS / "build_unsigned_candidate.sh").read_text(
            encoding="utf-8"
        )
        native = (SCRIPTS / "build_native_products.sh").read_text(encoding="utf-8")
        publication = (SCRIPTS / "prepare_publication_evidence.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("cfw_seal_release_tool_environment production", signed)
        self.assertIn("--validation-python-executable", unsigned)
        self.assertIn("cfw_seal_release_tool_environment unsigned-validation", unsigned)
        self.assertIn("--unsigned-validation-toolchain", unsigned)
        node_root = unsigned.index('node_root="$toolchain_root/node-$NODE_VERSION"')
        node_verification = unsigned.index(
            'cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"',
            node_root,
        )
        dependency_verification = unsigned.index(
            '/bin/bash -p "$repo_root/scripts/build_ui_with_pinned_node.sh"',
            node_verification,
        )
        dependency_verification_mode = unsigned.index(
            "--verify-dependencies",
            dependency_verification,
        )
        source_identity = unsigned.index(
            'source_identity_start="$(cfw_run_release_python_script',
            dependency_verification_mode,
        )
        self.assertLess(node_root, node_verification)
        self.assertLess(node_verification, dependency_verification)
        self.assertLess(dependency_verification, dependency_verification_mode)
        self.assertLess(dependency_verification_mode, source_identity)
        self.assertEqual(
            unsigned.count(
                '/bin/bash -p "$repo_root/scripts/build_ui_with_pinned_node.sh"'
            ),
            1,
        )
        self.assertNotIn("NPM_CONFIG_", unsigned)
        self.assertNotIn("export PATH=", unsigned)
        self.assertNotIn('PATH="$PATH:', unsigned)
        self.assertNotIn('PATH="${PATH}:', unsigned)
        self.assertIn('"${1:-}" == "--unsigned"', native)
        self.assertIn("cfw_seal_release_tool_environment production", publication)

    def test_closed_shell_environment_never_executes_ambient_apple_shadows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            marker = Path(temporary) / "ambient-apple-tool-ran"
            for tool in ("swift", "xcodebuild", "xcrun"):
                executable = fake_bin / tool
                executable.write_text(
                    f"#!/bin/sh\ntouch '{marker}'\nexit 99\n", encoding="utf-8"
                )
                executable.chmod(0o755)
            environment = dict(os.environ)
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "TOOLCHAINS": "untrusted",
                    "SDKROOT": str(Path(temporary) / "sdk"),
                    "SWIFT_EXEC": str(fake_bin / "swift"),
                }
            )
            role = (
                "unsigned-validation"
                if "CFW_UNSIGNED_VALIDATION_PYTHON" in environment
                else "production"
            )
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-p",
                    "-c",
                    "set -euo pipefail; "
                    'source "$1/scripts/release_tool_environment.sh"; '
                    'source "$1/scripts/dependency_pins.env"; '
                    'export DYLD_INSERT_LIBRARIES="$2"; '
                    'cfw_seal_release_tool_environment "$3"; '
                    "cfw_select_release_apple_toolchain; "
                    'printf "%s\\n%s\\n" "$PATH" "$DEVELOPER_DIR"',
                    "release-tool-environment-test",
                    str(REPOSITORY),
                    str(Path(temporary) / "inject.dylib"),
                    role,
                ],
                cwd=REPOSITORY,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertFalse(marker.exists())
            lines = completed.stdout.decode().splitlines()
            release_home = Path.home().resolve()
            policy_root = (
                release_home
                / ".cfm-release-tooling"
                / (
                    f"policy-{_pins()['CARGO_AUDIT_VERSION']}-"
                    f"{_pins()['CARGO_DENY_VERSION']}"
                )
            )
            self.assertEqual(
                lines[0],
                "/usr/bin:/bin:/usr/sbin:/sbin:"
                f"{release_home}/.rustup/toolchains/"
                f"{_pins()['RUST_VERSION']}-aarch64-apple-darwin/bin:"
                f"{policy_root}/bin",
            )
            self.assertTrue(lines[1].endswith("/Contents/Developer"))

    def test_candidate_builds_use_the_warning_free_unsigned_host_contract(self) -> None:
        contract = (SCRIPTS / "tauri_host_skeleton.sh").read_text(encoding="utf-8")
        for variable in (
            "APPLE_CERTIFICATE",
            "APPLE_CERTIFICATE_PASSWORD",
            "APPLE_SIGNING_IDENTITY",
        ):
            self.assertIn(variable, contract)
            self.assertIn(f"-u {variable}", contract)
        self.assertIn("tauri.macos.conf.json", contract)
        self.assertIn("tauri.macos.conf.json5", contract)
        self.assertIn("Tauri.macos.toml", contract)
        self.assertIn("signingIdentity", contract)
        self.assertNotIn("--no-sign", contract)
        self.assertIn(
            'source "$tauri_host_contract_directory/release_cargo_inputs.sh"',
            contract,
        )
        self.assertEqual(contract.count("cfw_verify_release_cargo_runtime"), 2)
        runtime_guard = contract.index(
            "Tauri build requires the verified candidate Cargo runtime"
        )
        runtime_verification_before = contract.index(
            "cfw_verify_release_cargo_runtime", runtime_guard
        )
        config_preflight = contract.index(
            "PYTHONDONTWRITEBYTECODE=1", runtime_verification_before
        )
        tauri_execution = contract.index(
            '"$contract_tauri_host_bin" build', config_preflight
        )
        runtime_verification_after = contract.index(
            "cfw_verify_release_cargo_runtime", tauri_execution
        )
        self.assertLess(runtime_guard, runtime_verification_before)
        self.assertLess(runtime_verification_before, config_preflight)
        self.assertLess(config_preflight, tauri_execution)
        self.assertLess(tauri_execution, runtime_verification_after)

        for relative in (
            "build_unsigned_candidate.sh",
            "build_signed_candidate.sh",
        ):
            with self.subTest(script=relative):
                source = (SCRIPTS / relative).read_text(encoding="utf-8")
                self.assertNotIn("--no-sign", source)
                self.assertIn("source \"$repo_root/scripts/tauri_host_skeleton.sh\"", source)
                runtime_create = source.index(
                    'candidate_cargo_home="$(cfw_create_release_cargo_runtime '
                    '"$repo_root")"'
                )
                cleanup_name = (
                    "cleanup_candidate_cargo_runtime()"
                    if relative == "build_unsigned_candidate.sh"
                    else "cleanup()"
                )
                cleanup_function = source.index(cleanup_name)
                cleanup_runtime_removal = source.index(
                    'cfw_remove_release_cargo_runtime "$candidate_cargo_home"',
                    cleanup_function,
                )
                cleanup_trap = source.index(
                    (
                        "trap cleanup_candidate_cargo_runtime EXIT"
                        if relative == "build_unsigned_candidate.sh"
                        else "trap cleanup EXIT"
                    ),
                    cleanup_runtime_removal,
                )
                scoped_host_environment = (
                    'CARGO_HOME="$candidate_cargo_home" \\\n'
                    '  CARGO_NET_OFFLINE=true \\\n'
                    '  CARGO_TARGET_DIR="$cargo_target" \\\n'
                    '  MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \\\n'
                    "  cfw_build_tauri_host_skeleton"
                )
                cargo_use = source.index(scoped_host_environment, runtime_create)
                build = source.index("cfw_build_tauri_host_skeleton", cargo_use)
                runtime_verification = source.index(
                    'cfw_verify_release_cargo_runtime "$repo_root" '
                    '"$candidate_cargo_home"',
                    build,
                )
                runtime_removal = source.index(
                    'cfw_remove_release_cargo_runtime "$candidate_cargo_home"',
                    runtime_verification,
                )
                runtime_clear = source.index(
                    'candidate_cargo_home=""', runtime_removal
                )
                verification = source.index(
                    "verify_candidate_bundle.sh", build
                )
                manifest = source.index("scripts/hash_artifact.py", verification)
                self.assertLess(runtime_create, cargo_use)
                self.assertLess(cleanup_function, cleanup_runtime_removal)
                self.assertLess(cleanup_runtime_removal, cleanup_trap)
                self.assertLess(cleanup_trap, cargo_use)
                self.assertLess(cargo_use, build)
                self.assertLess(build, runtime_verification)
                self.assertLess(runtime_verification, runtime_removal)
                self.assertLess(runtime_removal, runtime_clear)
                self.assertLess(runtime_clear, verification)
                self.assertLess(build, verification)
                self.assertLess(verification, manifest)
                self.assertIn(
                    "--context unsigned-host", source[verification:manifest]
                )
                self.assertNotIn("export CARGO_NET_OFFLINE", source)
                self.assertNotIn("export CARGO_TARGET_DIR", source)
                self.assertNotIn("export MACOSX_DEPLOYMENT_TARGET", source)

        signed = (SCRIPTS / "build_signed_candidate.sh").read_text(encoding="utf-8")
        pre_sign_copy = signed.index(
            '/usr/bin/ditto --noqtn "$built_app" "$pre_sign_app"'
        )
        pre_sign_verify = signed.index("verify_candidate_bundle.sh", pre_sign_copy)
        freeze = signed.index("scripts/candidate_freeze.py\" freeze", pre_sign_verify)
        frozen_verify = signed.index("scripts/candidate_freeze.py\" verify", freeze)
        signing_transaction = signed.index(
            "scripts/signing_attempt_transaction.py", frozen_verify
        )
        helper = (SCRIPTS / "run_ga_signing_attempt.sh").read_text(
            encoding="utf-8"
        )
        codesign_boundary = (SCRIPTS / "release_bundle_codesign.sh").read_text(
            encoding="utf-8"
        )
        signing_input_copy = helper.index(
            '/usr/bin/ditto --noqtn "$pre_sign_app" "$staged_app"',
        )
        host_profile_install = helper.index(
            '"$staged_app/Contents/embedded.provisionprofile"',
            signing_input_copy,
        )
        bridge_sign = helper.index(
            "--identifier com.bill.clashformac.native-bridge", host_profile_install
        )
        authority_sign = helper.index(
            "--identifier com.bill.clashformac.global-authority", bridge_sign
        )
        authority_requirement_extract = helper.index(
            '/usr/bin/codesign -d -r "$authority_requirement_text" "$authority"',
            authority_sign,
        )
        authority_requirement_expected = helper.index(
            '/usr/bin/csreq -r="$authority_designated_requirement"',
            authority_requirement_extract,
        )
        authority_requirement_actual = helper.index(
            '/usr/bin/csreq -r "$authority_requirement_text"',
            authority_requirement_expected,
        )
        authority_requirement_compare = helper.index(
            '/usr/bin/cmp -s -- "$authority_requirement_expected" '
            '"$authority_requirement_actual"',
            authority_requirement_actual,
        )
        proxy_sign = helper.index(
            '--entitlements "$proxy_release_xcent"', authority_requirement_compare
        )
        packet_sign = helper.index(
            '--entitlements "$packet_release_xcent"', proxy_sign
        )
        tombstone_sign = helper.index(
            '--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$tombstone"', packet_sign
        )
        manifest_promotion = helper.index(
            '"$repo_root/scripts/promote_signed_native_manifest.py"',
            tombstone_sign,
        )
        manifest_verification = helper.index(
            '"$repo_root/scripts/verify_artifact_manifest.py"',
            manifest_promotion,
        )
        tombstone_provenance_verification = helper.index(
            '"$repo_root/scripts/verify_legacy_tombstone_provenance.py"',
            manifest_verification,
        )
        pre_host_verification = helper.index(
            '"$repo_root/scripts/verify_candidate_bundle.sh"',
            tombstone_provenance_verification,
        )
        host_sign = helper.index(
            '--entitlements "$host_release_xcent"', pre_host_verification
        )
        deep_host_verification = helper.index(
            "/usr/bin/codesign --verify --deep --strict --verbose=4",
            host_sign,
        )
        release_app_verification = helper.index(
            '"$repo_root/scripts/verify_release_app.sh"',
            deep_host_verification,
        )
        self.assertLess(pre_sign_copy, pre_sign_verify)
        self.assertLess(pre_sign_verify, freeze)
        self.assertLess(freeze, frozen_verify)
        self.assertLess(frozen_verify, signing_transaction)
        self.assertLess(signing_input_copy, host_profile_install)
        self.assertLess(host_profile_install, bridge_sign)
        self.assertLess(bridge_sign, authority_sign)
        self.assertLess(authority_sign, authority_requirement_extract)
        self.assertLess(authority_requirement_extract, authority_requirement_expected)
        self.assertLess(authority_requirement_expected, authority_requirement_actual)
        self.assertLess(authority_requirement_actual, authority_requirement_compare)
        self.assertLess(authority_requirement_compare, proxy_sign)
        self.assertLess(proxy_sign, packet_sign)
        self.assertLess(packet_sign, tombstone_sign)
        self.assertLess(tombstone_sign, manifest_promotion)
        self.assertLess(manifest_promotion, manifest_verification)
        self.assertLess(
            manifest_verification, tombstone_provenance_verification
        )
        tombstone_provenance = helper[
            tombstone_provenance_verification:pre_host_verification
        ]
        self.assertIn('--embedded-app "$staged_app"', tombstone_provenance)
        self.assertIn("--context signing-attempt-work", tombstone_provenance)
        self.assertLess(
            tombstone_provenance_verification, pre_host_verification
        )
        self.assertLess(manifest_verification, pre_host_verification)
        self.assertLess(pre_host_verification, host_sign)
        self.assertLess(host_sign, deep_host_verification)
        self.assertLess(deep_host_verification, release_app_verification)
        self.assertIn(
            "--context unsigned-host", signed[pre_sign_verify:freeze]
        )
        self.assertIn(
            "--context signing-attempt-work",
            helper[pre_host_verification:host_sign],
        )
        self.assertIn(
            "--context signing-attempt-work",
            helper[release_app_verification:],
        )
        self.assertNotIn("/usr/bin/codesign --force", signed)
        self.assertNotIn("/usr/bin/codesign --force", helper)
        self.assertEqual(
            helper.count("cfw_codesign_distribution_bundle --force"), 6
        )
        self.assertEqual(helper.count("\numask 077\n"), 1)
        self.assertNotIn("\numask 022\n", helper)
        self.assertEqual(codesign_boundary.count("\n  umask 022\n"), 1)
        self.assertEqual(
            codesign_boundary.count('exec /usr/bin/codesign "$@"'), 1
        )
        self.assertNotIn('--sign "$MACOS_SIGN_IDENTITY"', helper)
        self.assertEqual(
            helper.count('--sign "$CFW_SIGNING_CERTIFICATE_SHA1"'),
            6,
        )
        self.assertEqual(helper.count("cfw_run_release_python_script"), 3)
        self.assertNotIn('"$python_bin" -I', helper)
        self.assertIn('"$repo_root/scripts/build_native_products.sh" --pre-sign', signed)
        self.assertIn(
            '"$repo_root/scripts/build_legacy_tombstone.sh" --pre-sign', signed
        )
        self.assertNotIn("--developer-id", signed)

        unsigned = (SCRIPTS / "build_unsigned_candidate.sh").read_text(
            encoding="utf-8"
        )
        manifest = unsigned.index("scripts/hash_artifact.py")
        final_verification = unsigned.rindex("verify_candidate_bundle.sh")
        manifest_reverification = unsigned.rindex("verify_artifact_manifest.py")
        self.assertLess(manifest, final_verification)
        self.assertLess(final_verification, manifest_reverification)
        self.assertIn(
            "--context unsigned-host",
            unsigned[final_verification:manifest_reverification],
        )

    def test_every_release_app_verifier_caller_declares_one_fixed_context(self) -> None:
        expected_canonical_calls = {
            "notarization_transaction.py": (4, 4),
            "make_dmg.sh": (2, 2),
            "make_updater_manifest.sh": (1, 1),
            "release_publication_gate.sh": (1, 1),
            "publication/ga_release_contract.py": (1, 1),
            "publication/preparer.py": (1, 1),
            "dormant_app_install.py": (2, 1),
        }
        for relative, counts in expected_canonical_calls.items():
            with self.subTest(caller=relative):
                verifier_count, context_count = counts
                source = (SCRIPTS / relative).read_text(encoding="utf-8")
                self.assertEqual(
                    source.count("verify_release_app.sh"), verifier_count
                )
                self.assertEqual(
                    source.count("canonical-native-content"), context_count
                )

        release_verifier = (SCRIPTS / "verify_release_app.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("signing_attempt_pattern", release_verifier)
        self.assertIn("candidate_bundle_verification_paths(", release_verifier)
        self.assertIn('--context "$verification_context"', release_verifier)

    def test_release_consumers_do_not_use_ambient_tauri(self) -> None:
        for relative in (
            "build_unsigned_candidate.sh",
            "build_signed_candidate.sh",
            "verify_release_environment.sh",
        ):
            text = (SCRIPTS / relative).read_text(encoding="utf-8")
            self.assertNotIn("cargo tauri", text, relative)
            self.assertIn("tauri-cli-$TAURI_CLI_VERSION", text, relative)

        updater = (SCRIPTS / "make_updater_manifest.sh").read_text(
            encoding="utf-8"
        )
        launcher = (SCRIPTS / "updater_signing_launcher.py").read_text(
            encoding="utf-8"
        )
        integration_child = (
            SCRIPTS / "tests/updater_signing_integration_child.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("cargo tauri", updater)
        self.assertNotIn("cargo-tauri", updater)
        self.assertIn("cfw_verify_tauri_toolchain_tree", updater)
        self.assertIn('"$repo_root/scripts/updater_signing_launcher.py"', updater)

        # Updater signing deliberately delegates custody to one fixed launcher.
        # Keep the cross-file contract stronger than the former shell-local
        # path check: the launcher must pin the same version and exact source
        # metadata as the release toolchain, bind the held signer bytes to the
        # unique verified manifest entry, and derive the executable only from
        # the repository-owned toolchain root. Compiled Mach-O output identity
        # is generated evidence, not a cross-host source constant.
        self.assertNotIn("cargo tauri", launcher)
        self.assertIn(
            f'TAURI_CLI_VERSION = "{_pins()["TAURI_CLI_VERSION"]}"', launcher
        )
        self.assertNotIn("PINNED_TAURI_TREE_SHA256", launcher)
        self.assertNotIn("PINNED_TAURI_SIGNER_SHA256", launcher)
        self.assertNotIn("PINNED_TAURI_SIGNER_BYTES", launcher)
        self.assertIn("MAX_TAURI_SIGNER_BYTES", launcher)
        self.assertIn('"--print-entry"', launcher)
        self.assertIn('"bin/cargo-tauri"', launcher)
        self.assertIn("_parse_verified_signer_entry", launcher)
        self.assertIn(
            f'"cacheContractSha256={_pins()["TAURI_CARGO_CACHE_CONTRACT_SHA256"]}"',
            launcher,
        )
        self.assertIn(
            'repository / "target/toolchains" / f"tauri-cli-{TAURI_CLI_VERSION}"',
            launcher,
        )
        self.assertIn('signer_path = toolchain / "bin/cargo-tauri"', launcher)
        self.assertIn("_verify_pinned_tauri_signer_with_runtime", launcher)
        self.assertIn("signer_verifier=verify_pinned_tauri_signer", launcher)
        self.assertNotIn("CFW_UNSIGNED_VALIDATION_PYTHON", launcher)
        self.assertIn(
            "require_closed_release_runtime(",
            integration_child,
        )
        self.assertIn("allow_unsigned_validation=True", integration_child)
        self.assertIn(
            "launcher._verify_pinned_tauri_signer_with_runtime(",
            integration_child,
        )

    def test_managed_tool_consumers_reference_tree_verification(self) -> None:
        expectations = {
            "build_ui_with_pinned_node.sh": "cfw_verify_node_toolchain_tree",
            "build_libbox.sh": "cfw_verify_go_module_cache_tree",
            "prepare_libbox_modules.sh": "cfw_verify_go_toolchain_tree",
            "scan_libbox_vulnerabilities.sh": "cfw_verify_go_release_tools_tree",
            "build_unsigned_candidate.sh": "cfw_verify_tauri_toolchain_tree",
            "build_signed_candidate.sh": "cfw_verify_tauri_toolchain_tree",
            "verify_release_environment.sh": "cfw_verify_go_module_cache_tree",
            "verify_xcode_project.sh": "cfw_verify_xcodegen_toolchain_tree",
            "make_updater_manifest.sh": "cfw_verify_tauri_toolchain_tree",
        }
        for relative, fragment in expectations.items():
            with self.subTest(script=relative):
                text = (SCRIPTS / relative).read_text(encoding="utf-8")
                self.assertIn(fragment, text)

    def test_xcode_project_verifier_uses_a_closed_xcodegen_environment(self) -> None:
        verifier = (SCRIPTS / "verify_xcode_project.sh").read_text(encoding="utf-8")
        for fragment in (
            "/usr/bin/env -i",
            'HOME="$isolated_home"',
            'TMPDIR="$isolated_tmp"',
            "USER=cfw-release",
            "LOGNAME=cfw-release",
            "LANG=C",
            "LC_ALL=C",
            'PATH="/usr/bin:/bin:/usr/sbin:/sbin"',
            'DEVELOPER_DIR="${DEVELOPER_DIR:?}"',
            '"$xcodegen" generate',
            "--no-env",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, verifier)

    def test_libbox_module_cache_seals_the_offline_test_graph(self) -> None:
        contract = (SCRIPTS / "libbox_module_cache_contract.bash").read_text(
            encoding="utf-8"
        )
        for array_name in (
            "LIBBOX_MODULE_BUILD_PACKAGES",
            "LIBBOX_GOMOBILE_BIND_PACKAGES",
            "LIBBOX_RACE_TEST_PACKAGES",
            "LIBBOX_TEST_PACKAGES",
            "LIBBOX_COMPILE_TEST_PACKAGES",
            "LIBBOX_VET_PACKAGES",
        ):
            with self.subTest(contract_array=array_name):
                self.assertIn(f"{array_name}=(", contract)
        self.assertIn('"./route"', contract)

        preparation = (SCRIPTS / "prepare_libbox_modules.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("-test", preparation)
        self.assertIn('libbox_load_module_cache_contract "$repo_root"', preparation)
        for array_name in (
            "LIBBOX_MODULE_BUILD_PACKAGES",
            "LIBBOX_GOMOBILE_BIND_PACKAGES",
            "LIBBOX_RACE_TEST_PACKAGES",
            "LIBBOX_TEST_PACKAGES",
            "LIBBOX_COMPILE_TEST_PACKAGES",
            "LIBBOX_VET_PACKAGES",
        ):
            with self.subTest(preparation_array=array_name):
                self.assertIn(f'"${{{array_name}[@]}}"', preparation)
        self.assertIn("artifactKind=pinned-go-module-cache-v2", preparation)
        self.assertIn(
            "moduleCacheContractSha256=$LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
            preparation,
        )

        source_tests = (SCRIPTS / "test_libbox_source.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('libbox_load_module_cache_contract "$repo_root"', source_tests)
        for array_name in (
            "LIBBOX_RACE_TEST_PACKAGES",
            "LIBBOX_TEST_PACKAGES",
            "LIBBOX_COMPILE_TEST_PACKAGES",
            "LIBBOX_VET_PACKAGES",
        ):
            with self.subTest(source_test_array=array_name):
                self.assertIn(f'"${{{array_name}[@]}}"', source_tests)

        verifier = (SCRIPTS / "release_toolchain_contract.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("artifactKind=pinned-go-module-cache-v2", verifier)
        self.assertIn(
            "moduleCacheContractSha256=$LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
            verifier,
        )

    def test_real_libbox_module_cache_contract_loads(self) -> None:
        shell = (
            'set -euo pipefail; source "$1"; source "$2"; '
            'libbox_load_module_cache_contract "$3"; '
            'printf "%s\\n" "${LIBBOX_COMPILE_TEST_PACKAGES[@]}"'
        )
        completed = subprocess.run(
            [
                "/bin/bash",
                "-c",
                shell,
                "module-cache-contract-test",
                str(PINS),
                str(SCRIPTS / "libbox_source_contract.sh"),
                str(REPOSITORY),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stdout.splitlines(), [b"./common/dialer", b"./route"])

    def test_libbox_module_cache_contract_rejects_unsafe_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "unsafe-contract.sh"
            contract.write_text(
                """\
LIBBOX_MODULE_BUILD_PACKAGES=("./experimental/libbox")
LIBBOX_GOMOBILE_BIND_PACKAGES=("github.com/sagernet/gomobile/bind")
LIBBOX_RACE_TEST_PACKAGES=("./dns")
LIBBOX_TEST_PACKAGES=(".")
LIBBOX_COMPILE_TEST_PACKAGES=("../escape")
LIBBOX_VET_PACKAGES=(".")
""",
                encoding="utf-8",
            )
            digest = hashlib.sha256(contract.read_bytes()).hexdigest()
            shell = (
                'set -euo pipefail; source "$1"; '
                'LIBBOX_MODULE_CACHE_CONTRACT_PATH=unsafe-contract.sh; '
                'LIBBOX_MODULE_CACHE_CONTRACT_SHA256="$2"; '
                'libbox_load_module_cache_contract "$3"'
            )
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    shell,
                    "module-cache-contract-test",
                    str(SCRIPTS / "libbox_source_contract.sh"),
                    digest,
                    str(root),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"unsafe compile-test package", completed.stderr)

    def test_libbox_consumers_share_the_exact_artifact_contract(self) -> None:
        contract = (SCRIPTS / "libbox_source_contract.sh").read_text(encoding="utf-8")
        self.assertIn("libbox_verify_xcframework_artifact()", contract)
        self.assertIn("--algorithm sha256-tree-v1", contract)
        self.assertIn("--exact-metadata", contract)
        self.assertIn("--print-tree-sha256", contract)
        for metadata in (
            "sourceTag=$SING_BOX_VERSION",
            "sourceCommit=$SING_BOX_COMMIT",
            "goVersion=$GO_VERSION",
            "goToolchainTreeSha256=$go_toolchain_tree_sha256",
            "goToolsTreeSha256=$go_tools_tree_sha256",
            "goModuleCacheTreeSha256=$go_module_cache_tree_sha256",
            "gomobileVersion=$GOMOBILE_VERSION",
            "gomobileCommit=$GOMOBILE_COMMIT",
            "gomobileModuleSum=$GOMOBILE_MODULE_SUM",
            "archiveDeterminism=zeroArDate-v1",
            "headerNormalization=angleBracketFrameworkImports-v1",
            "platform=$LIBBOX_APPLE_PLATFORM",
            "buildTags=$LIBBOX_BUILD_TAGS",
            "nonMacOsTags=$LIBBOX_NON_MACOS_TAGS",
            "upstreamGoModSha256=$SING_BOX_UPSTREAM_GO_MOD_SHA256",
            "upstreamGoSumSha256=$SING_BOX_UPSTREAM_GO_SUM_SHA256",
            "securityPatchSha256=$SING_BOX_SECURITY_PATCH_SHA256",
            "rawPacketPatchSha256=$SING_BOX_RAW_PACKET_PATCH_SHA256",
            "dnsFailoverPatchSha256=$SING_BOX_DNS_FAILOVER_PATCH_SHA256",
            "endpointConflictPatchSha256=$SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
            "patchedDiffSha256=$SING_BOX_PATCHED_DIFF_SHA256",
            "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256",
            "patchedGoModSha256=$SING_BOX_PATCHED_GO_MOD_SHA256",
            "patchedGoSumSha256=$SING_BOX_PATCHED_GO_SUM_SHA256",
        ):
            with self.subTest(metadata=metadata):
                self.assertIn(metadata, contract)

        for relative in (
            "build_libbox.sh",
            "build_native_products.sh",
            "build_unsigned_candidate.sh",
            "build_signed_candidate.sh",
            "verify_release_app.sh",
        ):
            with self.subTest(consumer=relative):
                source = (SCRIPTS / relative).read_text(encoding="utf-8")
                self.assertIn("libbox_verify_xcframework_artifact", source)

        native_builder = (SCRIPTS / "build_native_products.sh").read_text(
            encoding="utf-8"
        )
        first_verification = native_builder.index("libbox_tree_sha256_start=")
        first_build = native_builder.index("build_scheme CFWNativeBridge")
        second_verification = native_builder.index("libbox_tree_sha256=", first_build)
        self.assertLess(first_verification, first_build)
        self.assertGreater(second_verification, first_build)

        host_build = (REPOSITORY / "apps/cfw-tauri-shell/build.rs").read_text(
            encoding="utf-8"
        )
        for fragment in (
            "const LIBBOX_METADATA_KEYS: [&str; 24]",
            '"goToolchainTreeSha256"',
            '"goToolsTreeSha256"',
            '"goModuleCacheTreeSha256"',
            '"archiveDeterminism"',
            '"zeroArDate-v1"',
            "endpoint_conflict_patch: SingBoxSourcePatchLock",
            '"SING_BOX_ENDPOINT_CONFLICT_PATCH_PATH"',
            '"SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256"',
            "sing-box endpoint conflict patch digest differs from dependency lock",
            "actual_metadata_keys != expected_metadata_keys",
            "CFW_GO_TOOLCHAIN_TREE_SHA256",
            "CFW_GO_TOOLS_TREE_SHA256",
            "CFW_GO_MODULE_CACHE_TREE_SHA256",
        ):
            with self.subTest(host_build=fragment):
                self.assertIn(fragment, host_build)

    def test_release_environment_reverifies_every_managed_tree(self) -> None:
        text = (SCRIPTS / "verify_release_environment.sh").read_text(encoding="utf-8")
        for function in (
            "cfw_verify_go_toolchain_tree",
            "cfw_verify_node_toolchain_tree",
            "cfw_verify_xcodegen_toolchain_tree",
            "cfw_verify_tauri_toolchain_tree",
            "cfw_verify_go_release_tools_tree",
            "cfw_verify_go_module_cache_tree",
        ):
            with self.subTest(function=function):
                self.assertEqual(text.count(function), 2)

    def test_release_environment_requires_the_supported_python_line(self) -> None:
        contract = (SCRIPTS / "release_toolchain_contract.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("(3, 11) <= sys.version_info[:2] < (4, 0)", contract)
        self.assertIn("Python 3.11 through 3.x is required", contract)
        for relative in (
            "build_signed_candidate.sh",
            "build_unsigned_candidate.sh",
            "verify_release_environment.sh",
            "verify_build_boundaries.sh",
            "make_dmg.sh",
            "make_updater_manifest.sh",
        ):
            with self.subTest(script=relative):
                text = (SCRIPTS / relative).read_text(encoding="utf-8")
                self.assertIn("cfw_require_supported_python", text)

    def test_release_runbook_bootstraps_policy_tools_before_sealed_gates(self) -> None:
        runbook = (REPOSITORY / "RELEASE.md").read_text(encoding="utf-8")
        cargo_workspace_inputs = runbook.index(
            "./scripts/run_release_ci_gate.sh prepare-cargo-workspace-inputs"
        )
        policy_bootstrap = runbook.index(
            "./scripts/run_release_ci_gate.sh bootstrap-policy-tools"
        )
        release_toolchain = runbook.index(
            "./scripts/run_release_ci_gate.sh bootstrap-release-toolchain"
        )
        self.assertLess(cargo_workspace_inputs, policy_bootstrap)
        self.assertLess(policy_bootstrap, release_toolchain)

    def test_release_runbook_exports_atomic_journals_before_runtime_acceptance(self) -> None:
        runbook = (REPOSITORY / "RELEASE.md").read_text(encoding="utf-8")
        policy = (
            REPOSITORY / "docs/release/ga-assurance-policy-v040.md"
        ).read_text(encoding="utf-8")
        ordered_commands = (
            "scripts/run_current_service_transaction.sh --recommission",
            "scripts/run_ga_acceptance_journal_export.sh --export",
            "scripts/run_ga_acceptance_journal_export.sh --verify",
            "scripts/run_ga_runtime_acceptance.sh collect",
            "scripts/run_ga_runtime_acceptance.sh verify",
            "scripts/release_publication_gate.sh --seal-ga-acceptance",
        )
        positions = [runbook.index(command) for command in ordered_commands]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(
            "`--recover` is not a normal post-export step",
            runbook,
        )
        for required in (
            "service-transaction/environment.json",
            "cfm-ga-journal-export-intent-v1",
            "cfm-ga-journal-export-receipt-v1",
            "cfw-current-service-transaction-v3",
            "cfw-dormant-app-install-v2",
            "cfm-ga-runtime-acceptance-v2",
            "cfm-ga-runtime-check-v2",
            "cfm-ga-command-observation-v2",
            "cfm-ga-runtime-collection-intent-v2",
            "cfm-ga-runtime-collection-event-v2",
            "cfm-ga-prepackage-seal-v1",
            "cfm-ga-acceptance-seal-v2",
            "cfm-ga-publication-seal-v2",
            "Older service/runtime/stage markers cannot be accepted",
        ):
            with self.subTest(required=required):
                self.assertIn(required, policy)
        self.assertNotIn("migration-journals/environment.json", policy)

    def test_release_runbook_documents_candidate_identity_lifecycle(self) -> None:
        runbook = (REPOSITORY / "RELEASE.md").read_text(encoding="utf-8")
        ga_policy = (
            REPOSITORY / "docs/release/ga-assurance-policy-v040.md"
        ).read_text(encoding="utf-8")
        lifecycle = (
            REPOSITORY / "docs/release/candidate-identity-lifecycle.md"
        ).read_text(encoding="utf-8")

        link = (
            "docs/release/candidate-identity-lifecycle.md"
            "#build-number-allocation-and-consumption"
        )
        self.assertIn(link, runbook)
        self.assertIn(
            "(candidate-identity-lifecycle.md"
            "#build-number-allocation-and-consumption)",
            ga_policy,
        )
        self.assertIn("## Build-number allocation and consumption", ga_policy)
        for heading in (
            "## Authority and scope",
            "## Build-number allocation and consumption",
            "## Identity vocabulary",
            "## Lifecycle state machine",
            "## Consumption boundary",
            "## Consumption decision table",
            "## Design and review workflow",
            "## Required failure examples",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, lifecycle)
        for contract in (
            "not a credential, authenticator, nonce, signature",
            "or retry counter",
            "reserved_unconsumed",
            "active_ga_unconsumed",
            "candidate_frozen_consumed",
            "retired_unbuilt",
            "retired_consumed",
            "package_seal_sha256",
            "product_input_sha256",
            "candidate_source_identity",
            "evidence_policy_identity",
            "candidate-freeze",
            "quarantined_outcome_unknown",
            "source-owned, complete, and versioned",
            "new or unclassified release path fails",
            "complete unsigned pre-sign application tree",
            "No nested product or Host Developer ID signing command may run",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, lifecycle)
        self.assertIn(
            "Pre-candidate failures use append-only attempt or CI-run identities",
            runbook,
        )
        self.assertIn("(ga-assurance-policy-v040.md)", lifecycle)
        self.assertIn("(build-allocations-v040.json)", lifecycle)
        self.assertNotRegex(lifecycle, r"\b400[0-9]{2}\b")

    def test_ui_gates_do_not_expand_an_empty_array_under_nounset(self) -> None:
        wrapper = (SCRIPTS / "run_release_ci_gate.sh").read_text(encoding="utf-8")
        self.assertNotIn("ui_arguments", wrapper)
        self.assertIn(
            'ui-test)\n    [[ $# -eq 0 ]] || die "$gate accepts no arguments"\n'
            '    /bin/bash -p "$repo_root/scripts/build_ui_with_pinned_node.sh" \\\n'
            "      --test",
            wrapper,
        )
        self.assertIn(
            'ui-build)\n    [[ $# -eq 0 ]] || die "$gate accepts no arguments"\n'
            '    /bin/bash -p "$repo_root/scripts/build_ui_with_pinned_node.sh"',
            wrapper,
        )
        self.assertIn(
            'ui-audit)\n    [[ $# -eq 0 ]] || die "$gate accepts no arguments"\n'
            '    /bin/bash -p "$repo_root/scripts/build_ui_with_pinned_node.sh" \\\n'
            "      --audit",
            wrapper,
        )

    def test_readmes_use_the_closed_libbox_preparation_sequence(self) -> None:
        expected = (
            "prepare-cargo-workspace-inputs",
            "bootstrap-policy-tools",
            "bootstrap-release-toolchain",
            "fetch-libbox-upstream",
            "materialize-libbox-source",
            "prepare-libbox-modules",
            "libbox-vulnerability-scan",
            "build-libbox",
        )
        for relative in ("README.md", "RELEASE.md"):
            text = (REPOSITORY / relative).read_text(encoding="utf-8")
            offsets = [
                text.index(f"./scripts/run_release_ci_gate.sh {gate}")
                for gate in expected
            ]
            with self.subTest(relative=relative):
                self.assertEqual(offsets, sorted(offsets))

        native = (REPOSITORY / "native/macos/README.md").read_text(
            encoding="utf-8"
        )
        native_offsets = [
            native.index(f"./scripts/run_release_ci_gate.sh {gate}")
            for gate in expected[:3]
        ]
        self.assertEqual(native_offsets, sorted(native_offsets))

    def test_native_readme_keeps_unsigned_builds_out_of_active_validation(self) -> None:
        readme = (REPOSITORY / "native/macos/README.md").read_text(encoding="utf-8")
        self.assertIn("export CFW_BUILD_NUMBER=40000", readme)
        self.assertIn(
            "target/candidates/0.4.0/native-validation/40000/native-products",
            readme,
        )
        self.assertNotIn(
            "target/candidates/0.4.0/validation/40030/native-products",
            readme,
        )

    def test_tauri_installer_uses_isolated_clean_payload(self) -> None:
        installer = (SCRIPTS / "install_pinned_tauri_cli.sh").read_text(encoding="utf-8")
        lock_patch_command_prefix = (
            'GIT_CEILING_DIRECTORIES="$staging" ' + "\\" + "\n  "
        )
        lock_patch_check_command = (
            lock_patch_command_prefix
            + '/usr/bin/git -C "$source_root" apply --unidiff-zero --check "$lock_patch"'
        )
        lock_patch_apply_command = (
            lock_patch_command_prefix
            + '/usr/bin/git -C "$source_root" apply --unidiff-zero "$lock_patch"'
        )
        lock_patch_reverse_check_command = (
            lock_patch_command_prefix
            + '/usr/bin/git -C "$source_root" apply --unidiff-zero --reverse --check "$lock_patch"'
        )
        workspace_manifest_creation = (
            'render_tauri_workspace_manifest >"$staging_workspace_manifest"'
        )
        workspace_lock_creation = (
            '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"'
        )
        workspace_boundary_call = "\nverify_tauri_workspace_boundary\n"
        cargo_configuration_call = "\nreject_tauri_cargo_configuration\n"
        for fragment in (
            'readonly temporary_parent_input="${TMPDIR:-}"',
            '"$(/usr/bin/stat -f \'%u\' "$temporary_parent")" == "$(/usr/bin/id -u)"',
            '"$temporary_parent" == "$temporary_parent_input"',
            '[[ "$temporary_parent" != *:* ]]',
            'staging="$(/usr/bin/mktemp -d '
            '"$temporary_parent/cfw-tauri-cli.XXXXXX")"',
            "(( (8#$temporary_mode & 8#22) == 0 ))",
            "/usr/bin/env -i",
            'CARGO_HOME="$prepared_cargo_home"',
            'CARGO_HOME="$offline_cargo_home"',
            'CARGO_TARGET_DIR="$cargo_target"',
            "CARGO_NET_OFFLINE=true",
            '"$cargo_bin" fetch',
            "--manifest-path",
            "--offline",
            'cfw_verify_release_toolchain_manifest',
            'RUSTC="$rustc_bin"',
            "--target aarch64-apple-darwin",
            lock_patch_check_command,
            lock_patch_apply_command,
            lock_patch_reverse_check_command,
            'members = ["tauri-cli-%s"]',
            'resolver = "2"',
            workspace_manifest_creation,
            workspace_lock_creation,
            '--additional-working-directory "$source_root"',
            'readonly payload="$staging/payload/tauri-cli-$TAURI_CLI_VERSION"',
            '/bin/mv "$source_root" "$payload/source"',
            "artifactKind=pinned-tauri-cli-v2",
            "payloadLayout=bin-and-patched-source-v1",
            'PATH="$cargo_install_root/bin:$(dirname "$cargo_bin"):',
            'readonly cargo_cache_contract="$repo_root/scripts/tauri_cargo_cache_contract.py"',
            'cfw_run_release_python_script',
            '"$repo_root" "$cargo_cache_contract"',
            'reject_cargo_warnings "$fetch_log" "Tauri CLI dependency preparation"',
            'reject_cargo_warnings "$install_log" "tauri-cli installation"',
            "cacheContractSha256=$TAURI_CARGO_CACHE_CONTRACT_SHA256",
            "cacheNormalization=cargo-runtime-metadata-v1",
        ):
            self.assertIn(fragment, installer)
        self.assertNotIn('${TMPDIR:-/tmp}', installer)
        preparation_call = 'verify_cargo_preparation_cache "$prepared_cargo_home"'
        normalization_call = 'normalize_cargo_offline_cache "$offline_cargo_home"'
        fetch_warning_call = (
            'reject_cargo_warnings "$fetch_log" "Tauri CLI dependency preparation"'
        )
        install_warning_call = (
            'reject_cargo_warnings "$install_log" "tauri-cli installation"'
        )
        self.assertEqual(installer.count(preparation_call), 2)
        self.assertEqual(installer.count(normalization_call), 2)
        self.assertEqual(installer.count(fetch_warning_call), 1)
        self.assertEqual(installer.count(install_warning_call), 1)
        self.assertEqual(installer.count(lock_patch_check_command), 1)
        self.assertEqual(installer.count(lock_patch_apply_command), 1)
        self.assertEqual(installer.count(lock_patch_reverse_check_command), 1)
        self.assertEqual(installer.count(workspace_manifest_creation), 1)
        self.assertEqual(installer.count(workspace_lock_creation), 1)
        self.assertEqual(installer.count(workspace_boundary_call), 4)
        self.assertEqual(installer.count(cargo_configuration_call), 4)
        self.assertEqual(
            installer.count(
                'offline_cache_sha256_before="$(cfw_verify_release_toolchain_manifest'
            ),
            1,
        )
        self.assertEqual(
            installer.count(
                'offline_cache_sha256_after="$(cfw_verify_release_toolchain_manifest'
            ),
            1,
        )
        self.assertEqual(installer.count('--output "$offline_cache_manifest"'), 1)
        equality = '[[ "$offline_cache_sha256_after" == "$offline_cache_sha256_before" ]]'
        self.assertEqual(installer.count(equality), 1)
        self.assertNotIn("cargo_path_warning", installer)
        upstream_lock_digest = installer.index(
            'printf \'%s  %s\\n\' "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$cargo_lock"'
        )
        lock_patch_check = installer.index(lock_patch_check_command, upstream_lock_digest)
        lock_patch_apply = installer.index(lock_patch_apply_command, lock_patch_check)
        patched_lock_digest = installer.index(
            'printf \'%s  %s\\n\' "$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256" "$cargo_lock"',
            lock_patch_apply,
        )
        reverse_check = installer.index(
            lock_patch_reverse_check_command, patched_lock_digest
        )
        spin_semantic_check = installer.index(
            "patched Tauri CLI lock has unexpected spin records",
            reverse_check,
        )
        workspace_manifest = installer.index(
            workspace_manifest_creation, spin_semantic_check
        )
        workspace_lock = installer.index(workspace_lock_creation, workspace_manifest)
        workspace_boundary_before_fetch = installer.index(
            workspace_boundary_call, workspace_lock
        )
        cargo_configuration_before_fetch = installer.index(
            cargo_configuration_call, workspace_boundary_before_fetch
        )
        preparation_before = installer.index(preparation_call)
        fetch = installer.index('"$cargo_bin" fetch', cargo_configuration_before_fetch)
        fetch_warning = installer.index(fetch_warning_call, fetch)
        workspace_boundary_after_fetch = installer.index(
            workspace_boundary_call, fetch_warning
        )
        cargo_configuration_after_fetch = installer.index(
            cargo_configuration_call, workspace_boundary_after_fetch
        )
        preparation_after = installer.index(preparation_call, fetch_warning)
        copied = installer.index(
            '/usr/bin/ditto --noqtn "$prepared_cargo_home" "$offline_cargo_home"',
            preparation_after,
        )
        normalized_before = installer.index(
            normalization_call,
            copied,
        )
        manifest = installer.index('--output "$offline_cache_manifest"', normalized_before)
        verified_before = installer.index(
            'offline_cache_sha256_before="$(cfw_verify_release_toolchain_manifest',
            manifest,
        )
        workspace_boundary_before_install = installer.index(
            workspace_boundary_call, verified_before
        )
        cargo_configuration_before_install = installer.index(
            cargo_configuration_call, workspace_boundary_before_install
        )
        install = installer.index(
            '"$cargo_bin" install', cargo_configuration_before_install
        )
        install_warning = installer.index(install_warning_call, install)
        workspace_boundary_after_install = installer.index(
            workspace_boundary_call, install_warning
        )
        cargo_configuration_after_install = installer.index(
            cargo_configuration_call, workspace_boundary_after_install
        )
        normalized_after = installer.index(
            normalization_call,
            cargo_configuration_after_install,
        )
        verified_after = installer.index(
            'offline_cache_sha256_after="$(cfw_verify_release_toolchain_manifest',
            normalized_after,
        )
        compared = installer.index(equality, verified_after)
        self.assertEqual(
            sorted(
                (
                    preparation_before,
                    workspace_manifest,
                    workspace_lock,
                    workspace_boundary_before_fetch,
                    cargo_configuration_before_fetch,
                    fetch,
                    fetch_warning,
                    workspace_boundary_after_fetch,
                    cargo_configuration_after_fetch,
                    preparation_after,
                    copied,
                    normalized_before,
                    manifest,
                    verified_before,
                    workspace_boundary_before_install,
                    cargo_configuration_before_install,
                    install,
                    install_warning,
                    workspace_boundary_after_install,
                    cargo_configuration_after_install,
                    normalized_after,
                    verified_after,
                    compared,
                )
            ),
            [
                preparation_before,
                workspace_manifest,
                workspace_lock,
                workspace_boundary_before_fetch,
                cargo_configuration_before_fetch,
                fetch,
                fetch_warning,
                workspace_boundary_after_fetch,
                cargo_configuration_after_fetch,
                preparation_after,
                copied,
                normalized_before,
                manifest,
                verified_before,
                workspace_boundary_before_install,
                cargo_configuration_before_install,
                install,
                install_warning,
                workspace_boundary_after_install,
                cargo_configuration_after_install,
                normalized_after,
                verified_after,
                compared,
            ],
        )
        collector = (SCRIPTS / "publication/native_collector.py").read_text(encoding="utf-8")
        self.assertIn('tauri_source = (tauri_root / "source")', collector)
        self.assertNotIn('repository / "apps/cfw-tauri-shell/node_modules/esbuild"', collector)

    def test_xcodegen_bootstrap_uses_isolated_resolved_swiftpm(self) -> None:
        bootstrap = (SCRIPTS / "bootstrap_release_toolchain.sh").read_text(
            encoding="utf-8"
        )
        for fragment in (
            "/usr/bin/env -i",
            '"$swift_bin" package',
            "--only-use-versions-from-resolved-file",
            "--disable-netrc",
            "--disable-keychain",
            "--disable-automatic-resolution",
            'GIT_CEILING_DIRECTORIES="$toolchain_root"',
            '/usr/bin/git -C "$payload/source" apply --check "$xcodegen_patch"',
            '/usr/bin/git -C "$payload/source" apply --reverse --check "$xcodegen_patch"',
            "USER=cfw-release",
            "LOGNAME=cfw-release",
            "-Xswiftc -warnings-as-errors",
            '/usr/bin/strip -S "$build_root/release/xcodegen"',
            "isolated XcodeGen build emitted a warning",
            "XcodeGenResourceProbe.xcodeproj/project.pbxproj",
            "artifactKind=pinned-xcodegen-toolchain-v2",
            "buildPolicy=isolated-resolved-swiftpm-v1",
            "packageResolvedSha256=$XCODEGEN_PACKAGE_RESOLVED_SHA256",
            "patchSha256=$XCODEGEN_PATCH_SHA256",
            "patchedSettingsBuilderSha256=$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, bootstrap)
        self.assertNotIn("--skip-update", bootstrap)

    def test_native_project_keeps_script_sandboxing_and_omits_unused_app_intents(self) -> None:
        project_spec = (REPOSITORY / "native/macos/project.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("ENABLE_USER_SCRIPT_SANDBOXING: true", project_spec)
        self.assertNotIn("ENABLE_USER_SCRIPT_SANDBOXING: false", project_spec)
        self.assertNotRegex(
            project_spec,
            r"(?m)^\s*-\s+(?:sdk|framework):\s+AppIntents\.framework\s*(?:#.*)?$",
        )

        generated_project = (
            REPOSITORY / "native/macos/CFWNative.xcodeproj/project.pbxproj"
        ).read_text(encoding="utf-8")
        self.assertNotIn("AppIntents.framework in Frameworks", generated_project)
        self.assertNotIn(
            "/System/Library/Frameworks/AppIntents.framework", generated_project
        )

    def test_custom_toolchain_root_is_the_node_lane_execution_root(self) -> None:
        pins = _pins()
        role = (
            "unsigned-validation"
            if "CFW_UNSIGNED_VALIDATION_PYTHON" in os.environ
            else "production"
        )
        closed_environment = release_tool_environment(
            REPOSITORY, pins, dict(os.environ), role=role
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "verified-toolchains"
            root.mkdir()
            environment = lane_environment(
                REPOSITORY,
                Lane("node-fixture", "true", pinned_node=True),
                pins,
                REPOSITORY / "target/sources/fixture",
                REPOSITORY / "target/artifacts/fixture",
                REPOSITORY / "target/runner-temp/fixture",
                root,
                release_environment=closed_environment,
            )
        expected_bin = root / f"node-{pins['NODE_VERSION']}" / "bin"
        self.assertEqual(environment["CFW_TOOLCHAIN_ROOT"], str(root))
        self.assertEqual(environment["PATH"].split(":", 1)[0], str(expected_bin))


class PublicationToolchainBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "toolchains"
        self.root.mkdir()
        self.pins = _pins()
        role = (
            "unsigned-validation"
            if "CFW_UNSIGNED_VALIDATION_PYTHON" in os.environ
            else "production"
        )
        self.release_environment = release_tool_environment(
            REPOSITORY, self.pins, dict(os.environ), role=role
        )
        self.release_environment["CFW_TOOLCHAIN_ROOT"] = str(self.root)

    def _tree(self, relative: str, manifest_name: str, metadata: list[str]) -> Path:
        root = self.root / relative
        root.mkdir(parents=True)
        marker = root / "marker"
        marker.write_text(relative, encoding="utf-8")
        command = [
            sys.executable,
            "-B",
            str(HASH),
            str(root),
            "--output",
            str(self.root / manifest_name),
            "--algorithm",
            "sha256-tree-v2",
        ]
        for item in metadata:
            command.extend(("--metadata", item))
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return marker

    def _ui_dependencies(self) -> Path:
        node_manifest = self.root / f"node-{self.pins['NODE_VERSION']}.manifest.json"
        node_tree_sha256 = json.loads(node_manifest.read_text(encoding="utf-8"))["sha256"]
        package_lock = REPOSITORY / "apps/cfw-tauri-shell/package-lock.json"
        package_lock_sha256 = hashlib.sha256(package_lock.read_bytes()).hexdigest()
        manifest = self.root / "ui-node-modules.manifest.json"
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(HASH),
                str(REPOSITORY / "apps/cfw-tauri-shell/node_modules"),
                "--output",
                str(manifest),
                "--algorithm",
                "sha256-tree-v2",
                "--metadata",
                "artifactKind=pinned-ui-dependencies-v1",
                "--metadata",
                f"nodeToolchainTreeSha256={node_tree_sha256}",
                "--metadata",
                f"nodeVersion={self.pins['NODE_VERSION']}",
                "--metadata",
                f"packageLockSha256={package_lock_sha256}",
                "--metadata",
                "platform=darwin-arm64",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return manifest

    def _prepare(self) -> dict[str, Path]:
        return {
            "cargo-workspace-sources": Path(
                self.release_environment["CFW_RELEASE_CARGO_INPUT_ROOT"]
            )
            / "vendor.manifest.json",
            "go": self._tree(
                f"go-{self.pins['GO_VERSION']}",
                f"go-{self.pins['GO_VERSION']}.manifest.json",
                [
                    "artifactKind=pinned-go-toolchain-v1",
                    "platform=darwin-arm64",
                    f"sourceArchiveSha256={self.pins['GO_DARWIN_ARM64_SHA256']}",
                    f"version={self.pins['GO_VERSION']}",
                ],
            ),
            "node": self._tree(
                f"node-{self.pins['NODE_VERSION']}",
                f"node-{self.pins['NODE_VERSION']}.manifest.json",
                [
                    "artifactKind=pinned-node-toolchain-v1",
                    "platform=darwin-arm64",
                    f"sourceArchiveSha256={self.pins['NODE_DARWIN_ARM64_SHA256']}",
                    f"version={self.pins['NODE_VERSION']}",
                ],
            ),
            "ui-dependencies": self._ui_dependencies(),
            "xcodegen": self._tree(
                f"xcodegen-{self.pins['XCODEGEN_VERSION']}",
                f"xcodegen-{self.pins['XCODEGEN_VERSION']}.manifest.json",
                [
                    "artifactKind=pinned-xcodegen-toolchain-v2",
                    "buildPolicy=isolated-resolved-swiftpm-v1",
                    f"macosDeploymentTarget={self.pins['MACOS_DEPLOYMENT_TARGET']}",
                    f"packageResolvedSha256={self.pins['XCODEGEN_PACKAGE_RESOLVED_SHA256']}",
                    f"patchSha256={self.pins['XCODEGEN_PATCH_SHA256']}",
                    f"patchedSettingsBuilderSha256={self.pins['XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256']}",
                    "platform=darwin-arm64",
                    f"sourceArchiveSha256={self.pins['XCODEGEN_SOURCE_SHA256']}",
                    f"sourceCommit={self.pins['XCODEGEN_COMMIT']}",
                    f"version={self.pins['XCODEGEN_VERSION']}",
                    f"xcodeBuild={self.pins['XCODE_BUILD_VERSION']}",
                    f"xcodeVersion={self.pins['XCODE_VERSION']}",
                ],
            ),
            "tauri-cli": self._tree(
                f"tauri-cli-{self.pins['TAURI_CLI_VERSION']}",
                f"tauri-cli-{self.pins['TAURI_CLI_VERSION']}.manifest.json",
                [
                    "artifactKind=pinned-tauri-cli-v2",
                    f"cacheContractSha256={self.pins['TAURI_CARGO_CACHE_CONTRACT_SHA256']}",
                    "cacheNormalization=cargo-runtime-metadata-v1",
                    f"crateSha256={self.pins['TAURI_CLI_CRATE_SHA256']}",
                    "dependencyMode=isolated-fetch-offline-locked-v1",
                    f"lockPatchSha256={self.pins['TAURI_CLI_LOCK_PATCH_SHA256']}",
                    f"macosDeploymentTarget={self.pins['MACOS_DEPLOYMENT_TARGET']}",
                    f"patchedCargoLockSha256={self.pins['TAURI_CLI_PATCHED_CARGO_LOCK_SHA256']}",
                    "payloadLayout=bin-and-patched-source-v1",
                    "platform=darwin-arm64",
                    f"rustToolchain={self.pins['RUST_VERSION']}-aarch64-apple-darwin",
                    f"spinCrateSha256={self.pins['TAURI_CLI_SPIN_CRATE_SHA256']}",
                    f"spinVersion={self.pins['TAURI_CLI_SPIN_VERSION']}",
                    f"upstreamCargoLockSha256={self.pins['TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256']}",
                    f"version={self.pins['TAURI_CLI_VERSION']}",
                    f"xcodeBuild={self.pins['XCODE_BUILD_VERSION']}",
                    f"xcodeVersion={self.pins['XCODE_VERSION']}",
                ],
            ),
            "go-release-tools": self._tree(
                "go-workspace/bin",
                "go-workspace-bin.manifest.json",
                [
                    "artifactKind=pinned-go-release-tools-v1",
                    f"goVersion={self.pins['GO_VERSION']}",
                    f"gomobileModuleSum={self.pins['GOMOBILE_MODULE_SUM']}",
                    f"gomobileVersion={self.pins['GOMOBILE_VERSION']}",
                    f"govulncheckModuleSum={self.pins['GOVULNCHECK_MODULE_SUM']}",
                    f"govulncheckVersion={self.pins['GOVULNCHECK_VERSION']}",
                    "platform=darwin-arm64",
                ],
            ),
            "go-module-cache": self._tree(
                "go-workspace/pkg/mod",
                "go-module-cache.manifest.json",
                [
                    "artifactKind=pinned-go-module-cache-v2",
                    f"buildTags={self.pins['LIBBOX_BUILD_TAGS']}",
                    f"goVersion={self.pins['GO_VERSION']}",
                    "moduleCacheContractSha256="
                    f"{self.pins['LIBBOX_MODULE_CACHE_CONTRACT_SHA256']}",
                    f"patchedGoModSha256={self.pins['SING_BOX_PATCHED_GO_MOD_SHA256']}",
                    f"patchedGoSumSha256={self.pins['SING_BOX_PATCHED_GO_SUM_SHA256']}",
                    "platform=darwin-arm64",
                    f"sourceCommit={self.pins['SING_BOX_COMMIT']}",
                ],
            ),
        }

    def test_publication_binding_contains_every_verified_tree(self) -> None:
        markers = self._prepare()
        root, digests = verified_release_toolchain_trees(
            REPOSITORY, self.pins, self.release_environment
        )
        self.assertEqual(root, self.root.resolve())
        self.assertEqual(set(digests), set(markers))
        self.assertTrue(all(len(digest) == 64 for digest in digests.values()))

    def test_publication_binding_uses_the_supplied_closed_environment(self) -> None:
        markers = self._prepare()
        environment = dict(self.release_environment)
        environment["CFW_TOOLCHAIN_ROOT"] = str(self.root)
        with patch.dict(os.environ, {"PATH": "/tmp/untrusted"}):
            root, digests = verified_release_toolchain_trees(
                REPOSITORY, self.pins, environment=environment
            )
        self.assertEqual(root, self.root.resolve())
        self.assertEqual(set(digests), set(markers))

    def test_publication_binding_rejects_tree_drift(self) -> None:
        markers = self._prepare()
        markers["go-module-cache"].write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(PublicationError, "verification failed"):
            verified_release_toolchain_trees(
                REPOSITORY, self.pins, self.release_environment
            )

    def test_go_module_cache_rejects_previous_closure_contract(self) -> None:
        self._tree(
            "go-workspace/pkg/mod",
            "go-module-cache.manifest.json",
            [
                "artifactKind=pinned-go-module-cache-v1",
                f"buildTags={self.pins['LIBBOX_BUILD_TAGS']}",
                f"goVersion={self.pins['GO_VERSION']}",
                f"patchedGoModSha256={self.pins['SING_BOX_PATCHED_GO_MOD_SHA256']}",
                f"patchedGoSumSha256={self.pins['SING_BOX_PATCHED_GO_SUM_SHA256']}",
                "platform=darwin-arm64",
                f"sourceCommit={self.pins['SING_BOX_COMMIT']}",
            ],
        )
        shell = (
            'set -euo pipefail; source "$1"; source "$2"; '
            'cfw_verify_go_module_cache_tree "$3" "$4"'
        )
        completed = subprocess.run(
            [
                "/bin/bash",
                "-c",
                shell,
                "toolchain-test",
                str(PINS),
                str(CONTRACT),
                str(REPOSITORY),
                str(self.root),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"metadata field set mismatch", completed.stderr)

    def test_publication_binding_rejects_missing_or_symlink_root(self) -> None:
        linked_root = Path(self.temporary.name) / "linked-toolchains"
        linked_root.symlink_to(self.root, target_is_directory=True)
        for unsafe_root in (linked_root, Path(self.temporary.name) / "missing"):
            with self.subTest(root=unsafe_root):
                environment = dict(self.release_environment)
                environment["CFW_TOOLCHAIN_ROOT"] = str(unsafe_root)
                with self.assertRaisesRegex(PublicationError, "missing.*symlink"):
                    verified_release_toolchain_trees(
                        REPOSITORY, self.pins, environment
                    )

    def test_publication_binding_rejects_split_brain_pins(self) -> None:
        mismatched = dict(self.pins)
        mismatched["NODE_VERSION"] = "0.0.0"
        with self.assertRaisesRegex(PublicationError, "pins do not match"):
            verified_release_toolchain_trees(
                REPOSITORY, mismatched, self.release_environment
            )

    def test_contract_does_not_shadow_readonly_caller_paths(self) -> None:
        self._prepare()
        shell = (
            'set -euo pipefail; source "$1"; source "$2"; '
            'readonly toolchain_root="$4"; '
            'cfw_verify_node_toolchain_tree "$3" "$toolchain_root"'
        )
        completed = subprocess.run(
            [
                "/bin/bash",
                "-c",
                shell,
                "toolchain-test",
                str(PINS),
                str(CONTRACT),
                str(REPOSITORY),
                str(self.root),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())


if __name__ == "__main__":
    unittest.main()
