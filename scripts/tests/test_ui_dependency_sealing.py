#!/usr/bin/env python3
"""Release UI dependencies must be byte-bound before any build executes."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent.parent
REPOSITORY = SCRIPTS.parent
HASH = SCRIPTS / "hash_artifact.py"
PINS = SCRIPTS / "dependency_pins.env"
CONTRACT = SCRIPTS / "ui_dependency_contract.sh"
TOOLCHAIN_CONTRACT = SCRIPTS / "release_toolchain_contract.sh"


def _pins() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in PINS.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _hash_artifact(artifact: Path, manifest: Path, metadata: list[str]) -> None:
    command = [
        sys.executable,
        "-B",
        str(HASH),
        str(artifact),
        "--output",
        str(manifest),
        "--algorithm",
        "sha256-tree-v2",
    ]
    for item in metadata:
        command.extend(("--metadata", item))
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class PinnedNpmBoundaryFixture:
    def __init__(
        self,
        test_case: unittest.TestCase,
        *,
        npm_exit_code: int = 0,
        mutate_dependencies: bool = False,
        toolchain_directory_name: str = "toolchains",
    ) -> None:
        temporary = tempfile.TemporaryDirectory()
        test_case.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repository = self.base / "repository"
        self.scripts = self.repository / "scripts"
        self.shell_root = self.repository / "apps/cfw-tauri-shell"
        self.dependencies = self.shell_root / "node_modules"
        self.toolchains = self.repository / toolchain_directory_name
        self.pinned_marker = self.base / "pinned-node-ran"
        self.poison_marker = self.base / "ambient-node-ran"
        self.argument_capture = self.base / "pinned-node-arguments"
        self.environment_capture = self.base / "pinned-node-environment"
        self.empty_path = self.base / "empty-path"
        self.ambient_bin = self.base / "ambient-bin"
        self.pins = _pins()

        self.scripts.mkdir(parents=True)
        self.dependencies.mkdir(parents=True)
        self.toolchains.mkdir()
        self.empty_path.mkdir()
        self.ambient_bin.mkdir()
        for relative in (
            "build_ui_with_pinned_node.sh",
            "dependency_pins.env",
            "hash_artifact.py",
            "release_python_launcher.sh",
            "release_toolchain_contract.sh",
            "ui_dependency_contract.sh",
            "verify_artifact_manifest.py",
        ):
            shutil.copy2(SCRIPTS / relative, self.scripts / relative)
        shutil.copy2(
            REPOSITORY / "apps/cfw-tauri-shell/package-lock.json",
            self.shell_root / "package-lock.json",
        )
        self.dependency_file = self.dependencies / "package.js"
        self.dependency_file.write_text(
            "export const value = 1;\n", encoding="utf-8"
        )

        self.node_root = self.toolchains / f"node-{self.pins['NODE_VERSION']}"
        (self.node_root / "bin").mkdir(parents=True)
        self.node = self.node_root / "bin/node"
        self.npm = self.node_root / "bin/npm"
        mutation = ""
        if mutate_dependencies:
            mutation = (
                f"printf '%s\\n' 'mutated by npm' > "
                f"{shlex.quote(str(self.dependency_file))}\n"
            )
        self.node.write_text(
            "#!/bin/sh\n"
            "if [ \"${1:-}\" = '--version' ]; then\n"
            f"  printf '%s\\n' 'v{self.pins['NODE_VERSION']}'\n"
            "  exit 0\n"
            "fi\n"
            f"printf '%s\\n' pinned >> {shlex.quote(str(self.pinned_marker))}\n"
            f"printf '%s\\n' \"$@\" > {shlex.quote(str(self.argument_capture))}\n"
            "{\n"
            "  printf '%s\\n' \"$NPM_CONFIG_OFFLINE\"\n"
            "  printf '%s\\n' \"$NPM_CONFIG_USERCONFIG\"\n"
            "  printf '%s\\n' \"$PATH\"\n"
            f"}} > {shlex.quote(str(self.environment_capture))}\n"
            f"{mutation}"
            f"exit {npm_exit_code}\n",
            encoding="utf-8",
        )
        self.node.chmod(0o755)
        self.npm.write_text("#!/usr/bin/env node\n", encoding="utf-8")
        self.npm.chmod(0o755)

        node_manifest = self.toolchains / f"{self.node_root.name}.manifest.json"
        _hash_artifact(
            self.node_root,
            node_manifest,
            [
                "artifactKind=pinned-node-toolchain-v1",
                "platform=darwin-arm64",
                f"sourceArchiveSha256={self.pins['NODE_DARWIN_ARM64_SHA256']}",
                f"version={self.pins['NODE_VERSION']}",
            ],
        )
        node_tree_sha256 = json.loads(node_manifest.read_text(encoding="utf-8"))[
            "sha256"
        ]
        lock_sha256 = hashlib.sha256(
            (self.shell_root / "package-lock.json").read_bytes()
        ).hexdigest()
        _hash_artifact(
            self.dependencies,
            self.toolchains / "ui-node-modules.manifest.json",
            [
                "artifactKind=pinned-ui-dependencies-v1",
                f"nodeToolchainTreeSha256={node_tree_sha256}",
                f"nodeVersion={self.pins['NODE_VERSION']}",
                f"packageLockSha256={lock_sha256}",
                "platform=darwin-arm64",
            ],
        )

        ambient_node = self.ambient_bin / "node"
        ambient_node.write_text(
            "#!/bin/sh\n"
            f"touch {shlex.quote(str(self.poison_marker))}\n"
            "exit 90\n",
            encoding="utf-8",
        )
        ambient_node.chmod(0o755)

    def run_helper(self) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment.update(
            {
                "CFW_RELEASE_PYTHON_EXECUTABLE": sys.executable,
                "CFW_TOOLCHAIN_ROOT": str(self.toolchains),
                "PATH": f"{self.ambient_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            }
        )
        return subprocess.run(
            [
                str(self.scripts / "build_ui_with_pinned_node.sh"),
                "--verify-dependencies",
            ],
            cwd=self.repository,
            env=environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


class UIDependencyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.pins = _pins()
        self.toolchains = self.base / "toolchains"
        self.node_root = self.toolchains / f"node-{self.pins['NODE_VERSION']}"
        (self.node_root / "bin").mkdir(parents=True)
        (self.node_root / "bin/node").write_text("sealed node\n", encoding="utf-8")
        self._hash(
            self.node_root,
            self.toolchains / f"{self.node_root.name}.manifest.json",
            [
                "artifactKind=pinned-node-toolchain-v1",
                "platform=darwin-arm64",
                f"sourceArchiveSha256={self.pins['NODE_DARWIN_ARM64_SHA256']}",
                f"version={self.pins['NODE_VERSION']}",
            ],
        )
        self.node_tree_sha256 = self._manifest_sha256(
            self.toolchains / f"{self.node_root.name}.manifest.json"
        )

        self.dependencies = self.base / "node_modules"
        self.dependencies.mkdir()
        self.dependency_file = self.dependencies / "package.js"
        self.dependency_file.write_text("export const value = 1;\n", encoding="utf-8")
        lock = REPOSITORY / "apps/cfw-tauri-shell/package-lock.json"
        lock_sha256 = hashlib.sha256(lock.read_bytes()).hexdigest()
        self.dependency_manifest = self.base / "ui.manifest.json"
        self._hash(
            self.dependencies,
            self.dependency_manifest,
            [
                "artifactKind=pinned-ui-dependencies-v1",
                f"nodeToolchainTreeSha256={self.node_tree_sha256}",
                f"nodeVersion={self.pins['NODE_VERSION']}",
                f"packageLockSha256={lock_sha256}",
                "platform=darwin-arm64",
            ],
        )

    @staticmethod
    def _manifest_sha256(path: Path) -> str:
        return json.loads(path.read_text(encoding="utf-8"))["sha256"]

    def _hash(self, artifact: Path, manifest: Path, metadata: list[str]) -> None:
        _hash_artifact(artifact, manifest, metadata)

    def verify(self) -> subprocess.CompletedProcess[str]:
        shell = (
            'set -euo pipefail; source "$1"; source "$2"; source "$3"; '
            'cfw_verify_ui_dependencies_artifact "$4" "$5" "$6" "$7"'
        )
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                shell,
                "ui-dependency-test",
                str(PINS),
                str(TOOLCHAIN_CONTRACT),
                str(CONTRACT),
                str(REPOSITORY),
                str(self.toolchains),
                str(self.dependencies),
                str(self.dependency_manifest),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_sealed_dependency_tree_is_accepted(self) -> None:
        completed = self.verify()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, f"{self._manifest_sha256(self.dependency_manifest)}\n")

    def test_same_version_dependency_byte_drift_is_rejected(self) -> None:
        self.dependency_file.write_text("export const value = 2;\n", encoding="utf-8")
        completed = self.verify()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("manifest sha256 mismatch", completed.stderr)

    def test_node_tree_drift_invalidates_dependency_evidence(self) -> None:
        (self.node_root / "bin/node").write_text("same version, different bytes\n", encoding="utf-8")
        completed = self.verify()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("manifest sha256 mismatch", completed.stderr)


class UIDependencyConsumerTests(unittest.TestCase):
    def test_build_verifies_dependencies_before_and_after_execution(self) -> None:
        text = (SCRIPTS / "build_ui_with_pinned_node.sh").read_text(encoding="utf-8")
        self.assertGreaterEqual(text.count("cfw_verify_ui_dependencies_tree"), 2)
        self.assertIn("/usr/bin/env -i", text)
        self.assertIn("npm_offline=true", text)
        self.assertIn('NPM_CONFIG_OFFLINE="$npm_offline"', text)
        self.assertIn('"$npm_bin" "${npm_arguments[@]}"', text)

    def test_verify_dependencies_executes_env_node_npm_with_only_pinned_node(self) -> None:
        fixture = PinnedNpmBoundaryFixture(self)
        legacy_environment = {"PATH": str(fixture.empty_path)}
        legacy = subprocess.run(
            [
                str(fixture.npm),
                "--prefix",
                str(fixture.shell_root),
                "ls",
                "--all",
                "--offline",
            ],
            env=legacy_environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(legacy.returncode, 127, legacy.stderr)
        self.assertIn("node", legacy.stderr)
        self.assertFalse(fixture.pinned_marker.exists())
        self.assertFalse(fixture.poison_marker.exists())

        completed = fixture.run_helper()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(fixture.pinned_marker.read_text(encoding="utf-8"), "pinned\n")
        self.assertFalse(fixture.poison_marker.exists())
        self.assertEqual(
            fixture.argument_capture.read_text(encoding="utf-8").splitlines(),
            [
                str(fixture.npm),
                "ls",
                "--all",
                "--offline",
            ],
        )
        self.assertEqual(
            fixture.environment_capture.read_text(encoding="utf-8").splitlines(),
            [
                "true",
                "/dev/null",
                f"{fixture.node_root}/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            ],
        )

    def test_verify_dependencies_propagates_pinned_npm_failure(self) -> None:
        fixture = PinnedNpmBoundaryFixture(self, npm_exit_code=42)
        completed = fixture.run_helper()
        self.assertEqual(completed.returncode, 42, completed.stderr)
        self.assertEqual(fixture.pinned_marker.read_text(encoding="utf-8"), "pinned\n")
        self.assertFalse(fixture.poison_marker.exists())

    def test_verify_dependencies_rejects_unrepresentable_node_root(self) -> None:
        fixture = PinnedNpmBoundaryFixture(
            self, toolchain_directory_name="toolchains:invalid"
        )
        completed = fixture.run_helper()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot be represented safely in PATH", completed.stderr)
        self.assertFalse(fixture.pinned_marker.exists())
        self.assertFalse(fixture.poison_marker.exists())

    def test_verify_dependencies_never_falls_back_from_unusable_pinned_node(self) -> None:
        fixture = PinnedNpmBoundaryFixture(self)
        fixture.node.chmod(0o644)
        completed = fixture.run_helper()
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(fixture.pinned_marker.exists())
        self.assertFalse(fixture.poison_marker.exists())

    def test_verify_dependencies_rejects_dependency_drift_before_npm(self) -> None:
        fixture = PinnedNpmBoundaryFixture(self)
        fixture.dependency_file.write_text(
            "export const value = 2;\n", encoding="utf-8"
        )
        completed = fixture.run_helper()
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(fixture.pinned_marker.exists())
        self.assertFalse(fixture.poison_marker.exists())

    def test_verify_dependencies_rejects_dependency_drift_caused_by_npm(self) -> None:
        fixture = PinnedNpmBoundaryFixture(self, mutate_dependencies=True)
        completed = fixture.run_helper()
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(fixture.pinned_marker.read_text(encoding="utf-8"), "pinned\n")
        self.assertFalse(fixture.poison_marker.exists())

    def test_preparation_uses_clean_network_boundary_and_breaks_hardlinks(self) -> None:
        text = (SCRIPTS / "prepare_ui_dependencies.sh").read_text(encoding="utf-8")
        for required in (
            "/usr/bin/env -i",
            "NPM_CONFIG_REGISTRY=https://registry.npmjs.org/",
            "ci --ignore-scripts=false --install-links=true",
            '/bin/cp -R "$workspace/node_modules"',
            "--algorithm sha256-tree-v2",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
