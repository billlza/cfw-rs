#!/usr/bin/env python3
"""Release UI dependencies must be byte-bound before any build executes."""

from __future__ import annotations

import hashlib
from pathlib import Path
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
        import json

        return json.loads(path.read_text(encoding="utf-8"))["sha256"]

    def _hash(self, artifact: Path, manifest: Path, metadata: list[str]) -> None:
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
