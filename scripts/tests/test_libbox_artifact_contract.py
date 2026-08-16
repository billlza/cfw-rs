#!/usr/bin/env python3
"""Fail-closed tests for the exact shipped Libbox artifact contract."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.publication.graph_model import load_pins


REPOSITORY = Path(__file__).resolve().parent.parent.parent
SCRIPTS = REPOSITORY / "scripts"
HASH = SCRIPTS / "hash_artifact.py"
PIN_PATH = SCRIPTS / "dependency_pins.env"
TOOLCHAIN_SHA = "a" * 64
TOOLS_SHA = "b" * 64
MODULE_CACHE_SHA = "c" * 64


class LibboxArtifactContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "Libbox.xcframework"
        self.artifact.mkdir()
        (self.artifact / "Libbox").write_bytes(b"source-bound-libbox")
        self.manifest = self.root / "Libbox.xcframework.manifest.json"
        self.pins = load_pins(PIN_PATH)
        self.metadata = {
            "sourceTag": self.pins["SING_BOX_VERSION"],
            "sourceCommit": self.pins["SING_BOX_COMMIT"],
            "goVersion": self.pins["GO_VERSION"],
            "goToolchainTreeSha256": TOOLCHAIN_SHA,
            "goToolsTreeSha256": TOOLS_SHA,
            "goModuleCacheTreeSha256": MODULE_CACHE_SHA,
            "gomobileVersion": self.pins["GOMOBILE_VERSION"],
            "gomobileCommit": self.pins["GOMOBILE_COMMIT"],
            "gomobileModuleSum": self.pins["GOMOBILE_MODULE_SUM"],
            "archiveDeterminism": "zeroArDate-v1",
            "headerNormalization": "angleBracketFrameworkImports-v1",
            "platform": self.pins["LIBBOX_APPLE_PLATFORM"],
            "buildTags": self.pins["LIBBOX_BUILD_TAGS"],
            "nonMacOsTags": self.pins["LIBBOX_NON_MACOS_TAGS"],
            "upstreamGoModSha256": self.pins["SING_BOX_UPSTREAM_GO_MOD_SHA256"],
            "upstreamGoSumSha256": self.pins["SING_BOX_UPSTREAM_GO_SUM_SHA256"],
            "securityPatchSha256": self.pins["SING_BOX_SECURITY_PATCH_SHA256"],
            "rawPacketPatchSha256": self.pins["SING_BOX_RAW_PACKET_PATCH_SHA256"],
            "dnsFailoverPatchSha256": self.pins["SING_BOX_DNS_FAILOVER_PATCH_SHA256"],
            "patchedDiffSha256": self.pins["SING_BOX_PATCHED_DIFF_SHA256"],
            "combinedDiffSha256": self.pins["SING_BOX_COMBINED_DIFF_SHA256"],
            "patchedGoModSha256": self.pins["SING_BOX_PATCHED_GO_MOD_SHA256"],
            "patchedGoSumSha256": self.pins["SING_BOX_PATCHED_GO_SUM_SHA256"],
        }
        self.write_manifest()

    def write_manifest(self) -> None:
        self.manifest.unlink(missing_ok=True)
        command = [
            sys.executable,
            "-B",
            str(HASH),
            str(self.artifact),
            "--output",
            str(self.manifest),
            "--algorithm",
            "sha256-tree-v1",
        ]
        for key, value in self.metadata.items():
            command.extend(("--metadata", f"{key}={value}"))
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def verify(
        self,
        *,
        toolchain_sha: str = TOOLCHAIN_SHA,
        tools_sha: str = TOOLS_SHA,
        module_cache_sha: str = MODULE_CACHE_SHA,
    ) -> subprocess.CompletedProcess[str]:
        script = r"""
set -euo pipefail
source "$1/scripts/dependency_pins.env"
source "$1/scripts/libbox_source_contract.sh"
libbox_verify_xcframework_artifact "$1" "$2" "$3" "$4" "$5" "$6"
"""
        return subprocess.run(
            [
                "bash",
                "-c",
                script,
                "bash",
                str(REPOSITORY),
                str(self.artifact),
                str(self.manifest),
                toolchain_sha,
                tools_sha,
                module_cache_sha,
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def mutate_manifest(self, mutation) -> None:
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        mutation(document)
        self.manifest.write_text(
            json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_exact_generated_contract_is_accepted(self) -> None:
        completed = self.verify()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertRegex(completed.stdout, r"^[0-9a-f]{64}\n$")

    def test_every_stale_or_missing_metadata_field_is_rejected(self) -> None:
        for key in self.metadata:
            with self.subTest(stale=key):
                self.write_manifest()
                self.mutate_manifest(
                    lambda document, key=key: document["metadata"].__setitem__(
                        key, "stale"
                    )
                )
                self.assertNotEqual(self.verify().returncode, 0)
            with self.subTest(missing=key):
                self.write_manifest()
                self.mutate_manifest(
                    lambda document, key=key: document["metadata"].pop(key)
                )
                self.assertNotEqual(self.verify().returncode, 0)

    def test_unknown_metadata_is_rejected(self) -> None:
        self.mutate_manifest(
            lambda document: document["metadata"].__setitem__("unexpected", "value")
        )
        self.assertNotEqual(self.verify().returncode, 0)

    def test_toolchain_digest_drift_is_rejected(self) -> None:
        for arguments in (
            {"toolchain_sha": "d" * 64},
            {"tools_sha": "d" * 64},
            {"module_cache_sha": "d" * 64},
            {
                "toolchain_sha": TOOLS_SHA,
                "tools_sha": MODULE_CACHE_SHA,
                "module_cache_sha": TOOLCHAIN_SHA,
            },
        ):
            with self.subTest(arguments=arguments):
                self.assertNotEqual(self.verify(**arguments).returncode, 0)

    def test_artifact_content_drift_is_rejected(self) -> None:
        (self.artifact / "Libbox").write_bytes(b"changed-after-manifest")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_algorithm_drift_is_rejected(self) -> None:
        self.mutate_manifest(
            lambda document: document.__setitem__("algorithm", "sha256-tree-v2")
        )
        self.assertNotEqual(self.verify().returncode, 0)

    def test_build_script_forces_zero_archive_dates_and_binds_the_policy(self) -> None:
        build_source = (SCRIPTS / "build_libbox.sh").read_text(encoding="utf-8")
        contract_source = (SCRIPTS / "libbox_source_contract.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("export ZERO_AR_DATE=1", build_source)
        binding = '--metadata "archiveDeterminism=zeroArDate-v1"'
        self.assertIn(binding, build_source)
        self.assertIn(binding, contract_source)


if __name__ == "__main__":
    unittest.main()
