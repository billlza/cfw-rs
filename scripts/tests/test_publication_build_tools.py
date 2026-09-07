from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.publication import graph_model
from scripts.publication.build_tool_preparation import build_tool_specs
from scripts.publication.common import PublicationError
from scripts.publication.graph_model import ComponentSeed
from scripts.publication.license_resolution import resolve_license
from scripts.publication.source_preparation import source_input_evidence


MIT_TEXT = """MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
"""


class PublicationBuildToolTests(unittest.TestCase):
    def test_graph_output_limit_terminates_the_real_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(
            graph_model, "MAX_COMMAND_BYTES", 1024
        ):
            with self.assertRaisesRegex(PublicationError, "fixed bound"):
                graph_model.run(
                    ["/usr/bin/yes", "bounded-graph-output"],
                    Path(directory).resolve(),
                    {
                        "HOME": str(Path.home()),
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PATH": "/usr/bin:/bin",
                    },
                )

    def test_successful_graph_command_with_stderr_is_release_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(PublicationError, "emitted diagnostics"):
                graph_model.run(
                    [
                        "/bin/bash",
                        "-p",
                        "-c",
                        "printf '{}'; printf 'warning: degraded graph\\n' >&2",
                    ],
                    Path(directory).resolve(),
                    {
                        "HOME": str(Path.home()),
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PATH": "/usr/bin:/bin",
                    },
                )

    def test_repository_source_enumeration_uses_fixed_git_with_closed_environment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            subprocess.run(
                ["/usr/bin/git", "-C", str(repository), "init", "-q"],
                check=True,
                capture_output=True,
            )
            source = repository / "source"
            source.mkdir()
            source_file = source / "main.rs"
            source_file.write_text("fn main() {}\n", encoding="utf-8")
            subprocess.run(
                ["/usr/bin/git", "-C", str(repository), "add", "source/main.rs"],
                check=True,
                capture_output=True,
            )
            fake_bin = repository / "fake-bin"
            fake_bin.mkdir()
            marker = repository / "ambient-git-ran"
            fake_git = fake_bin / "git"
            fake_git.write_text(
                f"#!/bin/sh\n/usr/bin/touch '{marker}'\nexit 97\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            seed = ComponentSeed(
                identifier="cargo:fixture:0000000000000000",
                name="fixture",
                version="1.0.0",
                ecosystem="cargo",
                scope="runtime",
                purl="pkg:cargo/fixture@1.0.0",
                source_root=source,
                repository_source=True,
            )

            evidence = source_input_evidence(
                repository,
                seed,
                source,
                {
                    "HOME": str(repository / "hostile-home"),
                    "PATH": str(fake_bin),
                    "GIT_DIR": str(repository / "attacker-git-dir"),
                },
            )

            self.assertEqual(evidence["method"], "git-tracked-files-v1")
            self.assertEqual(evidence["file_count"], 1)
            self.assertFalse(marker.exists())

    def test_repository_root_source_uses_the_release_identity_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            subprocess.run(
                ["/usr/bin/git", "-C", str(repository), "init", "-q"],
                check=True,
                capture_output=True,
            )
            (repository / "README.md").write_text(
                "release source\n", encoding="utf-8"
            )
            workspace_settings = repository / ".vscode/settings.json"
            workspace_settings.parent.mkdir()
            workspace_settings.write_text(
                '{"editor.tabSize": 4}\n', encoding="utf-8"
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(repository),
                    "add",
                    "README.md",
                    ".vscode/settings.json",
                ],
                check=True,
                capture_output=True,
            )
            seed = ComponentSeed(
                identifier="application:fixture:0000000000000000",
                name="fixture",
                version="1.0.0",
                ecosystem="application",
                scope="runtime",
                purl="pkg:generic/fixture@1.0.0",
                source_root=repository,
                repository_source=True,
            )

            evidence = source_input_evidence(repository, seed, repository)

            self.assertEqual(evidence["method"], "git-tracked-files-v1")
            self.assertEqual(evidence["file_count"], 1)
            self.assertEqual(evidence["total_bytes"], len(b"release source\n"))

    def test_external_build_tool_keeps_hashes_but_not_corresponding_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            root = repository / "tool"
            root.mkdir()
            metadata = root / "package.json"
            metadata.write_text(
                '{"name":"fixture-tool","version":"1.0.0","license":"MIT"}',
                encoding="utf-8",
            )
            (root / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
            executable = root / "fixture-tool"
            executable.write_bytes(b"build-tool-binary")
            hardlink = root / "fixture-tool-hardlink"
            os.link(executable, hardlink)
            seed = ComponentSeed(
                identifier="npm:fixture-tool:0000000000000000",
                name="fixture-tool",
                version="1.0.0",
                ecosystem="npm",
                scope="build",
                purl="pkg:npm/fixture-tool@1.0.0",
                source_root=None,
                license_root=root,
                metadata_path=metadata,
                declared_license="MIT",
                external_build_tool=True,
                provenance_paths=(hardlink,),
            )
            review = {
                "source_evidence": source_input_evidence(repository, seed, None),
                "license_resolution": resolve_license(seed),
            }
            specs = build_tool_specs(repository, {seed.identifier: seed}, {seed.identifier: review})
            self.assertEqual(len(specs), 1)
            self.assertEqual(specs[0]["distribution"], "external-build-tool-not-distributed")
            self.assertEqual(specs[0]["executables"][0]["size"], len(b"build-tool-binary"))
            self.assertNotIn("source_path", specs[0])

    def test_xcode_manual_required_and_forged_mit_reviews_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            resources = repository / "Xcode.app/Contents/Resources"
            resources.mkdir(parents=True)
            license_path = resources / "License.rtf"
            license_path.write_text("Pinned Apple Xcode license terms", encoding="utf-8")
            metadata = repository / "dependency_pins.env"
            metadata.write_text("XCODE_VERSION=26.6\n", encoding="utf-8")
            executable = repository / "xcodebuild"
            executable.write_bytes(b"xcodebuild-fixture")
            expression = "LicenseRef-Apple-Xcode-EULA-26.6"
            seed = ComponentSeed(
                identifier="toolchain:xcode:0000000000000000",
                name="xcode",
                version="26.6",
                ecosystem="toolchain",
                scope="toolchain",
                purl="pkg:generic/xcode@26.6",
                source_root=None,
                license_root=resources,
                metadata_path=metadata,
                declared_license=expression,
                external_build_tool=True,
                provenance_paths=(executable,),
            )
            source_evidence = source_input_evidence(repository, seed, None)
            required = resolve_license(seed)
            self.assertEqual(required["status"], "manual-required")

            with self.assertRaisesRegex(PublicationError, "requires legal license review"):
                build_tool_specs(
                    repository,
                    {seed.identifier: seed},
                    {
                        seed.identifier: {
                            "source_evidence": source_evidence,
                            "license_resolution": required,
                        }
                    },
                )

            forged_automatic = {
                **required,
                "status": "automatic",
                "expression": "MIT",
                "method": "declared-spdx-selected-branch-plus-license-text-v2",
                "reason": "",
            }
            with self.assertRaisesRegex(PublicationError, "no longer recomputes"):
                build_tool_specs(
                    repository,
                    {seed.identifier: seed},
                    {
                        seed.identifier: {
                            "source_evidence": source_evidence,
                            "license_resolution": forged_automatic,
                        }
                    },
                )

            forged_manual = {
                **required,
                "status": "manual-reviewed",
                "expression": "MIT",
                "method": "human-legal-review",
                "reason": "Incorrectly reclassified the Apple EULA as MIT.",
                "files": [{**item, "supports": ["MIT"]} for item in required["files"]],
            }
            with self.assertRaisesRegex(PublicationError, "changed declared"):
                build_tool_specs(
                    repository,
                    {seed.identifier: seed},
                    {
                        seed.identifier: {
                            "source_evidence": source_evidence,
                            "license_resolution": forged_manual,
                        }
                    },
                )

            reviewed = {
                **required,
                "status": "manual-reviewed",
                "method": "human-legal-review",
                "reason": "Reviewed the exact pinned Xcode EULA for build-only use.",
                "files": [
                    {**item, "supports": [expression]} for item in required["files"]
                ],
            }
            specs = build_tool_specs(
                repository,
                {seed.identifier: seed},
                {
                    seed.identifier: {
                        "source_evidence": source_evidence,
                        "license_resolution": reviewed,
                    }
                },
            )
            self.assertEqual(specs[0]["license_reference"], expression)


if __name__ == "__main__":
    unittest.main()
