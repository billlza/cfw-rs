from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.publication.common import PublicationError
from scripts.publication import graph_collectors
from scripts.publication.native_collector import _normalize_native_graph


class NativeCollectorTests(unittest.TestCase):
    def test_project_root_is_normalized_and_relative_paths_remain_relative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "Sources/CFWNative"
            source.mkdir(parents=True)
            graph = {
                "path": str(root),
                "targets": [{"name": "CFWNative", "path": "Sources/CFWNative"}],
            }
            self.assertEqual(
                _normalize_native_graph(graph, root),
                {
                    "path": ".",
                    "targets": [{"name": "CFWNative", "path": "Sources/CFWNative"}],
                },
            )

    def test_absolute_path_outside_project_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaisesRegex(PublicationError, "escaped"):
                _normalize_native_graph({"path": "/private/tmp/other"}, root)

    def test_non_path_absolute_string_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaisesRegex(PublicationError, "absolute path"):
                _normalize_native_graph({"command": "/usr/bin/swift"}, root)


class PublicationCollectorEnvironmentTests(unittest.TestCase):
    def test_every_command_collector_receives_one_closed_environment(self) -> None:
        repository = Path("/release/repository")
        libbox_source = Path("/release/libbox")
        release_environment = {
            "HOME": "/Users/release",
            "PATH": "/fixed/rust:/usr/bin:/bin",
            "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
        }
        empty_result = ({}, set(), {}, {})
        with (
            patch.object(graph_collectors, "load_pins", return_value={"PIN": "value"}),
            patch.object(
                graph_collectors, "collect_cargo", return_value=empty_result
            ) as cargo,
            patch.object(graph_collectors, "collect_npm", return_value=empty_result),
            patch.object(
                graph_collectors, "collect_go", return_value=empty_result
            ) as go,
            patch.object(
                graph_collectors, "collect_native", return_value=empty_result
            ) as native,
            patch.object(
                graph_collectors, "collect_toolchains", return_value=({}, set())
            ) as toolchains,
        ):
            graph_collectors.collect_all(
                repository, libbox_source, release_environment
            )

        self.assertIs(cargo.call_args.args[-1], release_environment)
        self.assertIs(go.call_args.args[-1], release_environment)
        self.assertIs(native.call_args.args[-1], release_environment)
        self.assertIs(toolchains.call_args.args[-1], release_environment)

    def test_publication_entry_has_no_ambient_environment_fallback(self) -> None:
        release_toolchains_source = (
            Path(graph_collectors.__file__).with_name("release_toolchains.py")
        ).read_text(encoding="utf-8")
        preparer_source = Path(graph_collectors.__file__).with_name(
            "preparer.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("os.environ", release_toolchains_source)
        self.assertIn("run_bounded_process(", release_toolchains_source)
        self.assertIn("MAX_TOOLCHAIN_VERIFICATION_OUTPUT_BYTES", release_toolchains_source)
        self.assertIn("release_tool_environment(repository, pins)", preparer_source)
        self.assertIn(
            "collect_all(repository, libbox_source, release_environment)",
            preparer_source,
        )

        repository = Path(graph_collectors.__file__).parents[2]
        source_preparation = (repository / "scripts/publication/source_preparation.py").read_text(
            encoding="utf-8"
        )
        artifact_preparation = (
            repository / "scripts/publication/artifact_preparation.py"
        ).read_text(encoding="utf-8")
        bootstrap = repository / "scripts/prepare_publication_evidence.sh"
        bootstrap_source = bootstrap.read_text(encoding="utf-8")
        release_guide = (repository / "RELEASE.md").read_text(encoding="utf-8")
        self.assertIn("run_release_git(", source_preparation)
        self.assertIn("protected_roots=protected_roots", source_preparation)
        self.assertIn("environment=release_environment", artifact_preparation)
        self.assertTrue(bootstrap.stat().st_mode & stat.S_IXUSR)
        self.assertTrue(bootstrap_source.startswith("#!/bin/bash -p\n"))
        self.assertIn("cfw_seal_release_tool_environment", bootstrap_source)
        self.assertIn("cfw_select_release_apple_toolchain", bootstrap_source)
        self.assertIn("cfw_run_release_python_script", bootstrap_source)
        self.assertIn(
            '"$repo_root/scripts/prepare_publication_evidence.py"',
            bootstrap_source,
        )
        self.assertIn("scripts/prepare_publication_evidence.sh prepare", release_guide)
        self.assertNotIn("scripts/prepare_publication_evidence.py prepare", release_guide)


if __name__ == "__main__":
    unittest.main()
