from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.publication import native_collector
from scripts.publication.common import PublicationError
from scripts.publication import graph_collectors
from scripts.publication.native_collector import _normalize_native_graph
from scripts.publication.release_environment import SwiftToolchainIdentity


REPOSITORY = Path(__file__).resolve().parents[2]


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

    def test_apple_identity_uses_the_shared_structured_swift_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            developer = Path(temporary) / "Xcode.app/Contents/Developer"
            swift = developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/swift"
            xcodebuild = developer / "usr/bin/xcodebuild"
            for executable in (swift, xcodebuild):
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_text("fixture\n", encoding="utf-8")
            pins = {
                "XCODE_VERSION": "26.6",
                "XCODE_BUILD_VERSION": "17F113",
                "MACOS_DEPLOYMENT_TARGET": "15.0",
            }
            environment = {"DEVELOPER_DIR": str(developer)}
            calls: list[list[str]] = []

            def run(argv, _repository, _environment):
                calls.append(list(argv))
                if argv == ["/usr/bin/xcodebuild", "-version"]:
                    return b"Xcode 26.6\nBuild version 17F113\n"
                if argv == ["/usr/bin/xcrun", "--find", "swift"]:
                    return f"{swift}\n".encode()
                if argv == ["/usr/bin/xcrun", "--find", "xcodebuild"]:
                    return f"{xcodebuild}\n".encode()
                raise AssertionError(argv)

            structured = SwiftToolchainIdentity("6.3.3", "structured-swift")
            with patch.object(
                native_collector,
                "run",
                side_effect=run,
            ), patch.object(
                native_collector,
                "swift_toolchain_identity",
                return_value=structured,
            ) as resolve_swift:
                observed = native_collector._apple_tool_identity(
                    REPOSITORY,
                    pins,
                    environment,
                )

        resolve_swift.assert_called_once_with(REPOSITORY, environment, "15.0")
        self.assertEqual(
            observed,
            (
                "Xcode 26.6\nBuild version 17F113",
                structured.canonical,
                str(swift.resolve(strict=False)),
                str(xcodebuild.resolve(strict=False)),
            ),
        )
        self.assertNotIn(["/usr/bin/swift", "--version"], calls)

    def test_checked_versions_reuses_the_structured_swift_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            toolchain_root = root / "toolchains"
            pins = {
                "RUST_VERSION": "1.97.1",
                "NODE_VERSION": "24.18.0",
                "GO_VERSION": "1.26.1",
                "XCODEGEN_VERSION": "2.45.3",
                "GOMOBILE_VERSION": "v0.0.0-fixture",
                "GOMOBILE_MODULE_SUM": "h1:fixture",
                "TAURI_CLI_VERSION": "2.9.6",
                "XCODE_VERSION": "26.6",
                "XCODE_BUILD_VERSION": "17F113",
                "MACOS_DEPLOYMENT_TARGET": "15.0",
            }
            executables = {
                toolchain_root / "node-24.18.0/bin/node",
                toolchain_root / "go-1.26.1/bin/go",
                toolchain_root / "xcodegen-2.45.3/bin/xcodegen",
                toolchain_root / "go-workspace/bin/gomobile",
                toolchain_root / "tauri-cli-2.9.6/bin/cargo-tauri",
                root / "rust/bin/rustc",
            }
            for executable in executables:
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_text("#!/bin/sh\n", encoding="utf-8")
                executable.chmod(0o700)
            rustc = root / "rust/bin/rustc"
            environment = {
                "CFW_RELEASE_RUSTC_EXECUTABLE": str(rustc),
                "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
            }
            calls: list[list[str]] = []

            def run(argv, _repository, _environment):
                calls.append(list(argv))
                executable = argv[0]
                if argv == [str(rustc), "--version"]:
                    return b"rustc 1.97.1 (fixture)\n"
                if argv == ["/usr/bin/xcodebuild", "-version"]:
                    return b"Xcode 26.6\nBuild version 17F113\n"
                if executable.endswith("/node"):
                    return b"v24.18.0\n"
                if executable.endswith("/go") and argv[1:] == ["version"]:
                    return b"go version go1.26.1 darwin/arm64\n"
                if executable.endswith("/xcodegen"):
                    return b"Version: 2.45.3\n"
                if executable.endswith("/cargo-tauri"):
                    return b"tauri-cli 2.9.6\n"
                if executable.endswith("/go") and argv[1:3] == ["version", "-m"]:
                    return (
                        b"mod\tgithub.com/sagernet/gomobile\t"
                        b"v0.0.0-fixture\th1:fixture\n"
                    )
                raise AssertionError(argv)

            structured = SwiftToolchainIdentity("6.3.3", "structured-swift")
            verified_rust = SimpleNamespace(surface={"fixture": "identity"})
            with patch.object(
                native_collector,
                "verified_release_toolchain_trees",
                return_value=(toolchain_root, {}),
            ), patch.object(
                native_collector,
                "verify_pinned_toolchain",
                return_value=verified_rust,
            ), patch.object(
                native_collector,
                "run",
                side_effect=run,
            ), patch.object(
                native_collector,
                "swift_toolchain_identity",
                return_value=structured,
            ) as resolve_swift:
                observation = native_collector._checked_versions(
                    REPOSITORY,
                    pins,
                    environment,
                )

        resolve_swift.assert_called_once_with(REPOSITORY, environment, "15.0")
        versions = dict(observation.versions)
        self.assertEqual(observation.toolchain_root, toolchain_root)
        self.assertEqual(versions["swift"], structured.version)
        self.assertEqual(observation.swift_identity, structured.canonical)
        self.assertNotIn(["/usr/bin/swift", "--version"], calls)

    def test_toolchain_collection_rejects_same_version_swift_identity_drift(self) -> None:
        initial = native_collector._CheckedToolchainObservation(
            versions=(("swift", "6.3.3"),),
            toolchain_root=Path("/release/toolchains"),
            swift_identity="canonical-a",
        )
        changed = native_collector._CheckedToolchainObservation(
            versions=initial.versions,
            toolchain_root=initial.toolchain_root,
            swift_identity="canonical-b",
        )

        with self.assertRaisesRegex(
            PublicationError,
            "release toolchain changed",
        ):
            native_collector._require_unchanged_toolchains(initial, changed)
        native_collector._require_unchanged_toolchains(initial, initial)

    def test_native_collection_rejects_swift_identity_drift(self) -> None:
        initial = ("xcode", "swift-a", "/swift", "/xcodebuild")
        changed = ("xcode", "swift-b", "/swift", "/xcodebuild")
        with patch.object(
            native_collector,
            "_apple_tool_identity",
            side_effect=(initial, changed),
        ), patch.object(
            native_collector,
            "run_json",
            return_value={},
        ), self.assertRaisesRegex(
            PublicationError,
            "Apple toolchain changed",
        ):
            native_collector.collect_native(REPOSITORY, {}, {})

    def test_native_consumers_do_not_reintroduce_swift_version_output(self) -> None:
        source = Path(native_collector.__file__).read_text(encoding="utf-8")
        self.assertNotIn('["/usr/bin/swift", "--version"]', source)
        self.assertEqual(source.count("swift_toolchain_identity("), 2)


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
