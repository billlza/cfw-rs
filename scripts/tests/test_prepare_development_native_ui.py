from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_development_native_ui as dev


class DevelopmentNativeUiTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        repository = root / "repository"
        for relative in dev.SOURCE_PATHS:
            path = repository / relative
            if relative.endswith(("/Sources", "/include")):
                path.mkdir(parents=True)
                (path / "source.txt").write_text("source")
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("source")
        return repository

    def tool(self, arguments, **kwargs):
        if arguments[0] == "/usr/bin/lipo":
            return subprocess.CompletedProcess(arguments, 0, b"arm64\n", b"")
        if arguments[1:2] == ["vtool"]:
            return subprocess.CompletedProcess(arguments, 0, b"platform MACOS\nminos 15.0\n", b"")
        scratch = Path(arguments[arguments.index("--scratch-path") + 1])
        output = scratch / "arm64-apple-macosx/debug"
        if "--show-bin-path" in arguments:
            return subprocess.CompletedProcess(arguments, 0, (str(output) + "\n").encode(), b"")
        output.mkdir(parents=True)
        (output / dev.LIBRARY).write_bytes(b"test library at mocked Swift boundary")
        resources = output / dev.RESOURCES
        resources.mkdir()
        (resources / "Localizable.strings").write_text('"key" = "value";')
        return subprocess.CompletedProcess(arguments, 0, b"Swift build fixture\n", b"")

    def test_receipt_binds_sources_and_the_library_with_its_resources_beside_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.fixture(Path(temporary).resolve())
            with patch.object(dev, "run_bounded_process", side_effect=self.tool) as run:
                products = dev.prepare(repository)
            receipt = json.loads((products / "receipt.json").read_text())
            self.assertEqual(
                sorted(receipt),
                ["artifact_kind", "configuration", "products", "repository", "schema_version",
                 "source_sha256", "sources", "target"],
            )
            self.assertEqual(receipt["schema_version"], 2)
            self.assertEqual(receipt["artifact_kind"], "development-native-ui-v2")
            self.assertEqual(receipt["configuration"], "debug")
            self.assertEqual(receipt["sources"], dev.source_manifests(repository))
            self.assertEqual(receipt["source_sha256"], products.parent.parent.name)
            self.assertEqual(run.call_count, 4)
            # The library finds its resources beside itself, so both are in
            # the products directory and nothing else needs a copy.
            self.assertEqual(
                sorted(path.name for path in products.iterdir()),
                sorted([dev.RESOURCES, dev.LIBRARY, "receipt.json"]),
            )
            for name in (dev.LIBRARY, dev.RESOURCES):
                self.assertEqual(dev.manifest(products / name), receipt["products"][name])
            self.assertTrue((products.parent / "build.log").exists())
            self.assertFalse((products.parent / "swift-build").exists())

    def test_cargo_output_is_neither_read_nor_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.fixture(Path(temporary).resolve())
            # Resources an earlier preparation left in Cargo's directories,
            # with other bytes: they are no input and are left alone.
            old = repository / "target/debug/deps" / dev.RESOURCES
            old.mkdir(parents=True)
            (old / "Localizable.strings").write_text("keep")
            with patch.object(dev, "run_bounded_process", side_effect=self.tool):
                products = dev.prepare(repository)
            self.assertTrue((products / "receipt.json").exists())
            self.assertEqual((old / "Localizable.strings").read_text(), "keep")
            self.assertEqual(
                sorted(path.relative_to(repository / "target").as_posix()
                       for path in (repository / "target").rglob("*") if "native-ui-development" not in path.parts),
                ["debug", "debug/deps", f"debug/deps/{dev.RESOURCES}",
                 f"debug/deps/{dev.RESOURCES}/Localizable.strings"],
            )

    def test_command_line_no_longer_takes_a_cargo_directory(self):
        for arguments in (["--cargo-target-dir", "/x/target"], ["--target", "aarch64-apple-darwin"]):
            with self.subTest(arguments=arguments), patch.object(dev, "prepare") as prepare:
                with patch.object(sys, "argv", ["prepare_development_native_ui.py", *arguments]):
                    with contextlib.redirect_stderr(io.StringIO()) as errors:
                        with self.assertRaises(SystemExit) as raised:
                            dev.main()
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("unrecognized arguments", errors.getvalue())
                prepare.assert_not_called()

    def test_new_source_attempt_never_replaces_prior_receipt_or_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.fixture(Path(temporary).resolve())
            with patch.object(dev, "run_bounded_process", side_effect=self.tool):
                first = dev.prepare(repository)
                original = (first / "receipt.json").read_bytes()
                (repository / "native/dashboard/Sources/new.swift").write_text("new input")
                second = dev.prepare(repository)
            self.assertNotEqual(first.parent.parent, second.parent.parent)
            self.assertEqual((first / "receipt.json").read_bytes(), original)
            self.assertNotEqual(json.loads(original)["sources"], dev.source_manifests(repository))

    def test_source_mutation_during_build_prevents_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.fixture(Path(temporary).resolve())
            def change(arguments, **kwargs):
                result = self.tool(arguments, **kwargs)
                (repository / "native/dashboard/Package.swift").write_text("changed while building")
                return result
            with patch.object(dev, "run_bounded_process", side_effect=change):
                with self.assertRaisesRegex(ValueError, "inputs changed during"):
                    dev.prepare(repository)
            self.assertEqual(list((repository / "target/native-ui-development").rglob("receipt.json")), [])

    def test_refuses_a_symlinked_target_before_any_build_or_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository = self.fixture(base)
            outside = base / "outside"
            outside.mkdir()
            (repository / "target").symlink_to(outside, target_is_directory=True)
            with patch.object(dev, "run_bounded_process") as run:
                with self.assertRaisesRegex(ValueError, "not canonical"):
                    dev.prepare(repository)
                run.assert_not_called()
            self.assertEqual(list(outside.iterdir()), [])

    def test_failed_compiler_keeps_log_without_a_completion_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.fixture(Path(temporary).resolve())
            with patch.object(dev, "run_bounded_process", return_value=subprocess.CompletedProcess([], 1, b"", b"fixture failure")):
                with self.assertRaisesRegex(ValueError, "build failed"):
                    dev.prepare(repository)
            attempts = repository / "target/native-ui-development"
            self.assertEqual(len(list(attempts.rglob("build.log"))), 1)
            self.assertEqual(list(attempts.rglob("receipt.json")), [])

    def test_source_manifest_rejects_links_and_tracks_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.fixture(Path(temporary).resolve())
            initial = dev.source_manifests(repository)
            source = repository / "native/dashboard/Sources/source.txt"
            source.unlink()
            self.assertNotEqual(dev.source_manifests(repository), initial)
            source.symlink_to(repository / "native/dashboard/Package.swift")
            with self.assertRaisesRegex(ValueError, "symlink"):
                dev.source_manifests(repository)

    def test_bounded_timeout_retains_failure_reason_and_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.fixture(Path(temporary).resolve())
            error = dev.BoundedProcessError("timeout", "fixture timeout", stdout=b"partial output")
            with patch.object(dev, "run_bounded_process", side_effect=error):
                with self.assertRaisesRegex(ValueError, "process boundary.*timeout"):
                    dev.prepare(repository)
            attempts = repository / "target/native-ui-development"
            record = json.loads(next(attempts.rglob("build.result.json")).read_text())
            self.assertEqual(record["failure"], "timeout")
            self.assertEqual(next(attempts.rglob("build.log")).read_bytes(), b"partial output")
            self.assertEqual(list(attempts.rglob("receipt.json")), [])

    def test_actual_architecture_check_refuses_a_non_arm_library_despite_requested_triple(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.fixture(Path(temporary).resolve())
            def wrong_architecture(arguments, **kwargs):
                if arguments[0] == "/usr/bin/lipo":
                    return subprocess.CompletedProcess(arguments, 0, b"x86_64\n", b"")
                if "build" in arguments:
                    self.assertIn("arm64-apple-macosx15.0", arguments)
                return self.tool(arguments, **kwargs)
            with patch.object(dev, "run_bounded_process", side_effect=wrong_architecture):
                with self.assertRaisesRegex(ValueError, "thin arm64"):
                    dev.prepare(repository)
            attempts = repository / "target/native-ui-development"
            self.assertEqual(list(attempts.rglob("receipt.json")), [])
            # A failed attempt keeps its compiler scratch for diagnosis.
            self.assertEqual(len(list(attempts.glob("*/*/swift-build"))), 1)


if __name__ == "__main__":
    unittest.main()
