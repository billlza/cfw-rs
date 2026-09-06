from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts.hash_artifact import build_manifest
from scripts.tauri_cargo_cache_contract import (
    CargoCacheContractError,
    RUNTIME_FILES,
    normalize_offline_cache,
    validate_preparation_cache,
)


class CacheFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        (root / "registry/cache/index.crates.io").mkdir(parents=True)
        (root / "registry/index/index.crates.io/.cache/pkg").mkdir(parents=True)
        (root / "registry/src/index.crates.io/example-1.0.0/src").mkdir(parents=True)
        (root / "registry/cache/index.crates.io/example-1.0.0.crate").write_bytes(
            b"crate archive"
        )
        (root / "registry/index/index.crates.io/.cache/pkg/example").write_bytes(
            b"index record"
        )
        (root / "registry/src/index.crates.io/example-1.0.0/src/lib.rs").write_text(
            "pub fn example() {}\n", encoding="utf-8"
        )
        self.recreate_runtime_files()

    def recreate_runtime_files(self) -> None:
        database = self.root / ".global-cache"
        with closing(sqlite3.connect(database)) as connection:
            with connection:
                connection.execute("create table if not exists global_data(value integer)")
        for name in (".package-cache", ".package-cache-mutate"):
            (self.root / name).touch()


class TauriCargoCacheContractTests(unittest.TestCase):
    def fixture(self, temporary: str) -> CacheFixture:
        return CacheFixture(Path(temporary) / "cargo-home")

    def test_empty_preparation_cache_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cargo-home"
            root.mkdir()
            validate_preparation_cache(root)

    def test_isolated_python_does_not_load_ambient_sitecustomize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            ambient = Path(temporary) / "ambient"
            ambient.mkdir()
            marker = Path(temporary) / "sitecustomize-loaded"
            (ambient / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('loaded')\n",
                encoding="utf-8",
            )
            helper = Path(__file__).resolve().parents[1] / "tauri_cargo_cache_contract.py"
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ambient)
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(helper),
                    "validate-preparation",
                    str(fixture.root),
                ],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertFalse(marker.exists())

    def test_normalization_removes_only_runtime_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            before = build_manifest(fixture.root / "registry", algorithm="sha256-tree-v2")
            registry = normalize_offline_cache(fixture.root)
            after = build_manifest(registry, algorithm="sha256-tree-v2")
            self.assertEqual(before["sha256"], after["sha256"])
            self.assertEqual({entry.name for entry in fixture.root.iterdir()}, {"registry"})
            normalize_offline_cache(fixture.root)

    def test_recreated_runtime_metadata_does_not_hide_registry_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            normalize_offline_cache(fixture.root)
            sealed = build_manifest(fixture.root, algorithm="sha256-tree-v2")
            fixture.recreate_runtime_files()
            (fixture.root / ".global-cache").write_bytes(
                (fixture.root / ".global-cache").read_bytes() + b"runtime drift"
            )
            normalize_offline_cache(fixture.root)
            self.assertEqual(
                sealed["sha256"],
                build_manifest(fixture.root, algorithm="sha256-tree-v2")["sha256"],
            )
            source = fixture.root / "registry/src/index.crates.io/example-1.0.0/src/lib.rs"
            source.write_text("pub fn tampered() {}\n", encoding="utf-8")
            self.assertNotEqual(
                sealed["sha256"],
                build_manifest(fixture.root, algorithm="sha256-tree-v2")["sha256"],
            )

    def test_unknown_top_level_entries_are_rejected(self) -> None:
        for name in ("config.toml", ".global-cache-wal", ".package-cache-extra"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(temporary)
                (fixture.root / name).write_text("unsafe", encoding="utf-8")
                with self.assertRaisesRegex(CargoCacheContractError, "unsafe top-level"):
                    normalize_offline_cache(fixture.root)

    def test_runtime_symlink_hardlink_directory_and_fifo_are_rejected(self) -> None:
        kinds = ("symlink", "hardlink", "directory", "fifo")
        for name in RUNTIME_FILES:
            for kind in kinds:
                with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as temporary:
                    fixture = self.fixture(temporary)
                    path = fixture.root / name
                    path.unlink()
                    outside = Path(temporary) / f"outside-{name.removeprefix('.')}"
                    if kind == "symlink":
                        outside.write_bytes(b"outside")
                        path.symlink_to(outside)
                    elif kind == "hardlink":
                        outside.write_bytes(b"outside")
                        os.link(outside, path)
                    elif kind == "directory":
                        path.mkdir()
                    else:
                        os.mkfifo(path)
                    with self.assertRaisesRegex(
                        CargoCacheContractError,
                        "single-link regular file",
                    ):
                        normalize_offline_cache(fixture.root)
                    if outside.exists():
                        self.assertEqual(outside.read_bytes(), b"outside")

    def test_invalid_tracker_and_nonempty_locks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            (fixture.root / ".global-cache").write_bytes(b"not sqlite")
            with self.assertRaisesRegex(CargoCacheContractError, "size|header"):
                normalize_offline_cache(fixture.root)
        for name in (".package-cache", ".package-cache-mutate"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(temporary)
                (fixture.root / name).write_bytes(b"not a lock")
                with self.assertRaisesRegex(CargoCacheContractError, "must be empty"):
                    normalize_offline_cache(fixture.root)

    def test_registry_symlink_is_rejected_by_the_registry_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            original = fixture.root / "registry"
            moved = Path(temporary) / "registry-real"
            original.rename(moved)
            original.symlink_to(moved)
            with self.assertRaisesRegex(
                CargoCacheContractError,
                "Cargo registry must be a real directory",
            ):
                normalize_offline_cache(fixture.root)

    def test_group_or_other_writable_entries_are_rejected(self) -> None:
        locations = (
            ".",
            "registry",
            "registry/cache/index.crates.io/example-1.0.0.crate",
            ".package-cache",
        )
        for relative in locations:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(temporary)
                path = fixture.root if relative == "." else fixture.root / relative
                path.chmod(path.stat().st_mode | 0o022)
                with self.assertRaisesRegex(
                    CargoCacheContractError,
                    "group/other writable",
                ):
                    normalize_offline_cache(fixture.root)

    def test_owner_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            with mock.patch(
                "scripts.tauri_cargo_cache_contract.os.getuid",
                return_value=os.getuid() + 1,
            ):
                with self.assertRaisesRegex(
                    CargoCacheContractError,
                    "not owned by the release user",
                ):
                    normalize_offline_cache(fixture.root)

    def test_nested_symlink_hardlink_and_fifo_are_rejected(self) -> None:
        for kind, pattern in (
            ("symlink", "contains a symlink"),
            ("hardlink", "hard-linked file"),
            ("fifo", "unsupported entry"),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(temporary)
                nested = fixture.root / "registry/cache/index.crates.io/unsafe"
                outside = Path(temporary) / "outside"
                outside.write_bytes(b"outside")
                if kind == "symlink":
                    nested.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, nested)
                else:
                    os.mkfifo(nested)
                with self.assertRaisesRegex(CargoCacheContractError, pattern):
                    normalize_offline_cache(fixture.root)

    def test_traversal_and_enumeration_errors_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)

            def failing_walk(*_args: object, **kwargs: object):
                onerror = kwargs["onerror"]
                onerror(PermissionError("fixture traversal denied"))
                yield from ()

            with mock.patch(
                "scripts.tauri_cargo_cache_contract.os.walk",
                side_effect=failing_walk,
            ):
                with self.assertRaisesRegex(
                    CargoCacheContractError,
                    "cannot traverse Cargo cache",
                ):
                    validate_preparation_cache(fixture.root)
            with mock.patch.object(
                Path,
                "iterdir",
                side_effect=PermissionError("fixture enumeration denied"),
            ):
                with self.assertRaisesRegex(
                    CargoCacheContractError,
                    "cannot enumerate Cargo cache root",
                ):
                    validate_preparation_cache(fixture.root)

    def test_unlink_failure_is_contextual_and_preserves_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            with mock.patch(
                "scripts.tauri_cargo_cache_contract.os.unlink",
                side_effect=PermissionError("fixture unlink denied"),
            ):
                with self.assertRaisesRegex(
                    CargoCacheContractError,
                    "cannot remove Cargo runtime metadata",
                ):
                    normalize_offline_cache(fixture.root)
            self.assertTrue((fixture.root / ".global-cache").is_file())

    def test_registry_cache_index_source_add_remove_and_modify_change_digest(self) -> None:
        mutations = (
            (
                "crate",
                "registry/cache/index.crates.io/example-1.0.0.crate",
                "modify",
            ),
            (
                "index",
                "registry/index/index.crates.io/.cache/pkg/example",
                "modify",
            ),
            (
                "source",
                "registry/src/index.crates.io/example-1.0.0/src/lib.rs",
                "modify",
            ),
            ("add", "registry/src/index.crates.io/example-1.0.0/src/added.rs", "add"),
            (
                "remove",
                "registry/cache/index.crates.io/example-1.0.0.crate",
                "remove",
            ),
        )
        for name, relative, operation in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(temporary)
                normalize_offline_cache(fixture.root)
                sealed = build_manifest(fixture.root, algorithm="sha256-tree-v2")
                target = fixture.root / relative
                if operation == "remove":
                    target.unlink()
                else:
                    target.write_bytes(b"mutated input")
                self.assertNotEqual(
                    sealed["sha256"],
                    build_manifest(fixture.root, algorithm="sha256-tree-v2")["sha256"],
                )


if __name__ == "__main__":
    unittest.main()
