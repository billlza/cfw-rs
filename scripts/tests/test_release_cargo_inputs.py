from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import release_cargo_inputs as cargo_inputs_module
from scripts.release_cargo_inputs import (
    CRATES_IO_SOURCE,
    ReleaseCargoInputsError,
    create_runtime_cargo_home,
    prepare_workspace_cargo_inputs,
    verify_runtime_cargo_home,
    verify_workspace_cargo_inputs,
    workspace_input_root,
)
from scripts.hash_artifact import build_manifest
from scripts.publication.common import canonical_json


class ReleaseCargoInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        self.repository = root / "repository"
        self.home = root / "home"
        self.source_cargo_home = root / "preparation-cargo-home"
        (self.repository / "apps/cfw-tauri-shell").mkdir(parents=True)
        (self.home / ".cfm-release-tooling").mkdir(parents=True, mode=0o700)
        self.source_cache = (
            self.source_cargo_home / "registry/cache/index.crates.io-fixture"
        )
        self.source_cache.mkdir(parents=True, mode=0o700)
        self.source_cargo_home.chmod(0o700)

    def _archive(self, *, unsafe_name: str | None = None) -> tuple[Path, str]:
        archive = self.source_cache / "fixture-dependency-1.2.3.crate"
        with tarfile.open(archive, "w:gz") as stream:
            for name, payload, mode in (
                (
                    unsafe_name or "fixture-dependency-1.2.3/Cargo.toml",
                    b'[package]\nname="fixture-dependency"\nversion="1.2.3"\n',
                    0o644,
                ),
                (
                    "fixture-dependency-1.2.3/src/lib.rs",
                    b'pub const ORIGIN: &str = "verified-vendor";\n',
                    0o644,
                ),
            ):
                entry = tarfile.TarInfo(name)
                entry.size = len(payload)
                entry.mode = mode
                stream.addfile(entry, io.BytesIO(payload))
        encoded = archive.read_bytes()
        return archive, hashlib.sha256(encoded).hexdigest()

    def _write_lock(self, checksum: str, *, source: str = CRATES_IO_SOURCE) -> None:
        (self.repository / "Cargo.lock").write_text(
            "\n".join(
                (
                    "version = 4",
                    "",
                    "[[package]]",
                    'name = "fixture-app"',
                    'version = "0.4.0"',
                    'dependencies = ["fixture-dependency"]',
                    "",
                    "[[package]]",
                    'name = "fixture-dependency"',
                    'version = "1.2.3"',
                    f'source = "{source}"',
                    f'checksum = "{checksum}"',
                    "",
                )
            ),
            encoding="utf-8",
        )

    def _prepare(self):
        _archive, checksum = self._archive()
        self._write_lock(checksum)
        workspace_root = workspace_input_root(self.repository, self.home)
        return prepare_workspace_cargo_inputs(
            self.repository,
            self.source_cargo_home,
            workspace_root,
        )

    def test_complete_lock_verified_vendor_is_prepared_and_reused(self) -> None:
        poisoned = self.source_cargo_home / "registry/src/poison/fixture-dependency-1.2.3"
        poisoned.mkdir(parents=True)
        (poisoned / "Cargo.toml").write_text("poison", encoding="utf-8")

        inputs = self._prepare()
        self.assertEqual(len(inputs.crate_records), 1)
        self.assertEqual(inputs.root.stat().st_mode & 0o777, 0o500)
        self.assertEqual(inputs.vendor.stat().st_mode & 0o777, 0o500)
        self.assertEqual(
            (
                inputs.vendor
                / "fixture-dependency-1.2.3/src/lib.rs"
            ).read_text(encoding="utf-8"),
            'pub const ORIGIN: &str = "verified-vendor";\n',
        )
        self.assertNotIn("poison", "\n".join(str(path) for path in inputs.vendor.rglob("*")))
        self.assertEqual(
            verify_workspace_cargo_inputs(self.repository, inputs.root),
            inputs,
        )
        self.assertEqual(
            prepare_workspace_cargo_inputs(
                self.repository,
                self.source_cargo_home,
                inputs.root,
            ),
            inputs,
        )

    def test_vendor_mutation_is_rejected(self) -> None:
        inputs = self._prepare()
        source = inputs.vendor / "fixture-dependency-1.2.3/src/lib.rs"
        source.parent.chmod(0o700)
        source.chmod(0o600)
        source.write_text("mutated", encoding="utf-8")
        with self.assertRaisesRegex(ReleaseCargoInputsError, "vendor tree"):
            verify_workspace_cargo_inputs(self.repository, inputs.root)

    def test_vendor_hardlink_mode_and_extra_directory_are_rejected(self) -> None:
        mutations = ("hardlink", "mode", "directory")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                inputs = self._prepare()
                package = inputs.vendor / "fixture-dependency-1.2.3"
                source = package / "src/lib.rs"
                if mutation == "hardlink":
                    source.parent.chmod(0o700)
                    os.link(source, source.parent / "linked.rs")
                    source.parent.chmod(0o500)
                elif mutation == "mode":
                    source.chmod(0o500)
                else:
                    package.chmod(0o700)
                    (package / "unexpected-empty-directory").mkdir(mode=0o500)
                    package.chmod(0o500)
                with self.assertRaisesRegex(ReleaseCargoInputsError, "vendor tree"):
                    verify_workspace_cargo_inputs(self.repository, inputs.root)
                if mutation == "hardlink":
                    source.parent.chmod(0o700)
                    (source.parent / "linked.rs").unlink()
                    source.parent.chmod(0o500)
                elif mutation == "mode":
                    source.chmod(0o400)
                else:
                    package.chmod(0o700)
                    (package / "unexpected-empty-directory").rmdir()
                    package.chmod(0o500)
                self.assertEqual(
                    verify_workspace_cargo_inputs(self.repository, inputs.root),
                    inputs,
                )

    def test_archive_container_hardlink_is_rejected(self) -> None:
        inputs = self._prepare()
        archive = inputs.archives / "fixture-dependency-1.2.3.crate"
        retained = Path(self.temporary.name) / archive.name
        inputs.archives.chmod(0o700)
        archive.rename(retained)
        os.link(retained, archive)
        inputs.archives.chmod(0o500)
        with self.assertRaisesRegex(ReleaseCargoInputsError, "single-link"):
            verify_workspace_cargo_inputs(self.repository, inputs.root)

    def test_archive_identity_change_during_inventory_is_rejected(self) -> None:
        inputs = self._prepare()
        archive = inputs.archives / "fixture-dependency-1.2.3.crate"
        real_consume = cargo_inputs_module._consume_archive_file
        changed = False

        def consume_then_change(*args, **kwargs):
            nonlocal changed
            digest = real_consume(*args, **kwargs)
            if not changed:
                changed = True
                archive.chmod(0o600)
                archive.chmod(0o400)
            return digest

        with mock.patch.object(
            cargo_inputs_module,
            "_consume_archive_file",
            side_effect=consume_then_change,
        ), self.assertRaisesRegex(ReleaseCargoInputsError, "changed during inspection"):
            verify_workspace_cargo_inputs(self.repository, inputs.root)

    def test_vendor_mtime_only_change_preserves_semantic_identity(self) -> None:
        inputs = self._prepare()
        source = inputs.vendor / "fixture-dependency-1.2.3/src/lib.rs"
        metadata = source.stat()
        os.utime(
            source,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
        )
        self.assertEqual(
            verify_workspace_cargo_inputs(self.repository, inputs.root),
            inputs,
        )

    def test_self_consistent_vendor_and_manifest_rewrite_is_rejected(self) -> None:
        inputs = self._prepare()
        package = inputs.vendor / "fixture-dependency-1.2.3"
        source = package / "src/lib.rs"
        checksum_path = package / ".cargo-checksum.json"
        original_size = source.stat().st_size

        inputs.root.chmod(0o700)
        inputs.vendor.chmod(0o700)
        for directory, _names, filenames in os.walk(package):
            directory_path = Path(directory)
            directory_path.chmod(0o700)
            for filename in filenames:
                (directory_path / filename).chmod(0o600)
        forged_source = b'pub const ORIGIN: &str = "self-consistent-forgery";\n'
        source.write_bytes(forged_source)
        checksum = json.loads(checksum_path.read_text(encoding="utf-8"))
        checksum["files"]["src/lib.rs"] = hashlib.sha256(forged_source).hexdigest()
        checksum_path.write_bytes(canonical_json(checksum))
        for directory, _names, filenames in os.walk(
            package, topdown=False, followlinks=False
        ):
            directory_path = Path(directory)
            for filename in filenames:
                (directory_path / filename).chmod(0o400)
            directory_path.chmod(0o500)
        package_manifest = build_manifest(package, algorithm="sha256-tree-v2")

        binding_path = inputs.root / "binding.json"
        vendor_manifest_path = inputs.root / "vendor.manifest.json"
        binding_path.chmod(0o600)
        vendor_manifest_path.chmod(0o600)
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        binding["crates"][0]["source_tree_sha256"] = package_manifest["sha256"]
        binding["source_file_bytes"] += len(forged_source) - original_size
        binding["crates_sha256"] = hashlib.sha256(
            canonical_json(binding["crates"])
        ).hexdigest()
        inputs.vendor.chmod(0o500)
        manifest_metadata = {
            "artifactKind": "cfw-verified-cargo-vendor-v1",
            "cargoLockSha256": inputs.cargo_lock_sha256,
            "crateCount": "1",
            "cratesSha256": binding["crates_sha256"],
            "registry": CRATES_IO_SOURCE,
        }
        vendor_manifest = build_manifest(
            inputs.vendor,
            metadata=manifest_metadata,
            algorithm="sha256-tree-v2",
        )
        binding["vendor_tree_sha256"] = vendor_manifest["sha256"]
        binding_path.write_bytes(canonical_json(binding))
        vendor_manifest_path.write_bytes(canonical_json(vendor_manifest))
        binding_path.chmod(0o400)
        vendor_manifest_path.chmod(0o400)
        inputs.root.chmod(0o500)

        with self.assertRaisesRegex(ReleaseCargoInputsError, "authenticated archive"):
            verify_workspace_cargo_inputs(self.repository, inputs.root)

    def test_archive_checksum_mismatch_is_rejected(self) -> None:
        self._archive()
        self._write_lock("0" * 64)
        workspace_root = workspace_input_root(self.repository, self.home)
        with self.assertRaisesRegex(ReleaseCargoInputsError, "checksum differs"):
            prepare_workspace_cargo_inputs(
                self.repository,
                self.source_cargo_home,
                workspace_root,
            )

    def test_archive_traversal_is_rejected(self) -> None:
        _archive, checksum = self._archive(
            unsafe_name="fixture-dependency-1.2.3/../escape"
        )
        self._write_lock(checksum)
        workspace_root = workspace_input_root(self.repository, self.home)
        with self.assertRaisesRegex(ReleaseCargoInputsError, "unsafe path"):
            prepare_workspace_cargo_inputs(
                self.repository,
                self.source_cargo_home,
                workspace_root,
            )

    def test_archive_link_members_are_rejected(self) -> None:
        for link_type in (tarfile.LNKTYPE, tarfile.SYMTYPE):
            with self.subTest(link_type=link_type):
                archive = self.source_cache / "fixture-dependency-1.2.3.crate"
                with tarfile.open(archive, "w:gz") as stream:
                    cargo_toml = b'[package]\nname="fixture-dependency"\nversion="1.2.3"\n'
                    manifest = tarfile.TarInfo(
                        "fixture-dependency-1.2.3/Cargo.toml"
                    )
                    manifest.size = len(cargo_toml)
                    manifest.mode = 0o644
                    stream.addfile(manifest, io.BytesIO(cargo_toml))
                    linked = tarfile.TarInfo(
                        "fixture-dependency-1.2.3/src/linked.rs"
                    )
                    linked.type = link_type
                    linked.linkname = "../Cargo.toml"
                    stream.addfile(linked)
                checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
                self._write_lock(checksum)
                workspace_root = workspace_input_root(self.repository, self.home)
                with self.assertRaisesRegex(
                    ReleaseCargoInputsError,
                    "non-regular source entry",
                ):
                    prepare_workspace_cargo_inputs(
                        self.repository,
                        self.source_cargo_home,
                        workspace_root,
                    )

    def test_non_crates_io_source_is_rejected(self) -> None:
        _archive, checksum = self._archive()
        self._write_lock(checksum, source="git+https://example.invalid/repository")
        with self.assertRaisesRegex(ReleaseCargoInputsError, "non-crates.io"):
            workspace_input_root(self.repository, self.home)

    def test_runtime_home_has_one_exact_source_replacement(self) -> None:
        inputs = self._prepare()
        cargo_home = Path(self.temporary.name) / "runtime-cargo-home"
        cargo_home.mkdir(mode=0o700)
        create_runtime_cargo_home(self.repository, inputs, cargo_home)
        configuration = (cargo_home / "config.toml").read_text(encoding="utf-8")
        self.assertIn('replace-with = "cfw-verified-vendor"', configuration)
        self.assertIn(f'directory = "{inputs.vendor!s}"', configuration)
        verify_runtime_cargo_home(self.repository, inputs, cargo_home)

    def test_repository_configuration_is_rejected_at_runtime(self) -> None:
        inputs = self._prepare()
        configuration = self.repository / ".cargo/config.toml"
        configuration.parent.mkdir()
        configuration.write_text("[build]\nrustc-wrapper='injector'\n", encoding="utf-8")
        cargo_home = Path(self.temporary.name) / "runtime-cargo-home"
        cargo_home.mkdir(mode=0o700)
        with self.assertRaisesRegex(ReleaseCargoInputsError, "ambient Cargo configuration"):
            create_runtime_cargo_home(self.repository, inputs, cargo_home)

    def test_runtime_registry_source_is_rejected(self) -> None:
        inputs = self._prepare()
        cargo_home = Path(self.temporary.name) / "runtime-cargo-home"
        cargo_home.mkdir(mode=0o700)
        create_runtime_cargo_home(self.repository, inputs, cargo_home)
        (cargo_home / "registry/src/poison").mkdir(parents=True)
        with self.assertRaisesRegex(ReleaseCargoInputsError, "forbidden source"):
            verify_runtime_cargo_home(self.repository, inputs, cargo_home)

    def test_additional_working_directory_ancestor_configuration_is_rejected(self) -> None:
        inputs = self._prepare()
        external_parent = Path(self.temporary.name) / "external-build-parent"
        external_workspace = external_parent / "workspace"
        external_workspace.mkdir(parents=True)
        configuration = external_parent / ".cargo/config.toml"
        configuration.parent.mkdir()
        configuration.write_text("[build]\nrustc-wrapper='injector'\n", encoding="utf-8")
        cargo_home = Path(self.temporary.name) / "runtime-cargo-home"
        cargo_home.mkdir(mode=0o700)
        with self.assertRaisesRegex(ReleaseCargoInputsError, "ambient Cargo configuration"):
            create_runtime_cargo_home(
                self.repository,
                inputs,
                cargo_home,
                additional_working_directories=(external_workspace,),
            )

    def test_duplicate_archive_cache_is_rejected(self) -> None:
        archive, checksum = self._archive()
        duplicate_directory = self.source_cargo_home / "registry/cache/duplicate"
        duplicate_directory.mkdir()
        (duplicate_directory / archive.name).write_bytes(archive.read_bytes())
        self._write_lock(checksum)
        workspace_root = workspace_input_root(self.repository, self.home)
        with self.assertRaisesRegex(ReleaseCargoInputsError, "expected one private archive"):
            prepare_workspace_cargo_inputs(
                self.repository,
                self.source_cargo_home,
                workspace_root,
            )


if __name__ == "__main__":
    unittest.main()
