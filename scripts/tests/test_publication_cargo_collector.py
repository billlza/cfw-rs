from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.publication import cargo_collector
from scripts.publication.common import PublicationError
from scripts.release_cargo_inputs import CRATES_IO_SOURCE, WorkspaceCargoInputs


class CargoCollectorVerifiedSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        self.repository = root / "repository"
        self.vendor = root / "verified-vendor"
        self.input_root = root / "cargo-inputs"
        self.repository.mkdir()
        self.vendor.mkdir()
        self.input_root.mkdir()
        self.local_manifest = self.repository / "apps/cfw-tauri-shell/Cargo.toml"
        self.registry_manifest = self.vendor / "fixture-dependency-1.2.3/Cargo.toml"
        self.local_manifest.parent.mkdir(parents=True)
        self.registry_manifest.parent.mkdir(parents=True)
        self.local_manifest.write_text("[package]\n", encoding="utf-8")
        self.registry_manifest.write_text("[package]\n", encoding="utf-8")
        self.cargo = root / "cargo"
        self.cargo.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.cargo.chmod(0o700)
        self.inputs = WorkspaceCargoInputs(
            root=self.input_root,
            archives=self.input_root / "archives",
            vendor=self.vendor,
            cargo_lock_sha256="1" * 64,
            crates_sha256="2" * 64,
            vendor_tree_sha256="3" * 64,
            crate_records=(),
        )
        self.environment = {
            "CFW_RELEASE_CARGO_EXECUTABLE": str(self.cargo),
            "CFW_RELEASE_CARGO_INPUT_ROOT": str(self.input_root),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }

    def _metadata(
        self,
        *,
        registry_manifest: Path | None = None,
        local_manifest: Path | None = None,
    ) -> dict[str, object]:
        local_id = "path+file:///fixture#cfw-tauri-shell@0.4.0"
        registry_id = (
            f"{CRATES_IO_SOURCE}#fixture-dependency@1.2.3"
        )
        return {
            "packages": [
                {
                    "id": local_id,
                    "name": "cfw-tauri-shell",
                    "version": "0.4.0",
                    "source": None,
                    "manifest_path": str(local_manifest or self.local_manifest),
                    "license": "GPL-3.0-or-later",
                    "targets": [{"kind": ["bin"]}],
                },
                {
                    "id": registry_id,
                    "name": "fixture-dependency",
                    "version": "1.2.3",
                    "source": CRATES_IO_SOURCE,
                    "checksum": "4" * 64,
                    "manifest_path": str(registry_manifest or self.registry_manifest),
                    "license": "MIT",
                    "targets": [{"kind": ["lib"]}],
                },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": local_id,
                        "deps": [
                            {
                                "pkg": registry_id,
                                "dep_kinds": [{"kind": None}],
                            }
                        ],
                    },
                    {"id": registry_id, "deps": []},
                ]
            },
        }

    def _collect_with(self, metadata, *, callback=None):
        observed_cargo_home: list[Path] = []

        def run_json(_command, _cwd, environment):
            cargo_home = Path(environment["CARGO_HOME"])
            observed_cargo_home.append(cargo_home)
            self.assertNotEqual(cargo_home, Path.home() / ".cargo")
            self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
            configuration = (cargo_home / "config.toml").read_text(encoding="utf-8")
            self.assertIn(str(self.vendor), configuration)
            if callback is not None:
                callback(cargo_home)
            return metadata

        with (
            mock.patch.object(
                cargo_collector,
                "verify_workspace_cargo_inputs",
                side_effect=(self.inputs, self.inputs),
            ),
            mock.patch.object(cargo_collector, "run_json", side_effect=run_json),
        ):
            result = cargo_collector.collect_cargo(
                self.repository,
                self.environment,
            )
        self.assertEqual(len(observed_cargo_home), 1)
        self.assertFalse(observed_cargo_home[0].exists())
        return result

    def test_metadata_uses_fresh_runtime_and_verified_source_roots(self) -> None:
        components, _relationships, _graphs, _graph_components = self._collect_with(
            self._metadata()
        )
        self.assertEqual({component.ecosystem for component in components.values()}, {"cargo"})

    def test_ambient_registry_source_manifest_is_rejected(self) -> None:
        ambient = Path(self.temporary.name) / ".cargo/registry/src/poison/Cargo.toml"
        ambient.parent.mkdir(parents=True)
        ambient.write_text("[package]\n", encoding="utf-8")
        with self.assertRaisesRegex(PublicationError, "verified vendor"):
            self._collect_with(self._metadata(registry_manifest=ambient))

    def test_local_package_outside_repository_is_rejected(self) -> None:
        outside = Path(self.temporary.name) / "outside/Cargo.toml"
        outside.parent.mkdir()
        outside.write_text("[package]\n", encoding="utf-8")
        with self.assertRaisesRegex(PublicationError, "repository source root"):
            self._collect_with(self._metadata(local_manifest=outside))

    def test_runtime_configuration_drift_after_metadata_is_rejected(self) -> None:
        def mutate(cargo_home: Path) -> None:
            configuration = cargo_home / "config.toml"
            configuration.chmod(0o600)
            configuration.write_text("[net]\noffline=false\n", encoding="utf-8")

        with self.assertRaisesRegex(PublicationError, "verified workspace input boundary"):
            self._collect_with(self._metadata(), callback=mutate)

    def test_workspace_input_drift_after_metadata_is_rejected(self) -> None:
        drifted = replace(self.inputs, vendor_tree_sha256="f" * 64)
        with (
            mock.patch.object(
                cargo_collector,
                "verify_workspace_cargo_inputs",
                side_effect=(self.inputs, drifted),
            ),
            mock.patch.object(
                cargo_collector,
                "run_json",
                return_value=self._metadata(),
            ),
        ):
            with self.assertRaisesRegex(PublicationError, "changed during metadata"):
                cargo_collector.collect_cargo(self.repository, self.environment)


if __name__ == "__main__":
    unittest.main()
