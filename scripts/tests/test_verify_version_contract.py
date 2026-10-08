from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_version_contract as contract
from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY, SIGNED_PREVIEW_IDENTITY
from scripts.verify_version_contract import (
    EXPECTED_BUILD,
    EXPECTED_VERSION,
    PRODUCT_PACKAGES,
    verify,
)


class VersionContractTests(unittest.TestCase):
    def make_repository(self, root: Path) -> None:
        version = EXPECTED_VERSION
        build = EXPECTED_BUILD
        (root / "apps/cfw-tauri-shell").mkdir(parents=True)
        (root / "native/macos/Config").mkdir(parents=True)
        (root / "crates").mkdir()
        for name in sorted(PRODUCT_PACKAGES):
            if name == "cfw-tauri-shell":
                manifest = root / "apps/cfw-tauri-shell/Cargo.toml"
            else:
                manifest = root / f"crates/{name}/Cargo.toml"
                manifest.parent.mkdir(parents=True)
            manifest.write_text(
                f'[package]\nname = "{name}"\nversion = "{version}"\n',
                encoding="utf-8",
            )
        (root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        (root / "Cargo.lock").write_text(
            "version = 4\n\n" + "\n".join(
                f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
                for name in sorted(PRODUCT_PACKAGES)
            ), encoding="utf-8",
        )
        (root / "crates/cfw-core/src").mkdir()
        (root / "crates/cfw-core/src/lib.rs").write_text(
            f'pub const PRODUCT_VERSION: &str = "{version}";\n', encoding="utf-8"
        )
        (root / "apps/cfw-tauri-shell/tauri.conf.json").write_text(
            f'{{"version":"{version}"}}', encoding="utf-8"
        )
        (root / "native/macos/project.yml").write_text(
            f"settings:\n  base:\n    MARKETING_VERSION: {version}\n"
            f"    CFW_BUILD_NUMBER: {build}\n"
            "    CURRENT_PROJECT_VERSION: $(CFW_BUILD_NUMBER)\n",
            encoding="utf-8",
        )
        for name in ("ProxyAgent-Info.plist", "PacketTunnel-Info.plist"):
            (root / "native/macos/Config" / name).write_text(
                "<plist><dict><key>CFBundleVersion</key>"
                "<string>$(CURRENT_PROJECT_VERSION)</string></dict></plist>\n",
                encoding="utf-8",
            )
        (root / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## {version} - Unreleased\n", encoding="utf-8"
        )
        admission = root / "apps/cfw-tauri-shell/src/legacy/admission.rs"
        admission.parent.mkdir(parents=True)
        admission.write_text(f'const RELEASE_VERSION: &str = "{version}";\nconst RELEASE_BUILD: &str = "{build}";\n')
        observation = root / "native/macos/Sources/CFWSharedProtocol/ReleaseObservation.swift"
        observation.parent.mkdir(parents=True)
        observation.write_text(
            f'  static let releaseProductVersion = "{version}"\n'
            f'  static let releaseBuildNumber = "{build}"\n', encoding="utf-8",
        )

    def test_complete_contract_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.make_repository(repository)
            verify(repository)

    def test_tauri_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.make_repository(repository)
            (repository / "apps/cfw-tauri-shell/tauri.conf.json").write_text(
                '{"version":"0.5.1"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "Tauri version"):
                verify(repository)

    def test_runtime_admission_must_match_the_release_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.make_repository(repository)
            source = repository / "apps/cfw-tauri-shell/src/legacy/admission.rs"
            source.write_text(source.read_text().replace("50028", "50025"))
            with self.assertRaisesRegex(ValueError, "runtime migration admission RELEASE_BUILD"):
                verify(repository)

    def test_release_identity_remains_frozen(self) -> None:
        self.assertEqual((EXPECTED_VERSION, EXPECTED_BUILD), ("0.5.0", "50028"))
        self.assertEqual(
            (ACTIVE_RELEASE_IDENTITY.product_version, ACTIVE_RELEASE_IDENTITY.ga_build),
            ("0.5.0", "50028"),
        )
        # The retained signed preview shares the product version; a tree still
        # carrying its build number is not the release.
        self.assertEqual(SIGNED_PREVIEW_IDENTITY.build_number, "50025")
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.make_repository(repository)
            project = repository / "native/macos/project.yml"
            project.write_text(project.read_text().replace("50028", "50025"))
            with self.assertRaisesRegex(ValueError, "Xcode build differs from the fixed release identity"):
                verify(repository)

    def test_controller_version_is_included(self) -> None:
        self.assertIn("cfw-controller", PRODUCT_PACKAGES)
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.make_repository(repository)
            manifest = repository / "crates/cfw-controller/Cargo.toml"
            manifest.write_text(manifest.read_text().replace("0.5.0", "0.4.0"))
            with self.assertRaisesRegex(ValueError, "cfw-controller"):
                verify(repository)

    def test_lockfile_version_and_local_origin_are_checked(self) -> None:
        mutations = (
            (lambda text: text.replace('version = "0.5.0"', 'version = "0.4.0"', 1),
             "Cargo.lock version differs"),
            (lambda text: text.replace('name = "cfw-core"',
                                       'name = "cfw-core"\nsource = "registry+https://example.test"'),
             "must remain local"),
            (lambda text: text.replace('name = "cfw-core"', 'name = "missing-core"'),
             "package set differs"),
            (lambda text: text + '\n[[package]]\nname = "cfw-core"\nversion = "0.5.0"\n',
             "duplicate product Cargo.lock"),
        )
        for mutate, error in mutations:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                self.make_repository(repository)
                lock = repository / "Cargo.lock"
                lock.write_text(mutate(lock.read_text()))
                with self.assertRaisesRegex(ValueError, error):
                    verify(repository)

    def test_core_version_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.make_repository(repository)
            source = repository / "crates/cfw-core/src/lib.rs"
            source.write_text(source.read_text().replace("0.5.0", "0.4.0"))
            with self.assertRaisesRegex(ValueError, "cfw-core PRODUCT_VERSION"):
                verify(repository)

    def test_optional_workspace_version_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.make_repository(repository)
            (repository / "Cargo.toml").write_text(
                '[workspace.package]\nversion = "0.4.0"\n'
            )
            with self.assertRaisesRegex(ValueError, "workspace package version"):
                verify(repository)

    def test_release_build_is_exact_and_canonical(self) -> None:
        for build in ("40073", "50025", "50026", "50027", "50029", "050028", "5002", "+50028", "50028a"):
            with self.subTest(build=build), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                self.make_repository(repository)
                project = repository / "native/macos/project.yml"
                project.write_text(project.read_text().replace("50028", build))
                with self.assertRaisesRegex(ValueError, "fixed release identity|canonical positive"):
                    verify(repository)

    def test_observation_identity_is_checked(self) -> None:
        for original, replacement in (("50028", "50025"), ("0.5.0", "0.4.0")):
            with self.subTest(original=original), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                self.make_repository(repository)
                observation = (
                    repository / "native/macos/Sources/CFWSharedProtocol/ReleaseObservation.swift"
                )
                observation.write_text(observation.read_text().replace(original, replacement))
                with self.assertRaisesRegex(ValueError, "native release observation"):
                    verify(repository)

    def test_every_version_surface_is_checked(self) -> None:
        for relative, old, new, error in (
            ("apps/cfw-tauri-shell/tauri.conf.json", "0.5.0", "0.4.0", "Tauri version"),
            ("native/macos/project.yml", "0.5.0", "0.4.0", "MARKETING_VERSION"),
            ("CHANGELOG.md", "0.5.0", "0.4.0", "first changelog release"),
            ("native/macos/Config/ProxyAgent-Info.plist", "$(CURRENT_PROJECT_VERSION)",
             "50028", "must inherit the canonical"),
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                self.make_repository(repository)
                path = repository / relative
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaisesRegex(ValueError, error):
                    verify(repository)

    def test_the_preview_selector_is_retired(self) -> None:
        # One tree carries one identity; there is no second contract to select.
        with patch.object(sys, "argv", ["verify_version_contract.py", "--preview"]):
            with self.assertRaises(SystemExit) as raised:
                contract.main()
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
