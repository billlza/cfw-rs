from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.verify_version_contract import EXPECTED_VERSION, PRODUCT_PACKAGES, verify


class VersionContractTests(unittest.TestCase):
    def make_repository(self, root: Path) -> None:
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
                f'[package]\nname = "{name}"\nversion = "{EXPECTED_VERSION}"\n',
                encoding="utf-8",
            )
        (root / "apps/cfw-tauri-shell/tauri.conf.json").write_text(
            '{"version":"0.4.0"}', encoding="utf-8"
        )
        (root / "native/macos/project.yml").write_text(
            "settings:\n  base:\n    MARKETING_VERSION: 0.4.0\n"
            "    CFW_BUILD_NUMBER: 40000\n"
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
            "# Changelog\n\n## 0.4.0 - Unreleased\n", encoding="utf-8"
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
                '{"version":"0.4.1"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "Tauri version"):
                verify(repository)


if __name__ == "__main__":
    unittest.main()
