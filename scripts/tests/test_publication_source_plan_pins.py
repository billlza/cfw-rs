#!/usr/bin/env python3
"""Publication source plans must follow the canonical release pins."""

from __future__ import annotations

from pathlib import Path
import unittest

from scripts.publication.preparer import _SOURCE_CLOSURE_PLANS


REPOSITORY = Path(__file__).resolve().parents[2]


def _pins() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (REPOSITORY / "scripts/dependency_pins.env").read_text(
        encoding="utf-8"
    ).splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


class PublicationSourcePlanPinTests(unittest.TestCase):
    def test_build_tool_source_references_match_release_pins(self) -> None:
        pins = _pins()
        expected = {
            "node": f"node-v{pins['NODE_VERSION']}.tar.gz",
            "go": f"go{pins['GO_VERSION']}.darwin-arm64",
            "gomobile": pins["GOMOBILE_VERSION"],
            "rust": f"rustc-{pins['RUST_VERSION']}-src.tar.xz",
            "tauri-cli": f"tauri-cli-{pins['TAURI_CLI_VERSION']}.crate",
            "xcodegen": pins["XCODEGEN_VERSION"],
        }
        for component, reference in expected.items():
            with self.subTest(component=component):
                self.assertEqual(_SOURCE_CLOSURE_PLANS[component]["reference"], reference)
        self.assertIn(pins["XCODE_VERSION"], _SOURCE_CLOSURE_PLANS["xcode"]["reference"])


if __name__ == "__main__":
    unittest.main()
