#!/usr/bin/env python3
"""Publication source plans must follow the canonical release pins."""

from __future__ import annotations

from pathlib import Path
import unittest

from scripts.publication.graph_model import ComponentSeed
from scripts.publication.preparer import _SOURCE_CLOSURE_PLANS, _source_closure


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


def _toolchain_seed(name: str, version: str) -> ComponentSeed:
    return ComponentSeed(
        identifier=f"toolchain:{name}:0000000000000000",
        name=name,
        version=version,
        ecosystem="toolchain",
        scope="toolchain",
        purl=f"pkg:generic/{name}@{version}",
        source_root=None,
        license_root=Path("/nonexistent"),
    )


class PublicationSourcePlanPinTests(unittest.TestCase):
    def test_build_tool_source_references_match_release_pins(self) -> None:
        pins = _pins()
        expected = {
            "node": f"node-v{pins['NODE_VERSION']}.tar.gz",
            "gomobile": pins["GOMOBILE_VERSION"],
            "rust": f"rustc-{pins['RUST_VERSION']}-src.tar.xz",
            "tauri-cli": f"tauri-cli-{pins['TAURI_CLI_VERSION']}.crate",
            "xcodegen": pins["XCODEGEN_VERSION"],
        }
        for component, reference in expected.items():
            with self.subTest(component=component):
                self.assertEqual(_SOURCE_CLOSURE_PLANS[component]["reference"], reference)
        self.assertEqual(
            _SOURCE_CLOSURE_PLANS["tauri-cli"]["upstream"],
            f"https://crates.io/crates/tauri-cli/{pins['TAURI_CLI_VERSION']}",
        )

    def test_go_source_reference_names_the_collected_toolchain_version(self) -> None:
        # The Go toolchain seed's version is the collected `go version`, which
        # the native collector requires to equal GO_VERSION; the archive
        # reference follows it, so a Go bump edits only the pin file.
        for version in (_pins()["GO_VERSION"], "1.99.7"):
            with self.subTest(version=version):
                plan = _source_closure(_toolchain_seed("go", version))
                self.assertEqual(plan["reference"], f"go{version}.darwin-arm64")
                self.assertNotIn("reference_template", plan)

    def test_xcode_source_reference_names_the_collected_toolchain_version(self) -> None:
        # The Xcode toolchain seed's version is XCODE_VERSION, which the native
        # collector requires `xcodebuild -version` to report; the reference
        # follows it, so an Xcode bump leaves the plan unchanged.
        for version in (_pins()["XCODE_VERSION"], "99.9"):
            with self.subTest(version=version):
                plan = _source_closure(_toolchain_seed("xcode", version))
                self.assertEqual(
                    plan["reference"], f"Xcode {version} exact build from dependency_pins.env"
                )
                self.assertNotIn("reference_template", plan)

    def test_each_plan_names_its_source_once(self) -> None:
        for component, plan in _SOURCE_CLOSURE_PLANS.items():
            with self.subTest(component=component):
                self.assertEqual(
                    len({"reference", "reference_template"} & set(plan)), 1
                )
        self.assertEqual(
            {
                component
                for component, plan in _SOURCE_CLOSURE_PLANS.items()
                if "reference_template" in plan
            },
            {"go", "xcode"},
        )


if __name__ == "__main__":
    unittest.main()
