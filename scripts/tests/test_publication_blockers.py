from __future__ import annotations

import unittest
from pathlib import Path

from scripts.publication.graph_model import ComponentSeed
from scripts.publication.preparer import _source_closure


class PublicationBlockerTests(unittest.TestCase):
    def seed(self, name: str) -> ComponentSeed:
        return ComponentSeed(
            identifier=f"toolchain:{name}:0000000000000000",
            name=name,
            version="1.0.0",
            ecosystem="toolchain",
            scope="toolchain",
            purl=f"pkg:generic/{name}@1.0.0",
            source_root=None,
            license_root=Path("/nonexistent"),
        )

    def test_reconstructible_source_has_an_executable_closure_plan(self) -> None:
        plan = _source_closure(self.seed("rust"))
        self.assertEqual(plan["release_impact"], "non-blocking-external-build-tool-provenance")
        self.assertIn("executable SHA-256", plan["closure_action"])
        self.assertIn("8bab26f4", plan["acceptance"])

    def test_xcode_is_not_misreported_as_redistributable_source(self) -> None:
        plan = _source_closure(self.seed("xcode"))
        self.assertEqual(plan["release_impact"], "non-blocking-external-build-tool-provenance")
        self.assertEqual(plan["classification"], "apple-proprietary-source-not-redistributable")
        self.assertIn("nonredistributable external prerequisite", plan["closure_action"])


if __name__ == "__main__":
    unittest.main()
