from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path

from scripts.publication.graph_model import ComponentSeed
from scripts.publication.preparer import _blocker_document, _source_closure


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
        seed = replace(self.seed("xcode"), external_build_tool=True)
        plan = _source_closure(seed)
        self.assertEqual(plan["release_impact"], "non-blocking-external-build-tool-provenance")
        self.assertEqual(plan["classification"], "apple-proprietary-source-not-redistributable")
        self.assertIn("nonredistributable external prerequisite", plan["closure_action"])
        report = _blocker_document(
            [
                {
                    "id": seed.identifier,
                    "name": seed.name,
                    "version": seed.version,
                    "copyright_text": "NOASSERTION",
                    "license_resolution": {
                        "status": "manual-required",
                        "reason": "Xcode EULA requires human review",
                    },
                    "source_evidence": {"method": "missing-source"},
                }
            ],
            {seed.identifier: seed},
        )
        self.assertEqual(report["external_build_tool_license_review_required_count"], 1)
        self.assertEqual(
            report["external_build_tool_license_review_required"][0]["name"], "xcode"
        )

    def test_copyright_noassertion_is_informational_not_a_blocker(self) -> None:
        seed = ComponentSeed(
            identifier="cargo:fixture:0000000000000000",
            name="fixture",
            version="1.0.0",
            ecosystem="cargo",
            scope="runtime",
            purl="pkg:cargo/fixture@1.0.0",
            source_root=Path("/fixture"),
        )
        record = {
            "id": seed.identifier,
            "name": seed.name,
            "version": seed.version,
            "copyright_text": "NOASSERTION",
            "license_resolution": {"status": "automatic", "reason": ""},
            "source_evidence": {"method": "repository-source"},
        }
        report = _blocker_document([record], {seed.identifier: seed})
        self.assertEqual(report["copyright_noassertion_count"], 1)
        self.assertEqual(report["copyright_noassertion"][0]["id"], seed.identifier)
        self.assertNotIn("copyright_review_required_count", report)
        self.assertNotIn("copyright_review_required", report)


if __name__ == "__main__":
    unittest.main()
