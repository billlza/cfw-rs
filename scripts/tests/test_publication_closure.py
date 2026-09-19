from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.publication.artifact_preparation import (
    _prepackage_evidence_sources,
    _reject_absolute_graph_paths,
)
from scripts.publication.closure import (
    ALLOWED_CODE_PATHS,
    REQUIRED_ARTIFACT_KINDS,
    REQUIRED_ECOSYSTEMS,
    REQUIRED_GRAPH_KINDS,
    scan_app_code,
    validate_production_sets,
)
from scripts.publication.common import PublicationError


EXPECTED_CODE_PATHS = {
    "Contents/MacOS/clash-for-mac",
    "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/CFWNativeBridge",
    "Contents/Library/HelperTools/CFWGlobalAuthority",
    "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent",
    "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension/Contents/MacOS/CFWPacketTunnel",
    "Contents/Library/HelperTools/cfw-helper-tombstone",
}


class PublicationClosureTests(unittest.TestCase):
    def validate_tool_inventory(self, names: tuple[str, ...]) -> None:
        validate_production_sets(
            [{"ecosystem": value} for value in REQUIRED_ECOSYSTEMS],
            [{"name": name} for name in names],
            [{"kind": value} for value in REQUIRED_ARTIFACT_KINDS],
            [{"kind": value} for value in REQUIRED_GRAPH_KINDS],
        )

    def test_current_external_tool_inventory_includes_independent_npm(self) -> None:
        # The dependency refresh installs npm separately from the Node archive.
        # This is the observed producer inventory, independent of the consumer set.
        self.validate_tool_inventory((
            "@esbuild/darwin-arm64", "esbuild", "go", "gomobile", "node", "npm",
            "rust", "swift", "tauri-cli", "xcode", "xcodegen",
        ))

    def test_external_tool_inventory_rejects_missing_duplicate_and_extra_tools(self) -> None:
        complete = (
            "@esbuild/darwin-arm64", "esbuild", "go", "gomobile", "node", "npm",
            "rust", "swift", "tauri-cli", "xcode", "xcodegen",
        )
        for name in complete:
            with self.subTest(missing=name), self.assertRaisesRegex(PublicationError, "build-tool provenance"):
                self.validate_tool_inventory(tuple(value for value in complete if value != name))
        for unexpected in ("npm", "unreviewed-tool"):
            with self.subTest(extra=unexpected), self.assertRaisesRegex(PublicationError, "build-tool provenance"):
                self.validate_tool_inventory((*complete, unexpected))

    def make_app_code(self, app: Path) -> None:
        for relative in EXPECTED_CODE_PATHS:
            path = app / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"MZfixture")
            path.chmod(0o755)

    def test_unknown_executable_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Clash for Mac.app"
            self.make_app_code(app)
            unknown = app / "Contents/MacOS/unmanifested"
            unknown.write_bytes(b"MZunknown")
            unknown.chmod(0o755)
            with self.assertRaises(PublicationError):
                scan_app_code(app, fixture=False)

    def test_exact_code_closure_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Clash for Mac.app"
            self.make_app_code(app)
            scan_app_code(app, fixture=False)

    def test_code_closure_matches_independent_product_contract(self) -> None:
        self.assertEqual(ALLOWED_CODE_PATHS, EXPECTED_CODE_PATHS)

    def test_missing_global_authority_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Clash for Mac.app"
            self.make_app_code(app)
            (app / "Contents/Library/HelperTools/CFWGlobalAuthority").unlink()
            with self.assertRaisesRegex(PublicationError, "code closure is incomplete"):
                scan_app_code(app, fixture=False)

    def test_reference_reverse_tree_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Clash for Mac.app"
            self.make_app_code(app)
            payload = app / "Contents/Resources/reverse/reference.bin"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"reference")
            with self.assertRaises(PublicationError):
                scan_app_code(app, fixture=False)

    def test_absolute_build_graph_path_fails_closed(self) -> None:
        with self.assertRaisesRegex(PublicationError, "absolute path"):
            _reject_absolute_graph_paths({"targets": [{"path": "/Users/example/project"}]})

    def test_relative_build_graph_paths_are_accepted(self) -> None:
        _reject_absolute_graph_paths(
            {"targets": [{"path": "Sources/CFWNative"}], "repository": "pkg:swift/cfwnative"}
        )

    def test_prepackage_evidence_has_no_future_stage_dependency(self) -> None:
        root = Path("target/candidates/0.4.0/ga/40072")
        sources = _prepackage_evidence_sources(root)
        self.assertEqual(
            set(sources),
            {
                "candidate-freeze-intent",
                "ga-product-input",
                "hosted-ci-receipt",
                "signing-transformation",
            },
        )
        for path in sources.values():
            self.assertNotIn("prepackage", path.parts)
            self.assertNotIn("ga-acceptance", path.parts)
            self.assertNotIn("publication", path.parts)
        self.assertNotIn("prepackage-manifest", REQUIRED_ARTIFACT_KINDS)
        self.assertNotIn("ga-acceptance-manifest", REQUIRED_ARTIFACT_KINDS)
        self.assertIn("hosted-ci-receipt", REQUIRED_ARTIFACT_KINDS)
        self.assertNotIn("local-deterministic-ci-lanes", REQUIRED_ARTIFACT_KINDS)


if __name__ == "__main__":
    unittest.main()
