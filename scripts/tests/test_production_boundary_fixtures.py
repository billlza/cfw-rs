"""Whole-tree production-boundary integration coverage for task 9.13.

The existing ``test_verify_production_boundary_removal`` suite unit-tests
``scan_source`` on individual snippets.  It does not drive ``verify_repository``
over a populated multi-root production tree, and it does not assert that a
Release product carrying *every* forbidden construct at once fails closed with
each category reported.

This file builds temporary production trees spanning all production roots and
asserts:

* a clean tree passes;
* a single forbidden construct in any root fails closed;
* a tree seeded with a legacy root data plane, a direct-payload transport, a
  private Network Extension access, a provider-local production authority, and
  an executable/alternate-core fallback fails closed and reports **all** of
  those categories together (no fixture can enable any of them); and
* the same forbidden constructs placed in an explicitly named test fixture are
  exempt, proving the boundary distinguishes production data-plane code from
  fixtures.

Validates: Requirements 1.2, 5.1, 7.3, 7.5
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.verify_production_boundary_removal import (
    PRODUCTION_ROOTS,
    ProductionBoundaryViolation,
    verify_repository,
)

# A representative production file under each scanned root, keyed by the root.
_CLEAN_SOURCES = {
    "native/macos/Sources": ("CFWPacketTunnel/PacketTunnelProvider.swift", "let owner = TicketOnlyStart()\n"),
    "native/macos/SystemExtension": ("main.swift", "startProvider()\n"),
    "apps/cfw-tauri-shell/src": ("engine.rs", "let coordinator = EngineModeCoordinator::new();\n"),
    "crates": ("cfw-core/src/lib.rs", "pub fn coordinate() {}\n"),
}

# Forbidden production constructs, one per retired-boundary category, each in a
# Swift data-plane file so the structural rules apply.
_FORBIDDEN = {
    "retired helper / root data-plane startup": "SMJobBless(kSMDomainSystemLaunchd, l, a, &e)\n",
    "direct Tunnel payload transport": "let p = try TunnelStartPayloadCodec.encode(d)\n",
    "private Network Extension access": "let fd = socket.fileDescriptor\n",
    "provider-local lease authority": "let s = CrossProcessEngineLeaseStore(productionPort: 1)\n",
    "executable-launch or alternate-core fallback": "let t = Process()\n",
}


def _write_clean_tree(root: Path) -> Path:
    for relative_root, (relative_file, body) in _CLEAN_SOURCES.items():
        path = root / relative_root / relative_file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


class CleanTreeTests(unittest.TestCase):
    def test_all_production_roots_are_covered_by_the_fixture(self) -> None:
        # Guards against the gate adding a root the integration fixture forgets.
        self.assertEqual(set(_CLEAN_SOURCES), set(PRODUCTION_ROOTS))

    def test_clean_multi_root_tree_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            verify_repository(_write_clean_tree(Path(tmp)))


class SingleViolationTests(unittest.TestCase):
    def test_direct_payload_in_system_extension_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _write_clean_tree(Path(tmp))
            (root / "native/macos/SystemExtension/main.swift").write_text(
                "let p = try TunnelStartPayloadCodec.encode(d)\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ProductionBoundaryViolation, "direct Tunnel payload transport"
            ):
                verify_repository(root)

    def test_insecure_authority_override_in_rust_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _write_clean_tree(Path(tmp))
            (root / "apps/cfw-tauri-shell/src/engine.rs").write_text(
                'let f = "CFW_GLOBAL_AUTHORITY_REQUIRED=0";\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ProductionBoundaryViolation, "insecure Authority override"
            ):
                verify_repository(root)


class NoFixtureCanEnableLegacyPathsTests(unittest.TestCase):
    def test_every_retired_category_fails_closed_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _write_clean_tree(Path(tmp))
            # Seed one forbidden construct per category into a production file.
            seeded = "".join(_FORBIDDEN.values())
            (root / "native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift").write_text(
                seeded, encoding="utf-8"
            )
            with self.assertRaises(ProductionBoundaryViolation) as caught:
                verify_repository(root)
            message = str(caught.exception)
            for category in _FORBIDDEN:
                self.assertIn(category, message)

    def test_forbidden_constructs_in_named_fixture_are_exempt(self) -> None:
        # The identical constructs inside an explicitly named test fixture must
        # not trip the gate: fixtures may reference retired constructs, but no
        # production data-plane file may.
        with tempfile.TemporaryDirectory() as tmp:
            root = _write_clean_tree(Path(tmp))
            fixture = root / "native/macos/Sources/CFWPacketTunnel/LegacyLeaseTests.swift"
            fixture.write_text("".join(_FORBIDDEN.values()), encoding="utf-8")
            # The clean tree plus a fixture-only reference still verifies.
            verify_repository(root)


class FailClosedTreeTests(unittest.TestCase):
    def test_missing_production_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _write_clean_tree(Path(tmp))
            # Remove one required root entirely.
            for path in sorted((root / "crates").rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
            (root / "crates/cfw-core/src").rmdir()
            (root / "crates/cfw-core").rmdir()
            (root / "crates").rmdir()
            with self.assertRaisesRegex(ProductionBoundaryViolation, "unavailable"):
                verify_repository(root)


if __name__ == "__main__":
    unittest.main()
