"""Negative coverage for native product-graph target/entitlement/plist omissions.

The existing ``test_verify_native_product_graph`` suite exercises the Tauri
embedding map, the launchd daemon plist, and the inside-out signing order.  It
does not exercise the XcodeGen spec, the SwiftPM manifest, the candidate native
build script, the Packet Tunnel ``Info.plist``, or the per-product entitlements.

This file adds the genuinely missing scenarios required by task 9.13: a Release
product that omits a signed target, drops the ``CFW_GLOBAL_AUTHORITY_REQUIRED=1``
gate, loses the Packet Tunnel Mach-service/provider declaration, or ships
entitlements that grant a data plane (or drop a required grant) must fail closed.

Each positive test binds the shipped tracked file so the real product graph is
guarded; each negative test mutates exactly one required input and asserts the
verifier raises.

Validates: Requirements 1.2, 5.1, 7.3, 7.5
"""

from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path

from scripts.verify_native_product_graph import (
    MACH_SERVICE,
    NativeProductGraphError,
    verify_entitlements,
    verify_native_build_script,
    verify_packet_tunnel_info,
    verify_swiftpm_manifest,
    verify_xcodegen_spec,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# XcodeGen spec: target and Release-gate omissions.
# ---------------------------------------------------------------------------
class XcodeGenSpecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project = _read("native/macos/project.yml")

    def test_shipped_spec_passes(self) -> None:
        verify_xcodegen_spec(self.project)

    def test_missing_release_authority_gate_fails_closed(self) -> None:
        mutated = self.project.replace("CFW_GLOBAL_AUTHORITY_REQUIRED=1", "CFW_UNRELATED=1")
        with self.assertRaisesRegex(NativeProductGraphError, "Release configuration"):
            verify_xcodegen_spec(mutated)

    def test_missing_proxy_agent_target_fails_closed(self) -> None:
        mutated = self.project.replace("CFWProxyAgent:", "CFWRemovedAgent:")
        with self.assertRaisesRegex(NativeProductGraphError, "targets"):
            verify_xcodegen_spec(mutated)

    def test_missing_packet_tunnel_mach_service_declaration_fails_closed(self) -> None:
        mutated = self.project.replace(
            "NEMachServiceName: $(TeamIdentifierPrefix)com.bill.clashformac.packet-tunnel",
            "NEMachServiceName: com.example.wrong",
        )
        with self.assertRaisesRegex(NativeProductGraphError, "Mach service"):
            verify_xcodegen_spec(mutated)

    def test_missing_manual_code_sign_style_fails_closed(self) -> None:
        mutated = self.project.replace("CODE_SIGN_STYLE: Manual", "CODE_SIGN_STYLE: Automatic")
        with self.assertRaisesRegex(NativeProductGraphError, "signed target settings"):
            verify_xcodegen_spec(mutated)

    def test_missing_deployment_target_fails_closed(self) -> None:
        mutated = self.project.replace('macOS: "15.0"', 'macOS: "14.0"')
        with self.assertRaisesRegex(NativeProductGraphError, "deployment target"):
            verify_xcodegen_spec(mutated)


# ---------------------------------------------------------------------------
# SwiftPM manifest: platform and Release-gate omissions.
# ---------------------------------------------------------------------------
class SwiftPMManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.package = _read("native/macos/Package.swift")

    def test_shipped_manifest_passes(self) -> None:
        verify_swiftpm_manifest(self.package)

    def test_missing_macos_15_platform_fails_closed(self) -> None:
        mutated = self.package.replace(".macOS(.v15)", ".macOS(.v14)")
        with self.assertRaisesRegex(NativeProductGraphError, "platform"):
            verify_swiftpm_manifest(mutated)

    def test_missing_release_gate_define_fails_closed(self) -> None:
        mutated = self.package.replace(
            '.define("CFW_GLOBAL_AUTHORITY_REQUIRED", .when(configuration: .release))',
            '.define("CFW_UNRELATED", .when(configuration: .release))',
        )
        with self.assertRaisesRegex(NativeProductGraphError, "Release configuration"):
            verify_swiftpm_manifest(mutated)

    def test_missing_authority_daemon_product_fails_closed(self) -> None:
        mutated = self.package.replace(
            'name: "CFWGlobalAuthorityDaemon"', 'name: "CFWRemovedDaemon"'
        )
        with self.assertRaisesRegex(NativeProductGraphError, "Global Authority daemon"):
            verify_swiftpm_manifest(mutated)


# ---------------------------------------------------------------------------
# Candidate native build script: product/provisioning omissions.
# ---------------------------------------------------------------------------
class NativeBuildScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.build = _read("scripts/build_native_products.sh")

    def test_shipped_build_script_passes(self) -> None:
        verify_native_build_script(self.build)

    def test_missing_release_gate_fails_closed(self) -> None:
        mutated = self.build.replace("CFW_GLOBAL_AUTHORITY_REQUIRED=1", "CFW_UNRELATED=1")
        with self.assertRaisesRegex(NativeProductGraphError, "candidate native build"):
            verify_native_build_script(mutated)

    def test_missing_packet_tunnel_provisioning_fails_closed(self) -> None:
        mutated = self.build.replace(
            "PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER", "REMOVED_SPECIFIER"
        )
        with self.assertRaisesRegex(NativeProductGraphError, "provisioning"):
            verify_native_build_script(mutated)

    def test_missing_arm64_architecture_fails_closed(self) -> None:
        mutated = self.build.replace("ARCHS=arm64", "ARCHS=x86_64")
        with self.assertRaisesRegex(NativeProductGraphError, "architecture"):
            verify_native_build_script(mutated)


# ---------------------------------------------------------------------------
# Packet Tunnel Info.plist: NetworkExtension declaration omissions.
# ---------------------------------------------------------------------------
def _valid_packet_info() -> dict[str, object]:
    return {
        "NetworkExtension": {
            "NEMachServiceName": "$(TeamIdentifierPrefix)com.bill.clashformac.packet-tunnel",
            "NEProviderClasses": {
                "com.apple.networkextension.packet-tunnel": "CFWPacketTunnel.PacketTunnelProvider"
            },
        }
    }


class PacketTunnelInfoTests(unittest.TestCase):
    def test_valid_info_passes(self) -> None:
        verify_packet_tunnel_info(_valid_packet_info())

    def test_missing_network_extension_dict_fails_closed(self) -> None:
        with self.assertRaisesRegex(NativeProductGraphError, "NetworkExtension"):
            verify_packet_tunnel_info({"CFBundleIdentifier": "x"})

    def test_wrong_mach_service_fails_closed(self) -> None:
        info = _valid_packet_info()
        info["NetworkExtension"]["NEMachServiceName"] = "com.example.wrong"
        with self.assertRaisesRegex(NativeProductGraphError, "Mach service"):
            verify_packet_tunnel_info(info)

    def test_missing_provider_class_fails_closed(self) -> None:
        info = _valid_packet_info()
        del info["NetworkExtension"]["NEProviderClasses"]
        with self.assertRaisesRegex(NativeProductGraphError, "provider class"):
            verify_packet_tunnel_info(info)


# ---------------------------------------------------------------------------
# Entitlements: data-plane grant and required-grant omissions.
# ---------------------------------------------------------------------------
_APP_GROUP = ["$(TeamIdentifierPrefix)group.com.bill.clashformac"]
_NE_ROLE = ["packet-tunnel-provider-systemextension"]


def _valid_entitlements() -> dict[str, dict[str, object]]:
    return {
        "GlobalAuthority.entitlements": {},
        "PacketTunnel.entitlements": {
            "com.apple.developer.networking.networkextension": list(_NE_ROLE),
            "com.apple.security.app-sandbox": True,
            "com.apple.security.network.client": True,
            "com.apple.security.network.server": True,
        },
        "ProxyAgent.entitlements": {
            "com.apple.security.application-groups": list(_APP_GROUP),
            "keychain-access-groups": ["$(AppIdentifierPrefix)com.bill.clashformac.proxy-agent"],
        },
        "Host.entitlements": {
            "com.apple.developer.system-extension.install": True,
            "com.apple.developer.networking.networkextension": list(_NE_ROLE),
            "com.apple.security.application-groups": list(_APP_GROUP),
        },
    }


def _write_config(root: Path, entitlements: dict[str, dict[str, object]]) -> Path:
    config = root / "native" / "macos" / "Config"
    config.mkdir(parents=True, exist_ok=True)
    for name, value in entitlements.items():
        with (config / name).open("wb") as handle:
            plistlib.dump(value, handle)
    return root


class EntitlementTests(unittest.TestCase):
    def _verify(self, entitlements: dict[str, dict[str, object]]) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            verify_entitlements(_write_config(Path(tmp), entitlements))

    def _assert_fails(self, entitlements: dict[str, dict[str, object]], pattern: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _write_config(Path(tmp), entitlements)
            with self.assertRaisesRegex(NativeProductGraphError, pattern):
                verify_entitlements(root)

    def test_valid_entitlement_set_passes(self) -> None:
        self._verify(_valid_entitlements())

    def test_global_authority_data_plane_grant_fails_closed(self) -> None:
        # A non-empty Authority entitlement set is a data-plane / broad grant.
        entitlements = _valid_entitlements()
        entitlements["GlobalAuthority.entitlements"] = {
            "com.apple.security.network.server": True
        }
        self._assert_fails(entitlements, "must be empty")

    def test_packet_tunnel_missing_role_fails_closed(self) -> None:
        entitlements = _valid_entitlements()
        del entitlements["PacketTunnel.entitlements"][
            "com.apple.developer.networking.networkextension"
        ]
        self._assert_fails(entitlements, "packet-tunnel-provider-systemextension")

    def test_packet_tunnel_without_sandbox_fails_closed(self) -> None:
        entitlements = _valid_entitlements()
        entitlements["PacketTunnel.entitlements"]["com.apple.security.app-sandbox"] = False
        self._assert_fails(entitlements, "app-sandbox")

    def test_packet_tunnel_claiming_app_group_fails_closed(self) -> None:
        # The sandboxed Provider must not resolve a shared App Group container.
        entitlements = _valid_entitlements()
        entitlements["PacketTunnel.entitlements"][
            "com.apple.security.application-groups"
        ] = list(_APP_GROUP)
        self._assert_fails(entitlements, "must not claim an App Group")

    def test_proxy_agent_missing_app_group_fails_closed(self) -> None:
        entitlements = _valid_entitlements()
        del entitlements["ProxyAgent.entitlements"]["com.apple.security.application-groups"]
        self._assert_fails(entitlements, "shared App Group")

    def test_host_missing_system_extension_install_fails_closed(self) -> None:
        entitlements = _valid_entitlements()
        del entitlements["Host.entitlements"]["com.apple.developer.system-extension.install"]
        self._assert_fails(entitlements, "System Extension installation")


if __name__ == "__main__":
    unittest.main()
