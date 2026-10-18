from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.verify_production_boundary_removal import (
    ProductionBoundaryViolation,
    read_source,
    scan_source,
    strip_comments_and_strings,
    verify_repository,
)

PRODUCTION_SWIFT = "native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift"
PRODUCTION_RUST = "apps/cfw-tauri-shell/src/engine.rs"
TEST_FIXTURE = "native/macos/Tests/CFWSharedProtocolTests/CrossProcessEngineLeaseTests.swift"


def _categories(relative_path: str, source: str) -> set[str]:
    return {finding.category for finding in scan_source(relative_path, source)}


class ForbiddenPatternDetectionTests(unittest.TestCase):
    def test_direct_tunnel_payload_codec_use_detected(self) -> None:
        source = "let payload = try TunnelStartPayloadCodec.encode(descriptor: d)\n"
        self.assertIn(
            "direct Tunnel payload transport", _categories(PRODUCTION_SWIFT, source)
        )

    def test_tunnel_start_payload_option_key_use_detected(self) -> None:
        source = "options[NativeProtocolConstants.tunnelStartPayloadOptionKey] = data\n"
        self.assertIn(
            "direct Tunnel payload transport", _categories(PRODUCTION_SWIFT, source)
        )

    def test_provider_local_lease_store_construction_detected(self) -> None:
        source = "let store = CrossProcessEngineLeaseStore(productionPort: 49_373)\n"
        self.assertIn(
            "provider-local lease authority", _categories(PRODUCTION_SWIFT, source)
        )

    def test_provider_local_acceptance_store_construction_detected(self) -> None:
        source = "let store = SandboxConfigurationAcceptanceStore(rootURL: root)\n"
        self.assertIn(
            "provider-local acceptance authority", _categories(PRODUCTION_SWIFT, source)
        )

    def test_durable_runtime_configuration_store_is_detected(self) -> None:
        source = 'let store = AppGroupConfigurationStore(appGroupIdentifier: "group")\n'
        self.assertIn(
            "durable runtime configuration fallback",
            _categories(PRODUCTION_SWIFT, source),
        )

    def test_retired_helper_startup_detected(self) -> None:
        source = "SMJobBless(kSMDomainSystemLaunchd, label, auth, &error)\n"
        self.assertIn(
            "retired helper / root data-plane startup",
            _categories(PRODUCTION_SWIFT, source),
        )

    def test_executable_launch_fallback_detected(self) -> None:
        for snippet in (
            "let task = Process()\n",
            "let handle = dlopen(path, RTLD_NOW)\n",
            "posix_spawn(&pid, path, nil, nil, argv, environ)\n",
        ):
            with self.subTest(snippet=snippet):
                self.assertIn(
                    "executable-launch or alternate-core fallback",
                    _categories(PRODUCTION_SWIFT, snippet),
                )

    def test_private_network_extension_access_detected(self) -> None:
        for snippet in (
            "let fd = socket.fileDescriptor\n",
            "let value = packetFlow.value(forKey: \"socket\")\n",
        ):
            with self.subTest(snippet=snippet):
                self.assertIn(
                    "private Network Extension access",
                    _categories(PRODUCTION_SWIFT, snippet),
                )

    def test_insecure_authority_override_detected_in_swift_and_rust(self) -> None:
        for relative_path, snippet in (
            (PRODUCTION_SWIFT, "if allowInsecureAuthority { start() }\n"),
            (PRODUCTION_RUST, "let flag = \"CFW_GLOBAL_AUTHORITY_REQUIRED=0\";\n"),
        ):
            with self.subTest(relative_path=relative_path):
                self.assertIn(
                    "insecure Authority override", _categories(relative_path, snippet)
                )

    def test_fail_closed_owner_composition_is_release_blocking(self) -> None:
        for type_name in (
            "FailClosedProxyOwnerAuthorityClient",
            "FailClosedProxyOwnerCapabilitySource",
            "FailClosedEffectiveSystemProxyObserver",
            "FailClosedEngineOwnerAuthorityClient",
        ):
            with self.subTest(type_name=type_name):
                self.assertIn(
                    "fail-closed production composition",
                    _categories(PRODUCTION_SWIFT, f"let value = {type_name}()\n"),
                )

    def test_unproven_signed_channel_default_and_call_are_release_blocking(self) -> None:
        for snippet in (
            "let value = production(authority: client, signedChannelProven: false)\n",
            "func production(signedChannelProven: Bool = false) {}\n",
            "let signedChannelProven = false\n",
        ):
            with self.subTest(snippet=snippet):
                self.assertIn(
                    "unproven signed Authority channel",
                    _categories(PRODUCTION_SWIFT, snippet),
                )

    def test_permanently_unavailable_release_gate_is_detected(self) -> None:
        source = "try validate(.availabilityUnproven)\n"
        self.assertIn(
            "permanently unavailable Authority release gate",
            _categories(PRODUCTION_SWIFT, source),
        )

    def test_private_xpc_audit_token_access_is_detected(self) -> None:
        for snippet in (
            "let token = connection.auditToken\n",
            "let token = NSXPCConnection.current()?.auditToken\n",
            'let selector = NSSelectorFromString("auditToken")\n',
            (
                "let accessor = unsafeBitCast(connection, "
                "to: CFWXPCAuditTokenProviding.self)\n"
            ),
        ):
            with self.subTest(snippet=snippet):
                self.assertIn(
                    "private NSXPCConnection audit-token access",
                    _categories(PRODUCTION_SWIFT, snippet),
                )


class AllowedContextTests(unittest.TestCase):
    def test_comment_reference_to_forbidden_construct_is_allowed(self) -> None:
        source = (
            "// The Provider must never construct CrossProcessEngineLeaseStore(port)\n"
            "/// It also never calls TunnelStartPayloadCodec.decode in a start path.\n"
            '// It never uses NSSelectorFromString("auditToken") either.\n'
            "let owner = UnleasedEngineOwnership()\n"
        )
        self.assertEqual(scan_source(PRODUCTION_SWIFT, source), [])

    def test_string_literal_reference_is_allowed(self) -> None:
        source = 'let message = "dlopen and Process() are not used here"\n'
        self.assertEqual(scan_source(PRODUCTION_SWIFT, source), [])

    def test_option_key_definition_is_allowed(self) -> None:
        source = 'public static let tunnelStartPayloadOptionKey = "cfw.tunnel-start-payload-v1"\n'
        self.assertEqual(scan_source(PRODUCTION_SWIFT, source), [])

    def test_dictionary_remove_value_is_not_flagged(self) -> None:
        source = "configuration.removeValue(forKey: field.rawValue)\n"
        self.assertEqual(scan_source(PRODUCTION_SWIFT, source), [])

    def test_plural_file_descriptors_property_is_not_flagged(self) -> None:
        source = "self.fileDescriptors = fileDescriptors\n"
        self.assertEqual(scan_source(PRODUCTION_SWIFT, source), [])

    def test_rust_dlopen_bridge_load_is_not_flagged(self) -> None:
        source = "let handle = unsafe { libc::dlopen(framework_c.as_ptr(), flags) };\n"
        self.assertEqual(scan_source(PRODUCTION_RUST, source), [])

    def test_forbidden_construct_allowed_in_named_test_fixture(self) -> None:
        source = """
        let store = CrossProcessEngineLeaseStore(testingPort: 0)
        let owner = FailClosedEngineOwnerAuthorityClient()
        let selector = NSSelectorFromString("auditToken")
        let accessor = unsafeBitCast(connection, to: CFWXPCAuditTokenProviding.self)
        try validate(.availabilityUnproven)
        """
        self.assertEqual(scan_source(TEST_FIXTURE, source), [])


class StripperTests(unittest.TestCase):
    def test_stripping_preserves_line_numbers(self) -> None:
        source = "a\n// comment\n/* block\nblock */\n\"string\"\nb\n"
        stripped = strip_comments_and_strings(source, "swift")
        self.assertEqual(len(stripped.splitlines()), len(source.splitlines()))
        self.assertNotIn("comment", stripped)
        self.assertNotIn("block", stripped)
        self.assertNotIn("string", stripped)

    def test_comment_marker_inside_string_is_not_treated_as_comment(self) -> None:
        source = 'let url = "https://example.com" // trailing\nProcess()\n'
        stripped = strip_comments_and_strings(source, "swift")
        # The `//` inside the URL string must not swallow the whole line, and the
        # real trailing comment must be removed.
        self.assertNotIn("trailing", stripped)
        self.assertIn("Process()", stripped)


class FailClosedTests(unittest.TestCase):
    def test_unreadable_input_fails_closed(self) -> None:
        with self.assertRaisesRegex(ProductionBoundaryViolation, "unreadable"):
            read_source(Path("/nonexistent/does-not-exist.swift"))

    def test_malformed_non_utf8_input_fails_closed(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".swift", delete=True) as handle:
            handle.write(b"\xff\xfe\x00\x01 not utf-8")
            handle.flush()
            with self.assertRaisesRegex(ProductionBoundaryViolation, "malformed"):
                read_source(Path(handle.name))

    def test_missing_production_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                ProductionBoundaryViolation, "unavailable"
            ):
                verify_repository(Path(directory))


if __name__ == "__main__":
    unittest.main()
