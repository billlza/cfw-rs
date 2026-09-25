from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_release_authority_gate import (
    AuthorityGateContractError,
    reject_insecure_or_fallback,
    require_authority_before,
    require_current_host_authority_binding,
    require_text,
    verify_repository,
)


class ReleaseAuthorityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = Path(__file__).resolve().parents[2]
        cls.host_sources = tuple(
            (cls.repository / relative).read_text(encoding="utf-8")
            for relative in (
                "native/macos/Sources/CFWNativeBridge/NativeBridgeABI.swift",
                "native/macos/Sources/CFWSharedProtocol/AuthorityClients.swift",
                "native/macos/Sources/CFWSharedProtocol/ServiceCodeHash.swift",
            )
        )

    def test_current_production_authority_composition_passes_repository_gate(self) -> None:
        verify_repository(self.repository)

    def test_repository_gate_rejects_the_old_unpinned_host_constructor(self) -> None:
        bridge = self.repository / "native/macos/Sources/CFWNativeBridge/NativeBridgeABI.swift"
        current = (
            "NSXPCGlobalAuthorityRemote(\n"
            "          currentHostCodeHash: try serviceBuildObserver.currentCodeHash(for: .globalAuthority))"
        )
        self.assertEqual(self.host_sources[0].count(current), 1)
        old_source = self.host_sources[0].replace(current, "NSXPCGlobalAuthorityRemote(role: .host)")
        read_text = Path.read_text

        def mutated_read(path: Path, *args: object, **kwargs: object) -> str:
            return old_source if path == bridge else read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", mutated_read):
            with self.assertRaisesRegex(AuthorityGateContractError, "current Authority composition"):
                verify_repository(self.repository)

    def test_current_host_binding_rejects_role_hash_and_enforcement_regressions(self) -> None:
        old_constructor = "NSXPCGlobalAuthorityRemote(role: .host)"
        current_constructor = (
            "NSXPCGlobalAuthorityRemote(\n"
            "          currentHostCodeHash: try serviceBuildObserver.currentCodeHash(for: .globalAuthority))"
        )
        mutations = (
            (0, current_constructor, old_constructor, "current Authority composition"),
            (0, "currentCodeHash(for: .globalAuthority)", "currentCodeHash(for: .proxyAgent)", "current Authority composition"),
            (0, "let serviceBuildObserver = try CurrentAppServiceBuildObserver()", "let serviceBuildObserver = otherObserver", "embedded service identity"),
            (1, "self.init(role: .host)", "self.init(role: .provider)", "role and build policy"),
            (1, "buildPolicy = .currentHost(currentHostCodeHash)", "buildPolicy = .protocolPeer", "role and build policy"),
            (1, "requiresCurrentBuild = method == .prepareStart", "requiresCurrentBuild = false", "start code requirement"),
            (1, "currentCodeHash: hash, requestingCurrentBuild: requiresCurrentBuild", "currentCodeHash: hash, requestingCurrentBuild: false", "designated requirement plus current code"),
            (1, "value.setCodeSigningRequirement(requirement)", "", "connection enforcement"),
            (2, "requiresCurrentBuild = requiresCurrentBuild || requestingCurrentBuild", "requiresCurrentBuild = requestingCurrentBuild", "reconnect code constraint"),
            (2, "? currentCodeHash.constraining(base) : base", "? base : base", "selected code constraint"),
            (2, 'requirement + " and cdhash', '"cdhash', "additive CDHash requirement"),
        )
        for index, old, new, failure in mutations:
            with self.subTest(mutation=old):
                sources = list(self.host_sources)
                self.assertEqual(sources[index].count(old), 1)
                sources[index] = sources[index].replace(old, new)
                with self.assertRaisesRegex(AuthorityGateContractError, failure):
                    require_current_host_authority_binding(*sources)
                if new == old_constructor:
                    # The retired predicate accepts exactly the unpinned path
                    # that the current production composition must now reject.
                    require_text(sources[0], old_constructor, "old Host predicate")

    def test_current_host_binding_cannot_be_supplied_only_by_comments_or_strings(self) -> None:
        for source_index, fragment in (
            (0, "let serviceBuildObserver = try CurrentAppServiceBuildObserver()"),
            (1, "value.setCodeSigningRequirement(requirement)"),
        ):
            for decoy in ("/* " + fragment + " */", 'let decoy = "' + fragment + '"'):
                with self.subTest(fragment=fragment, decoy=decoy):
                    sources = list(self.host_sources)
                    self.assertEqual(sources[source_index].count(fragment), 1)
                    sources[source_index] = sources[source_index].replace(fragment, decoy)
                    with self.assertRaises(AuthorityGateContractError):
                        require_current_host_authority_binding(*sources)

    def test_current_host_binding_tolerates_swift_formatting_and_comments(self) -> None:
        sources = list(self.host_sources)
        sources[0] = sources[0].replace(
            "currentHostCodeHash:", "currentHostCodeHash: /* reviewed embedded Authority */\n"
        )
        sources[1] = sources[1].replace("self.init(role: .host)", "self.init(\nrole: .host\n)")
        require_current_host_authority_binding(*sources)

    def test_missing_production_authority_composition_fails_closed(self) -> None:
        with self.assertRaisesRegex(AuthorityGateContractError, "missing"):
            require_text(
                "NativeBridge",
                "RegistrationGatedAuthorityClient(",
                "NativeBridge composition",
            )

    def test_authority_proof_after_mutation_is_rejected(self) -> None:
        source = (
            "func startTunnel { startVPNTunnel(); "
            "preparer.prepareTunnelStart() }"
        )
        with self.assertRaisesRegex(AuthorityGateContractError, "before startVPNTunnel"):
            require_authority_before(
                source,
                "func startTunnel",
                "preparer.prepareTunnelStart()",
                "startVPNTunnel",
                "Host Tunnel",
            )

    def test_authority_proof_before_mutation_is_allowed(self) -> None:
        source = (
            "func startTunnel { preparer.prepareTunnelStart(); "
            "startVPNTunnel() }"
        )
        require_authority_before(
            source,
            "func startTunnel",
            "preparer.prepareTunnelStart()",
            "startVPNTunnel",
            "Host Tunnel",
        )

    def test_insecure_override_is_rejected(self) -> None:
        insecure_forms = (
            "CFW_ALLOW_INSECURE_AUTHORITY=1",
            "CFW_GLOBAL_AUTHORITY_REQUIRED=0",
            "globalAuthorityFallback = true",
        )
        for source in insecure_forms:
            with self.subTest(source=source), self.assertRaisesRegex(
                AuthorityGateContractError, "insecure"
            ):
                reject_insecure_or_fallback(source, "fixture")

    def test_authority_error_fallback_is_rejected(self) -> None:
        sources = (
            "catch let error as GlobalAuthorityGateError { startVPNTunnel() }",
            "do { authority.redeem(ticket) } catch { lifecycle.start() }",
            "case .globalAuthorityUnavailable: engine.start()\ncase .internal: break",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaisesRegex(
                AuthorityGateContractError, "fallback"
            ):
                reject_insecure_or_fallback(source, "fixture")

    def test_typed_authority_failure_without_mutation_is_allowed(self) -> None:
        source = (
            "do { authority.bind(request) } "
            "catch { throw GlobalAuthorityGateError.proofMissing(.availabilityUnproven) }"
        )
        reject_insecure_or_fallback(source, "fixture")


if __name__ == "__main__":
    unittest.main()
