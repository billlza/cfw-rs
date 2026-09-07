from __future__ import annotations

import unittest

from scripts.verify_release_authority_gate import (
    AuthorityGateContractError,
    reject_insecure_or_fallback,
    require_authority_before,
    require_text,
)


class ReleaseAuthorityGateTests(unittest.TestCase):
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
