from __future__ import annotations

import re
import sys
from pathlib import Path


class AuthorityGateContractError(RuntimeError):
    pass


MUTATION_PATTERN = (
    r"TunnelStartPayloadCodec|CrossProcessEngineLeaseStore|startVPNTunnel|"
    r"saveToPreferences|configurationStore\.persist|credentialVault\.resolve|"
    r"lifecycle\.start|sessionLifecycle\.start|engine\.start|preferences\.apply|"
    r"setTunnelNetworkSettings|Process\(|NSTask|clashformac\.helper|"
    r"downloaded.?core|alternate.?core"
)
MUTATION_RE = re.compile(MUTATION_PATTERN, re.IGNORECASE)


def require_text(text: str, expected: str, label: str) -> None:
    if expected not in text:
        raise AuthorityGateContractError(f"{label} is missing {expected!r}")


def _matching_brace(text: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise AuthorityGateContractError("source contains an unterminated block")


def _block_contains_mutation(text: str, opening: int) -> bool:
    return MUTATION_RE.search(text[opening + 1 : _matching_brace(text, opening)]) is not None


def require_authority_before(
    text: str,
    anchor: str,
    authority_proof: str,
    mutation: str,
    label: str,
) -> None:
    start = text.find(anchor)
    if start < 0:
        raise AuthorityGateContractError(f"{label} start seam is missing")
    proof = text.find(authority_proof, start)
    change = text.find(mutation, start)
    if proof < 0 or change < 0 or proof > change:
        raise AuthorityGateContractError(
            f"{label} must establish {authority_proof} before {mutation}"
        )


def reject_insecure_or_fallback(text: str, label: str) -> None:
    insecure = re.compile(
        r"CFW_(?:ALLOW_INSECURE|BYPASS|DISABLE|SKIP)[A-Z0-9_]*AUTHORITY|"
        r"CFW_GLOBAL_AUTHORITY_REQUIRED\s*=\s*(?:0|NO|false)|"
        r"allowInsecureAuthority|globalAuthority(?:Fallback|Bypass|Optional)|"
        r"authorityErrorFallback",
        re.IGNORECASE,
    )
    if insecure.search(text):
        raise AuthorityGateContractError(f"{label} contains an insecure Authority override")

    catch_pattern = re.compile(r"\bcatch\b[^\{]*\{")
    do_pattern = re.compile(r"\bdo\s*\{")
    authority_call = re.compile(
        r"(?:GlobalAuthority|globalAuthority|\bauthority\.|AuthorityBacked|"
        r"systemProxyPreparer\.prepare|preparer\.prepareTunnelStart)"
    )
    for catch in catch_pattern.finditer(text):
        opening = catch.end() - 1
        header = catch.group(0)
        preceding = text[max(0, catch.start() - 1_500) : catch.start()]
        preceding_do = list(do_pattern.finditer(preceding))
        catches_authority = "Authority" in header or "authority" in header
        if preceding_do:
            catches_authority = catches_authority or bool(
                authority_call.search(preceding[preceding_do[-1].start() :])
            )
        if catches_authority and _block_contains_mutation(text, opening):
            raise AuthorityGateContractError(
                f"{label} contains an Authority-error data-plane fallback"
            )

    conditional_pattern = re.compile(
        r"\bif\b[^\{]{0,400}(?:GlobalAuthority|globalAuthority)[^\{]*\{"
    )
    for conditional in conditional_pattern.finditer(text):
        if _block_contains_mutation(text, conditional.end() - 1):
            raise AuthorityGateContractError(
                f"{label} contains an Authority-error data-plane fallback"
            )

    case_fallback = re.compile(
        rf"\bcase\b[^:\n]*(?:GlobalAuthority|globalAuthority)[^:\n]*:"
        rf"(?:(?!\bcase\b).){{0,1200}}(?:{MUTATION_PATTERN})",
        re.IGNORECASE | re.DOTALL,
    )
    if case_fallback.search(text):
        raise AuthorityGateContractError(
            f"{label} contains an Authority-error data-plane fallback"
        )


def verify_repository(root: Path) -> None:
    seams = [
        (
            "native/macos/Sources/CFWNativeBridge/NativeEngineOperations.swift",
            "func startSystemProxy(",
            "systemProxyPreparer.prepareSystemProxyStart(",
            "preflightCredentials(request)",
            "Host System Proxy",
        ),
        (
            "native/macos/Sources/CFWAppleNetwork/HostBridge.swift",
            "enum TicketOnlyTunnelStartFlow",
            "preparer.prepareTunnelStart(",
            "manager.saveDescriptorOnly(",
            "Host Tunnel preferences",
        ),
        (
            "native/macos/Sources/CFWProxyAgent/ProxyAuthorityOwnership.swift",
            "private func performStart(",
            "authority.bind(",
            "lifecycle.start(",
            "ProxyAgent owner",
        ),
        (
            "native/macos/Sources/CFWPacketTunnel/TunnelTicketStartCoordinator.swift",
            "private func performStart(",
            "authority.redeem(",
            "sessionLifecycle.start(",
            "Packet Tunnel owner",
        ),
    ]
    for relative, anchor, proof, mutation, label in seams:
        require_authority_before(
            (root / relative).read_text(encoding="utf-8"),
            anchor,
            proof,
            mutation,
            label,
        )

    compositions = {
        "native/macos/Sources/CFWNativeBridge/NativeBridgeABI.swift": (
            "RegistrationGatedAuthorityClient(",
            "NSXPCGlobalAuthorityRemote(role: .host)",
            "AuthorityBackedTunnelStartPreparer(",
            "AuthorityBackedSystemProxyStartPreparer(",
        ),
        "native/macos/Sources/CFWProxyAgent/ProxyAgentExecutable.swift": (
            "NSXPCGlobalAuthorityRemote(",
            "role: .proxyAgent",
            "ProxySystemProxyOwnerCoordinator(",
        ),
        "native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift": (
            "NSXPCGlobalAuthorityRemote(",
            "role: .provider",
            "TunnelTicketStartCoordinator(",
        ),
    }
    for relative, required in compositions.items():
        text = (root / relative).read_text(encoding="utf-8")
        for expected in required:
            require_text(text, expected, relative)

    source_roots = [
        root / "native/macos/Sources",
        root / "native/macos/SystemExtension",
        root / "apps/cfw-tauri-shell/src",
        root / "crates",
    ]
    candidates: list[Path] = []
    for source_root in source_roots:
        candidates.extend(
            path for path in source_root.rglob("*") if path.suffix in {".swift", ".rs"}
        )
    candidates.extend(
        [
            root / "native/macos/Package.swift",
            root / "native/macos/project.yml",
            root / "scripts/build_native_products.sh",
            root / "apps/cfw-tauri-shell/build.rs",
        ]
    )
    for path in candidates:
        text = path.read_text(encoding="utf-8")
        if "GlobalAuthorityReleaseGate.requireStartAuthorization" in text:
            raise AuthorityGateContractError(
                f"{path.relative_to(root)} contains the retired static Authority gate"
            )
        reject_insecure_or_fallback(text, str(path.relative_to(root)))


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        verify_repository(root)
    except (AuthorityGateContractError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("Release Global Authority proof ordering verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
