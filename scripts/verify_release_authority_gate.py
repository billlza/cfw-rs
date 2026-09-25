from __future__ import annotations

import re
import sys
from pathlib import Path

if __package__:
    from .verify_production_boundary_removal import strip_comments_and_strings
else:
    from verify_production_boundary_removal import strip_comments_and_strings


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


def require_current_host_authority_binding(
    bridge: str, clients: str, code_hash: str
) -> None:
    """Guard the reviewed Host composition, not the retired role-only spelling.

    These are source-contract checks, not a Swift semantic proof. Ignore comments
    and strings for executable fragments so prose cannot replace the binding.
    Keep the role, embedded Authority selection and connection enforcement linked.
    """
    def compact(source: str, *, strings: bool = False) -> str:
        return re.sub(
            r"\s+", "",
            strip_comments_and_strings(source, "swift", strip_strings=not strings),
        )

    bridge_code = compact(bridge)
    client_code = compact(clients)
    require_text(
        bridge_code,
        compact("let serviceBuildObserver = try CurrentAppServiceBuildObserver()"),
        "Host embedded service identity",
    )
    require_text(
        bridge_code,
        compact("""let authorityClient = RegistrationGatedAuthorityClient(
          authority: BoundedAuthorityXPCClient(remote: NSXPCGlobalAuthorityRemote(
            currentHostCodeHash: try serviceBuildObserver.currentCodeHash(for: .globalAuthority))))"""),
        "Host current Authority composition",
    )
    require_text(
        client_code,
        compact("""public convenience init(currentHostCodeHash: ServiceCodeHash) {
          self.init(role: .host)
          buildPolicy = .currentHost(currentHostCodeHash)
        }"""),
        "Host Authority role and build policy",
    )
    require_text(
        client_code,
        compact("""switch buildPolicy {
          case .currentHost: requiresCurrentBuild = method == .prepareStart
          case .protocolPeer: requiresCurrentBuild = false
        }"""),
        "Host Authority start code requirement",
    )
    require_text(
        client_code,
        compact("""case .currentHost(let hash):
          requirement = buildConstraint.requirement(
            base: GlobalAuthorityConnectionContract.authorityDesignatedRequirement,
            currentCodeHash: hash, requestingCurrentBuild: requiresCurrentBuild)
          case .protocolPeer:"""),
        "Host Authority designated requirement plus current code",
    )
    require_text(
        client_code,
        compact("""let value = NSXPCConnection(
          machServiceName: machServiceName, options: .privileged)
          value.setCodeSigningRequirement(requirement)
          value.remoteObjectInterface = NSXPCInterface("""),
        "Host Authority connection enforcement",
    )
    require_authority_before(
        client_code, "privatefuncconnected(",
        "value.setCodeSigningRequirement(requirement)", "value.activate()",
        "Host Authority connection activation",
    )
    hash_code = compact(code_hash)
    require_text(
        hash_code,
        compact("""package mutating func select(requestingCurrentBuild: Bool) -> Bool {
          requiresCurrentBuild = requiresCurrentBuild || requestingCurrentBuild
          return requiresCurrentBuild
        }"""),
        "Host Authority reconnect code constraint",
    )
    require_text(
        hash_code,
        compact("""select(requestingCurrentBuild: requestingCurrentBuild)
          ? currentCodeHash.constraining(base) : base"""),
        "Host Authority selected code constraint",
    )
    hash_surface = strip_comments_and_strings(code_hash, "swift")
    builders = list(re.finditer(
        r"package\s+func\s+constraining\s*\(\s*_\s+requirement\s*:\s*String\s*\)"
        r"\s*->\s*String\s*\{", hash_surface,
    ))
    if len(builders) != 1:
        raise AuthorityGateContractError("Host Authority additive CDHash builder is missing or ambiguous")
    builder = builders[0]
    builder_end = _matching_brace(hash_surface, builder.end() - 1)
    require_text(
        compact(code_hash[builder.start() : builder_end + 1], strings=True),
        compact(r'''package func constraining(_ requirement: String) -> String {
          requirement + " and cdhash H\"\(bytes.map { String(format: "%02x", $0) }.joined())\""
        }''', strings=True),
        "Host Authority additive CDHash requirement",
    )


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

    require_current_host_authority_binding(
        (root / "native/macos/Sources/CFWNativeBridge/NativeBridgeABI.swift").read_text(encoding="utf-8"),
        (root / "native/macos/Sources/CFWSharedProtocol/AuthorityClients.swift").read_text(encoding="utf-8"),
        (root / "native/macos/Sources/CFWSharedProtocol/ServiceCodeHash.swift").read_text(encoding="utf-8"),
    )

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
