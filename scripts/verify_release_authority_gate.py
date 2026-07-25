from __future__ import annotations

import re
import sys
from pathlib import Path


class AuthorityGateContractError(RuntimeError):
    pass


GUARD = "GlobalAuthorityReleaseGate.requireStartAuthorization()"
MUTATION_PATTERN = (
    r"TunnelStartPayloadCodec|CrossProcessEngineLeaseStore|startVPNTunnel|"
    r"saveToPreferences|configurationStore\.persist|credentialVault\.resolve|"
    r"lifecycle\.start|engine\.start|preferences\.apply|setTunnelNetworkSettings|"
    r"Process\(|NSTask|clashformac\.helper|downloaded.?core|alternate.?core"
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


def require_guard_before(
    text: str, anchor: str, mutation: str, label: str
) -> None:
    start = text.find(anchor)
    if start < 0:
        raise AuthorityGateContractError(f"{label} start seam is missing")
    guard = text.find(GUARD, start)
    change = text.find(mutation, start)
    if guard < 0 or change < 0 or guard > change:
        raise AuthorityGateContractError(
            f"{label} must require Global Authority before {mutation}"
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
    for catch in catch_pattern.finditer(text):
        opening = catch.end() - 1
        header = catch.group(0)
        preceding = text[max(0, catch.start() - 1_200) : catch.start()]
        preceding_do = list(do_pattern.finditer(preceding))
        catches_authority = "GlobalAuthority" in header or "globalAuthority" in header
        if preceding_do:
            catches_authority = catches_authority or GUARD in preceding[preceding_do[-1].start() :]
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
    project = (root / "native/macos/project.yml").read_text()
    package = (root / "native/macos/Package.swift").read_text()
    pbx = (root / "native/macos/CFWNative.xcodeproj/project.pbxproj").read_text()
    build = (root / "scripts/build_native_products.sh").read_text()

    require_text(
        project,
        "CFW_GLOBAL_AUTHORITY_REQUIRED=1",
        "XcodeGen Release configuration",
    )
    require_text(
        project,
        "SWIFT_ACTIVE_COMPILATION_CONDITIONS: $(inherited) CFW_GLOBAL_AUTHORITY_REQUIRED",
        "XcodeGen Release configuration",
    )
    require_text(
        package,
        '.define("CFW_GLOBAL_AUTHORITY_REQUIRED", .when(configuration: .release))',
        "SwiftPM Release configuration",
    )
    require_text(
        pbx,
        'CFW_GLOBAL_AUTHORITY_REQUIRED=1',
        "generated Xcode Release configuration",
    )
    require_text(
        build,
        'CFW_GLOBAL_AUTHORITY_REQUIRED=1',
        "candidate Release build",
    )

    seams = [
        (
            "native/macos/Sources/CFWNativeBridge/NativeEngineOperations.swift",
            "func startSystemProxy(",
            "preflightCredentials(request)",
            "Host System Proxy",
        ),
        (
            "native/macos/Sources/CFWNativeBridge/NativeEngineOperations.swift",
            "func startTunnel(",
            "credentialVault.resolve",
            "Host Tunnel coordinator",
        ),
        (
            "native/macos/Sources/CFWAppleNetwork/HostBridge.swift",
            "public func startTunnel(",
            "save(manager)",
            "Host Tunnel preferences",
        ),
        (
            "native/macos/Sources/CFWProxyAgent/ProxyAgentService.swift",
            "case .startSystemProxy:",
            "lifecycle.start",
            "ProxyAgent",
        ),
        (
            "native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift",
            "public override func startTunnel(",
            "startCoordinator.start",
            "Packet Tunnel Provider",
        ),
    ]
    for relative, anchor, mutation, label in seams:
        require_guard_before((root / relative).read_text(), anchor, mutation, label)

    gate = (root / "native/macos/Sources/CFWSharedProtocol/GlobalAuthorityReleaseGate.swift").read_text()
    require_text(gate, "#if CFW_GLOBAL_AUTHORITY_REQUIRED", "Release gate")
    require_text(gate, "throw GlobalAuthorityGateError.proofMissing", "Release gate")

    source_roots = [
        root / "native/macos/Sources",
        root / "native/macos/SystemExtension",
        root / "apps/cfw-tauri-shell/src",
        root / "crates",
    ]
    candidates: list[Path] = []
    for source_root in source_roots:
        candidates.extend(path for path in source_root.rglob("*") if path.suffix in {".swift", ".rs"})
    candidates.extend(
        [
            root / "native/macos/Package.swift",
            root / "native/macos/project.yml",
            root / "native/macos/CFWNative.xcodeproj/project.pbxproj",
            root / "scripts/build_native_products.sh",
            root / "apps/cfw-tauri-shell/build.rs",
        ]
    )
    for path in candidates:
        reject_insecure_or_fallback(path.read_text(), str(path.relative_to(root)))


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        verify_repository(root)
    except (AuthorityGateContractError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("Release Global Authority gate contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
