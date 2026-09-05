"""Static native product-graph packaging gate.

This gate proves — without building, signing, notarizing, or installing
anything — that the tracked generation inputs describe the *complete* native
product graph the macOS 15 Network Extension migration requires:

* the Host application, the ProxyAgent, the Packet Tunnel System Extension, and
  the Global Authority launchd daemon are all present as XcodeGen targets, are
  reflected in the generated Xcode project, are built by the candidate build
  script, and are embedded by the Tauri bundle configuration;
* every product uses the macOS 15 arm64 release settings and every Global
  Authority role is bound to a separate code-signing-pinned Mach service;
* the launchd daemon plist embeds under ``Contents/Library/LaunchDaemons`` and
  the daemon executable embeds under ``Contents/Library/HelperTools``, exports
  exactly the fixed root-context Mach service, and declares no data-plane or
  broad-resource launchd surface;
* the exact entitlements, bundle identifiers, and provisioning inputs are
  present for each signed product;
* the canonical inside-out signing-order manifest lists every nested component
  before the outer host app, its destinations agree with the Tauri embedding
  map, and the transaction-owned GA signing helper signs the outer app strictly
  after every nested component;
* the candidate builder freezes and reopens the GA input before entering the
  signing-attempt transaction, while the transaction is the only tracked caller
  permitted to invoke the signing helper.

The gate is offline and non-recursive: it only reads tracked files and never
invokes another build system, a network client, or a solver.  It fails closed —
a missing target, plist, entitlement, Mach service, embedding path, signing
stage, or Release gate raises rather than silently passing.
"""

from __future__ import annotations

import hashlib
import json
import plistlib
import sys
from pathlib import Path
from typing import Any


class NativeProductGraphError(RuntimeError):
    """Raised when the tracked generation inputs do not describe the complete,
    correctly configured native product graph, or when a required input is
    unavailable, unreadable, or malformed."""


TEAM_ID = "YKUPL7Z869"
APP_GROUP = "group.com.bill.clashformac"
MACH_SERVICES = tuple(
    f"{TEAM_ID}.{APP_GROUP}.global-authority.{suffix}"
    for suffix in ("host", "proxy-agent", "provider")
)
HOST_ID = "com.bill.clashformac"
BRIDGE_ID = "com.bill.clashformac.native-bridge"
AGENT_ID = "com.bill.clashformac.proxy-agent"
EXTENSION_ID = "com.bill.clashformac.packet-tunnel"
EXTENSION_EXECUTABLE = "CFWPacketTunnel"
EXTENSION_WRAPPER = f"{EXTENSION_ID}.systemextension"
AUTHORITY_ID = "com.bill.clashformac.global-authority"
AUTHORITY_DESIGNATED_REQUIREMENT = (
    'designated => anchor apple generic and identifier '
    '"com.bill.clashformac.global-authority" and certificate '
    '1[field.1.2.840.113635.100.6.2.6] exists and certificate '
    'leaf[field.1.2.840.113635.100.6.1.13] exists and certificate '
    'leaf[subject.OU] = "YKUPL7Z869"'
)
DISTRIBUTION_CODESIGN_COMMAND = "cfw_codesign_distribution_bundle"
DISTRIBUTION_CODESIGN_FUNCTION = "\n".join(
    (
        "cfw_codesign_distribution_bundle() (",
        "  umask 022",
        '  exec /usr/bin/codesign "$@"',
        ")",
    )
)
AUTHORITY_SIGNING_CRITICAL_BLOCK = "\n".join(
    (
        f"{DISTRIBUTION_CODESIGN_COMMAND} --force --options runtime --timestamp \\",
        "  --identifier com.bill.clashformac.native-bridge \\",
        '  --sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$bridge"',
        f"{DISTRIBUTION_CODESIGN_COMMAND} --force --options runtime --timestamp \\",
        "  --identifier com.bill.clashformac.global-authority \\",
        '  -r="$authority_designated_requirement" \\',
        '  --entitlements "$authority_entitlements" \\',
        '  --sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$authority"',
        'readonly authority_requirement_root="$attempt_work/authority-requirement"',
        'readonly authority_requirement_text="$authority_requirement_root/signed.txt"',
        'readonly authority_requirement_expected="$authority_requirement_root/expected.csreq"',
        'readonly authority_requirement_actual="$authority_requirement_root/actual.csreq"',
        '/bin/mkdir -m 0700 "$authority_requirement_root" ||',
        '  die "cannot create the private Global Authority requirement verification root"',
        '/usr/bin/codesign -d -r "$authority_requirement_text" "$authority" \\',
        '  >/dev/null 2>&1 || die "cannot extract the Global Authority designated requirement"',
        '/usr/bin/csreq -r="$authority_designated_requirement" \\',
        '  -b "$authority_requirement_expected" >/dev/null 2>&1 ||',
        '  die "cannot compile the expected Global Authority designated requirement"',
        '/usr/bin/csreq -r "$authority_requirement_text" \\',
        '  -b "$authority_requirement_actual" >/dev/null 2>&1 ||',
        '  die "cannot compile the signed Global Authority designated requirement"',
        '/usr/bin/cmp -s -- "$authority_requirement_expected" '
        '"$authority_requirement_actual" ||',
        '  die "Global Authority designated requirement mismatch"',
        "/bin/rm -- \\",
        '  "$authority_requirement_text" \\',
        '  "$authority_requirement_expected" \\',
        '  "$authority_requirement_actual" >/dev/null 2>&1 ||',
        '  die "cannot remove the Global Authority requirement verification files"',
        '/bin/rmdir "$authority_requirement_root" >/dev/null 2>&1 ||',
        '  die "cannot remove the private Global Authority requirement verification root"',
        f"{DISTRIBUTION_CODESIGN_COMMAND} --force --options runtime --timestamp \\",
        '  --entitlements "$proxy_release_xcent" \\',
        '  --sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$proxy_app"',
    )
)
# Level 1 structural identities of the decoded UTF-8 source text around the
# critical signing block. Together with the unique exact block, they detect
# accidental or unreviewed reachability and post-verification drift; they are
# not an authentication mechanism and do not defend against the repository
# owner. The release-freeze source digest independently binds the raw file.
AUTHORITY_SIGNING_PREFIX_SHA256 = (
    "924c7b3b9faf8e5ceab52425c39749f20bf50ca4edc59c4abd3742ea9900104a"
)
AUTHORITY_SIGNING_SUFFIX_SHA256 = (
    "2501f3ed3909d57d0d0601c62ab864d6a1697819f86a74aaa99dc10004f088eb"
)
DEPLOYMENT_TARGET = "15.0"
TOMBSTONE_PROVENANCE_COMMAND = "\n".join(
    (
        "cfw_run_release_python_script \\",
        '  "$repo_root" "$repo_root/scripts/verify_legacy_tombstone_provenance.py" \\',
        '  --repository "$repo_root" \\',
        '  --build-number "$CFW_BUILD_NUMBER" \\',
        '  --deployment-target "$MACOS_DEPLOYMENT_TARGET" \\',
        '  --rust-version "$RUST_VERSION" \\',
        '  --pre-sign-artifact "$native_products/CFWLegacyTombstone" \\',
        '  --pre-sign-manifest "$native_products/CFWLegacyTombstone.manifest.json" \\',
        '  --signed-artifact "$signed_native_products/CFWLegacyTombstone" \\',
        '  --signed-manifest "$signed_native_products/CFWLegacyTombstone.manifest.json" \\',
        '  --embedded-app "$staged_app" \\',
        "  --context signing-attempt-work",
    )
)

DAEMON_EMBED = "Library/HelperTools/CFWGlobalAuthority"
DAEMON_PLIST_EMBED = "Library/LaunchDaemons/com.bill.clashformac.global-authority.plist"
BRIDGE_EMBED = "Frameworks/CFWNativeBridge.framework"
AGENT_EMBED = "Library/LoginItems/CFWProxyAgent.app"
EXTENSION_EMBED = f"Library/SystemExtensions/{EXTENSION_WRAPPER}"


def _verify_top_level_straight_line_shell_block(
    source: str,
    expected_block: str,
    *,
    required_prefix_sha256: str,
    required_suffix_sha256: str,
) -> None:
    """Bind the exact block and decoded source text before and after it."""

    for position, required_sha256 in (
        ("prefix", required_prefix_sha256),
        ("suffix", required_suffix_sha256),
    ):
        if (
            not isinstance(required_sha256, str)
            or len(required_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in required_sha256
            )
        ):
            raise NativeProductGraphError(
                f"GA signing helper critical-{position} identity is malformed"
            )
    if source.count(expected_block) != 1:
        raise NativeProductGraphError(
            "GA signing helper does not contain one exact straight-line "
            "Global Authority signing block"
        )
    block_index = source.find(expected_block)
    prefix_sha256 = hashlib.sha256(source[:block_index].encode("utf-8")).hexdigest()
    if prefix_sha256 != required_prefix_sha256:
        raise NativeProductGraphError(
            "GA signing helper critical-prefix identity differs from the "
            "reviewed straight-line release policy"
        )
    block_end = block_index + len(expected_block)
    suffix_sha256 = hashlib.sha256(source[block_end:].encode("utf-8")).hexdigest()
    if suffix_sha256 != required_suffix_sha256:
        raise NativeProductGraphError(
            "GA signing helper critical-suffix identity differs from the "
            "reviewed straight-line release policy"
        )


def verify_distribution_codesign_boundary(
    boundary_source: str, signing_helper: str
) -> None:
    source_fragment = (
        "# shellcheck source=scripts/release_bundle_codesign.sh\n"
        'source "$repo_root/scripts/release_bundle_codesign.sh"'
    )
    if signing_helper.count(source_fragment) != 1:
        raise NativeProductGraphError(
            "GA signing helper does not source the fixed distribution codesign boundary"
        )
    if boundary_source.count(DISTRIBUTION_CODESIGN_FUNCTION) != 1:
        raise NativeProductGraphError(
            "distribution codesign boundary does not contain one exact scoped function"
        )
    if boundary_source.count("/usr/bin/codesign") != 1:
        raise NativeProductGraphError(
            "distribution codesign boundary does not use one fixed Apple codesign path"
        )
    if boundary_source.count("umask 022") != 1 or "eval" in boundary_source:
        raise NativeProductGraphError(
            "distribution codesign boundary does not have one closed distribution umask"
        )


# ---------------------------------------------------------------------------
# Low-level readers (fail closed on missing / malformed inputs).
# ---------------------------------------------------------------------------


def read_text(root: Path, relative: str) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise NativeProductGraphError(
            f"required generation input is unavailable: {relative} ({error})"
        ) from error
    except UnicodeDecodeError as error:
        raise NativeProductGraphError(
            f"required generation input is malformed (non-UTF-8): {relative} ({error})"
        ) from error


def read_json(root: Path, relative: str) -> Any:
    text = read_text(root, relative)
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise NativeProductGraphError(
            f"required generation input is not valid JSON: {relative} ({error})"
        ) from error


def read_plist(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    try:
        value = plistlib.loads(path.read_bytes())
    except OSError as error:
        raise NativeProductGraphError(
            f"required property list is unavailable: {relative} ({error})"
        ) from error
    except plistlib.InvalidFileException as error:
        raise NativeProductGraphError(
            f"required property list is malformed: {relative} ({error})"
        ) from error
    if not isinstance(value, dict):
        raise NativeProductGraphError(
            f"required property list root is not a dictionary: {relative}"
        )
    return value


def require_text(text: str, expected: str, label: str) -> None:
    if expected not in text:
        raise NativeProductGraphError(f"{label} is missing {expected!r}")


def _pbx_section_objects(pbx: str, section: str) -> dict[str, tuple[str, str]]:
    begin = f"/* Begin {section} section */"
    end = f"/* End {section} section */"
    if pbx.count(begin) != 1 or pbx.count(end) != 1:
        raise NativeProductGraphError(
            f"generated Xcode project {section} section is missing or ambiguous"
        )
    body = pbx.split(begin, 1)[1].split(end, 1)[0]
    objects: dict[str, tuple[str, str]] = {}
    identifier: str | None = None
    label = ""
    lines: list[str] = []
    for line in body.splitlines():
        if identifier is None:
            if not line.startswith("\t\t") or line.startswith("\t\t\t"):
                continue
            prefix, separator, suffix = line.partition(" /* ")
            object_label, closing, tail = suffix.partition(" */ = {")
            candidate = prefix.strip()
            if (
                not separator
                or not closing
                or tail
                or len(candidate) != 24
                or any(character not in "0123456789ABCDEF" for character in candidate)
            ):
                continue
            identifier = candidate
            label = object_label
            lines = [line]
            continue
        lines.append(line)
        if line != "\t\t};":
            continue
        if identifier in objects:
            raise NativeProductGraphError(
                f"generated Xcode project {section} contains duplicate object {identifier}"
            )
        objects[identifier] = (label, "\n".join(lines))
        identifier = None
        label = ""
        lines = []
    if identifier is not None:
        raise NativeProductGraphError(
            f"generated Xcode project {section} contains an unterminated object"
        )
    return objects


def _verify_pbx_project_package_access(pbx: str) -> None:
    setting = "SWIFT_PACKAGE_NAME = macos;"
    if pbx.count("SWIFT_PACKAGE_NAME =") != 2 or pbx.count(setting) != 2:
        raise NativeProductGraphError(
            "generated Xcode project Swift package-access identity must exist only "
            "in the Debug and Release project configurations"
        )

    configuration_lists = _pbx_section_objects(pbx, "XCConfigurationList")
    project_lists = [
        block
        for label, block in configuration_lists.values()
        if label == 'Build configuration list for PBXProject "CFWNative"'
    ]
    if len(project_lists) != 1:
        raise NativeProductGraphError(
            "generated Xcode project Swift package-access identity lacks one "
            "unambiguous PBXProject configuration list"
        )

    configuration_ids: dict[str, str] = {}
    for line in project_lists[0].splitlines():
        stripped = line.strip()
        for name in ("Debug", "Release"):
            suffix = f" /* {name} */,"
            if not stripped.endswith(suffix):
                continue
            candidate = stripped[: -len(suffix)]
            if (
                len(candidate) != 24
                or any(character not in "0123456789ABCDEF" for character in candidate)
                or name in configuration_ids
            ):
                raise NativeProductGraphError(
                    "generated Xcode project Swift package-access identity has an "
                    "invalid PBXProject configuration reference"
                )
            configuration_ids[name] = candidate
    if set(configuration_ids) != {"Debug", "Release"}:
        raise NativeProductGraphError(
            "generated Xcode project Swift package-access identity must bind both "
            "Debug and Release project configurations"
        )

    build_configurations = _pbx_section_objects(pbx, "XCBuildConfiguration")
    for name, identifier in configuration_ids.items():
        configuration = build_configurations.get(identifier)
        if configuration is None:
            raise NativeProductGraphError(
                "generated Xcode project Swift package-access identity references "
                f"a missing {name} project configuration"
            )
        label, block = configuration
        if (
            label != name
            or block.count(f"\n\t\t\tname = {name};") != 1
            or block.count(setting) != 1
        ):
            raise NativeProductGraphError(
                "generated Xcode project Swift package-access identity differs in "
                f"the PBXProject {name} configuration"
            )


# ---------------------------------------------------------------------------
# XcodeGen spec, SwiftPM manifest, generated project, build script.
# ---------------------------------------------------------------------------
def verify_xcodegen_spec(project: str) -> None:
    require_text(project, 'macOS: "15.0"', "XcodeGen deployment target")
    require_text(project, "ARCHS: arm64", "XcodeGen base settings")
    require_text(
        project,
        "CODE_SIGN_INJECT_BASE_ENTITLEMENTS: false",
        "Xcode release entitlement injection boundary",
    )
    require_text(
        project,
        "SWIFT_INSTALL_OBJC_HEADER: false",
        "XcodeGen Swift-to-Objective-C header boundary",
    )
    require_text(
        project,
        "SWIFT_PACKAGE_NAME: macos",
        "XcodeGen Swift package-access identity",
    )
    require_text(
        project,
        "LM_FORCE_LINK_GENERATION: true",
        "Xcode App Intents empty-extraction configuration",
    )
    if "LM_FILTER_WARNINGS" in project:
        raise NativeProductGraphError(
            "Xcode App Intents diagnostics must not be filtered"
        )
    # Each of the four products must be a declared target.
    for target in (
        "CFWGlobalAuthorityDaemon:",
        "CFWProxyAgent:",
        "CFWPacketTunnelExtension:",
        "CFWNativeBridge:",
    ):
        require_text(project, f"  {target}", "XcodeGen targets")

    # Product identities.
    require_text(
        project,
        f"PRODUCT_BUNDLE_IDENTIFIER: {AUTHORITY_ID}",
        "Global Authority daemon target",
    )
    require_text(
        project, "productName: CFWGlobalAuthority", "Global Authority daemon target"
    )
    require_text(
        project,
        "path: Config/GlobalAuthority-Info.plist",
        "Global Authority embedded Info.plist",
    )
    require_text(
        project,
        "CREATE_INFOPLIST_SECTION_IN_BINARY: true",
        "Global Authority embedded Info.plist",
    )
    require_text(
        project, f"PRODUCT_BUNDLE_IDENTIFIER: {AGENT_ID}", "ProxyAgent target"
    )
    require_text(
        project, f"PRODUCT_BUNDLE_IDENTIFIER: {EXTENSION_ID}", "Packet Tunnel target"
    )
    require_text(
        project,
        f"productName: {EXTENSION_ID}",
        "Packet Tunnel declared product name",
    )
    require_text(
        project,
        f"PRODUCT_NAME: {EXTENSION_ID}",
        "Packet Tunnel wrapper product name",
    )
    require_text(
        project,
        f"EXECUTABLE_NAME: {EXTENSION_EXECUTABLE}",
        "Packet Tunnel executable name",
    )
    require_text(
        project, f"PRODUCT_BUNDLE_IDENTIFIER: {BRIDGE_ID}", "Native Bridge target"
    )

    # The Packet Tunnel Mach service must be declared in the generated project.
    require_text(
        project,
        f"NEMachServiceName: $(TeamIdentifierPrefix){EXTENSION_ID}",
        "Packet Tunnel Mach service declaration",
    )

    # Each product must have a build scheme so the candidate build can drive it.
    for scheme in (
        "  CFWGlobalAuthorityDaemon:",
        "  CFWProxyAgent:",
        "  CFWPacketTunnelExtension:",
        "  CFWNativeBridge:",
    ):
        require_text(project, scheme, "XcodeGen schemes")

    # Manual signing so provisioning is applied per product at signing time.
    require_text(project, "CODE_SIGN_STYLE: Manual", "XcodeGen signed target settings")
    require_text(
        project,
        "PROVISIONING_PROFILE_SPECIFIER: $(CFW_PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER)",
        "ProxyAgent target-local provisioning",
    )
    require_text(
        project,
        "PROVISIONING_PROFILE_SPECIFIER: $(CFW_PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER)",
        "Packet Tunnel target-local provisioning",
    )


def verify_swiftpm_manifest(package: str) -> None:
    require_text(package, ".macOS(.v15)", "SwiftPM platform")
    require_text(
        package,
        'name: "CFWGlobalAuthorityDaemon"',
        "SwiftPM Global Authority daemon product",
    )
    require_text(
        package, 'name: "CFWProxyAgent"', "SwiftPM ProxyAgent product"
    )
    require_text(
        package, 'name: "CFWNativeBridge"', "SwiftPM Native Bridge product"
    )


def verify_generated_project(pbx: str) -> None:
    require_text(
        pbx,
        "SWIFT_INSTALL_OBJC_HEADER = NO;",
        "generated Xcode project Swift-to-Objective-C header boundary",
    )
    _verify_pbx_project_package_access(pbx)
    require_text(
        pbx,
        "CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO;",
        "generated Xcode release entitlement injection boundary",
    )
    if "Copy Swift Objective-C Interface Header" in pbx:
        raise NativeProductGraphError(
            "generated project must not contain XcodeGen's sandbox-incompatible "
            "Swift Objective-C header copy phase"
        )
    require_text(
        pbx,
        "LM_FORCE_LINK_GENERATION = YES;",
        "generated Xcode App Intents empty-extraction configuration",
    )
    require_text(
        pbx,
        "INFOPLIST_FILE = \"Config/GlobalAuthority-Info.plist\";",
        "generated Global Authority embedded Info.plist",
    )
    require_text(
        pbx,
        "CREATE_INFOPLIST_SECTION_IN_BINARY = YES;",
        "generated Global Authority embedded Info.plist",
    )
    for identifier in (AUTHORITY_ID, AGENT_ID, EXTENSION_ID):
        require_text(pbx, identifier, "generated Xcode project bundle identifiers")
    require_text(
        pbx,
        f'path = "{EXTENSION_WRAPPER}";',
        "generated Packet Tunnel wrapper product",
    )
    require_text(
        pbx,
        f"EXECUTABLE_NAME = {EXTENSION_EXECUTABLE};",
        "generated Packet Tunnel executable name",
    )
    require_text(
        pbx,
        f'PRODUCT_NAME = "{EXTENSION_ID}";',
        "generated Packet Tunnel product name",
    )
    for setting in (
        "PROVISIONING_PROFILE_SPECIFIER = \"$(CFW_PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER)\";",
        "PROVISIONING_PROFILE_SPECIFIER = \"$(CFW_PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER)\";",
    ):
        require_text(pbx, setting, "generated target-local provisioning")


def verify_packet_tunnel_info(info: dict[str, Any]) -> None:
    if info.get("CFBundleExecutable") != "$(EXECUTABLE_NAME)":
        raise NativeProductGraphError(
            "generated Packet Tunnel Info.plist must bind CFBundleExecutable to EXECUTABLE_NAME"
        )
    network = info.get("NetworkExtension")
    if not isinstance(network, dict):
        raise NativeProductGraphError(
            "generated Packet Tunnel Info.plist has no NetworkExtension dictionary"
        )
    if (
        network.get("NEMachServiceName")
        != f"$(TeamIdentifierPrefix){EXTENSION_ID}"
    ):
        raise NativeProductGraphError(
            "generated Packet Tunnel Info.plist Mach service declaration is missing or wrong"
        )
    provider_classes = network.get("NEProviderClasses")
    if (
        not isinstance(provider_classes, dict)
        or provider_classes.get("com.apple.networkextension.packet-tunnel")
        != "CFWPacketTunnel.PacketTunnelProvider"
    ):
        raise NativeProductGraphError(
            "generated Packet Tunnel Info.plist provider class declaration is missing or wrong"
        )


def verify_global_authority_info(info: dict[str, Any]) -> None:
    expected = {
        "CFBundleDevelopmentRegion": "$(DEVELOPMENT_LANGUAGE)",
        "CFBundleExecutable": "$(EXECUTABLE_NAME)",
        "CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "$(PRODUCT_NAME)",
        "CFBundleShortVersionString": "$(MARKETING_VERSION)",
        "CFBundleVersion": "$(CURRENT_PROJECT_VERSION)",
        "LSMinimumSystemVersion": "$(MACOSX_DEPLOYMENT_TARGET)",
    }
    if info != expected:
        raise NativeProductGraphError(
            "Global Authority embedded Info.plist must be the exact fixed "
            "identity and version contract"
        )


def verify_native_build_script(build: str) -> None:
    require_text(
        build,
        "verify_native_product_graph.py",
        "candidate native build product-graph gate",
    )
    for product in (
        "CFWGlobalAuthority",
        "CFWNativeBridge.framework",
        "CFWProxyAgent.app",
        EXTENSION_WRAPPER,
    ):
        require_text(build, product, "candidate native build products")
    for scheme in (
        "build_scheme CFWNativeBridge",
        "build_scheme CFWGlobalAuthorityDaemon",
        "build_scheme CFWProxyAgent",
        "build_scheme CFWPacketTunnelExtension",
    ):
        require_text(build, scheme, "candidate native build schemes")
    # The builder is deliberately pre-sign only. Provisioning, designated
    # requirements, and Developer ID mutations belong to the separate
    # post-freeze signing transaction and must never move back into this step.
    for contract in (
        "usage: scripts/build_native_products.sh --unsigned|--pre-sign",
        'signing_mode="pre-sign"',
        "CODE_SIGNING_ALLOWED=NO",
        "CODE_SIGNING_REQUIRED=NO",
    ):
        require_text(build, contract, "candidate native pre-sign contract")
    forbidden_signing_fragments = (
        "--developer-id",
        "MACOS_SIGN_IDENTITY",
        "PROVISIONING_PROFILE_SPECIFIER",
        "codesign",
        "authority_designated_requirement",
    )
    present = [fragment for fragment in forbidden_signing_fragments if fragment in build]
    if present:
        raise NativeProductGraphError(
            "candidate native builder contains pre-freeze signing operations: "
            f"{present!r}"
        )
    require_text(build, "ARCHS=arm64", "candidate native build architecture")


# ---------------------------------------------------------------------------
# Tauri embedding map.
# ---------------------------------------------------------------------------
def tauri_embedding(tauri: Any) -> dict[str, str]:
    if not isinstance(tauri, dict):
        raise NativeProductGraphError("Tauri configuration root is not an object")
    bundle = tauri.get("bundle")
    macos = bundle.get("macOS") if isinstance(bundle, dict) else None
    if not isinstance(macos, dict):
        raise NativeProductGraphError("Tauri configuration has no bundle.macOS object")
    if macos.get("minimumSystemVersion") != DEPLOYMENT_TARGET:
        raise NativeProductGraphError(
            "Tauri bundle.macOS.minimumSystemVersion is not "
            f"{DEPLOYMENT_TARGET}: {macos.get('minimumSystemVersion')!r}"
        )
    files = macos.get("files")
    if not isinstance(files, dict):
        raise NativeProductGraphError("Tauri bundle.macOS.files is not an object")
    return files


def verify_tauri_embedding(files: dict[str, str]) -> None:
    required = {
        BRIDGE_EMBED: "Host native bridge framework",
        DAEMON_EMBED: "Global Authority daemon executable",
        DAEMON_PLIST_EMBED: "Global Authority launchd daemon plist",
        AGENT_EMBED: "ProxyAgent application",
        EXTENSION_EMBED: "Packet Tunnel system extension",
    }
    for destination, label in required.items():
        if destination not in files:
            raise NativeProductGraphError(
                f"Tauri bundle is missing the {label} embedding: {destination}"
            )
    # The daemon executable must embed under HelperTools and its launchd plist
    # under LaunchDaemons; assert the exact Contents-relative layout.
    if not DAEMON_EMBED.startswith("Library/HelperTools/"):
        raise NativeProductGraphError(
            "Global Authority daemon must embed under Contents/Library/HelperTools"
        )
    if not DAEMON_PLIST_EMBED.startswith("Library/LaunchDaemons/"):
        raise NativeProductGraphError(
            "Global Authority launchd plist must embed under Contents/Library/LaunchDaemons"
        )


# ---------------------------------------------------------------------------
# launchd daemon plist and entitlements.
# ---------------------------------------------------------------------------
def verify_daemon_plist(plist: dict[str, Any]) -> None:
    if plist.get("Label") != AUTHORITY_ID:
        raise NativeProductGraphError(
            f"Global Authority launchd Label mismatch: {plist.get('Label')!r}"
        )
    if plist.get("BundleProgram") != f"Contents/{DAEMON_EMBED}":
        raise NativeProductGraphError(
            "Global Authority launchd BundleProgram must be the HelperTools daemon: "
            f"{plist.get('BundleProgram')!r}"
        )
    if plist.get("UserName") != "root":
        raise NativeProductGraphError(
            "Global Authority launchd daemon must run as root"
        )
    services = plist.get("MachServices")
    expected_services = {service: True for service in MACH_SERVICES}
    if services != expected_services:
        raise NativeProductGraphError(
            f"Global Authority launchd MachServices must be exactly {expected_services!r}"
        )
    for forbidden in ("ProgramArguments", "Sockets", "WatchPaths", "QueueDirectories"):
        if forbidden in plist:
            raise NativeProductGraphError(
                f"Global Authority launchd plist declares a forbidden key: {forbidden}"
            )


def verify_entitlements(root: Path) -> None:
    def require_exact_keys(
        entitlements: dict[str, Any], expected: set[str], label: str
    ) -> None:
        actual = set(entitlements)
        if actual != expected:
            raise NativeProductGraphError(
                f"{label} entitlement keys must be exact; "
                f"missing={sorted(expected - actual)!r}, "
                f"unexpected={sorted(actual - expected)!r}"
            )

    authority = read_plist(root, "native/macos/Config/GlobalAuthority.entitlements")
    if authority:
        raise NativeProductGraphError(
            "Global Authority entitlements must be empty (no data-plane or broad grants)"
        )

    packet = read_plist(root, "native/macos/Config/PacketTunnel.entitlements")
    require_exact_keys(
        packet,
        {
            "com.apple.developer.networking.networkextension",
            "com.apple.security.app-sandbox",
            "com.apple.security.application-groups",
            "com.apple.security.network.client",
            "com.apple.security.network.server",
        },
        "Packet Tunnel",
    )
    if packet.get("com.apple.developer.networking.networkextension") != [
        "packet-tunnel-provider-systemextension"
    ]:
        raise NativeProductGraphError(
            "Packet Tunnel entitlements must declare the packet-tunnel-provider-systemextension role"
        )
    for key in (
        "com.apple.security.app-sandbox",
        "com.apple.security.network.client",
        "com.apple.security.network.server",
    ):
        if packet.get(key) is not True:
            raise NativeProductGraphError(
                f"Packet Tunnel entitlements must set {key} to true"
            )
    if packet.get("com.apple.security.application-groups") != [
        "$(TeamIdentifierPrefix)group.com.bill.clashformac"
    ]:
        raise NativeProductGraphError(
            "Packet Tunnel entitlements must declare the Authority Mach-service App Group"
        )

    agent = read_plist(root, "native/macos/Config/ProxyAgent.entitlements")
    require_exact_keys(
        agent,
        {
            "com.apple.security.application-groups",
            "keychain-access-groups",
        },
        "ProxyAgent",
    )
    if agent.get("com.apple.security.application-groups") != [
        "$(TeamIdentifierPrefix)group.com.bill.clashformac"
    ]:
        raise NativeProductGraphError(
            "ProxyAgent entitlements must declare the shared App Group"
        )
    if agent.get("keychain-access-groups") != [
        "$(AppIdentifierPrefix)com.bill.clashformac.proxy-agent",
        "$(AppIdentifierPrefix)com.bill.clashformac.credentials",
    ]:
        raise NativeProductGraphError(
            "ProxyAgent entitlements must declare its exact private and shared Keychain groups"
        )

    host = read_plist(root, "native/macos/Config/Host.entitlements")
    require_exact_keys(
        host,
        {
            "com.apple.developer.networking.networkextension",
            "com.apple.developer.system-extension.install",
            "com.apple.security.application-groups",
            "keychain-access-groups",
        },
        "Host",
    )
    if host.get("com.apple.developer.system-extension.install") is not True:
        raise NativeProductGraphError(
            "Host entitlements must permit System Extension installation"
        )
    if host.get("com.apple.developer.networking.networkextension") != [
        "packet-tunnel-provider-systemextension"
    ]:
        raise NativeProductGraphError(
            "Host entitlements must declare the packet-tunnel-provider-systemextension role"
        )
    if host.get("com.apple.security.application-groups") != [
        "$(TeamIdentifierPrefix)group.com.bill.clashformac"
    ]:
        raise NativeProductGraphError(
            "Host entitlements must declare the shared App Group"
        )
    if host.get("keychain-access-groups") != [
        "$(AppIdentifierPrefix)com.bill.clashformac",
        "$(AppIdentifierPrefix)com.bill.clashformac.credentials",
    ]:
        raise NativeProductGraphError(
            "Host entitlements must declare its exact private and shared Keychain groups"
        )


# ---------------------------------------------------------------------------
# Inside-out signing-order manifest.
# ---------------------------------------------------------------------------
def verify_signing_order(
    manifest: Any,
    files: dict[str, str],
    signing_script: str,
    *,
    critical_prefix_sha256: str,
    critical_suffix_sha256: str,
) -> None:
    if not isinstance(manifest, dict):
        raise NativeProductGraphError("signing-order manifest root is not an object")
    if manifest.get("schemaVersion") != 1:
        raise NativeProductGraphError("signing-order manifest schema version must be 1")
    if manifest.get("teamIdentifier") != TEAM_ID:
        raise NativeProductGraphError("signing-order manifest Team ID mismatch")

    nested = manifest.get("nested")
    outer = manifest.get("outer")
    if not isinstance(nested, list) or not nested:
        raise NativeProductGraphError("signing-order manifest has no nested components")
    if not isinstance(outer, dict):
        raise NativeProductGraphError("signing-order manifest has no outer app entry")

    # The outer app is always signed last.
    if outer.get("signedLast") is not True:
        raise NativeProductGraphError("signing-order manifest outer app must be signed last")
    if outer.get("bundleIdentifier") != HOST_ID:
        raise NativeProductGraphError("signing-order manifest outer bundle identifier mismatch")

    # Every native product in the graph must be a nested signing stage, and the
    # daemon stage must bind the HelperTools destination, LaunchDaemons plist,
    # and the fixed Mach service.
    destinations = {entry.get("destination") for entry in nested if isinstance(entry, dict)}
    required_nested = {
        f"Contents/{BRIDGE_EMBED}",
        f"Contents/{DAEMON_EMBED}",
        f"Contents/{AGENT_EMBED}",
        f"Contents/{EXTENSION_EMBED}",
    }
    missing = required_nested - destinations
    if missing:
        raise NativeProductGraphError(
            f"signing-order manifest is missing nested components: {sorted(missing)}"
        )

    daemon = next(
        (
            entry
            for entry in nested
            if isinstance(entry, dict)
            and entry.get("destination") == f"Contents/{DAEMON_EMBED}"
        ),
        None,
    )
    if daemon is None:
        raise NativeProductGraphError("signing-order manifest has no daemon stage")
    if daemon.get("launchdPlist") != f"Contents/{DAEMON_PLIST_EMBED}":
        raise NativeProductGraphError(
            "signing-order daemon stage must bind the LaunchDaemons plist"
        )
    if daemon.get("machServices") != list(MACH_SERVICES):
        raise NativeProductGraphError(
            "signing-order daemon stage must bind every role-scoped root Mach service"
        )

    # Every nested destination under Contents/ must map to a Tauri embedding.
    for entry in nested:
        if not isinstance(entry, dict):
            raise NativeProductGraphError("signing-order nested entry is not an object")
        destination = entry.get("destination")
        if not isinstance(destination, str) or not destination.startswith("Contents/"):
            raise NativeProductGraphError(
                f"signing-order nested destination is invalid: {destination!r}"
            )
        embed_key = destination[len("Contents/") :]
        if embed_key not in files:
            raise NativeProductGraphError(
                "signing-order nested component is not embedded by the Tauri bundle: "
                f"{destination}"
            )

    # The transaction-owned helper must sign every nested component and the
    # legacy tombstone before applying the sole outer-app signature.  Bind the
    # frozen certificate fingerprint rather than a mutable identity name.
    signing_selector = '--sign "$CFW_SIGNING_CERTIFICATE_SHA1"'
    writing_codesign = f"{DISTRIBUTION_CODESIGN_COMMAND} --force"
    if "/usr/bin/codesign --force" in signing_script:
        raise NativeProductGraphError(
            "GA signing helper bypasses the scoped distribution codesign boundary"
        )
    if signing_script.count(writing_codesign) != len(nested) + 1:
        raise NativeProductGraphError(
            "GA signing helper must route every signing mutation through the "
            "distribution codesign boundary"
        )
    if '"$MACOS_SIGN_IDENTITY"' in signing_script:
        raise NativeProductGraphError(
            "GA signing helper must not use a mutable signing identity name"
        )
    outer_fragment = f'{signing_selector} "$staged_app"'
    outer_index = signing_script.find(outer_fragment)
    if outer_index < 0 or signing_script.count(outer_fragment) != 1:
        raise NativeProductGraphError(
            "GA signing helper does not sign the outer host app exactly once"
        )
    if signing_script.count(signing_selector) != len(nested) + 1:
        raise NativeProductGraphError(
            "GA signing helper must apply exactly one signature per nested "
            "component and one outer host signature"
        )
    nested_variables = {
        f"Contents/{BRIDGE_EMBED}": "bridge",
        f"Contents/{DAEMON_EMBED}": "authority",
        f"Contents/{AGENT_EMBED}": "proxy_app",
        f"Contents/{EXTENSION_EMBED}": "packet_extension",
        "Contents/Library/HelperTools/cfw-helper-tombstone": "tombstone",
    }
    for entry in nested:
        destination = entry["destination"]
        variable = nested_variables.get(destination)
        if variable is None:
            raise NativeProductGraphError(
                f"GA signing helper has no fixed variable for nested component: {destination}"
            )
        assignment = f'{variable}="$staged_app/{destination}"'
        if signing_script.count(assignment) != 1:
            raise NativeProductGraphError(
                f"GA signing helper does not bind nested component exactly once: {destination}"
            )
        nested_fragment = f'{signing_selector} "${variable}"'
        nested_index = signing_script.find(nested_fragment)
        if nested_index < 0 or signing_script.count(nested_fragment) != 1:
            raise NativeProductGraphError(
                f"GA signing helper does not sign nested component exactly once: {destination}"
            )
        if nested_index > outer_index:
            raise NativeProductGraphError(
                "GA signing helper signs the outer app before nested component: "
                f"{destination}"
            )

    promotion_index = signing_script.find("promote_signed_native_manifest.py")
    tombstone_provenance_fragment = "verify_legacy_tombstone_provenance.py"
    tombstone_provenance_block = TOMBSTONE_PROVENANCE_COMMAND + "\n"
    tombstone_provenance_index = signing_script.find(tombstone_provenance_block)
    if (
        promotion_index < 0
        or signing_script.count(tombstone_provenance_fragment) != 1
        or signing_script.count(tombstone_provenance_block) != 1
        or not promotion_index < tombstone_provenance_index < outer_index
    ):
        raise NativeProductGraphError(
            "GA signing helper must use the exact promoted tombstone lineage "
            "command after manifest promotion and before outer Host signing"
        )

    authority_sign = f'{signing_selector} "$authority"'
    authority_index = signing_script.find(authority_sign)
    authority_requirement_signing_fragment = (
        '--identifier com.bill.clashformac.global-authority \\\n'
        '  -r="$authority_designated_requirement" \\\n'
        '  --entitlements "$authority_entitlements" \\\n'
        f'  {authority_sign}'
    )
    if signing_script.count(authority_requirement_signing_fragment) != 1:
        raise NativeProductGraphError(
            "GA signing helper does not apply the exact Global Authority "
            "designated requirement while signing"
        )
    proxy_sign = f'{signing_selector} "$proxy_app"'
    proxy_index = signing_script.find(proxy_sign)
    requirement_assignment = (
        "readonly authority_designated_requirement="
        + repr(AUTHORITY_DESIGNATED_REQUIREMENT)
    )
    requirement_assignment_index = signing_script.find(requirement_assignment)
    if (
        signing_script.count(requirement_assignment) != 1
        or requirement_assignment_index >= authority_index
    ):
        raise NativeProductGraphError(
            "GA signing helper does not bind the exact Global Authority "
            "designated requirement"
        )
    verification_fragments = (
        'readonly authority_requirement_root="$attempt_work/authority-requirement"',
        'readonly authority_requirement_text="$authority_requirement_root/signed.txt"',
        'readonly authority_requirement_expected="$authority_requirement_root/expected.csreq"',
        'readonly authority_requirement_actual="$authority_requirement_root/actual.csreq"',
        '/bin/mkdir -m 0700 "$authority_requirement_root" ||\n'
        '  die "cannot create the private Global Authority requirement verification root"',
        '/usr/bin/codesign -d -r "$authority_requirement_text" "$authority" \\\n'
        '  >/dev/null 2>&1 || die "cannot extract the Global Authority designated requirement"',
        '/usr/bin/csreq -r="$authority_designated_requirement" \\\n'
        '  -b "$authority_requirement_expected" >/dev/null 2>&1 ||\n'
        '  die "cannot compile the expected Global Authority designated requirement"',
        '/usr/bin/csreq -r "$authority_requirement_text" \\\n'
        '  -b "$authority_requirement_actual" >/dev/null 2>&1 ||\n'
        '  die "cannot compile the signed Global Authority designated requirement"',
        '/usr/bin/cmp -s -- "$authority_requirement_expected" '
        '"$authority_requirement_actual" ||\n'
        '  die "Global Authority designated requirement mismatch"',
        '/bin/rm -- \\\n'
        '  "$authority_requirement_text" \\\n'
        '  "$authority_requirement_expected" \\\n'
        '  "$authority_requirement_actual" >/dev/null 2>&1 ||\n'
        '  die "cannot remove the Global Authority requirement verification files"',
        '/bin/rmdir "$authority_requirement_root" >/dev/null 2>&1 ||\n'
        '  die "cannot remove the private Global Authority requirement verification root"',
    )
    verification_indices: list[int] = []
    for fragment in verification_fragments:
        if signing_script.count(fragment) != 1:
            raise NativeProductGraphError(
                "GA signing helper does not verify the exact Global Authority "
                f"designated requirement: missing {fragment!r}"
            )
        verification_indices.append(signing_script.find(fragment))
    policy_variables = (
        "authority_designated_requirement",
        "authority_requirement_root",
        "authority_requirement_text",
        "authority_requirement_expected",
        "authority_requirement_actual",
    )
    for variable in policy_variables:
        if signing_script.count(f"{variable}=") != 1:
            raise NativeProductGraphError(
                "GA signing helper reassigns a readonly Global Authority "
                f"requirement policy variable: {variable}"
            )
    if not (
        authority_index
        < verification_indices[0]
        < verification_indices[1]
        < verification_indices[2]
        < verification_indices[3]
        < verification_indices[4]
        < verification_indices[5]
        < verification_indices[6]
        < verification_indices[7]
        < verification_indices[8]
        < verification_indices[9]
        < verification_indices[10]
        < proxy_index
        < outer_index
    ):
        raise NativeProductGraphError(
            "GA signing helper verifies the Global Authority designated "
            "requirement outside the signed nested-code boundary"
        )
    _verify_top_level_straight_line_shell_block(
        signing_script,
        AUTHORITY_SIGNING_CRITICAL_BLOCK,
        required_prefix_sha256=critical_prefix_sha256,
        required_suffix_sha256=critical_suffix_sha256,
    )


def verify_signing_transaction_boundary(
    candidate_builder: str, transaction_script: str, signing_helper: str
) -> None:
    freeze = 'candidate_freeze.py" freeze'
    reopen = 'candidate_freeze.py" verify'
    transaction = 'signing_attempt_transaction.py"'
    freeze_index = candidate_builder.find(freeze)
    transaction_index = candidate_builder.find(transaction)
    if freeze_index < 0 or transaction_index < 0 or freeze_index > transaction_index:
        raise NativeProductGraphError(
            "candidate builder must freeze the GA input before signing-attempt entry"
        )
    reopen_index = candidate_builder.rfind(reopen, 0, transaction_index)
    if reopen_index < freeze_index:
        raise NativeProductGraphError(
            "candidate builder must reopen the frozen GA input immediately before signing"
        )
    if (
        "run_ga_signing_attempt.sh" in candidate_builder
        or "/usr/bin/codesign" in candidate_builder
    ):
        raise NativeProductGraphError(
            "candidate builder must not bypass the signing-attempt transaction"
        )
    if transaction_script.count('"scripts/run_ga_signing_attempt.sh"') != 1:
        raise NativeProductGraphError(
            "signing-attempt transaction must own exactly one GA signing helper invocation"
        )
    if transaction_script.count('"--transaction-owned"') != 1:
        raise NativeProductGraphError(
            "signing-attempt transaction must invoke its helper through the private boundary"
        )
    if (
        '[[ $# -eq 1 && "$1" == "--transaction-owned" ]]' not in signing_helper
        or "CFW_SIGNING_ATTEMPT_WORK" not in signing_helper
    ):
        raise NativeProductGraphError(
            "GA signing helper does not enforce transaction ownership"
        )


# ---------------------------------------------------------------------------
# Top-level verification.
# ---------------------------------------------------------------------------
def verify_repository(root: Path) -> None:
    project = read_text(root, "native/macos/project.yml")
    package = read_text(root, "native/macos/Package.swift")
    pbx = read_text(root, "native/macos/CFWNative.xcodeproj/project.pbxproj")
    native_build = read_text(root, "scripts/build_native_products.sh")
    candidate_builder = read_text(root, "scripts/build_signed_candidate.sh")
    signing_transaction = read_text(root, "scripts/signing_attempt_transaction.py")
    signing_helper = read_text(root, "scripts/run_ga_signing_attempt.sh")
    codesign_boundary = read_text(root, "scripts/release_bundle_codesign.sh")
    authority_contract = read_text(
        root,
        "native/macos/Sources/CFWSharedProtocol/GlobalAuthorityConnectionContract.swift",
    )
    authority_runtime = read_text(
        root, "native/macos/Sources/CFWGlobalAuthority/GlobalAuthorityDaemon.swift"
    )

    for service in MACH_SERVICES:
        require_text(
            authority_contract,
            service.rsplit(".", 1)[-1],
            "role-scoped Authority connection contract",
        )
    for signing_identifier in (HOST_ID, AGENT_ID, EXTENSION_ID):
        require_text(
            authority_contract,
            signing_identifier,
            "role-scoped Authority signing-identity contract",
        )
    for forbidden_custom_entitlement in (
        "com.bill.clashformac.global-authority.client",
        "com.bill.clashformac.global-authority.engine-owner",
    ):
        if forbidden_custom_entitlement in authority_contract:
            raise NativeProductGraphError(
                "Authority admission must not depend on a custom entitlement that "
                "Apple provisioning profiles cannot authorize"
            )
    require_text(
        authority_runtime,
        "setConnectionCodeSigningRequirement",
        "Global Authority listener code-signing admission",
    )

    verify_xcodegen_spec(project)
    verify_swiftpm_manifest(package)
    verify_generated_project(pbx)
    verify_native_build_script(native_build)

    tauri = read_json(root, "apps/cfw-tauri-shell/tauri.conf.json")
    files = tauri_embedding(tauri)
    verify_tauri_embedding(files)

    daemon_plist = read_plist(
        root, "native/macos/Config/com.bill.clashformac.global-authority.plist"
    )
    verify_daemon_plist(daemon_plist)
    packet_info = read_plist(root, "native/macos/Config/PacketTunnel-Info.plist")
    verify_packet_tunnel_info(packet_info)
    authority_info = read_plist(
        root, "native/macos/Config/GlobalAuthority-Info.plist"
    )
    verify_global_authority_info(authority_info)
    verify_entitlements(root)

    manifest = read_json(root, "native/macos/Config/signing-order.json")
    verify_distribution_codesign_boundary(codesign_boundary, signing_helper)
    verify_signing_order(
        manifest,
        files,
        signing_helper,
        critical_prefix_sha256=AUTHORITY_SIGNING_PREFIX_SHA256,
        critical_suffix_sha256=AUTHORITY_SIGNING_SUFFIX_SHA256,
    )
    verify_signing_transaction_boundary(
        candidate_builder, signing_transaction, signing_helper
    )


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        verify_repository(root)
    except NativeProductGraphError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("Native product graph packaging contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
