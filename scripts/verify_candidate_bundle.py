#!/usr/bin/env python3
"""Validate an unsigned or signed 0.4.0 app skeleton without launching it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .hash_artifact import build_manifest
    from .release_build_identity import bundle_build_identity
else:
    from hash_artifact import build_manifest
    from release_build_identity import bundle_build_identity


EXPECTED_APP_NAME = "Clash for Mac.app"
EXPECTED_VERSION = "0.4.0"
EXPECTED_APP_ID = "com.bill.clashformac"
EXPECTED_AGENT_ID = "com.bill.clashformac.proxy-agent"
EXPECTED_EXTENSION_ID = "com.bill.clashformac.packet-tunnel"
EXPECTED_TEAM_ID = "YKUPL7Z869"
EXPECTED_AGENT_KEYCHAIN_GROUP = f"{EXPECTED_TEAM_ID}.{EXPECTED_AGENT_ID}"
EXPECTED_CREDENTIAL_KEYCHAIN_GROUP = f"{EXPECTED_TEAM_ID}.{EXPECTED_APP_ID}.credentials"
EXPECTED_MINIMUM_SYSTEM = "15.0"


class CandidateError(RuntimeError):
    """The application skeleton violates the release bundle contract."""


def require_real_directory(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise CandidateError(f"required path is not a real directory: {path}")


def require_regular_file(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise CandidateError(f"required path is not a regular file: {path}")
    if metadata.st_nlink != 1:
        raise CandidateError(f"release file has multiple hard links: {path}")


def read_plist(path: Path) -> dict[str, Any]:
    require_regular_file(path)
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise CandidateError(f"cannot parse property list {path}: {error}") from error
    if not isinstance(value, dict):
        raise CandidateError(f"property list root is not a dictionary: {path}")
    return value


def require_plist_value(plist: dict[str, Any], key: str, expected: Any, path: Path) -> None:
    actual = plist.get(key)
    if actual != expected:
        raise CandidateError(
            f"{path} has {key}={actual!r}; expected {expected!r}"
        )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_embedded_tree(
    embedded: Path, manifest_path: Path, expected_build_number: str
) -> None:
    require_real_directory(embedded)
    require_regular_file(manifest_path)
    try:
        expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot parse artifact manifest {manifest_path}: {error}") from error
    if not isinstance(expected, dict) or expected.get("algorithm") != "sha256-tree-v1":
        raise CandidateError(f"unsupported artifact manifest: {manifest_path}")
    metadata = expected.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("buildNumber") != expected_build_number:
        raise CandidateError(f"artifact manifest build number mismatch: {manifest_path}")
    actual = build_manifest(embedded)
    if expected.get("root") != embedded.name:
        raise CandidateError(f"artifact manifest root differs from {embedded.name}")
    if expected.get("sha256") != actual.get("sha256"):
        raise CandidateError(f"embedded artifact tree digest mismatch: {embedded}")
    if expected.get("entries") != actual.get("entries"):
        raise CandidateError(f"embedded artifact entries differ from manifest: {embedded}")


def command_output(arguments: list[str]) -> str:
    try:
        result = subprocess.run(arguments, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        raise CandidateError(
            f"command failed ({' '.join(arguments)}): {error.stderr.strip()}"
        ) from error
    return result.stdout


def verify_macho(path: Path) -> None:
    architectures = command_output(["lipo", "-archs", str(path)]).strip()
    if architectures != "arm64":
        raise CandidateError(f"Mach-O must be thin arm64: {path} ({architectures})")
    build = command_output(["vtool", "-show-build", str(path)])
    if not re.search(r"\bplatform\s+MACOS\b", build):
        raise CandidateError(f"Mach-O is not a macOS binary: {path}")
    if not re.search(rf"\bminos\s+{re.escape(EXPECTED_MINIMUM_SYSTEM)}(?:\s|$)", build):
        raise CandidateError(
            f"Mach-O deployment target is not {EXPECTED_MINIMUM_SYSTEM}: {path}"
        )

    linked = command_output(["otool", "-L", str(path)]).splitlines()[1:]
    for line in linked:
        dependency = line.strip().split(" ", 1)[0]
        if dependency.startswith(("/System/Library/", "/usr/lib/", "@rpath/", "@loader_path/", "@executable_path/")):
            continue
        raise CandidateError(f"Mach-O links an external absolute dependency: {path} -> {dependency}")


def enumerate_bundle(root: Path) -> list[Path]:
    files: list[Path] = []

    def walk_error(error: OSError) -> None:
        raise CandidateError(f"cannot enumerate bundle: {error}")

    for directory, names, filenames in os.walk(root, followlinks=False, onerror=walk_error):
        directory_path = Path(directory)
        for name in names + filenames:
            path = directory_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(root)
                except (OSError, ValueError) as error:
                    raise CandidateError(f"bundle symlink escapes or is broken: {path}") from error
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise CandidateError(f"bundle file has multiple hard links: {path}")
                files.append(path)
            elif not stat.S_ISDIR(metadata.st_mode):
                raise CandidateError(f"unsupported special file in bundle: {path}")
    return files


def classify_binary(path: Path) -> bool:
    description = command_output(["file", "-b", str(path)]).strip()
    macho = description.startswith("Mach-O")
    if not macho and path.stat().st_mode & 0o111:
        raise CandidateError(f"executable non-Mach-O file is forbidden: {path}")
    return macho


def verify_candidate(repository: Path, app: Path, native_products: Path) -> None:
    if not app.is_absolute():
        raise CandidateError("application path must be absolute")
    require_real_directory(app)
    if app.name != EXPECTED_APP_NAME:
        raise CandidateError(f"unexpected application name: {app.name}")
    app = app.resolve(strict=True)
    if not native_products.is_absolute():
        raise CandidateError("native products root must be absolute")
    require_real_directory(native_products)
    native_products = native_products.resolve(strict=True)
    candidate_root = (repository / "target/candidates/0.4.0").resolve(strict=True)
    try:
        relative_native = native_products.relative_to(candidate_root)
    except ValueError as error:
        raise CandidateError("native products root is not candidate-specific") from error
    if native_products.name != "native-products" or len(relative_native.parts) < 2:
        raise CandidateError("native products root has an invalid candidate layout")

    tauri = json.loads(
        (repository / "apps/cfw-tauri-shell/tauri.conf.json").read_text(encoding="utf-8")
    )
    if tauri.get("version") != EXPECTED_VERSION:
        raise CandidateError("Tauri configuration version differs from the 0.4.0 release contract")

    contents = app / "Contents"
    info_path = contents / "Info.plist"
    extension = contents / "Library/SystemExtensions/CFWPacketTunnel.systemextension"
    agent = contents / "Library/LoginItems/CFWProxyAgent.app"
    bridge = contents / "Frameworks/CFWNativeBridge.framework"
    tombstone = contents / "Library/HelperTools/cfw-helper-tombstone"
    tombstone_plist = contents / "Library/LaunchDaemons/com.bill.clashformac.helper.plist"
    proxy_agent_plist = contents / "Library/LaunchAgents/com.bill.clashformac.proxy-agent.plist"
    main_binary = contents / "MacOS/clash-for-mac"
    for directory in (contents, extension, agent, bridge):
        require_real_directory(directory)
    for file_path in (info_path, tombstone, tombstone_plist, proxy_agent_plist, main_binary):
        require_regular_file(file_path)

    app_info = read_plist(info_path)
    extension_info_path = extension / "Contents/Info.plist"
    agent_info_path = agent / "Contents/Info.plist"
    extension_info = read_plist(extension_info_path)
    agent_info = read_plist(agent_info_path)
    try:
        build_identity = bundle_build_identity(app)
    except ValueError as error:
        raise CandidateError(str(error)) from error
    for plist, path, identifier, package_type in (
        (app_info, info_path, EXPECTED_APP_ID, "APPL"),
        (extension_info, extension_info_path, EXPECTED_EXTENSION_ID, "SYSX"),
        (agent_info, agent_info_path, EXPECTED_AGENT_ID, "APPL"),
    ):
        require_plist_value(plist, "CFBundleIdentifier", identifier, path)
        require_plist_value(plist, "CFBundlePackageType", package_type, path)
        require_plist_value(plist, "CFBundleShortVersionString", EXPECTED_VERSION, path)
        require_plist_value(plist, "LSMinimumSystemVersion", EXPECTED_MINIMUM_SYSTEM, path)

    network_extension = extension_info.get("NetworkExtension")
    if not isinstance(network_extension, dict):
        raise CandidateError("Packet Tunnel Info.plist has no NetworkExtension dictionary")
    require_plist_value(
        network_extension,
        "NEMachServiceName",
        f"{EXPECTED_TEAM_ID}.{EXPECTED_EXTENSION_ID}",
        extension_info_path,
    )
    provider_classes = network_extension.get("NEProviderClasses")
    if not isinstance(provider_classes, dict) or provider_classes.get(
        "com.apple.networkextension.packet-tunnel"
    ) != "CFWPacketTunnel.PacketTunnelProvider":
        raise CandidateError("Packet Tunnel provider class identity mismatch")
    require_plist_value(
        agent_info,
        "CFWProxyAgentMachServiceName",
        EXPECTED_AGENT_ID,
        agent_info_path,
    )
    require_plist_value(
        agent_info,
        "CFWProxyJournalKeychainAccessGroup",
        EXPECTED_AGENT_KEYCHAIN_GROUP,
        agent_info_path,
    )
    require_plist_value(
        agent_info,
        "CFWCredentialKeychainAccessGroup",
        EXPECTED_CREDENTIAL_KEYCHAIN_GROUP,
        agent_info_path,
    )

    for embedded, staged_name in (
        (bridge, "CFWNativeBridge.framework"),
        (agent, "CFWProxyAgent.app"),
        (extension, "CFWPacketTunnel.systemextension"),
    ):
        verify_embedded_tree(
            embedded,
            native_products / f"{staged_name}.manifest.json",
            build_identity.build_version,
        )
    staged_tombstone = native_products / "CFWLegacyTombstone/cfw-helper-tombstone"
    require_regular_file(staged_tombstone)
    if sha256(tombstone) != sha256(staged_tombstone):
        raise CandidateError("embedded tombstone differs from its staged artifact")
    tombstone_manifest = native_products / "CFWLegacyTombstone.manifest.json"
    verify_embedded_tree(
        native_products / "CFWLegacyTombstone",
        tombstone_manifest,
        build_identity.build_version,
    )
    reviewed_plist = (
        repository
        / "apps/cfw-tauri-shell/macos/legacy-tombstone/com.bill.clashformac.helper.plist"
    )
    require_regular_file(reviewed_plist)
    if tombstone_plist.read_bytes() != reviewed_plist.read_bytes():
        raise CandidateError("embedded tombstone launchd plist differs from reviewed source")
    reviewed_agent_plist = (
        repository / "native/macos/Config/com.bill.clashformac.proxy-agent.plist"
    )
    require_regular_file(reviewed_agent_plist)
    if proxy_agent_plist.read_bytes() != reviewed_agent_plist.read_bytes():
        raise CandidateError("embedded ProxyAgent launchd plist differs from reviewed source")
    proxy_launchd = read_plist(proxy_agent_plist)
    require_plist_value(proxy_launchd, "Label", EXPECTED_AGENT_ID, proxy_agent_plist)
    require_plist_value(
        proxy_launchd,
        "BundleProgram",
        "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent",
        proxy_agent_plist,
    )
    mach_services = proxy_launchd.get("MachServices")
    if mach_services != {EXPECTED_AGENT_ID: True}:
        raise CandidateError("ProxyAgent launchd MachServices contract mismatch")

    retired_names = {"mihomo", "clash-rs", "clash-darwin", "cfw-helper", "cores"}
    for path in contents.rglob("*"):
        lowered = path.name.lower()
        if lowered in retired_names or any(
            lowered.startswith(prefix) for prefix in ("mihomo", "clash-rs", "clash-darwin")
        ):
            raise CandidateError(f"retired engine artifact is present: {path}")

    macho_files = [path for path in enumerate_bundle(app) if classify_binary(path)]
    if not macho_files:
        raise CandidateError("application bundle contains no Mach-O code")
    for binary in macho_files:
        verify_macho(binary)

    main_links = command_output(["otool", "-L", str(main_binary)])
    if "@rpath/CFWNativeBridge.framework/Versions/A/CFWNativeBridge" not in main_links:
        raise CandidateError("host executable is not linked to the fixed native bridge")
    load_commands = command_output(["otool", "-l", str(main_binary)])
    if "path @executable_path/../Frameworks" not in load_commands:
        raise CandidateError("host executable has no bundle-relative Frameworks rpath")

    print(f"candidate bundle verified: {app}")
    print(
        f"identity: {EXPECTED_VERSION} ({build_identity.build_version}) / "
        f"arm64 / macOS {EXPECTED_MINIMUM_SYSTEM}+"
    )
    print(f"Mach-O objects: {len(macho_files)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("app", type=Path)
    parser.add_argument("--native-products-root", required=True, type=Path)
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        verify_candidate(repository, arguments.app, arguments.native_products_root)
    except (CandidateError, FileNotFoundError, json.JSONDecodeError, OSError) as error:
        raise SystemExit(f"error: candidate bundle verification failed: {error}") from error


if __name__ == "__main__":
    main()
