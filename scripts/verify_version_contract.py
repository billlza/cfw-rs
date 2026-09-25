#!/usr/bin/env python3
"""Verify the frozen release, or the explicitly selected signed-preview version."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path

if __package__:
    from .release_build_identity import (
        PRODUCT_VERSION,
        SIGNED_PREVIEW_IDENTITY,
        canonical_build_version,
    )
else:
    from release_build_identity import (
        PRODUCT_VERSION,
        SIGNED_PREVIEW_IDENTITY,
        canonical_build_version,
    )


EXPECTED_VERSION = PRODUCT_VERSION
PRODUCT_PACKAGES = frozenset(
    {
        "cfw-apple-network",
        "cfw-application",
        "cfw-controller",
        "cfw-core",
        "cfw-engine-api",
        "cfw-legacy-tombstone",
        "cfw-platform",
        "cfw-profiles",
        "cfw-release-verifier",
        "cfw-singbox-config",
        "cfw-tauri-shell",
    }
)


def package_versions(repository: Path) -> dict[str, str]:
    manifests = [repository / "apps/cfw-tauri-shell/Cargo.toml"]
    manifests.extend(sorted((repository / "crates").glob("*/Cargo.toml")))
    versions: dict[str, str] = {}
    for manifest in manifests:
        with manifest.open("rb") as handle:
            package = tomllib.load(handle).get("package")
        if not isinstance(package, dict):
            raise ValueError(f"manifest has no package table: {manifest}")
        name = package.get("name")
        version = package.get("version")
        if name in PRODUCT_PACKAGES:
            if not isinstance(version, str):
                raise ValueError(f"product package has no version: {manifest}")
            if name in versions:
                raise ValueError(f"duplicate product package: {name}")
            versions[name] = version
    if set(versions) != PRODUCT_PACKAGES:
        missing = sorted(PRODUCT_PACKAGES.difference(versions))
        raise ValueError(f"product package manifests are missing: {missing}")
    return versions


def verify(repository: Path, *, preview: bool = False) -> None:
    expected_version = SIGNED_PREVIEW_IDENTITY.product_version if preview else EXPECTED_VERSION
    versions = package_versions(repository)
    wrong = {name: version for name, version in versions.items() if version != expected_version}
    if wrong:
        raise ValueError(f"product Cargo versions differ from {expected_version}: {wrong}")

    with (repository / "Cargo.toml").open("rb") as handle:
        workspace = tomllib.load(handle).get("workspace", {})
    workspace_version = workspace.get("package", {}).get("version")
    if workspace_version is not None and workspace_version != expected_version:
        raise ValueError("Cargo workspace package version differs from the version contract")

    with (repository / "Cargo.lock").open("rb") as handle:
        locked_packages = tomllib.load(handle).get("package", [])
    locked_versions: dict[str, str] = {}
    for package in locked_packages:
        name = package.get("name")
        if name not in PRODUCT_PACKAGES:
            continue
        if name in locked_versions:
            raise ValueError(f"duplicate product Cargo.lock package: {name}")
        if "source" in package or "checksum" in package:
            raise ValueError(f"product Cargo.lock package must remain local: {name}")
        if package.get("version") != expected_version:
            raise ValueError(f"product Cargo.lock version differs from {expected_version}: {name}")
        locked_versions[name] = package["version"]
    if set(locked_versions) != PRODUCT_PACKAGES:
        raise ValueError("product Cargo.lock package set differs from the version contract")

    core = (repository / "crates/cfw-core/src/lib.rs").read_text(encoding="utf-8")
    core_versions = re.findall(r'^pub const PRODUCT_VERSION: &str = "([^"]+)";$', core, re.M)
    if core_versions != [expected_version]:
        raise ValueError("cfw-core PRODUCT_VERSION differs from the version contract")

    tauri = json.loads(
        (repository / "apps/cfw-tauri-shell/tauri.conf.json").read_text(encoding="utf-8")
    )
    if tauri.get("version") != expected_version:
        raise ValueError("Tauri version differs from the release contract")

    project = (repository / "native/macos/project.yml").read_text(encoding="utf-8")
    marketing_versions = re.findall(r"^\s*MARKETING_VERSION:\s*([^\s#]+)\s*$", project, re.M)
    if marketing_versions != [expected_version]:
        raise ValueError(
            f"Xcode MARKETING_VERSION must occur once as {expected_version}: {marketing_versions}"
        )
    build_numbers = re.findall(r"^\s*CFW_BUILD_NUMBER:\s*([^\s#]+)\s*$", project, re.M)
    if len(build_numbers) != 1:
        raise ValueError(
            f"Xcode CFW_BUILD_NUMBER must occur once: {build_numbers}"
        )
    canonical_build_version(build_numbers[0], "Xcode CFW_BUILD_NUMBER")
    if preview and build_numbers[0] != SIGNED_PREVIEW_IDENTITY.build_number:
        raise ValueError("Xcode preview build differs from the fixed signed-preview identity")
    current_project_versions = re.findall(
        r"^\s*CURRENT_PROJECT_VERSION:\s*([^\s#]+)\s*$", project, re.M
    )
    if current_project_versions != ["$(CFW_BUILD_NUMBER)"]:
        raise ValueError(
            "Xcode CURRENT_PROJECT_VERSION must inherit exactly $(CFW_BUILD_NUMBER)"
        )

    for name in ("ProxyAgent-Info.plist", "PacketTunnel-Info.plist"):
        info = (repository / "native/macos/Config" / name).read_text(encoding="utf-8")
        if info.count("<key>CFBundleVersion</key>") != 1 or info.count(
            "<string>$(CURRENT_PROJECT_VERSION)</string>"
        ) != 1:
            raise ValueError(f"{name} must inherit the canonical Xcode build version")

    changelog = (repository / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^##\s+([^\s]+)", changelog, re.M)
    if not headings or headings[0] != expected_version:
        raise ValueError(f"the first changelog release is not {expected_version}")

    if preview:
        admission = (repository / "apps/cfw-tauri-shell/src/legacy/admission.rs").read_text(encoding="utf-8")
        for constant, expected in (("RELEASE_VERSION", expected_version), ("RELEASE_BUILD", SIGNED_PREVIEW_IDENTITY.build_number)):
            values = re.findall(rf'^const {constant}: &str = "([^"]+)";$', admission, re.M)
            if values != [expected]:
                raise ValueError(f"runtime migration admission {constant} differs from preview identity")
        observation = (
            repository / "native/macos/Sources/CFWSharedProtocol/ReleaseObservation.swift"
        ).read_text(encoding="utf-8")
        for name, expected in (
            ("previewProductVersion", SIGNED_PREVIEW_IDENTITY.product_version),
            ("previewBuildNumber", SIGNED_PREVIEW_IDENTITY.build_number),
        ):
            values = re.findall(
                rf'^\s*static let {name} = "([^"]+)"$', observation, re.M
            )
            if values != [expected]:
                raise ValueError(f"native release observation {name} differs from preview identity")

    print(
        f"version contract verified: {expected_version} ({'signed preview' if preview else 'release'}) "
        f"across {len(versions)} Cargo packages and lock entries, cfw-core, Tauri, "
        "Xcode marketing/build identity, and changelog"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preview", action="store_true",
        help="explicitly verify the fixed 0.5.0/50008 signed preview; default remains 0.4.0",
    )
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        verify(repository, preview=arguments.preview)
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise SystemExit(f"error: version contract failed: {error}") from error


if __name__ == "__main__":
    main()
