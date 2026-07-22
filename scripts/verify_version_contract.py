#!/usr/bin/env python3
"""Verify every product-owned release surface is exactly version 0.4.0."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

if __package__:
    from .release_build_identity import canonical_build_version
else:
    from release_build_identity import canonical_build_version


EXPECTED_VERSION = "0.4.0"
PRODUCT_PACKAGES = frozenset(
    {
        "cfw-apple-network",
        "cfw-application",
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


def verify(repository: Path) -> None:
    versions = package_versions(repository)
    wrong = {name: version for name, version in versions.items() if version != EXPECTED_VERSION}
    if wrong:
        raise ValueError(f"product Cargo versions differ from {EXPECTED_VERSION}: {wrong}")

    tauri = json.loads(
        (repository / "apps/cfw-tauri-shell/tauri.conf.json").read_text(encoding="utf-8")
    )
    if tauri.get("version") != EXPECTED_VERSION:
        raise ValueError("Tauri version differs from the release contract")

    project = (repository / "native/macos/project.yml").read_text(encoding="utf-8")
    marketing_versions = re.findall(r"^\s*MARKETING_VERSION:\s*([^\s#]+)\s*$", project, re.M)
    if marketing_versions != [EXPECTED_VERSION]:
        raise ValueError(
            f"Xcode MARKETING_VERSION must occur once as {EXPECTED_VERSION}: {marketing_versions}"
        )
    build_numbers = re.findall(r"^\s*CFW_BUILD_NUMBER:\s*([^\s#]+)\s*$", project, re.M)
    if len(build_numbers) != 1:
        raise ValueError(
            f"Xcode CFW_BUILD_NUMBER must occur once: {build_numbers}"
        )
    canonical_build_version(build_numbers[0], "Xcode CFW_BUILD_NUMBER")
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
    if not headings or headings[0] != EXPECTED_VERSION:
        raise ValueError("the first changelog release is not 0.4.0")

    print(
        f"version contract verified: {EXPECTED_VERSION} across "
        f"{len(versions)} Cargo packages, Tauri, Xcode marketing/build identity, and changelog"
    )


def main() -> None:
    repository = Path(__file__).resolve().parent.parent
    try:
        verify(repository)
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise SystemExit(f"error: version contract failed: {error}") from error


if __name__ == "__main__":
    main()
