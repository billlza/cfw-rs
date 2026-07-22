#!/usr/bin/env python3
"""Validate the monotonic macOS bundle-build identity used by release gates."""

from __future__ import annotations

import plistlib
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PRODUCT_VERSION = "0.4.0"
POSITIVE_INTEGER_RE = re.compile(r"^[1-9][0-9]*$")
MAX_BUILD_VERSION = 9_223_372_036_854_775_807


class BuildIdentityError(ValueError):
    """A candidate bundle does not have one canonical product identity."""


@dataclass(frozen=True)
class BundleBuildIdentity:
    product_version: str
    build_version: str


def canonical_build_version(value: Any, label: str = "CFBundleVersion") -> str:
    if not isinstance(value, str) or not POSITIVE_INTEGER_RE.fullmatch(value):
        raise BuildIdentityError(f"{label} must be one canonical positive decimal integer")
    if int(value) > MAX_BUILD_VERSION:
        raise BuildIdentityError(f"{label} exceeds the signed 64-bit release bound")
    return value


def _read_plist(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_nlink != 1:
        raise BuildIdentityError(f"bundle identity plist is not a single-link regular file: {path}")
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise BuildIdentityError(f"cannot parse bundle identity plist: {path}") from error
    if not isinstance(value, dict):
        raise BuildIdentityError(f"bundle identity plist is not a dictionary: {path}")
    return value


def bundle_build_identity(app: Path) -> BundleBuildIdentity:
    app = app.resolve(strict=True)
    plists = {
        "host": app / "Contents/Info.plist",
        "native-bridge": (
            app
            / "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/Resources/Info.plist"
        ),
        "proxy-agent": (
            app
            / "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/Info.plist"
        ),
        "packet-tunnel": (
            app
            / "Contents/Library/SystemExtensions/CFWPacketTunnel.systemextension/Contents/Info.plist"
        ),
    }
    identities = {}
    for name, path in plists.items():
        value = _read_plist(path)
        product_version = value.get("CFBundleShortVersionString")
        if product_version != PRODUCT_VERSION:
            raise BuildIdentityError(
                f"{name} CFBundleShortVersionString is {product_version!r}, expected {PRODUCT_VERSION}"
            )
        identities[name] = canonical_build_version(
            value.get("CFBundleVersion"), f"{name} CFBundleVersion"
        )
    unique = set(identities.values())
    if len(unique) != 1:
        raise BuildIdentityError(f"Host/Agent/System Extension build versions differ: {identities}")
    return BundleBuildIdentity(PRODUCT_VERSION, unique.pop())


def release_native_products_root(repository: Path, build_version: str) -> Path:
    canonical = canonical_build_version(build_version, "release build version")
    return repository / f"target/candidates/0.4.0/release-build/{canonical}/native-products"


def validation_native_products_root(repository: Path, build_version: str) -> Path:
    canonical = canonical_build_version(build_version, "validation build version")
    return repository / f"target/candidates/0.4.0/validation/{canonical}/native-products"


def require_newer_build(final_build: str, validated_build: str) -> None:
    final = int(canonical_build_version(final_build, "final release build"))
    validated = int(canonical_build_version(validated_build, "validated candidate build"))
    if final <= validated:
        raise BuildIdentityError(
            "final release build must be strictly greater than the installed validated candidate"
        )
