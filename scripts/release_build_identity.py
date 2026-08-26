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
MAX_BUILD_VERSION_TEXT = str(MAX_BUILD_VERSION)


class BuildIdentityError(ValueError):
    """A candidate bundle does not have one canonical product identity."""


@dataclass(frozen=True)
class BundleBuildIdentity:
    product_version: str
    build_version: str


def canonical_build_version(value: Any, label: str = "CFBundleVersion") -> str:
    if not isinstance(value, str) or not POSITIVE_INTEGER_RE.fullmatch(value):
        raise BuildIdentityError(f"{label} must be one canonical positive decimal integer")
    if len(value) > len(MAX_BUILD_VERSION_TEXT) or (
        len(value) == len(MAX_BUILD_VERSION_TEXT) and value > MAX_BUILD_VERSION_TEXT
    ):
        raise BuildIdentityError(f"{label} exceeds the signed 64-bit release bound")
    return value


@dataclass(frozen=True)
class ReleaseIdentity:
    """The one application identity eligible for the active product release."""

    product_version: str
    ga_build: str

    def __post_init__(self) -> None:
        if self.product_version != PRODUCT_VERSION:
            raise BuildIdentityError(
                "active release identity product version differs from policy"
            )
        canonical_build_version(self.ga_build, "active GA build")


ACTIVE_RELEASE_IDENTITY = ReleaseIdentity(PRODUCT_VERSION, "40032")
UNSIGNED_VALIDATION_BUILD = "40000"


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
            / "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension/Contents/Info.plist"
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


def ga_preflight_root(repository: Path) -> Path:
    return (
        repository
        / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/"
        f"{ACTIVE_RELEASE_IDENTITY.ga_build}"
    )


def ga_root(repository: Path) -> Path:
    return (
        repository
        / f"target/candidates/{PRODUCT_VERSION}/ga/"
        f"{ACTIVE_RELEASE_IDENTITY.ga_build}"
    )


def ga_pre_sign_native_products_root(repository: Path) -> Path:
    return ga_preflight_root(repository) / "native-products"


def ga_signed_root(repository: Path) -> Path:
    return ga_root(repository) / "signed"


def ga_signing_output_root(repository: Path) -> Path:
    return ga_root(repository) / "signing-output"


def ga_signing_input_root(repository: Path) -> Path:
    return ga_signing_output_root(repository) / "signing-input"


def ga_signed_native_products_root(repository: Path) -> Path:
    return ga_signing_output_root(repository) / "signed-native-products"


def _candidate_directory_output(
    repository: Path,
    output: str,
    allowed: set[Path],
    label: str,
) -> Path:
    if (
        not isinstance(output, str)
        or not output.startswith("/")
        or "\x00" in output
        or any(part in ("", ".", "..") for part in output.split("/")[1:])
    ):
        raise BuildIdentityError(
            f"{label} must be a canonical absolute path"
        )
    try:
        canonical_repository = repository.resolve(strict=True)
    except OSError as error:
        raise BuildIdentityError("release repository is unavailable") from error
    if repository != canonical_repository or not repository.is_dir():
        raise BuildIdentityError("release repository path is not canonical")
    output_path = Path(output)
    if output_path not in allowed:
        raise BuildIdentityError(f"{label} is not an approved build root")

    current = canonical_repository
    relative = output_path.relative_to(canonical_repository)
    for component in relative.parts:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError as error:
            raise BuildIdentityError(f"{label} ancestor is unreadable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BuildIdentityError(
                f"{label} ancestor is not a real directory"
            )
    if output_path.exists():
        try:
            if output_path.resolve(strict=True) != output_path:
                raise BuildIdentityError(f"{label} is not canonical")
        except OSError as error:
            raise BuildIdentityError(f"{label} is unreadable") from error
    return output_path


def candidate_native_products_output(
    repository: Path, output: str, build_version: str
) -> Path:
    """Validate one exact candidate output without following path aliases."""

    canonical_build = canonical_build_version(
        build_version, "candidate build version"
    )
    candidate_base = repository / f"target/candidates/{PRODUCT_VERSION}"
    if canonical_build == UNSIGNED_VALIDATION_BUILD:
        allowed = {candidate_base / "unsigned/native-products"}
    elif canonical_build == ACTIVE_RELEASE_IDENTITY.ga_build:
        allowed = {ga_pre_sign_native_products_root(repository)}
    else:
        raise BuildIdentityError(
            "candidate build is neither the unsigned validation build nor the active GA build"
        )
    return _candidate_directory_output(
        repository,
        output,
        allowed,
        "candidate native-products output",
    )


def candidate_native_derived_data_output(
    repository: Path,
    native_products_output: str,
    derived_data_output: str,
    build_version: str,
) -> Path:
    native_products = candidate_native_products_output(
        repository, native_products_output, build_version
    )
    expected = native_products.parent / "xcode-derived-data"
    return _candidate_directory_output(
        repository,
        derived_data_output,
        {expected},
        "candidate Xcode derived-data output",
    )
