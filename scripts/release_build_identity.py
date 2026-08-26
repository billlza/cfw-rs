#!/usr/bin/env python3
"""Validate the monotonic macOS bundle-build identity used by release gates."""

from __future__ import annotations

import os
import plistlib
import re
import stat
from dataclasses import dataclass
from enum import Enum
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


ACTIVE_RELEASE_IDENTITY = ReleaseIdentity(PRODUCT_VERSION, "40034")
UNSIGNED_VALIDATION_BUILD = "40000"
SIGNING_OUTPUT_RELATIVE = Path("signing-output")
SIGNING_INPUT_NAME = "signing-input"
SIGNED_APP_NAME = "Clash for Mac.app"
SIGNED_APP_WITHIN_OUTPUT = Path(SIGNING_INPUT_NAME) / SIGNED_APP_NAME
SIGNED_NATIVE_PRODUCTS_NAME = "signed-native-products"
SIGNING_ATTEMPT_ID_RE = re.compile(r"\A[0-9]{8}\Z")


class CandidateBundleContext(str, Enum):
    """One explicit path provenance accepted by the bundle verifiers."""

    UNSIGNED_HOST = "unsigned-host"
    SIGNING_ATTEMPT_WORK = "signing-attempt-work"
    SIGNING_ATTEMPT_PUBLISH_READY = "signing-attempt-publish-ready"
    CANONICAL_NATIVE_CONTENT = "canonical-native-content"


_SIGNING_ATTEMPT_STAGE_BY_CONTEXT = {
    CandidateBundleContext.SIGNING_ATTEMPT_WORK: "work",
    CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY: "publish-ready",
}
_SIGNING_ATTEMPT_CONTEXT_BY_STAGE = {
    stage: context for context, stage in _SIGNING_ATTEMPT_STAGE_BY_CONTEXT.items()
}


@dataclass(frozen=True)
class CandidateBundleVerificationPaths:
    app: Path
    native_products: Path
    build_identity: BundleBuildIdentity
    context: CandidateBundleContext


@dataclass(frozen=True)
class CandidateSigningOutput:
    root: Path
    context: CandidateBundleContext


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
    return ga_root(repository) / SIGNING_OUTPUT_RELATIVE


def ga_signing_input_root(repository: Path) -> Path:
    return ga_signing_output_root(repository) / SIGNING_INPUT_NAME


def ga_signed_native_products_root(repository: Path) -> Path:
    return ga_signing_output_root(repository) / SIGNED_NATIVE_PRODUCTS_NAME


def ga_signing_attempts_root(repository: Path) -> Path:
    return ga_root(repository) / "transactions/signing-attempts"


def ga_signing_attempt_output_root(
    repository: Path,
    attempt_id: str,
    context: CandidateBundleContext,
) -> Path:
    if (
        not isinstance(attempt_id, str)
        or not SIGNING_ATTEMPT_ID_RE.fullmatch(attempt_id)
        or attempt_id == "00000000"
    ):
        raise BuildIdentityError(
            "signing attempt identifier must be one positive eight-digit ASCII decimal"
        )
    try:
        stage = _SIGNING_ATTEMPT_STAGE_BY_CONTEXT[context]
    except KeyError as error:
        raise BuildIdentityError(
            "candidate bundle context is not a private signing-attempt stage"
        ) from error
    return ga_signing_attempts_root(repository) / attempt_id / stage


def _canonical_real_directory(value: str | Path, label: str) -> Path:
    raw = os.fspath(value)
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or "\x00" in raw
        or any(part in ("", ".", "..") for part in raw.split("/")[1:])
    ):
        raise BuildIdentityError(f"{label} must be a canonical absolute path")
    path = Path(raw)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise BuildIdentityError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != path
    ):
        raise BuildIdentityError(f"{label} must be a canonical real directory")
    return path


def _require_private_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BuildIdentityError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise BuildIdentityError(
            f"{label} must be a current-user 0700 real directory"
        )


def candidate_signing_output(
    repository: Path,
    signing_output: str | Path,
) -> CandidateSigningOutput:
    """Classify one exact active-GA canonical or private signing output."""

    canonical_repository = _canonical_real_directory(repository, "release repository")
    output_root = _canonical_real_directory(signing_output, "signing output")
    canonical_root = ga_signing_output_root(canonical_repository)
    if output_root == canonical_root:
        _require_private_directory(output_root, "canonical signing-output root")
        return CandidateSigningOutput(
            root=output_root,
            context=CandidateBundleContext.CANONICAL_NATIVE_CONTENT,
        )

    attempts_root = ga_signing_attempts_root(canonical_repository)
    try:
        relative = output_root.relative_to(attempts_root)
    except ValueError as error:
        raise BuildIdentityError(
            "signing output is outside the fixed active GA transaction root"
        ) from error
    if len(relative.parts) != 2:
        raise BuildIdentityError("private signing output layout is invalid")
    attempt_id, stage = relative.parts
    context = _SIGNING_ATTEMPT_CONTEXT_BY_STAGE.get(stage)
    if context is None:
        raise BuildIdentityError("private signing output stage is invalid")
    expected_root = ga_signing_attempt_output_root(
        canonical_repository, attempt_id, context
    )
    if output_root != expected_root:
        raise BuildIdentityError("private signing output root is not exact")
    _require_private_directory(attempts_root.parent, "signing transactions root")
    _require_private_directory(attempts_root, "signing attempts root")
    _require_private_directory(output_root.parent, "signing attempt root")
    _require_private_directory(output_root, "signing attempt output")
    return CandidateSigningOutput(root=output_root, context=context)


def candidate_bundle_verification_paths(
    repository: Path,
    app: str | Path,
    native_products: str | Path,
    context: CandidateBundleContext,
) -> CandidateBundleVerificationPaths:
    """Bind one app/native pair to an explicit release verification context."""

    if not isinstance(context, CandidateBundleContext):
        raise BuildIdentityError("candidate bundle context is invalid")
    canonical_repository = _canonical_real_directory(repository, "release repository")
    app_path = _canonical_real_directory(app, "candidate application")
    native_path = _canonical_real_directory(
        native_products, "candidate native-products root"
    )
    if app_path.name != SIGNED_APP_NAME:
        raise BuildIdentityError("candidate application name is invalid")
    identity = bundle_build_identity(app_path)

    if context is CandidateBundleContext.UNSIGNED_HOST:
        expected_native = candidate_native_products_output(
            canonical_repository,
            str(native_path),
            identity.build_version,
        )
        if native_path != expected_native:
            raise BuildIdentityError(
                "unsigned native-products root is not the fixed candidate build root"
            )
    else:
        if (
            identity.product_version != ACTIVE_RELEASE_IDENTITY.product_version
            or identity.build_version != ACTIVE_RELEASE_IDENTITY.ga_build
        ):
            raise BuildIdentityError(
                "candidate application is not the fixed active GA identity"
            )
        if context is CandidateBundleContext.CANONICAL_NATIVE_CONTENT:
            if native_path != ga_signed_native_products_root(canonical_repository):
                raise BuildIdentityError(
                    "signed native-products root is not the fixed active GA root"
                )
            classified_output = candidate_signing_output(
                canonical_repository, native_path.parent
            )
            if classified_output.context is not context:
                raise BuildIdentityError(
                    "canonical native content has the wrong signing-output context"
                )
            _require_private_directory(
                native_path, "canonical signed native-products root"
            )
            try:
                app_path.relative_to(ga_signing_attempts_root(canonical_repository))
            except ValueError:
                pass
            else:
                raise BuildIdentityError(
                    "canonical native content cannot be mixed with a private signing-attempt app"
                )
        else:
            attempts_root = ga_signing_attempts_root(canonical_repository)
            try:
                app_relative = app_path.relative_to(attempts_root)
                native_relative = native_path.relative_to(attempts_root)
            except ValueError as error:
                raise BuildIdentityError(
                    "private signing-attempt paths are outside the fixed active GA root"
                ) from error
            if len(app_relative.parts) != 4 or len(native_relative.parts) != 3:
                raise BuildIdentityError(
                    "private signing-attempt app or native-products layout is invalid"
                )
            attempt_id = app_relative.parts[0]
            output_root = ga_signing_attempt_output_root(
                canonical_repository, attempt_id, context
            )
            if (
                native_relative.parts[0] != attempt_id
                or app_path != output_root / SIGNED_APP_WITHIN_OUTPUT
                or native_path != output_root / SIGNED_NATIVE_PRODUCTS_NAME
            ):
                raise BuildIdentityError(
                    "private signing-attempt app and native-products do not share one exact output"
                )
            classified_output = candidate_signing_output(
                canonical_repository, output_root
            )
            if classified_output.context is not context:
                raise BuildIdentityError(
                    "private signing-attempt stage differs from its verification context"
                )
            _require_private_directory(
                output_root / SIGNING_INPUT_NAME, "signing input root"
            )
            _require_private_directory(native_path, "signed native-products root")

    return CandidateBundleVerificationPaths(
        app=app_path,
        native_products=native_path,
        build_identity=identity,
        context=context,
    )


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
