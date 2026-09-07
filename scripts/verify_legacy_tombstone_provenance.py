#!/usr/bin/env python3
"""Verify the exact pre-sign to Developer ID legacy tombstone lineage."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Final, Sequence

if __package__:
    from .hash_artifact import tree_sha256_from_records
    from .promote_signed_native_manifest import (
        SignedNativeManifestError,
        verify_promoted_manifest,
    )
    from .release_build_identity import (
        BuildIdentityError,
        CandidateBundleContext,
        candidate_bundle_verification_paths,
        ga_root,
    )
    from .release_regular_file import (
        ReleaseRegularFileError,
        read_bounded_regular_file,
    )
else:
    from hash_artifact import tree_sha256_from_records
    from promote_signed_native_manifest import (
        SignedNativeManifestError,
        verify_promoted_manifest,
    )
    from release_build_identity import (
        BuildIdentityError,
        CandidateBundleContext,
        candidate_bundle_verification_paths,
        ga_root,
    )
    from release_regular_file import (
        ReleaseRegularFileError,
        read_bounded_regular_file,
    )


ARTIFACT_NAME: Final = "CFWLegacyTombstone"
MANIFEST_NAME: Final = f"{ARTIFACT_NAME}.manifest.json"
BINARY_NAME: Final = "cfw-helper-tombstone"
TOMBSTONE_EXECUTABLE_MODE: Final = 0o755
MAX_SOURCE_BYTES: Final = 64 * 1024 * 1024
MAX_ERROR_DETAIL_CHARACTERS: Final = 512
BUILD_NUMBER_RE: Final = re.compile(r"[1-9][0-9]*\Z")
VERSION_RE: Final = re.compile(r"[1-9][0-9]*[.][0-9]+[.][0-9]+\Z")
DEPLOYMENT_TARGET_RE: Final = re.compile(r"[1-9][0-9]*[.][0-9]+\Z")
RETIRED_MARKERS: Final = (
    b"mihomo",
    b"clash-rs",
    b"clash-darwin",
    b"CFW_CORE_KIND",
    b"core install",
    b"want_core",
)


class LegacyTombstoneProvenanceError(ValueError):
    """The signed tombstone is not the exact promotion of its frozen input."""


def _read_regular(
    path: Path,
    *,
    label: str,
    exact_mode: int | None = None,
) -> bytes:
    try:
        return read_bounded_regular_file(
            path,
            label=label,
            maximum_bytes=MAX_SOURCE_BYTES,
            allowed_owner_uids=frozenset({os.geteuid()}),
            exact_mode=exact_mode,
        )
    except ReleaseRegularFileError as error:
        raise LegacyTombstoneProvenanceError(str(error)) from error


def _canonical_repository(repository: Path) -> Path:
    try:
        resolved = repository.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        raise LegacyTombstoneProvenanceError(
            "release repository is unavailable"
        ) from error
    if (
        not repository.is_absolute()
        or repository != resolved
        or resolved.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise LegacyTombstoneProvenanceError(
            "release repository is not one canonical owned directory"
        )
    return resolved


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_identity_paths(
    unsigned_artifact: Path,
    unsigned_manifest: Path,
    signed_artifact: Path,
    signed_manifest: Path,
) -> None:
    if (
        unsigned_artifact.name != ARTIFACT_NAME
        or signed_artifact.name != ARTIFACT_NAME
        or unsigned_manifest.name != MANIFEST_NAME
        or signed_manifest.name != MANIFEST_NAME
        or unsigned_manifest.parent != unsigned_artifact.parent
        or signed_manifest.parent != signed_artifact.parent
    ):
        raise LegacyTombstoneProvenanceError(
            "legacy tombstone artifact or manifest identity is invalid"
        )


def _require_owned_directory(path: Path, *, label: str) -> None:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise LegacyTombstoneProvenanceError(f"{label} is unavailable") from error
    if (
        not path.is_absolute()
        or path != resolved
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise LegacyTombstoneProvenanceError(
            f"{label} is not one canonical owned directory"
        )


def _single_file_tree(payload: bytes) -> tuple[dict[str, object], str]:
    entry: dict[str, object] = {
        "path": BINARY_NAME,
        "sha256": _sha256(payload),
        "size": len(payload),
        "type": "file",
    }
    return entry, tree_sha256_from_records((entry,))


def _bounded_error_detail(error: BaseException) -> str:
    detail = " ".join(str(error).split())
    if not detail:
        detail = type(error).__name__
    if len(detail) > MAX_ERROR_DETAIL_CHARACTERS:
        return detail[: MAX_ERROR_DETAIL_CHARACTERS - 3] + "..."
    return detail


def verify_legacy_tombstone_provenance(
    repository: Path,
    *,
    build_number: str,
    deployment_target: str,
    rust_version: str,
    unsigned_artifact: Path,
    unsigned_manifest: Path,
    signed_artifact: Path,
    signed_manifest: Path,
    embedded_app: Path,
    context: CandidateBundleContext,
) -> dict[str, object]:
    """Verify exact promotion lineage plus the current source and lock binding."""

    repository = _canonical_repository(repository)
    if BUILD_NUMBER_RE.fullmatch(build_number) is None:
        raise LegacyTombstoneProvenanceError("build number is not canonical")
    if DEPLOYMENT_TARGET_RE.fullmatch(deployment_target) is None:
        raise LegacyTombstoneProvenanceError("deployment target is not canonical")
    if VERSION_RE.fullmatch(rust_version) is None:
        raise LegacyTombstoneProvenanceError("Rust version is not canonical")
    if (
        not isinstance(context, CandidateBundleContext)
        or context is CandidateBundleContext.UNSIGNED_HOST
    ):
        raise LegacyTombstoneProvenanceError(
            "legacy tombstone requires one signed candidate bundle context"
        )
    _require_identity_paths(
        unsigned_artifact,
        unsigned_manifest,
        signed_artifact,
        signed_manifest,
    )
    for artifact_root, label in (
        (unsigned_artifact.parent, "pre-sign native-products root"),
        (unsigned_artifact, "pre-sign legacy tombstone root"),
        (signed_artifact.parent, "signed native-products root"),
        (signed_artifact, "signed legacy tombstone root"),
    ):
        _require_owned_directory(artifact_root, label=label)
    if unsigned_artifact.parent != ga_root(repository) / "native-products":
        raise LegacyTombstoneProvenanceError(
            "pre-sign native-products root is not the fixed active GA root"
        )
    try:
        verification_paths = candidate_bundle_verification_paths(
            repository,
            embedded_app,
            signed_artifact.parent,
            context,
        )
    except (BuildIdentityError, OSError) as error:
        raise LegacyTombstoneProvenanceError(
            "legacy tombstone candidate bundle binding is invalid: "
            f"{_bounded_error_detail(error)}"
        ) from error
    if build_number != verification_paths.build_identity.build_version:
        raise LegacyTombstoneProvenanceError(
            "legacy tombstone build number differs from the bound candidate application"
        )
    embedded_binary = (
        verification_paths.app
        / "Contents/Library/HelperTools"
        / BINARY_NAME
    )

    source = _read_regular(
        repository / "crates/cfw-legacy-tombstone/src/main.rs",
        label="legacy tombstone source",
    )
    cargo_manifest = _read_regular(
        repository / "crates/cfw-legacy-tombstone/Cargo.toml",
        label="legacy tombstone Cargo manifest",
    )
    cargo_lock = _read_regular(repository / "Cargo.lock", label="Cargo.lock")
    unsigned_payload = _read_regular(
        unsigned_artifact / BINARY_NAME,
        label="pre-sign legacy tombstone binary",
        exact_mode=TOMBSTONE_EXECUTABLE_MODE,
    )
    try:
        promoted = verify_promoted_manifest(
            unsigned_artifact,
            unsigned_manifest,
            signed_artifact,
            signed_manifest,
        )
    except (OSError, SignedNativeManifestError) as error:
        raise LegacyTombstoneProvenanceError(
            "legacy tombstone promotion lineage is invalid: "
            f"{_bounded_error_detail(error)}"
        ) from error

    metadata = promoted.get("metadata")
    expected_metadata = {
        "architecture": "arm64",
        "artifactKind": "legacy-service-tombstone-v1",
        "buildNumber": build_number,
        "cargoLockSha256": _sha256(cargo_lock),
        "cargoManifestSha256": _sha256(cargo_manifest),
        "deploymentTarget": deployment_target,
        "rustVersion": rust_version,
        "signingMode": "developer-id",
        "sourceSha256": _sha256(source),
    }
    expected_fields = set(expected_metadata) | {
        "preSignArtifactSha256",
        "preSignManifestSha256",
    }
    if type(metadata) is not dict or set(metadata) != expected_fields:
        raise LegacyTombstoneProvenanceError(
            "legacy tombstone metadata field set is invalid"
        )
    for key, value in expected_metadata.items():
        if metadata.get(key) != value:
            if key == "sourceSha256":
                detail = "source binding"
            elif key == "cargoManifestSha256":
                detail = "Cargo manifest binding"
            elif key == "cargoLockSha256":
                detail = "Cargo.lock binding"
            else:
                detail = "release identity"
            raise LegacyTombstoneProvenanceError(
                f"legacy tombstone {detail} is invalid"
            )

    _unsigned_entry, unsigned_tree_sha256 = _single_file_tree(unsigned_payload)
    if metadata.get("preSignArtifactSha256") != unsigned_tree_sha256:
        raise LegacyTombstoneProvenanceError(
            "legacy tombstone pre-sign tree identity is invalid"
        )

    signed_binary = signed_artifact / BINARY_NAME
    payload = _read_regular(
        signed_binary,
        label="signed legacy tombstone binary",
        exact_mode=TOMBSTONE_EXECUTABLE_MODE,
    )
    expected_entry, expected_tree_sha256 = _single_file_tree(payload)
    if (
        promoted.get("algorithm") != "sha256-tree-v1"
        or promoted.get("root") != ARTIFACT_NAME
        or promoted.get("entries") != [expected_entry]
        or promoted.get("sha256") != expected_tree_sha256
    ):
        raise LegacyTombstoneProvenanceError(
            "legacy tombstone tree identity is invalid"
        )
    found = [
        marker.decode("ascii") for marker in RETIRED_MARKERS if marker in payload
    ]
    if found:
        raise LegacyTombstoneProvenanceError(
            f"signed legacy tombstone contains retired supervisor markers: {found}"
        )
    embedded_payload = _read_regular(
        embedded_binary,
        label="embedded legacy tombstone binary",
        exact_mode=TOMBSTONE_EXECUTABLE_MODE,
    )
    if embedded_payload != payload:
        raise LegacyTombstoneProvenanceError(
            "embedded legacy tombstone differs from the exact promoted signed binary"
        )
    return promoted


def _canonical_cli_path(value: str) -> Path:
    if (
        not value.startswith("/")
        or "\x00" in value
        or any(part in ("", ".", "..") for part in value.split("/")[1:])
    ):
        raise argparse.ArgumentTypeError(
            "release path must be one canonical absolute path"
        )
    return Path(value)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=_canonical_cli_path, required=True)
    parser.add_argument("--build-number", required=True)
    parser.add_argument("--deployment-target", required=True)
    parser.add_argument("--rust-version", required=True)
    parser.add_argument("--pre-sign-artifact", type=_canonical_cli_path, required=True)
    parser.add_argument("--pre-sign-manifest", type=_canonical_cli_path, required=True)
    parser.add_argument("--signed-artifact", type=_canonical_cli_path, required=True)
    parser.add_argument("--signed-manifest", type=_canonical_cli_path, required=True)
    parser.add_argument("--embedded-app", type=_canonical_cli_path, required=True)
    parser.add_argument(
        "--context",
        choices=tuple(
            context.value
            for context in CandidateBundleContext
            if context is not CandidateBundleContext.UNSIGNED_HOST
        ),
        required=True,
    )
    arguments = parser.parse_args(argv)
    try:
        value = verify_legacy_tombstone_provenance(
            arguments.repository,
            build_number=arguments.build_number,
            deployment_target=arguments.deployment_target,
            rust_version=arguments.rust_version,
            unsigned_artifact=arguments.pre_sign_artifact,
            unsigned_manifest=arguments.pre_sign_manifest,
            signed_artifact=arguments.signed_artifact,
            signed_manifest=arguments.signed_manifest,
            embedded_app=arguments.embedded_app,
            context=CandidateBundleContext(arguments.context),
        )
    except (OSError, LegacyTombstoneProvenanceError) as error:
        raise SystemExit(f"error: legacy tombstone provenance: {error}") from error
    print(f"legacy tombstone provenance verified: {value['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
