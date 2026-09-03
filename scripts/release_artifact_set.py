#!/usr/bin/env python3
"""Seal and verify complete, atomically published release-asset sets.

The public release tree contains versioned directories, never a sequence of
independently published files.  A directory is uploadable only when its
canonical seal exists and every byte, filename, URL, signature, notarization
receipt, and verification result recomputes to the sealed value.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import threading
import tomllib
from typing import Any, Callable, Iterator
import uuid

if __package__:
    from .candidate_artifact_binding import TOOLCHAIN_METADATA_ORDER
    from .gatekeeper_assessment import (
        build_public_projection as build_gatekeeper_public_projection,
        GatekeeperEvidenceError,
        validate_evidence as validate_gatekeeper_evidence,
        validate_public_projection as validate_gatekeeper_public_projection,
    )
    from .hash_artifact import build_manifest, write_new_manifest
    from .notarization_transaction import (
        NOTARY_PROFILE,
        TransactionError,
        _run_bounded_process as _run_transaction_process,
        _fsync_tree,
        confirm_published_tree_durable,
        publish_exclusive,
    )
    from .publication.common import (
        PublicationError,
        canonical_json,
        enumerate_tree,
        open_regular,
        read_regular,
        regular_file_identity,
        tree_digest,
    )
    from .publication.source_archive import (
        MAX_SOURCE_ARCHIVE_BYTES as MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES,
    )
    from .repository_source_identity import SourceIdentityError, current_identity
    from .release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        ga_root,
        ga_signed_root,
    )
    from .release_apple_toolchain import (
        DEVELOPER_DIRECTORY_PLACEHOLDER,
        ReleaseAppleToolchainError,
        capture_release_apple_toolchain,
        validate_recorded_release_apple_toolchain,
    )
    from .release_cargo_inputs import (
        CRATES_IO_SOURCE,
        ReleaseCargoInputsError,
        WorkspaceCargoInputs,
        create_runtime_cargo_home,
        release_verifier_dependency_records,
        verify_runtime_cargo_home,
        verify_workspace_cargo_inputs,
    )
    from .release_rust_toolchain import (
        ReleaseRustToolchainError,
        build_toolchain_surface,
        pinned_toolchain_contract,
        validate_recorded_surface,
        verify_pinned_toolchain,
    )
    from .validate_updater_archive import (
        ArchiveContractError,
        build_archive_app_manifest,
        validate_strict_tar_gzip_stream,
    )
    from .verify_notary_log import NotaryLogError, validate_normalized_documents
else:
    from candidate_artifact_binding import TOOLCHAIN_METADATA_ORDER
    from gatekeeper_assessment import (
        build_public_projection as build_gatekeeper_public_projection,
        GatekeeperEvidenceError,
        validate_evidence as validate_gatekeeper_evidence,
        validate_public_projection as validate_gatekeeper_public_projection,
    )
    from hash_artifact import build_manifest, write_new_manifest
    from notarization_transaction import (
        NOTARY_PROFILE,
        TransactionError,
        _run_bounded_process as _run_transaction_process,
        _fsync_tree,
        confirm_published_tree_durable,
        publish_exclusive,
    )
    from publication.common import (
        PublicationError,
        canonical_json,
        enumerate_tree,
        open_regular,
        read_regular,
        regular_file_identity,
        tree_digest,
    )
    from publication.source_archive import (
        MAX_SOURCE_ARCHIVE_BYTES as MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES,
    )
    from repository_source_identity import SourceIdentityError, current_identity
    from release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        ga_root,
        ga_signed_root,
    )
    from release_apple_toolchain import (
        DEVELOPER_DIRECTORY_PLACEHOLDER,
        ReleaseAppleToolchainError,
        capture_release_apple_toolchain,
        validate_recorded_release_apple_toolchain,
    )
    from release_cargo_inputs import (
        CRATES_IO_SOURCE,
        ReleaseCargoInputsError,
        WorkspaceCargoInputs,
        create_runtime_cargo_home,
        release_verifier_dependency_records,
        verify_runtime_cargo_home,
        verify_workspace_cargo_inputs,
    )
    from release_rust_toolchain import (
        ReleaseRustToolchainError,
        build_toolchain_surface,
        pinned_toolchain_contract,
        validate_recorded_surface,
        verify_pinned_toolchain,
    )
    from validate_updater_archive import (
        ArchiveContractError,
        build_archive_app_manifest,
        validate_strict_tar_gzip_stream,
    )
    from verify_notary_log import NotaryLogError, validate_normalized_documents


PRODUCT = "Clash for Mac"
TEAM_ID = "YKUPL7Z869"
OFFICIAL_RELEASE_ORIGIN = "https://github.com/billlza/cfw-rs/releases/download"
UPDATER_SEAL_DOCUMENT = "cfw-updater-release-set-seal-v2"
UPDATER_VERIFICATION_DOCUMENT = "cfw-updater-embedded-pubkey-verification-v1"
RELEASE_VERIFIER_BINDING_DOCUMENT = "cfw-release-verifier-build-binding-v3"
RELEASE_VERIFIER_BINDING_SCHEMA_VERSION = 4
DMG_SEAL_DOCUMENT = "cfw-dmg-release-set-seal-v2"
DMG_SUBMISSION_DOCUMENT = "cfw-dmg-notarization-submission-receipt-v2"
DISTRIBUTION_SEAL_DOCUMENT = "cfw-ga-distribution-package-set-seal-v1"
UPDATER_SEAL_NAME = "updater-set.seal.json"
UPDATER_VERIFICATION_NAME = "embedded-pubkey-verification.json"
DMG_SEAL_NAME = "dmg-set.seal.json"
DISTRIBUTION_SEAL_NAME = "distribution-set.seal.json"
PUBLICATION_BUNDLE_MANIFEST_NAME = "publication-bundle.manifest.json"
CANDIDATE_VERSION = ACTIVE_RELEASE_IDENTITY.product_version
CANDIDATE_BUILD_NUMBER = ACTIVE_RELEASE_IDENTITY.ga_build
GA_APP_ARTIFACT_KIND = "notarized-ga-candidate-v1"
GA_CANDIDATE_RELATIVE = ga_root(Path("."))
GA_PACKAGE_RELATIVE = GA_CANDIDATE_RELATIVE / "packages"
CANDIDATE_APP_RELATIVE = str(
    ga_signed_root(Path(".")) / "Clash for Mac.app"
)
CANDIDATE_APP_MANIFEST_NAME = "Clash for Mac.app.manifest.json"
MAX_UPDATER_ARCHIVE_BYTES = 192 * 1024 * 1024
MAX_DMG_BYTES = 512 * 1024 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_SMALL_DOCUMENT_BYTES = 64 * 1024
MAX_TAURI_CONFIGURATION_BYTES = 1024 * 1024
MAX_APP_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_PUBLICATION_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_GITHUB_RELEASE_ASSET_BYTES_EXCLUSIVE = 2 * 1024 * 1024 * 1024
MAX_PUBLICATION_BUNDLE_BYTES = MAX_GITHUB_RELEASE_ASSET_BYTES_EXCLUSIVE - 1
MAX_PUBLICATION_BUNDLE_FILES = 100_000
MAX_PUBLICATION_BUNDLE_ENTRIES = 250_000
MAX_PUBLICATION_BUNDLE_RAW_ENTRIES = MAX_PUBLICATION_BUNDLE_ENTRIES * 2
MAX_PUBLICATION_BUNDLE_EXTENSION_BYTES = 128 * 1024 * 1024
MAX_PUBLICATION_BUNDLE_AUXILIARY_BYTES = 256 * 1024 * 1024
MAX_PUBLICATION_PUBLIC_FILE_BYTES = 256 * 1024 * 1024
MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_RELEASE_VERIFIER_CRATES = 128
PRIVATE_PUBLICATION_VISIBILITIES = frozenset(
    {"private-release-evidence", "private-release-operations"}
)
PRIVATE_PUBLICATION_SOURCE_IDS = frozenset(
    {
        "final-candidate-binding",
        "physical-evidence-aggregate",
        "physical-evidence-private-archive",
        "sealed-evidence-manifest",
    }
)
PRIVATE_PUBLICATION_FILENAMES = frozenset(
    {
        "final-candidate.json",
        "physical-evidence.json",
        "sealed-evidence-manifest.json",
    }
)
RELEASE_VERIFIER_TARGET = "aarch64-apple-darwin"
RELEASE_VERIFIER_SOURCE_INPUTS = {
    "cargo_lock": "Cargo.lock",
    "crate_manifest": "crates/cfw-release-verifier/Cargo.toml",
    "crate_source": "crates/cfw-release-verifier/src/main.rs",
    "dependency_pins": "scripts/dependency_pins.env",
    "pinned_build_inputs": "scripts/pinned_build_inputs.json",
    "rust_toolchain": "rust-toolchain.toml",
    "workspace_manifest": "Cargo.toml",
}
RELEASE_VERIFIER_PRIVATE_ROOT = "/cfw-release-verifier-build"
RELEASE_VERIFIER_VENDOR_ROOT = "/cfw-release-verifier-vendor"


def _release_verifier_build_argv(
    *,
    cargo: str,
    workspace: str,
    target: str,
    private_root: str,
    verified_vendor: str,
    clang: str,
    linker: str,
) -> list[str]:
    rustflags = [
        f"--remap-path-prefix={private_root}={RELEASE_VERIFIER_PRIVATE_ROOT}",
        f"--remap-path-prefix={verified_vendor}={RELEASE_VERIFIER_VENDOR_ROOT}",
        "-C",
        f"linker={clang}",
        "-C",
        f"link-arg=-fuse-ld={linker}",
        "-C",
        "link-arg=-Wl,-S",
        "-C",
        "link-arg=-Wl,-x",
    ]
    return [
        cargo,
        "build",
        "--offline",
        "--locked",
        "--quiet",
        "--release",
        "-p",
        "cfw-release-verifier",
        "--target",
        RELEASE_VERIFIER_TARGET,
        "--manifest-path",
        f"{workspace}/Cargo.toml",
        "--target-dir",
        target,
        "--config",
        "build.rustflags="
        + json.dumps(rustflags, ensure_ascii=True, separators=(",", ":")),
    ]


def _release_verifier_lock_argv(*, cargo: str, workspace: str) -> list[str]:
    return [
        cargo,
        "generate-lockfile",
        "--offline",
        "--quiet",
        "--manifest-path",
        f"{workspace}/Cargo.toml",
    ]


def _release_verifier_verify_argv(
    *,
    executable: str,
    configuration: str,
    archive: str,
    signature: str,
) -> list[str]:
    return [
        executable,
        configuration,
        archive,
        signature,
        "--json",
    ]


def _release_verifier_build_environment(
    *,
    tool_directory: str,
    developer_directory: str,
    deployment_target: str,
    sdk_root: str,
    cargo_home: str,
    home: str,
    rustc: str,
    temporary_directory: str,
) -> dict[str, str]:
    return {
        "CARGO_HOME": cargo_home,
        "CARGO_NET_OFFLINE": "true",
        "DEVELOPER_DIR": developer_directory,
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "MACOSX_DEPLOYMENT_TARGET": deployment_target,
        "PATH": f"{tool_directory}:/usr/bin:/bin:/usr/sbin:/sbin",
        "RUSTC": rustc,
        "SDKROOT": sdk_root,
        "TMPDIR": temporary_directory,
    }


RELEASE_VERIFIER_BUILD_ENVIRONMENT = _release_verifier_build_environment(
    tool_directory="<pinned-rust-bin>",
    developer_directory=DEVELOPER_DIRECTORY_PLACEHOLDER,
    deployment_target="<pinned-macos-deployment-target>",
    sdk_root="<selected-macos-sdk>",
    cargo_home="<private-runtime-cargo-home>",
    home="<private-home>",
    rustc="<pinned-rustc>",
    temporary_directory="<private-temp>",
)
RELEASE_VERIFIER_BUILD_INVOCATION = {
    "argv": _release_verifier_build_argv(
        cargo="cargo",
        workspace="<private-isolated-workspace>",
        target="<private-ephemeral-target>",
        private_root="<private-root>",
        verified_vendor="<verified-vendor>",
        clang="<selected-xcode-clang>",
        linker="<selected-xcode-ld>",
    ),
    "cwd": "<private-isolated-workspace>",
    "environment": RELEASE_VERIFIER_BUILD_ENVIRONMENT,
}
RELEASE_VERIFIER_LOCK_INVOCATION = {
    "argv": _release_verifier_lock_argv(
        cargo="cargo",
        workspace="<private-isolated-workspace>",
    ),
    "cwd": "<private-isolated-workspace>",
    "environment": RELEASE_VERIFIER_BUILD_ENVIRONMENT,
}
RELEASE_VERIFIER_VERIFY_INVOCATION = {
    "argv": _release_verifier_verify_argv(
        executable="cfw-release-verifier",
        configuration="<repository>/apps/cfw-tauri-shell/tauri.conf.json",
        archive="<staging>/updater-archive",
        signature="<staging>/updater-signature",
    ),
    "cwd": "<repository>",
    "environment": {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    },
}
RELEASE_VERIFIER_ISOLATED_WORKSPACE = """[workspace]
members = ["crates/cfw-release-verifier"]
resolver = "2"

[workspace.package]
edition = "2024"
license = "GPL-3.0-or-later"
rust-version = "1.97"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true

[workspace.dependencies]
base64 = { version = "0.23.0", default-features = false, features = ["std"] }
minisign-verify = "0.2.5"
serde_json = "1.0.151"
sha2 = "0.11"
"""
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:[.](?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:[+]([0-9A-Za-z-]+(?:[.][0-9A-Za-z-]+)*))?$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class ArtifactSetError(RuntimeError):
    """A release asset set is partial, mutable, or not bound by its seal."""


RELEASE_VERIFIER_OPERATIONAL_REASONS = frozenset(
    {"descendant", "output_limit", "pipe", "start", "timeout"}
)
_RELEASE_VERIFIER_PROCESS_REASON_BY_CODE = {
    "command_descendant_survived": "descendant",
    "command_output_oversized": "output_limit",
    "command_pipe_failed": "pipe",
    "command_start_failed": "start",
    "command_timeout": "timeout",
}


class ReleaseVerifierOperationalError(ArtifactSetError):
    """A fixed verifier command did not reach a completed process result."""

    code = "release_verifier_unavailable"

    def __init__(self, reason: str, label: str) -> None:
        if reason not in RELEASE_VERIFIER_OPERATIONAL_REASONS:
            raise ValueError("release verifier operational reason is not allowlisted")
        super().__init__(f"{label} did not complete ({reason})")
        self.reason = reason


class _DuplicateFieldError(ValueError):
    pass


Publisher = Callable[[Path, Path], None]
PackagedAppManifestReader = Callable[[Path], dict[str, object]]
PublicationSemanticVerifier = Callable[[Path, Path, Path], None]
PublicationStageVerifier = Callable[[Path], dict[str, Any]]
PrepackageStageVerifier = Callable[[Path], dict[str, Any]]


@dataclass(frozen=True)
class ReleaseVerifierBuild:
    executable: Path
    apple_toolchain: dict[str, object]
    cargo: Path
    cargo_version: str
    cargo_input_root: Path
    cargo_lock_sha256: str
    cargo_vendor_sha256: str
    dependency_sources: dict[str, Any]
    isolated_lock_sha256: str
    developer_directory: Path
    deployment_target: str
    rustc: Path
    rustc_version: str
    toolchain: str
    toolchain_surface: dict[str, Any]
    sdk_root: Path


UpdaterVerificationProducer = Callable[
    [Path, Path], tuple[dict[str, Any], dict[str, Any]]
]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateFieldError(f"duplicate field: {key}")
        result[key] = value
    return result


def _load_strict_json(path: Path, maximum: int) -> tuple[dict[str, Any], bytes]:
    try:
        data = read_regular(path, maximum)
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object)
    except (
        OSError,
        PublicationError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateFieldError,
    ) as error:
        raise ArtifactSetError(f"release evidence is not strict JSON: {path.name}") from error
    if not isinstance(value, dict):
        raise ArtifactSetError(f"release evidence is not a JSON object: {path.name}")
    return value, data


def _require_exact_keys(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ArtifactSetError(f"{label} has an unexpected field set")
    return value


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ArtifactSetError(f"{label} is not a canonical SHA-256")
    return value


def _require_uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise ArtifactSetError(f"{label} is not a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ArtifactSetError(f"{label} is not a canonical UUID") from error
    if str(parsed) != value:
        raise ArtifactSetError(f"{label} is not a canonical UUID")
    return value


def _require_semver(value: object) -> str:
    if not isinstance(value, str) or not SEMVER_RE.fullmatch(value):
        raise ArtifactSetError("release version is not strict SemVer")
    return value


def _require_active_version(value: object) -> str:
    version = _require_semver(value)
    if version != CANDIDATE_VERSION:
        raise ArtifactSetError(
            f"release asset tooling is fixed to GA version {CANDIDATE_VERSION}"
        )
    return version


def _ga_candidate_root(repository: Path) -> Path:
    return ga_root(repository)


def _package_root(repository: Path) -> Path:
    return _ga_candidate_root(repository) / "packages"


def _updater_set_root(repository: Path) -> Path:
    return _package_root(repository) / f"updater/v{CANDIDATE_VERSION}"


def _dmg_set_root(repository: Path) -> Path:
    return _package_root(repository) / f"dmg/v{CANDIDATE_VERSION}"


def _dmg_transaction_final_set_root(repository: Path) -> Path:
    return (
        _ga_candidate_root(repository)
        / f"transactions/dmg-notary/v{CANDIDATE_VERSION}/final-set"
    )


def _distribution_set_root(repository: Path) -> Path:
    return _package_root(repository) / f"distribution/v{CANDIDATE_VERSION}"


def _raw_publication_root(repository: Path) -> Path:
    return _ga_candidate_root(repository) / "stage-inputs/publication"


def _sealed_publication_root(repository: Path) -> Path:
    return _ga_candidate_root(repository) / "publication"


def _require_positive_decimal(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[1-9][0-9]*", value)
        or len(value) > 18
    ):
        raise ArtifactSetError(f"{label} is not a canonical positive integer")
    return value


def _require_utc_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 40:
        raise ArtifactSetError(f"{label} is not a bounded UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ArtifactSetError(f"{label} is not an ISO-8601 UTC timestamp") from error
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ArtifactSetError(f"{label} is not UTC")
    return value


def _require_bounded_text(value: object, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ArtifactSetError(f"{label} is not bounded canonical text")
    return value


def _source_identity(value: object) -> dict[str, str]:
    value = _require_exact_keys(
        value,
        {"release_source_sha256", "repository_commit"},
        "release source identity",
    )
    commit = value["repository_commit"]
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise ArtifactSetError("repository commit is not canonical lowercase hex")
    return {
        "repository_commit": commit,
        "release_source_sha256": _require_sha256(
            value["release_source_sha256"], "release source digest"
        ),
    }


def _canonical_source_identity(value: dict[str, str]) -> dict[str, str]:
    return _source_identity(
        {
            "repository_commit": value.get("repositoryCommit"),
            "release_source_sha256": value.get("releaseSourceSha256"),
        }
    )


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ArtifactSetError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ArtifactSetError(f"{label} is not a real directory")


def _inventory(directory: Path) -> set[str]:
    _require_real_directory(directory, "release set directory")
    try:
        entries = list(directory.iterdir())
    except OSError as error:
        raise ArtifactSetError("cannot enumerate release set directory") from error
    for entry in entries:
        try:
            metadata = entry.lstat()
        except OSError as error:
            raise ArtifactSetError("cannot inspect release set entry") from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ArtifactSetError(
                f"release set entry is not a single-link regular file: {entry.name}"
            )
    return {entry.name for entry in entries}


def _artifact_record(path: Path, maximum: int) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ArtifactSetError(f"release asset is unavailable: {path.name}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ArtifactSetError(
            f"release asset is not a single-link regular file: {path.name}"
        )
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise ArtifactSetError(
            f"release asset size is outside 1..={maximum}: {path.name}"
        )
    try:
        size, digest = regular_file_identity(path)
    except PublicationError as error:
        raise ArtifactSetError(
            f"cannot derive release asset identity: {path.name}"
        ) from error
    if size != metadata.st_size:
        raise ArtifactSetError(
            f"release asset changed while its identity was captured: {path.name}"
        )
    return {"filename": path.name, "sha256": digest, "size": size}


def _release_verifier_source_inputs(repository: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for key, relative in RELEASE_VERIFIER_SOURCE_INPUTS.items():
        record = _artifact_record(
            repository.joinpath(*PurePosixPath(relative).parts),
            MAX_PUBLICATION_DOCUMENT_BYTES,
        )
        records[key] = {
            "path": relative,
            "sha256": record["sha256"],
            "size": record["size"],
        }
    return records


def _validate_release_verifier_source_inputs(
    value: object,
    repository: Path,
) -> dict[str, dict[str, object]]:
    value = _require_exact_keys(
        value,
        set(RELEASE_VERIFIER_SOURCE_INPUTS),
        "release verifier source inputs",
    )
    validated: dict[str, dict[str, object]] = {}
    for key, relative in RELEASE_VERIFIER_SOURCE_INPUTS.items():
        record = _require_exact_keys(
            value[key],
            {"path", "sha256", "size"},
            f"release verifier source input {key}",
        )
        size = record["size"]
        if (
            record["path"] != relative
            or type(size) is not int
            or size <= 0
            or size > MAX_PUBLICATION_DOCUMENT_BYTES
        ):
            raise ArtifactSetError(
                f"release verifier source input {key} is malformed"
            )
        _require_sha256(
            record["sha256"],
            f"release verifier source input {key} digest",
        )
        validated[key] = record
    if validated != _release_verifier_source_inputs(repository):
        raise ArtifactSetError(
            "release verifier source inputs differ from the sealed build binding"
        )
    return validated


def _write_private_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    try:
        with path.open("xb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
    except OSError as error:
        raise ArtifactSetError(f"cannot materialize private build input: {path.name}") from error


def _validate_isolated_release_verifier_lock(
    path: Path, dependency_sources: dict[str, object]
) -> str:
    try:
        data = read_regular(path, MAX_PUBLICATION_DOCUMENT_BYTES)
        document = tomllib.loads(data.decode("utf-8"))
    except (PublicationError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ArtifactSetError("isolated release verifier lock is invalid") from error
    packages = document.get("package")
    if document.get("version") != 4 or not isinstance(packages, list):
        raise ArtifactSetError("isolated release verifier lock is not v4")
    actual_registry: set[tuple[str, str, str]] = set()
    local: list[tuple[object, object]] = []
    for package in packages:
        if not isinstance(package, dict):
            raise ArtifactSetError("isolated release verifier lock package is malformed")
        if package.get("source") is None:
            local.append((package.get("name"), package.get("version")))
            continue
        if package.get("source") != CRATES_IO_SOURCE:
            raise ArtifactSetError("isolated release verifier lock source is unexpected")
        name = package.get("name")
        version = package.get("version")
        checksum = package.get("checksum")
        if not all(isinstance(item, str) for item in (name, version, checksum)):
            raise ArtifactSetError("isolated release verifier lock identity is malformed")
        actual_registry.add((name, version, checksum))
    if local != [("cfw-release-verifier", "0.4.0")]:
        raise ArtifactSetError("isolated lock has an unexpected local package")
    crates = dependency_sources.get("crates")
    if not isinstance(crates, list):
        raise ArtifactSetError("release verifier dependency binding is malformed")
    expected_registry = {
        (str(crate["name"]), str(crate["version"]), str(crate["crate_sha256"]))
        for crate in crates
        if isinstance(crate, dict)
    }
    if actual_registry != expected_registry or len(expected_registry) != len(crates):
        raise ArtifactSetError(
            "isolated release verifier lock differs from authenticated dependencies"
        )
    return hashlib.sha256(data).hexdigest()


def _validate_recorded_executable(
    value: object,
    *,
    filename: str,
    label: str,
    include_version: bool,
) -> dict[str, object]:
    fields = {"filename", "sha256", "size"}
    if include_version:
        fields.add("version")
    value = _require_exact_keys(value, fields, label)
    if value["filename"] != filename:
        raise ArtifactSetError(f"{label} has the wrong executable name")
    _require_sha256(value["sha256"], f"{label} digest")
    size = value["size"]
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES
    ):
        raise ArtifactSetError(f"{label} size is outside its fixed limit")
    if include_version:
        _require_bounded_text(value["version"], f"{label} version", 4096)
    return value


def _validate_release_verifier_dependencies(value: object) -> dict[str, Any]:
    value = _require_exact_keys(
        value,
        {"algorithm", "crates", "sha256"},
        "release verifier dependency sources",
    )
    crates = value["crates"]
    if (
        value["algorithm"] != "crates-io-lock-archive-tree-v1"
        or not isinstance(crates, list)
        or not crates
        or len(crates) > MAX_RELEASE_VERIFIER_CRATES
    ):
        raise ArtifactSetError("release verifier dependency source set is malformed")
    canonical_crates: list[dict[str, Any]] = []
    for item in crates:
        item = _require_exact_keys(
            item,
            {
                "crate_sha256",
                "name",
                "source",
                "source_tree_sha256",
                "version",
            },
            "release verifier dependency source",
        )
        name = _require_bounded_text(
            item["name"], "release verifier dependency name", 256
        )
        version = _require_bounded_text(
            item["version"], "release verifier dependency version", 256
        )
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]+", name)
            or not re.fullmatch(r"[0-9A-Za-z.+_-]+", version)
            or item["source"] != CRATES_IO_SOURCE
        ):
            raise ArtifactSetError("release verifier dependency identity is malformed")
        _require_sha256(item["crate_sha256"], "release verifier crate archive digest")
        _require_sha256(
            item["source_tree_sha256"], "release verifier crate source tree digest"
        )
        canonical_crates.append(item)
    if canonical_crates != sorted(
        canonical_crates,
        key=lambda item: (item["name"], item["version"], item["crate_sha256"]),
    ):
        raise ArtifactSetError("release verifier dependencies are not canonically ordered")
    if value["sha256"] != hashlib.sha256(canonical_json(crates)).hexdigest():
        raise ArtifactSetError("release verifier dependency source digest is inconsistent")
    return value


def _validate_release_toolchain_surface(
    value: object, repository: Path
) -> dict[str, Any]:
    try:
        return validate_recorded_surface(repository, value)
    except ReleaseRustToolchainError as error:
        raise ArtifactSetError("Rust release toolchain surface is inconsistent") from error


def _validate_release_verifier_binding(
    value: object, repository: Path
) -> dict[str, Any]:
    value = _require_exact_keys(
        value,
        {
            "apple_toolchain",
            "build_invocation",
            "cargo",
            "cargo_workspace_lock_sha256",
            "cargo_workspace_vendor_sha256",
            "dependency_sources",
            "document",
            "executable",
            "isolated_workspace_sha256",
            "lock_invocation",
            "lock_sha256",
            "network",
            "rustc",
            "schema_version",
            "source_inputs",
            "target",
            "toolchain",
            "toolchain_surface",
            "verification_invocation",
        },
        "release verifier build binding",
    )
    if (
        value["document"] != RELEASE_VERIFIER_BINDING_DOCUMENT
        or type(value["schema_version"]) is not int
        or value["schema_version"] != RELEASE_VERIFIER_BINDING_SCHEMA_VERSION
        or value["network"] != "offline"
        or value["target"] != RELEASE_VERIFIER_TARGET
        or value["build_invocation"] != RELEASE_VERIFIER_BUILD_INVOCATION
        or value["lock_invocation"] != RELEASE_VERIFIER_LOCK_INVOCATION
        or value["verification_invocation"]
        != RELEASE_VERIFIER_VERIFY_INVOCATION
        or value["isolated_workspace_sha256"]
        != hashlib.sha256(
            RELEASE_VERIFIER_ISOLATED_WORKSPACE.encode("utf-8")
        ).hexdigest()
    ):
        raise ArtifactSetError("release verifier build policy is inconsistent")
    _require_sha256(value["lock_sha256"], "isolated release verifier lock digest")
    cargo_workspace_lock_sha256 = _require_sha256(
        value["cargo_workspace_lock_sha256"],
        "release verifier workspace Cargo.lock digest",
    )
    _require_sha256(
        value["cargo_workspace_vendor_sha256"],
        "release verifier workspace Cargo vendor digest",
    )
    try:
        validate_recorded_release_apple_toolchain(
            value["apple_toolchain"], repository
        )
    except ReleaseAppleToolchainError as error:
        raise ArtifactSetError(
            "release verifier Apple linker inputs are inconsistent"
        ) from error

    channel = _pinned_rust_channel(repository)
    expected_toolchain = f"{channel}-aarch64-apple-darwin"
    if value["toolchain"] != expected_toolchain:
        raise ArtifactSetError("release verifier toolchain is not the pinned target")
    cargo = _validate_recorded_executable(
        value["cargo"], filename="cargo", label="release verifier cargo", include_version=True
    )
    rustc = _validate_recorded_executable(
        value["rustc"], filename="rustc", label="release verifier rustc", include_version=True
    )
    _validate_recorded_executable(
        value["executable"],
        filename="cfw-release-verifier",
        label="release verifier executable",
        include_version=False,
    )
    if (
        not str(cargo["version"]).startswith("cargo ")
        or channel not in str(cargo["version"])
        or not str(rustc["version"]).startswith("rustc ")
        or channel not in str(rustc["version"])
    ):
        raise ArtifactSetError("release verifier compiler versions are inconsistent")
    dependency_sources = _validate_release_verifier_dependencies(
        value["dependency_sources"]
    )
    _validate_release_toolchain_surface(value["toolchain_surface"], repository)
    source_inputs = _validate_release_verifier_source_inputs(
        value["source_inputs"], repository
    )
    if cargo_workspace_lock_sha256 != source_inputs["cargo_lock"]["sha256"]:
        raise ArtifactSetError(
            "release verifier workspace Cargo.lock differs from its source binding"
        )
    try:
        workspace_inputs = verify_workspace_cargo_inputs(
            repository,
            Path(os.environ["CFW_RELEASE_CARGO_INPUT_ROOT"]),
        )
        expected_dependencies = release_verifier_dependency_records(
            repository, workspace_inputs
        )
    except (KeyError, OSError, ReleaseCargoInputsError) as error:
        raise ArtifactSetError(
            "cannot revalidate the release verifier Cargo workspace inputs"
        ) from error
    if (
        workspace_inputs.cargo_lock_sha256 != cargo_workspace_lock_sha256
        or workspace_inputs.vendor_tree_sha256
        != value["cargo_workspace_vendor_sha256"]
        or dependency_sources != expected_dependencies
    ):
        raise ArtifactSetError(
            "release verifier Cargo dependency binding differs from the verified vendor"
        )
    return value


def _run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: float,
    label: str,
    maximum_stdout: int = MAX_SMALL_DOCUMENT_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = _run_transaction_process(
            command,
            timeout,
            cwd=cwd,
            environment=environment,
        )
    except TransactionError as error:
        operational_reason = _RELEASE_VERIFIER_PROCESS_REASON_BY_CODE.get(
            error.code
        )
        if operational_reason is not None:
            raise ReleaseVerifierOperationalError(
                operational_reason, label
            ) from error
        raise ArtifactSetError(f"{label} did not complete") from error
    except OSError as error:
        raise ArtifactSetError(f"{label} did not complete") from error
    stdout = result.stdout.encode("utf-8")
    stderr = result.stderr.encode("utf-8")
    if (
        result.returncode != 0
        or stderr
        or len(stdout) > maximum_stdout
    ):
        raise ArtifactSetError(f"{label} failed or emitted diagnostics")
    return subprocess.CompletedProcess(command, result.returncode, stdout, stderr)


def _release_verifier_identity_environment(
    tool_directory: Path,
    *,
    developer_directory: Path,
    deployment_target: str,
    sdk_root: Path,
) -> dict[str, str]:
    return {
        "DEVELOPER_DIR": str(developer_directory),
        "LANG": "C",
        "LC_ALL": "C",
        "MACOSX_DEPLOYMENT_TARGET": deployment_target,
        "PATH": f"{tool_directory}:/usr/bin:/bin:/usr/sbin:/sbin",
        "SDKROOT": str(sdk_root),
    }


def _pinned_rust_channel(repository: Path) -> str:
    try:
        return pinned_toolchain_contract(repository)[0]
    except ReleaseRustToolchainError as error:
        raise ArtifactSetError("Rust release toolchain declaration is invalid") from error


def _release_toolchain_surface_pin(repository: Path) -> str:
    try:
        return pinned_toolchain_contract(repository)[1]
    except ReleaseRustToolchainError as error:
        raise ArtifactSetError("Rust toolchain surface pin is not manifest-bound") from error


def _pinned_rust_toolchain_root(toolchain: str) -> Path:
    selected_rustc = os.environ.get("CFW_RELEASE_RUSTC_EXECUTABLE")
    if not selected_rustc:
        raise ArtifactSetError(
            "closed release environment omitted its pinned Rust compiler"
        )
    candidate = Path(selected_rustc).parent.parent
    try:
        root = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ArtifactSetError("pinned Rust toolchain directory is unavailable") from error
    if root != candidate.absolute():
        raise ArtifactSetError("pinned Rust toolchain directory is not canonical")
    if root.name != toolchain:
        raise ArtifactSetError("pinned Rust compiler is from a different toolchain")
    _require_real_directory(root, "pinned Rust toolchain directory")
    return root


def _release_toolchain_surface(root: Path) -> dict[str, Any]:
    try:
        return build_toolchain_surface(root)
    except ReleaseRustToolchainError as error:
        raise ArtifactSetError("Rust toolchain surface is invalid") from error


def _tool_version(
    tool: Path,
    repository: Path,
    environment: dict[str, str],
    expected_prefix: str,
) -> str:
    result = _run_bounded_process(
        [str(tool), "--version"],
        cwd=repository,
        environment=environment,
        timeout=60,
        label=f"{expected_prefix} version check",
        maximum_stdout=4096,
    )
    try:
        version = result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ArtifactSetError(f"{expected_prefix} version is not UTF-8") from error
    _require_bounded_text(version, f"{expected_prefix} version", 4096)
    if not version.startswith(expected_prefix + " "):
        raise ArtifactSetError(f"{expected_prefix} version output is malformed")
    return version


@contextmanager
def _compiled_release_verifier(
    repository: Path,
    *,
    temporary_parent: Path | None = None,
):
    try:
        workspace_inputs = verify_workspace_cargo_inputs(
            repository,
            Path(os.environ["CFW_RELEASE_CARGO_INPUT_ROOT"]),
        )
    except (KeyError, OSError, ReleaseCargoInputsError) as error:
        raise ArtifactSetError(
            "verified Cargo workspace inputs are unavailable"
        ) from error
    try:
        apple_toolchain = capture_release_apple_toolchain(repository)
    except ReleaseAppleToolchainError as error:
        raise ArtifactSetError(
            "Apple release linker inputs are unavailable"
        ) from error
    channel = _pinned_rust_channel(repository)
    toolchain = f"{channel}-{RELEASE_VERIFIER_TARGET}"
    toolchain_root = _pinned_rust_toolchain_root(toolchain)
    try:
        verified_toolchain = verify_pinned_toolchain(repository, toolchain_root)
    except ReleaseRustToolchainError as error:
        raise ArtifactSetError("Rust release toolchain differs from its pin") from error
    toolchain_surface = verified_toolchain.surface
    cargo = verified_toolchain.cargo
    rustc = verified_toolchain.rustc
    _artifact_record(cargo, MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES)
    _artifact_record(rustc, MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES)
    if cargo.parent != rustc.parent:
        raise ArtifactSetError("cargo and rustc are from different toolchains")
    bootstrap_environment = _release_verifier_identity_environment(
        cargo.parent,
        developer_directory=apple_toolchain.developer_directory,
        deployment_target=apple_toolchain.deployment_target,
        sdk_root=apple_toolchain.sdk_root,
    )
    cargo_version = _tool_version(cargo, repository, bootstrap_environment, "cargo")
    rustc_version = _tool_version(rustc, repository, bootstrap_environment, "rustc")
    if channel not in cargo_version or channel not in rustc_version:
        raise ArtifactSetError("cargo or rustc differs from the pinned release channel")
    resolved_temporary_parent: Path | None = None
    if temporary_parent is not None:
        try:
            resolved_temporary_parent = temporary_parent.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ArtifactSetError(
                "release verifier temporary parent is unavailable"
            ) from error
        if (
            not temporary_parent.is_absolute()
            or resolved_temporary_parent != temporary_parent.absolute()
            or "=" in str(resolved_temporary_parent)
        ):
            raise ArtifactSetError(
                "release verifier temporary parent is not canonical"
            )
        _require_real_directory(
            resolved_temporary_parent,
            "release verifier temporary parent",
        )
    with tempfile.TemporaryDirectory(
        prefix="cfw-release-verifier-build.",
        dir=resolved_temporary_parent,
    ) as temporary:
        private_root = Path(temporary).resolve()
        cargo_home = private_root / "cargo-home"
        home = private_root / "home"
        temporary_directory = private_root / "tmp"
        target = private_root / "target"
        workspace = private_root / "isolated-workspace"
        crate_directory = workspace / "crates/cfw-release-verifier"
        for directory in (
            cargo_home,
            home,
            temporary_directory,
            target,
            workspace,
        ):
            directory.mkdir(mode=0o700)
        crate_directory.mkdir(parents=True, mode=0o700)
        (crate_directory / "src").mkdir(mode=0o700)
        try:
            dependency_sources = release_verifier_dependency_records(
                repository, workspace_inputs
            )
            create_runtime_cargo_home(
                repository,
                workspace_inputs,
                cargo_home,
                additional_working_directories=(workspace,),
            )
        except ReleaseCargoInputsError as error:
            raise ArtifactSetError(
                "release verifier Cargo inputs are invalid"
            ) from error
        _write_private_file(
            workspace / "Cargo.toml",
            RELEASE_VERIFIER_ISOLATED_WORKSPACE.encode("utf-8"),
        )
        for source, destination, maximum in (
            (
                repository / "crates/cfw-release-verifier/Cargo.toml",
                crate_directory / "Cargo.toml",
                MAX_SMALL_DOCUMENT_BYTES,
            ),
            (
                repository / "crates/cfw-release-verifier/src/main.rs",
                crate_directory / "src/main.rs",
                MAX_PUBLICATION_DOCUMENT_BYTES,
            ),
        ):
            _write_private_file(destination, read_regular(source, maximum))
        environment = _release_verifier_build_environment(
            tool_directory=str(cargo.parent),
            developer_directory=str(apple_toolchain.developer_directory),
            deployment_target=apple_toolchain.deployment_target,
            sdk_root=str(apple_toolchain.sdk_root),
            cargo_home=str(cargo_home),
            home=str(home),
            rustc=str(rustc),
            temporary_directory=str(temporary_directory),
        )
        if any(
            name in environment
            for name in (
                "CARGO_BUILD_RUSTC",
                "CARGO_BUILD_RUSTC_WRAPPER",
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
                "CARGO_BUILD_RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER",
                "RUSTFLAGS",
            )
        ):
            raise ArtifactSetError("release verifier build environment is injectable")
        lock_command = _release_verifier_lock_argv(
            cargo=str(cargo),
            workspace=str(workspace),
        )
        _run_bounded_process(
            lock_command,
            cwd=workspace,
            environment=environment,
            timeout=300,
            label="isolated release verifier lock generation",
        )
        isolated_lock_sha256 = _validate_isolated_release_verifier_lock(
            workspace / "Cargo.lock", dependency_sources
        )
        command = _release_verifier_build_argv(
            cargo=str(cargo),
            workspace=str(workspace),
            target=str(target),
            private_root=str(private_root),
            verified_vendor=str(workspace_inputs.vendor),
            clang=str(apple_toolchain.clang),
            linker=str(apple_toolchain.linker),
        )
        _run_bounded_process(
            command,
            cwd=workspace,
            environment=environment,
            timeout=1800,
            label="release verifier build",
        )
        executable = (
            target
            / RELEASE_VERIFIER_TARGET
            / "release/cfw-release-verifier"
        )
        _artifact_record(executable, MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES)
        try:
            verify_runtime_cargo_home(
                repository,
                workspace_inputs,
                cargo_home,
                additional_working_directories=(workspace,),
            )
            ending_workspace_inputs = verify_workspace_cargo_inputs(
                repository, workspace_inputs.root
            )
        except ReleaseCargoInputsError as error:
            raise ArtifactSetError(
                "release verifier Cargo inputs changed during compilation"
            ) from error
        if ending_workspace_inputs != workspace_inputs:
            raise ArtifactSetError(
                "release verifier Cargo inputs changed during compilation"
            )
        try:
            ending_apple_toolchain = capture_release_apple_toolchain(repository)
        except ReleaseAppleToolchainError as error:
            raise ArtifactSetError(
                "Apple release linker inputs changed during compilation"
            ) from error
        if ending_apple_toolchain != apple_toolchain:
            raise ArtifactSetError(
                "Apple release linker inputs changed during compilation"
            )
        yield ReleaseVerifierBuild(
            executable=executable,
            apple_toolchain=apple_toolchain.binding,
            cargo=cargo,
            cargo_version=cargo_version,
            cargo_input_root=workspace_inputs.root,
            cargo_lock_sha256=workspace_inputs.cargo_lock_sha256,
            cargo_vendor_sha256=workspace_inputs.vendor_tree_sha256,
            dependency_sources=dependency_sources,
            isolated_lock_sha256=isolated_lock_sha256,
            developer_directory=apple_toolchain.developer_directory,
            deployment_target=apple_toolchain.deployment_target,
            rustc=rustc,
            rustc_version=rustc_version,
            toolchain=toolchain,
            toolchain_surface=toolchain_surface,
            sdk_root=apple_toolchain.sdk_root,
        )


def _invoke_release_verifier(
    build: ReleaseVerifierBuild,
    repository: Path,
    archive: Path,
    signature: Path,
) -> dict[str, Any]:
    configuration = repository / "apps/cfw-tauri-shell/tauri.conf.json"
    result = _run_bounded_process(
        _release_verifier_verify_argv(
            executable=str(build.executable),
            configuration=str(configuration),
            archive=str(archive),
            signature=str(signature),
        ),
        cwd=repository,
        environment=dict(RELEASE_VERIFIER_VERIFY_INVOCATION["environment"]),
        timeout=300,
        label="release verifier execution",
    )
    try:
        value = json.loads(
            result.stdout.decode("utf-8"), object_pairs_hook=_strict_object
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateFieldError,
    ) as error:
        raise ArtifactSetError(
            "release verifier did not emit strict JSON"
        ) from error
    if not isinstance(value, dict):
        raise ArtifactSetError("release verifier receipt is not a JSON object")
    return value


def _release_verifier_binding(
    build: ReleaseVerifierBuild,
    *,
    cargo: dict[str, object],
    rustc: dict[str, object],
    executable: dict[str, object],
    source_inputs: dict[str, dict[str, object]],
) -> dict[str, Any]:
    return {
        "apple_toolchain": build.apple_toolchain,
        "build_invocation": RELEASE_VERIFIER_BUILD_INVOCATION,
        "cargo": {**cargo, "version": build.cargo_version},
        "cargo_workspace_lock_sha256": build.cargo_lock_sha256,
        "cargo_workspace_vendor_sha256": build.cargo_vendor_sha256,
        "dependency_sources": build.dependency_sources,
        "document": RELEASE_VERIFIER_BINDING_DOCUMENT,
        "executable": executable,
        "isolated_workspace_sha256": hashlib.sha256(
            RELEASE_VERIFIER_ISOLATED_WORKSPACE.encode("utf-8")
        ).hexdigest(),
        "lock_invocation": RELEASE_VERIFIER_LOCK_INVOCATION,
        "lock_sha256": build.isolated_lock_sha256,
        "network": "offline",
        "rustc": {**rustc, "version": build.rustc_version},
        "schema_version": RELEASE_VERIFIER_BINDING_SCHEMA_VERSION,
        "source_inputs": source_inputs,
        "target": RELEASE_VERIFIER_TARGET,
        "toolchain": build.toolchain,
        "toolchain_surface": build.toolchain_surface,
        "verification_invocation": RELEASE_VERIFIER_VERIFY_INVOCATION,
    }


def _fresh_release_verifier_binding(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateFieldError,
    ) as error:
        raise ArtifactSetError(
            "release verifier session binding is not strict JSON"
        ) from error
    if not isinstance(value, dict) or canonical_json(value) != data:
        raise ArtifactSetError(
            "release verifier session binding is not canonical JSON"
        )
    return value


def _verify_updater_verification_session_state(
    repository: Path,
    build: ReleaseVerifierBuild,
    *,
    workspace_inputs: WorkspaceCargoInputs,
    source_inputs: dict[str, dict[str, object]],
    cargo: dict[str, object],
    rustc: dict[str, object],
    executable: dict[str, object],
) -> None:
    if _release_verifier_source_inputs(repository) != source_inputs:
        raise ArtifactSetError(
            "release verifier source inputs changed during verification"
        )

    try:
        configured_cargo_root = Path(
            os.environ["CFW_RELEASE_CARGO_INPUT_ROOT"]
        )
        observed_workspace_inputs = verify_workspace_cargo_inputs(
            repository, configured_cargo_root
        )
    except (KeyError, OSError, ReleaseCargoInputsError) as error:
        raise ArtifactSetError(
            "verified Cargo workspace inputs changed during release verification"
        ) from error
    if (
        configured_cargo_root != build.cargo_input_root
        or observed_workspace_inputs != workspace_inputs
    ):
        raise ArtifactSetError(
            "verified Cargo workspace inputs changed during release verification"
        )

    if (
        _artifact_record(build.cargo, MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES)
        != cargo
        or _artifact_record(build.rustc, MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES)
        != rustc
        or _artifact_record(
            build.executable, MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES
        )
        != executable
    ):
        raise ArtifactSetError(
            "release verifier toolchain or executable changed during verification"
        )

    toolchain_surface = _release_toolchain_surface(build.cargo.parent.parent)
    if toolchain_surface != build.toolchain_surface:
        raise ArtifactSetError(
            "pinned Rust toolchain changed during release verification"
        )

    try:
        apple_toolchain = capture_release_apple_toolchain(repository)
    except ReleaseAppleToolchainError as error:
        raise ArtifactSetError(
            "Apple release linker inputs changed during release verification"
        ) from error
    if (
        apple_toolchain.binding != build.apple_toolchain
        or apple_toolchain.developer_directory != build.developer_directory
        or apple_toolchain.sdk_root != build.sdk_root
        or apple_toolchain.deployment_target != build.deployment_target
    ):
        raise ArtifactSetError(
            "Apple release linker inputs changed during release verification"
        )


def _new_updater_verification_session_lock():
    return threading.Lock()


@contextmanager
def _updater_verification_session(
    repository: Path,
) -> Iterator[UpdaterVerificationProducer]:
    """Build one private verifier and replay it against stable bound inputs."""

    try:
        workspace_inputs = verify_workspace_cargo_inputs(
            repository,
            Path(os.environ["CFW_RELEASE_CARGO_INPUT_ROOT"]),
        )
    except (KeyError, OSError, ReleaseCargoInputsError) as error:
        raise ArtifactSetError(
            "verified Cargo workspace inputs are unavailable"
        ) from error
    source_inputs = _release_verifier_source_inputs(repository)
    with _compiled_release_verifier(repository) as build:
        cargo = _artifact_record(
            build.cargo, MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES
        )
        rustc = _artifact_record(
            build.rustc, MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES
        )
        executable = _artifact_record(
            build.executable, MAX_RELEASE_VERIFIER_EXECUTABLE_BYTES
        )
        _verify_updater_verification_session_state(
            repository,
            build,
            workspace_inputs=workspace_inputs,
            source_inputs=source_inputs,
            cargo=cargo,
            rustc=rustc,
            executable=executable,
        )
        binding_data = canonical_json(
            _release_verifier_binding(
                build,
                cargo=cargo,
                rustc=rustc,
                executable=executable,
                source_inputs=source_inputs,
            )
        )
        active = True
        poisoned = False
        state_lock = _new_updater_verification_session_lock()
        replay_lock = _new_updater_verification_session_lock()

        def produce(
            archive: Path, signature: Path
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            nonlocal poisoned
            if not replay_lock.acquire(blocking=False):
                raise ArtifactSetError(
                    "release verifier session does not allow concurrent or reentrant replay"
                )

            accepted = False
            completed = False
            try:
                with state_lock:
                    if not active:
                        raise ArtifactSetError(
                            "release verifier session is no longer active"
                        )
                    if poisoned:
                        raise ArtifactSetError(
                            "release verifier session cannot continue after a failed replay"
                        )
                    accepted = True
                _verify_updater_verification_session_state(
                    repository,
                    build,
                    workspace_inputs=workspace_inputs,
                    source_inputs=source_inputs,
                    cargo=cargo,
                    rustc=rustc,
                    executable=executable,
                )
                archive_before = _artifact_record(
                    archive, MAX_UPDATER_ARCHIVE_BYTES
                )
                signature_before = _artifact_record(
                    signature, MAX_SIGNATURE_BYTES
                )
                try:
                    receipt = _invoke_release_verifier(
                        build, repository, archive, signature
                    )
                finally:
                    try:
                        if (
                            _artifact_record(
                                archive, MAX_UPDATER_ARCHIVE_BYTES
                            )
                            != archive_before
                            or _artifact_record(
                                signature, MAX_SIGNATURE_BYTES
                            )
                            != signature_before
                        ):
                            raise ArtifactSetError(
                                "updater archive or signature changed during "
                                "embedded-key verification"
                            )
                    finally:
                        _verify_updater_verification_session_state(
                            repository,
                            build,
                            workspace_inputs=workspace_inputs,
                            source_inputs=source_inputs,
                            cargo=cargo,
                            rustc=rustc,
                            executable=executable,
                        )
                fresh_binding = _fresh_release_verifier_binding(binding_data)
                completed = True
                return receipt, fresh_binding
            finally:
                if accepted and not completed:
                    with state_lock:
                        poisoned = True
                replay_lock.release()

        try:
            yield produce
        finally:
            with state_lock:
                active = False
            replay_lock.acquire()
            try:
                _verify_updater_verification_session_state(
                    repository,
                    build,
                    workspace_inputs=workspace_inputs,
                    source_inputs=source_inputs,
                    cargo=cargo,
                    rustc=rustc,
                    executable=executable,
                )
            finally:
                replay_lock.release()


def _produce_updater_verification(
    repository: Path,
    archive: Path,
    signature: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    with _updater_verification_session(repository) as produce:
        return produce(archive, signature)


def _candidate_app_paths(repository: Path) -> tuple[Path, Path]:
    app = repository / CANDIDATE_APP_RELATIVE
    return app, app.parent / CANDIDATE_APP_MANIFEST_NAME


def _candidate_app_binding(
    repository: Path,
    *,
    version: str,
    source_identity: dict[str, str],
    expected_build_number: str | None = None,
) -> dict[str, Any]:
    """Recompute the final notarized candidate and its immutable manifest."""
    _require_active_version(version)
    source = _source_identity(source_identity)
    app, manifest_path = _candidate_app_paths(repository)
    _require_real_directory(app, "signed candidate application")
    manifest_record_before = _artifact_record(
        manifest_path, MAX_APP_MANIFEST_BYTES
    )
    document, _data = _load_strict_json(
        manifest_path, MAX_APP_MANIFEST_BYTES
    )
    document = _require_exact_keys(
        document,
        {"algorithm", "entries", "metadata", "root", "rootMode", "sha256"},
        "signed candidate app manifest",
    )
    if document["algorithm"] != "sha256-tree-v2":
        raise ArtifactSetError("signed candidate app manifest must use sha256-tree-v2")
    try:
        actual = build_manifest(app, algorithm="sha256-tree-v2")
    except (OSError, ValueError) as error:
        raise ArtifactSetError("cannot recompute signed candidate application") from error
    for field in ("algorithm", "entries", "root", "rootMode", "sha256"):
        if document[field] != actual[field]:
            raise ArtifactSetError(
                "signed candidate app manifest differs from the application tree"
            )
    metadata_fields = {
        "architecture",
        "artifactKind",
        "buildNumber",
        "deploymentTarget",
        "releaseSourceSha256",
        "repositoryCommit",
        "teamID",
        "version",
        *TOOLCHAIN_METADATA_ORDER,
    }
    metadata = _require_exact_keys(
        document["metadata"], metadata_fields, "signed candidate app metadata"
    )
    build_number = _require_positive_decimal(
        metadata["buildNumber"], "signed candidate build number"
    )
    if build_number != CANDIDATE_BUILD_NUMBER:
        raise ArtifactSetError("signed candidate is not the active GA build")
    if expected_build_number is not None and build_number != expected_build_number:
        raise ArtifactSetError("signed candidate build differs from the release set")
    if (
        metadata["architecture"] != "arm64"
        or metadata["artifactKind"] != GA_APP_ARTIFACT_KIND
        or metadata["deploymentTarget"] != "15.0"
        or metadata["releaseSourceSha256"] != source["release_source_sha256"]
        or metadata["repositoryCommit"] != source["repository_commit"]
        or metadata["teamID"] != TEAM_ID
        or metadata["version"] != version
    ):
        raise ArtifactSetError(
            "signed candidate app manifest metadata differs from the release identity"
        )
    for key in TOOLCHAIN_METADATA_ORDER:
        _require_sha256(metadata[key], f"signed candidate metadata {key}")
    manifest_record_after = _artifact_record(
        manifest_path, MAX_APP_MANIFEST_BYTES
    )
    if manifest_record_after != manifest_record_before:
        raise ArtifactSetError("signed candidate app manifest changed while binding")
    tree_sha256 = _require_sha256(
        document["sha256"], "signed candidate app tree digest"
    )
    return {
        "build_number": build_number,
        "manifest": manifest_record_after,
        "path": CANDIDATE_APP_RELATIVE,
        "signed_app_tree_sha256": tree_sha256,
        "tree_algorithm": "sha256-tree-v2",
    }


def _validate_candidate_app_binding(
    value: object,
    repository: Path,
    *,
    version: str,
    source_identity: dict[str, str],
    expected_build_number: str | None = None,
) -> dict[str, Any]:
    value = _require_exact_keys(
        value,
        {
            "build_number",
            "manifest",
            "path",
            "signed_app_tree_sha256",
            "tree_algorithm",
        },
        "signed candidate app binding",
    )
    expected = _candidate_app_binding(
        repository,
        version=version,
        source_identity=source_identity,
        expected_build_number=expected_build_number,
    )
    if value != expected:
        raise ArtifactSetError(
            "release set is bound to a different signed candidate application"
        )
    return expected


def _validate_packaged_app_manifest(
    value: object,
    candidate: dict[str, Any],
    label: str,
) -> dict[str, object]:
    value = _require_exact_keys(
        value,
        {"algorithm", "entries", "root", "rootMode", "sha256"},
        label,
    )
    if (
        value["algorithm"] != candidate["tree_algorithm"]
        or value["root"] != Path(CANDIDATE_APP_RELATIVE).name
        or value["sha256"] != candidate["signed_app_tree_sha256"]
    ):
        raise ArtifactSetError(
            f"{label} is not the exact signed candidate application"
        )
    _require_sha256(value["sha256"], f"{label} tree digest")
    if not isinstance(value["entries"], list) or not isinstance(
        value["rootMode"], str
    ):
        raise ArtifactSetError(f"{label} has malformed tree evidence")
    return value


def _validate_artifact_record(
    value: object,
    path: Path,
    maximum: int,
    label: str,
) -> dict[str, object]:
    value = _require_exact_keys(value, {"filename", "sha256", "size"}, label)
    if (
        value["filename"] != path.name
        or type(value["size"]) is not int
        or value["size"] <= 0
        or value["size"] > maximum
    ):
        raise ArtifactSetError(f"{label} is malformed")
    _require_sha256(value["sha256"], f"{label} digest")
    actual = _artifact_record(path, maximum)
    if value != actual:
        raise ArtifactSetError(f"{label} differs from the sealed release asset")
    return actual


def _write_canonical_new(path: Path, value: object) -> None:
    try:
        write_new_manifest(path, canonical_json(value).decode("utf-8"))
    except (OSError, ValueError) as error:
        raise ArtifactSetError(f"cannot write release seal: {path.name}") from error


def _fsync_release_set(path: Path, label: str) -> None:
    try:
        _fsync_tree(path)
    except (OSError, TransactionError) as error:
        raise ArtifactSetError(f"cannot make {label} durable before publication") from error


def _confirm_release_set_durable(
    source: Path, destination: Path, label: str
) -> None:
    try:
        confirm_published_tree_durable(source, destination)
    except (OSError, TransactionError) as error:
        raise ArtifactSetError(
            f"cannot confirm durable atomic publication of {label}"
        ) from error


def _confirm_existing_release_set_durable(
    destination: Path, label: str
) -> None:
    source = destination.parent / f".{destination.name}.publish-source"
    if os.path.lexists(source):
        raise ArtifactSetError(
            f"cannot confirm {label}; its recovery source marker exists"
        )
    _confirm_release_set_durable(source, destination, label)


def _require_canonical_document(path: Path, value: object, data: bytes, label: str) -> None:
    if data != canonical_json(value):
        raise ArtifactSetError(f"{label} is not canonical JSON")


def _updater_names(version: str) -> tuple[str, str, str]:
    archive = f"Clash.for.Mac_{version}_aarch64.app.tar.gz"
    return archive, f"{archive}.sig", "latest.json"


def _reset_updater_generated_documents(staging: Path, version: str) -> None:
    """Remove only transaction-owned documents before deterministic replay."""
    payload = set(_updater_names(version))
    generated = {UPDATER_VERIFICATION_NAME, UPDATER_SEAL_NAME}
    inventory = _inventory(staging)
    if not payload.issubset(inventory) or inventory - payload - generated:
        raise ArtifactSetError("updater staging inventory is partial or contains extras")
    for name in sorted(generated & inventory):
        path = staging / name
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
            ):
                raise ArtifactSetError(
                    f"generated updater document is not privately owned: {name}"
                )
            path.unlink()
        except OSError as error:
            raise ArtifactSetError(
                f"cannot reset generated updater document: {name}"
            ) from error
    if _inventory(staging) != payload:
        raise ArtifactSetError("cannot reset updater staging for deterministic replay")


def _dmg_names(version: str) -> tuple[str, str, str, str, str, str]:
    prefix = f"Clash.for.Mac_{version}_arm64"
    return (
        f"{prefix}.dmg",
        f"{prefix}.dmg.manifest.json",
        f"{prefix}.notarization.json",
        f"{prefix}.notarization-log.json",
        f"{prefix}.gatekeeper.json",
        f"{prefix}.submission.json",
    )


def _official_url(version: str, filename: str) -> str:
    return f"{OFFICIAL_RELEASE_ORIGIN}/v{version}/{filename}"


def read_updater_app_manifest(archive: Path) -> dict[str, object]:
    try:
        return build_archive_app_manifest(
            str(archive), Path(CANDIDATE_APP_RELATIVE).name
        )
    except (ArchiveContractError, OSError, ValueError) as error:
        raise ArtifactSetError(
            "cannot reconstruct the application tree from updater archive bytes"
        ) from error


def read_dmg_app_manifest(dmg: Path) -> dict[str, object]:
    """Mount the final DMG read-only and hash its exact contained app tree."""
    mount_parent = Path(tempfile.mkdtemp(prefix="cfw-dmg-payload-verify."))
    os.chmod(mount_parent, 0o700)
    mountpoint = mount_parent / "volume"
    mountpoint.mkdir(mode=0o700)
    attached = False
    manifest: dict[str, object] | None = None
    primary_error: BaseException | None = None
    try:
        result = subprocess.run(
            [
                "/usr/bin/hdiutil",
                "attach",
                "-readonly",
                "-nobrowse",
                "-noautoopen",
                "-mountpoint",
                str(mountpoint),
                str(dmg),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
            check=False,
        )
        if result.returncode != 0:
            raise ArtifactSetError("cannot mount final DMG read-only for byte proof")
        attached = True
        try:
            entries = {entry.name: entry for entry in mountpoint.iterdir()}
        except OSError as error:
            raise ArtifactSetError("cannot enumerate mounted DMG payload") from error
        if set(entries) != {"Applications", Path(CANDIDATE_APP_RELATIVE).name}:
            raise ArtifactSetError("DMG payload inventory differs from its fixed layout")
        applications = entries["Applications"]
        try:
            if not applications.is_symlink() or os.readlink(applications) != "/Applications":
                raise ArtifactSetError("DMG Applications link differs from its fixed target")
        except OSError as error:
            raise ArtifactSetError("cannot inspect DMG Applications link") from error
        app = entries[Path(CANDIDATE_APP_RELATIVE).name]
        _require_real_directory(app, "application inside mounted DMG")
        try:
            manifest = build_manifest(app, algorithm="sha256-tree-v2")
        except (OSError, ValueError) as error:
            raise ArtifactSetError(
                "cannot reconstruct the application tree from final DMG bytes"
            ) from error
    except BaseException as error:
        primary_error = error
    finally:
        if attached:
            detached = subprocess.run(
                ["/usr/bin/hdiutil", "detach", str(mountpoint)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,
                check=False,
            )
            if detached.returncode != 0:
                raise ArtifactSetError(
                    "cannot detach final DMG verification mount"
                ) from primary_error
        try:
            mountpoint.rmdir()
            mount_parent.rmdir()
        except OSError as error:
            raise ArtifactSetError(
                "cannot remove final DMG verification mount directory"
            ) from (primary_error or error)
    if primary_error is not None:
        raise primary_error
    if manifest is None:
        raise ArtifactSetError("DMG application tree proof was not produced")
    return manifest


def verify_publication_semantics(
    repository: Path, publication: Path, app: Path
) -> None:
    """Reuse the authoritative CCS/SBOM/legal verifier inside seal operations."""
    if publication != _raw_publication_root(repository):
        raise ArtifactSetError("publication verifier requires the fixed GA raw input root")
    expected_app, _manifest = _candidate_app_paths(repository)
    if app != expected_app:
        raise ArtifactSetError("publication verifier requires the fixed GA signed app")
    try:
        if __package__:
            from .publication.verify import verify_evidence
        else:
            from publication.verify import verify_evidence

        verify_evidence(publication, app, False, repository=repository)
    except (ImportError, OSError, PublicationError, ValueError) as error:
        raise ArtifactSetError("GA publication evidence is invalid") from error


def _prepackage_manifest_path(repository: Path) -> Path:
    return _ga_candidate_root(repository) / "prepackage/manifest.json"


def _validate_prepackage_binding(
    value: object, repository: Path
) -> dict[str, Any]:
    """Validate a fixed-path prepackage authorization without trusting a caller record."""

    value = _require_exact_keys(
        value,
        {"manifest", "manifest_path"},
        "GA prepackage stage binding",
    )
    manifest_path = _prepackage_manifest_path(repository)
    expected_relative = str(manifest_path.relative_to(repository))
    if value["manifest_path"] != expected_relative:
        raise ArtifactSetError("GA prepackage stage binding uses a noncanonical path")
    manifest = _validate_artifact_record(
        value["manifest"],
        manifest_path,
        MAX_PUBLICATION_DOCUMENT_BYTES,
        "GA prepackage stage manifest",
    )
    return {"manifest": manifest, "manifest_path": expected_relative}


def _reopen_prepackage_binding(
    repository: Path, verifier: PrepackageStageVerifier | None
) -> dict[str, Any]:
    if verifier is None:
        raise ArtifactSetError("fixed GA prepackage stage verifier is unavailable")
    try:
        return _validate_prepackage_binding(verifier(repository), repository)
    except ArtifactSetError:
        raise
    except (ImportError, OSError, PublicationError, ValueError) as error:
        raise ArtifactSetError(
            "fixed GA prepackage stage authorization is invalid"
        ) from error

def _validate_updater_verification(
    path: Path,
    *,
    archive_record: dict[str, object],
    signature_record: dict[str, object],
    repository: Path,
) -> tuple[dict[str, Any], bytes]:
    value, data = _load_strict_json(path, MAX_SMALL_DOCUMENT_BYTES)
    fields = {
        "archive_filename",
        "archive_sha256",
        "archive_size",
        "document",
        "embedded_public_key_sha256",
        "result",
        "schema_version",
        "signature_filename",
        "signature_sha256",
        "signature_size",
        "tauri_config_sha256",
    }
    value = _require_exact_keys(value, fields, "embedded public-key verification")
    expected = {
        "archive_filename": archive_record["filename"],
        "archive_sha256": archive_record["sha256"],
        "archive_size": archive_record["size"],
        "document": UPDATER_VERIFICATION_DOCUMENT,
        "result": "verified",
        "schema_version": 1,
        "signature_filename": signature_record["filename"],
        "signature_sha256": signature_record["sha256"],
        "signature_size": signature_record["size"],
    }
    if (
        type(value["schema_version"]) is not int
        or type(value["archive_size"]) is not int
        or value["archive_size"] <= 0
        or value["archive_size"] > MAX_UPDATER_ARCHIVE_BYTES
        or type(value["signature_size"]) is not int
        or value["signature_size"] <= 0
        or value["signature_size"] > MAX_SIGNATURE_BYTES
    ):
        raise ArtifactSetError(
            "embedded public-key verification has malformed numeric fields"
        )
    if any(value[key] != item for key, item in expected.items()):
        raise ArtifactSetError(
            "embedded public-key verification does not bind the exact updater bytes"
        )
    _require_sha256(value["embedded_public_key_sha256"], "embedded public key digest")
    configuration = _artifact_record(
        repository / "apps/cfw-tauri-shell/tauri.conf.json",
        MAX_TAURI_CONFIGURATION_BYTES,
    )
    if (
        _require_sha256(value["tauri_config_sha256"], "Tauri configuration digest")
        != configuration["sha256"]
    ):
        raise ArtifactSetError(
            "embedded public-key verification does not bind the current Tauri configuration"
        )
    _require_canonical_document(
        path, value, data, "embedded public-key verification"
    )
    return value, data


def _validate_latest(
    path: Path,
    *,
    version: str,
    signature: str,
    official_url: str,
) -> tuple[dict[str, Any], bytes]:
    value, data = _load_strict_json(path, MAX_SMALL_DOCUMENT_BYTES)
    value = _require_exact_keys(
        value,
        {"notes", "platforms", "pub_date", "version"},
        "updater manifest",
    )
    if value["version"] != version:
        raise ArtifactSetError("updater manifest version differs from its release set")
    _require_bounded_text(value["notes"], "updater notes", 16 * 1024)
    _require_utc_timestamp(value["pub_date"], "updater publication date")
    platforms = _require_exact_keys(
        value["platforms"],
        {"darwin-aarch64", "darwin-arm64"},
        "updater platform map",
    )
    for target in ("darwin-aarch64", "darwin-arm64"):
        item = _require_exact_keys(
            platforms[target], {"signature", "url"}, f"updater target {target}"
        )
        if item != {"signature": signature, "url": official_url}:
            raise ArtifactSetError(
                f"updater target {target} does not bind the exact signature and URL"
            )
    return value, data


def _read_updater_signature(path: Path) -> str:
    try:
        signature = read_regular(path, MAX_SIGNATURE_BYTES).decode("utf-8").strip()
    except (PublicationError, UnicodeDecodeError) as error:
        raise ArtifactSetError("updater signature is not bounded UTF-8") from error
    _require_bounded_text(signature, "updater signature", MAX_SIGNATURE_BYTES)
    if any(character.isspace() for character in signature):
        raise ArtifactSetError("updater signature contains embedded whitespace")
    return signature


def _build_updater_seal(
    directory: Path,
    version: str,
    source_identity: dict[str, str],
    sealed_at: str,
    repository: Path,
    release_verifier: dict[str, Any],
    prepackage: dict[str, Any],
) -> dict[str, Any]:
    archive_name, signature_name, latest_name = _updater_names(version)
    archive = directory / archive_name
    signature_path = directory / signature_name
    latest = directory / latest_name
    verification_path = directory / UPDATER_VERIFICATION_NAME
    candidate_app = _candidate_app_binding(
        repository,
        version=version,
        source_identity=source_identity,
    )
    archive_record = _artifact_record(archive, MAX_UPDATER_ARCHIVE_BYTES)
    signature_record = _artifact_record(signature_path, MAX_SIGNATURE_BYTES)
    latest_record = _artifact_record(latest, MAX_SMALL_DOCUMENT_BYTES)
    verification_record = _artifact_record(
        verification_path, MAX_SMALL_DOCUMENT_BYTES
    )
    signature = _read_updater_signature(signature_path)
    official_url = _official_url(version, archive_name)
    _validate_latest(
        latest,
        version=version,
        signature=signature,
        official_url=official_url,
    )
    verification, _ = _validate_updater_verification(
        verification_path,
        archive_record=archive_record,
        signature_record=signature_record,
        repository=repository,
    )
    release_verifier = _validate_release_verifier_binding(
        release_verifier, repository
    )
    packaged_app = read_updater_app_manifest(archive)
    _validate_packaged_app_manifest(
        packaged_app, candidate_app, "updater archive application"
    )
    if _artifact_record(archive, MAX_UPDATER_ARCHIVE_BYTES) != archive_record:
        raise ArtifactSetError("updater archive changed during post-packaging proof")
    if (
        _candidate_app_binding(
            repository,
            version=version,
            source_identity=source_identity,
        )
        != candidate_app
    ):
        raise ArtifactSetError("signed candidate changed during updater sealing")
    return {
        "architecture": "aarch64",
        "artifacts": {
            "archive": archive_record,
            "embedded_public_key_verification": verification_record,
            "manifest": latest_record,
            "signature": signature_record,
        },
        "candidate_app": candidate_app,
        "document": UPDATER_SEAL_DOCUMENT,
        "embedded_public_key_sha256": verification["embedded_public_key_sha256"],
        "official_url": official_url,
        "prepackage": _validate_prepackage_binding(prepackage, repository),
        "product": PRODUCT,
        "release_verifier": release_verifier,
        "repository": _source_identity(source_identity),
        "schema_version": 2,
        "sealed_at": _require_utc_timestamp(sealed_at, "updater seal time"),
        "tauri_config_sha256": verification["tauri_config_sha256"],
        "version": version,
    }


def seal_updater_set(
    staging: Path,
    destination: Path,
    *,
    version: str,
    source_identity: dict[str, str],
    sealed_at: str,
    repository: Path,
    publisher: Publisher = publish_exclusive,
    prepackage_stage_verifier: PrepackageStageVerifier | None = None,
) -> Path:
    """Seal a complete updater group and publish the directory once."""
    version = _require_active_version(version)
    expected_destination = _updater_set_root(repository)
    if destination != expected_destination:
        raise ArtifactSetError("updater destination is not the fixed GA package path")
    if (
        staging.parent != expected_destination.parent
        or not staging.name.startswith("updater-stage.")
        or staging.name == "updater-stage."
    ):
        raise ArtifactSetError("updater staging is not inside the fixed GA package path")
    prepackage = _reopen_prepackage_binding(
        repository, prepackage_stage_verifier
    )
    if os.path.lexists(destination):
        verify_updater_set(
            destination,
            repository=repository,
            version=version,
            expected_source_identity=source_identity,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        _confirm_existing_release_set_durable(
            destination, "updater release set"
        )
        verify_updater_set(
            destination,
            repository=repository,
            version=version,
            expected_source_identity=source_identity,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        return destination
    _require_real_directory(staging, "updater staging directory")
    _reset_updater_generated_documents(staging, version)
    archive_name, signature_name, _latest_name = _updater_names(version)
    archive = staging / archive_name
    signature = staging / signature_name
    archive_before = _artifact_record(archive, MAX_UPDATER_ARCHIVE_BYTES)
    signature_before = _artifact_record(signature, MAX_SIGNATURE_BYTES)
    verification, release_verifier = _produce_updater_verification(
        repository, archive, signature
    )
    if (
        _artifact_record(archive, MAX_UPDATER_ARCHIVE_BYTES) != archive_before
        or _artifact_record(signature, MAX_SIGNATURE_BYTES) != signature_before
    ):
        raise ArtifactSetError(
            "updater archive or signature changed during embedded-key verification"
        )
    _write_canonical_new(staging / UPDATER_VERIFICATION_NAME, verification)
    _validate_updater_verification(
        staging / UPDATER_VERIFICATION_NAME,
        archive_record=archive_before,
        signature_record=signature_before,
        repository=repository,
    )
    seal = _build_updater_seal(
        staging,
        version,
        source_identity,
        sealed_at,
        repository,
        release_verifier,
        prepackage,
    )
    _write_canonical_new(staging / UPDATER_SEAL_NAME, seal)
    verify_updater_set(
        staging,
        repository=repository,
        version=version,
        expected_source_identity=source_identity,
        require_version_directory=False,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )
    _fsync_release_set(staging, "updater release set")
    try:
        publisher(staging, destination)
    except Exception as error:
        if not os.path.lexists(staging) and os.path.lexists(destination):
            try:
                verify_updater_set(
                    destination,
                    repository=repository,
                    version=version,
                    expected_source_identity=source_identity,
                    prepackage_stage_verifier=prepackage_stage_verifier,
                )
                _confirm_release_set_durable(
                    staging, destination, "updater release set"
                )
                verify_updater_set(
                    destination,
                    repository=repository,
                    version=version,
                    expected_source_identity=source_identity,
                    prepackage_stage_verifier=prepackage_stage_verifier,
                )
            except (ArtifactSetError, OSError, ValueError) as recovery_error:
                raise ArtifactSetError(
                    "updater release set exists but its durability is unconfirmed"
                ) from recovery_error
            return destination
        raise ArtifactSetError("cannot atomically publish updater release set") from error
    if os.path.lexists(staging) or not os.path.lexists(destination):
        raise ArtifactSetError("updater publisher returned an ambiguous result")
    _confirm_release_set_durable(staging, destination, "updater release set")
    verify_updater_set(
        destination,
        repository=repository,
        version=version,
        expected_source_identity=source_identity,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )
    return destination


def verify_updater_set(
    directory: Path,
    *,
    repository: Path,
    version: str,
    expected_source_identity: dict[str, str] | None = None,
    require_version_directory: bool = True,
    prepackage_stage_verifier: PrepackageStageVerifier | None = None,
) -> dict[str, Any]:
    version = _require_active_version(version)
    if require_version_directory and directory != _updater_set_root(repository):
        raise ArtifactSetError("updater release set is not at the fixed GA package path")
    if (
        not require_version_directory
        and (
            directory.parent != _updater_set_root(repository).parent
            or not directory.name.startswith("updater-stage.")
            or directory.name == "updater-stage."
        )
    ):
        raise ArtifactSetError("updater staging is not inside the fixed GA package path")
    prepackage = _reopen_prepackage_binding(
        repository, prepackage_stage_verifier
    )
    archive_name, signature_name, latest_name = _updater_names(version)
    expected = {
        archive_name,
        signature_name,
        latest_name,
        UPDATER_VERIFICATION_NAME,
        UPDATER_SEAL_NAME,
    }
    if _inventory(directory) != expected:
        raise ArtifactSetError("updater release set is partial or contains extras")
    seal, seal_data = _load_strict_json(
        directory / UPDATER_SEAL_NAME, MAX_SMALL_DOCUMENT_BYTES
    )
    seal = _require_exact_keys(
        seal,
        {
            "architecture",
            "artifacts",
            "candidate_app",
            "document",
            "embedded_public_key_sha256",
            "official_url",
            "prepackage",
            "product",
            "release_verifier",
            "repository",
            "schema_version",
            "sealed_at",
            "tauri_config_sha256",
            "version",
        },
        "updater release seal",
    )
    _require_canonical_document(
        directory / UPDATER_SEAL_NAME, seal, seal_data, "updater release seal"
    )
    if (
        type(seal["schema_version"]) is not int
        or seal["schema_version"] != 2
        or seal["document"] != UPDATER_SEAL_DOCUMENT
        or seal["product"] != PRODUCT
        or seal["version"] != version
        or seal["architecture"] != "aarch64"
        or seal["official_url"] != _official_url(version, archive_name)
    ):
        raise ArtifactSetError("updater release seal identity is inconsistent")
    if _validate_prepackage_binding(seal["prepackage"], repository) != prepackage:
        raise ArtifactSetError(
            "updater release seal targets a different GA prepackage stage"
        )
    source_identity = _source_identity(seal["repository"])
    if (
        expected_source_identity is not None
        and source_identity != _source_identity(expected_source_identity)
    ):
        raise ArtifactSetError("updater seal differs from the expected source identity")
    _require_utc_timestamp(seal["sealed_at"], "updater seal time")
    _require_sha256(seal["embedded_public_key_sha256"], "embedded public key digest")
    _require_sha256(seal["tauri_config_sha256"], "Tauri configuration digest")
    release_verifier = _validate_release_verifier_binding(
        seal["release_verifier"], repository
    )
    artifacts = _require_exact_keys(
        seal["artifacts"],
        {"archive", "embedded_public_key_verification", "manifest", "signature"},
        "updater sealed artifacts",
    )
    archive_record = _validate_artifact_record(
        artifacts["archive"],
        directory / archive_name,
        MAX_UPDATER_ARCHIVE_BYTES,
        "updater archive",
    )
    signature_record = _validate_artifact_record(
        artifacts["signature"],
        directory / signature_name,
        MAX_SIGNATURE_BYTES,
        "updater signature",
    )
    _validate_artifact_record(
        artifacts["manifest"],
        directory / latest_name,
        MAX_SMALL_DOCUMENT_BYTES,
        "updater manifest",
    )
    _validate_artifact_record(
        artifacts["embedded_public_key_verification"],
        directory / UPDATER_VERIFICATION_NAME,
        MAX_SMALL_DOCUMENT_BYTES,
        "embedded public-key verification evidence",
    )
    signature = _read_updater_signature(directory / signature_name)
    _validate_latest(
        directory / latest_name,
        version=version,
        signature=signature,
        official_url=seal["official_url"],
    )
    verification, _ = _validate_updater_verification(
        directory / UPDATER_VERIFICATION_NAME,
        archive_record=archive_record,
        signature_record=signature_record,
        repository=repository,
    )
    if (
        seal["embedded_public_key_sha256"]
        != verification["embedded_public_key_sha256"]
        or seal["tauri_config_sha256"] != verification["tauri_config_sha256"]
    ):
        raise ArtifactSetError("updater verification evidence differs from its seal")
    fresh_verification, fresh_release_verifier = _produce_updater_verification(
        repository,
        directory / archive_name,
        directory / signature_name,
    )
    if (
        _artifact_record(directory / archive_name, MAX_UPDATER_ARCHIVE_BYTES)
        != archive_record
        or _artifact_record(directory / signature_name, MAX_SIGNATURE_BYTES)
        != signature_record
    ):
        raise ArtifactSetError(
            "updater bytes changed while the embedded-key verifier was replayed"
        )
    if fresh_verification != verification:
        raise ArtifactSetError(
            "fresh embedded-key verification differs from the stored receipt"
        )
    if (
        _validate_release_verifier_binding(fresh_release_verifier, repository)
        != release_verifier
    ):
        raise ArtifactSetError(
            "fresh release verifier build differs from the sealed build binding"
        )
    verification_after, _ = _validate_updater_verification(
        directory / UPDATER_VERIFICATION_NAME,
        archive_record=archive_record,
        signature_record=signature_record,
        repository=repository,
    )
    if verification_after != verification:
        raise ArtifactSetError(
            "stored updater verification changed during verifier replay"
        )
    candidate_app = _validate_candidate_app_binding(
        seal["candidate_app"],
        repository,
        version=version,
        source_identity=source_identity,
    )
    archive_before = _artifact_record(
        directory / archive_name, MAX_UPDATER_ARCHIVE_BYTES
    )
    packaged_app = read_updater_app_manifest(directory / archive_name)
    _validate_packaged_app_manifest(
        packaged_app, candidate_app, "updater archive application"
    )
    if (
        _artifact_record(directory / archive_name, MAX_UPDATER_ARCHIVE_BYTES)
        != archive_before
        or archive_before != archive_record
    ):
        raise ArtifactSetError("updater archive changed during byte-proof verification")
    _validate_candidate_app_binding(
        seal["candidate_app"],
        repository,
        version=version,
        source_identity=source_identity,
    )
    if (
        _validate_release_verifier_binding(seal["release_verifier"], repository)
        != release_verifier
    ):
        raise ArtifactSetError("release verifier build inputs changed during verification")
    if _reopen_prepackage_binding(repository, prepackage_stage_verifier) != prepackage:
        raise ArtifactSetError(
            "GA prepackage stage changed during updater verification"
        )
    return seal


def _dmg_manifest_metadata(
    *,
    version: str,
    build_number: str,
    pre_staple_sha256: str,
    prepackage_manifest_sha256: str,
    source_identity: dict[str, str],
) -> dict[str, str]:
    identity = _source_identity(source_identity)
    return {
        "architecture": "arm64",
        "artifactKind": "notarized-dmg-v2",
        "buildNumber": build_number,
        "preStapleSha256": pre_staple_sha256,
        "prepackageManifestSha256": _require_sha256(
            prepackage_manifest_sha256, "GA prepackage manifest digest"
        ),
        "releaseSourceSha256": identity["release_source_sha256"],
        "repositoryCommit": identity["repository_commit"],
        "teamID": TEAM_ID,
        "version": version,
    }


def _validate_dmg_submission(
    value: object,
    *,
    version: str,
    build_number: str,
    dmg_name: str,
    pre_staple_sha256: str,
) -> dict[str, Any]:
    fields = {
        "acquisition",
        "attempt_id",
        "build_number",
        "document",
        "intent_sha256",
        "notary_created_at",
        "notary_profile",
        "observed_at",
        "pre_staple_dmg_sha256",
        "schema_version",
        "submission_id",
        "submitted_filename",
        "version",
    }
    value = _require_exact_keys(value, fields, "DMG submission receipt")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["document"] != DMG_SUBMISSION_DOCUMENT
        or value["version"] != version
        or value["build_number"] != build_number
        or value["submitted_filename"] != dmg_name
        or value["pre_staple_dmg_sha256"] != pre_staple_sha256
        or value["notary_profile"] != NOTARY_PROFILE
        or value["acquisition"] not in {"submit-no-wait", "explicit-recovery"}
    ):
        raise ArtifactSetError("DMG submission receipt identity is inconsistent")
    _require_uuid(value["attempt_id"], "DMG attempt id")
    _require_uuid(value["submission_id"], "DMG submission id")
    _require_sha256(value["intent_sha256"], "DMG notarization intent digest")
    _require_sha256(value["pre_staple_dmg_sha256"], "pre-staple DMG digest")
    _require_utc_timestamp(value["observed_at"], "DMG submission observation time")
    if value["acquisition"] == "explicit-recovery":
        _require_utc_timestamp(value["notary_created_at"], "Apple submission creation time")
    elif value["notary_created_at"] is not None:
        raise ArtifactSetError("direct DMG submission has an unexpected creation time")
    return value


def _build_dmg_seal(
    directory: Path,
    *,
    repository: Path,
    version: str,
    build_number: str,
    pre_staple_sha256: str,
    prepackage: dict[str, Any],
    source_identity: dict[str, str],
    sealed_at: str,
    packaged_app_manifest_reader: PackagedAppManifestReader,
) -> dict[str, Any]:
    dmg_name, manifest_name, result_name, log_name, gatekeeper_name, submission_name = (
        _dmg_names(version)
    )
    candidate_app = _candidate_app_binding(
        repository,
        version=version,
        source_identity=source_identity,
        expected_build_number=build_number,
    )
    dmg_record = _artifact_record(directory / dmg_name, MAX_DMG_BYTES)
    manifest_record = _artifact_record(
        directory / manifest_name, MAX_SMALL_DOCUMENT_BYTES
    )
    result_record = _artifact_record(directory / result_name, MAX_SMALL_DOCUMENT_BYTES)
    log_record = _artifact_record(directory / log_name, MAX_EVIDENCE_BYTES)
    gatekeeper_record = _artifact_record(
        directory / gatekeeper_name, MAX_EVIDENCE_BYTES
    )
    submission_record = _artifact_record(
        directory / submission_name, MAX_SMALL_DOCUMENT_BYTES
    )
    submission, _ = _load_strict_json(
        directory / submission_name, MAX_SMALL_DOCUMENT_BYTES
    )
    submission = _validate_dmg_submission(
        submission,
        version=version,
        build_number=build_number,
        dmg_name=dmg_name,
        pre_staple_sha256=pre_staple_sha256,
    )
    packaged_app = packaged_app_manifest_reader(directory / dmg_name)
    _validate_packaged_app_manifest(
        packaged_app, candidate_app, "DMG-contained application"
    )
    if _artifact_record(directory / dmg_name, MAX_DMG_BYTES) != dmg_record:
        raise ArtifactSetError("DMG changed during post-packaging byte proof")
    if (
        _candidate_app_binding(
            repository,
            version=version,
            source_identity=source_identity,
            expected_build_number=build_number,
        )
        != candidate_app
    ):
        raise ArtifactSetError("signed candidate changed during DMG sealing")
    return {
        "architecture": "arm64",
        "artifacts": {
            "dmg": dmg_record,
            "gatekeeper": gatekeeper_record,
            "manifest": manifest_record,
            "notarization_log": log_record,
            "notarization_result": result_record,
            "submission_receipt": submission_record,
        },
        "build_number": build_number,
        "candidate_app": candidate_app,
        "document": DMG_SEAL_DOCUMENT,
        "official_url": _official_url(version, dmg_name),
        "pre_staple_dmg_sha256": pre_staple_sha256,
        "prepackage": _validate_prepackage_binding(prepackage, repository),
        "product": PRODUCT,
        "repository": _source_identity(source_identity),
        "schema_version": 2,
        "sealed_at": _require_utc_timestamp(sealed_at, "DMG seal time"),
        "submission_id": submission["submission_id"],
        "version": version,
    }


def seal_dmg_set(
    directory: Path,
    *,
    repository: Path,
    version: str,
    build_number: str,
    pre_staple_sha256: str,
    prepackage: dict[str, Any],
    source_identity: dict[str, str],
    sealed_at: str,
    packaged_app_manifest_reader: PackagedAppManifestReader = read_dmg_app_manifest,
    prepackage_stage_verifier: PrepackageStageVerifier | None = None,
) -> Path:
    """Create or confirm the canonical seal in one private DMG staging set."""
    version = _require_active_version(version)
    build_number = _require_positive_decimal(build_number, "DMG build number")
    if build_number != CANDIDATE_BUILD_NUMBER:
        raise ArtifactSetError("DMG set is not the active GA build")
    if directory != _dmg_transaction_final_set_root(repository):
        raise ArtifactSetError("DMG staging is not the fixed GA transaction final-set")
    pre_staple_sha256 = _require_sha256(
        pre_staple_sha256, "pre-staple DMG digest"
    )
    bound_prepackage = _validate_prepackage_binding(prepackage, repository)
    current_prepackage = _reopen_prepackage_binding(
        repository, prepackage_stage_verifier
    )
    if bound_prepackage != current_prepackage:
        raise ArtifactSetError(
            "DMG transaction targets a different GA prepackage stage"
        )
    dmg_name, manifest_name, result_name, log_name, gatekeeper_name, submission_name = (
        _dmg_names(version)
    )
    allowed_without_seal = {
        dmg_name,
        result_name,
        log_name,
        gatekeeper_name,
        submission_name,
    }
    observed = _inventory(directory)
    if observed == allowed_without_seal:
        metadata = _dmg_manifest_metadata(
            version=version,
            build_number=build_number,
            pre_staple_sha256=pre_staple_sha256,
            prepackage_manifest_sha256=str(
                bound_prepackage["manifest"]["sha256"]
            ),
            source_identity=source_identity,
        )
        manifest = build_manifest(
            directory / dmg_name,
            metadata=metadata,
            algorithm="sha256-tree-v2",
        )
        _write_canonical_new(directory / manifest_name, manifest)
        observed.add(manifest_name)
    expected_before_seal = allowed_without_seal | {manifest_name}
    if observed == expected_before_seal:
        seal = _build_dmg_seal(
            directory,
            repository=repository,
            version=version,
            build_number=build_number,
            pre_staple_sha256=pre_staple_sha256,
            prepackage=bound_prepackage,
            source_identity=source_identity,
            sealed_at=sealed_at,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
        )
        _write_canonical_new(directory / DMG_SEAL_NAME, seal)
    elif observed != expected_before_seal | {DMG_SEAL_NAME}:
        raise ArtifactSetError("DMG staging inventory is partial or contains extras")
    verify_dmg_set(
        directory,
        repository=repository,
        version=version,
        expected_source_identity=source_identity,
        packaged_app_manifest_reader=packaged_app_manifest_reader,
        require_version_directory=False,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )
    return directory / DMG_SEAL_NAME


def verify_dmg_set(
    directory: Path,
    *,
    repository: Path,
    version: str,
    expected_source_identity: dict[str, str] | None = None,
    packaged_app_manifest_reader: PackagedAppManifestReader = read_dmg_app_manifest,
    require_version_directory: bool = True,
    prepackage_stage_verifier: PrepackageStageVerifier | None = None,
) -> dict[str, Any]:
    version = _require_active_version(version)
    if require_version_directory and directory != _dmg_set_root(repository):
        raise ArtifactSetError("DMG release set is not at the fixed GA package path")
    if (
        not require_version_directory
        and directory != _dmg_transaction_final_set_root(repository)
    ):
        raise ArtifactSetError("DMG staging is not the fixed GA transaction final-set")
    prepackage = _reopen_prepackage_binding(
        repository, prepackage_stage_verifier
    )
    dmg_name, manifest_name, result_name, log_name, gatekeeper_name, submission_name = (
        _dmg_names(version)
    )
    expected = {
        dmg_name,
        manifest_name,
        result_name,
        log_name,
        gatekeeper_name,
        submission_name,
        DMG_SEAL_NAME,
    }
    if _inventory(directory) != expected:
        raise ArtifactSetError("DMG release set is partial or contains extras")
    seal, seal_data = _load_strict_json(directory / DMG_SEAL_NAME, MAX_SMALL_DOCUMENT_BYTES)
    seal = _require_exact_keys(
        seal,
        {
            "architecture",
            "artifacts",
            "build_number",
            "candidate_app",
            "document",
            "official_url",
            "pre_staple_dmg_sha256",
            "prepackage",
            "product",
            "repository",
            "schema_version",
            "sealed_at",
            "submission_id",
            "version",
        },
        "DMG release seal",
    )
    _require_canonical_document(
        directory / DMG_SEAL_NAME, seal, seal_data, "DMG release seal"
    )
    if (
        type(seal["schema_version"]) is not int
        or seal["schema_version"] != 2
        or seal["document"] != DMG_SEAL_DOCUMENT
        or seal["product"] != PRODUCT
        or seal["version"] != version
        or seal["architecture"] != "arm64"
        or seal["official_url"] != _official_url(version, dmg_name)
    ):
        raise ArtifactSetError("DMG release seal identity is inconsistent")
    if _validate_prepackage_binding(seal["prepackage"], repository) != prepackage:
        raise ArtifactSetError(
            "DMG release seal targets a different GA prepackage stage"
        )
    build_number = _require_positive_decimal(seal["build_number"], "DMG build number")
    if build_number != CANDIDATE_BUILD_NUMBER:
        raise ArtifactSetError("DMG release set is not the active GA build")
    pre_staple_sha256 = _require_sha256(
        seal["pre_staple_dmg_sha256"], "pre-staple DMG digest"
    )
    source_identity = _source_identity(seal["repository"])
    if (
        expected_source_identity is not None
        and source_identity != _source_identity(expected_source_identity)
    ):
        raise ArtifactSetError("DMG seal differs from the expected source identity")
    _require_utc_timestamp(seal["sealed_at"], "DMG seal time")
    submission_id = _require_uuid(seal["submission_id"], "DMG submission id")
    artifacts = _require_exact_keys(
        seal["artifacts"],
        {
            "dmg",
            "gatekeeper",
            "manifest",
            "notarization_log",
            "notarization_result",
            "submission_receipt",
        },
        "DMG sealed artifacts",
    )
    dmg_record = _validate_artifact_record(
        artifacts["dmg"], directory / dmg_name, MAX_DMG_BYTES, "DMG artifact"
    )
    _validate_artifact_record(
        artifacts["manifest"],
        directory / manifest_name,
        MAX_SMALL_DOCUMENT_BYTES,
        "DMG manifest",
    )
    _validate_artifact_record(
        artifacts["notarization_result"],
        directory / result_name,
        MAX_SMALL_DOCUMENT_BYTES,
        "DMG notarization result",
    )
    _validate_artifact_record(
        artifacts["notarization_log"],
        directory / log_name,
        MAX_EVIDENCE_BYTES,
        "DMG notarization log",
    )
    _validate_artifact_record(
        artifacts["gatekeeper"],
        directory / gatekeeper_name,
        MAX_EVIDENCE_BYTES,
        "DMG Gatekeeper evidence",
    )
    _validate_artifact_record(
        artifacts["submission_receipt"],
        directory / submission_name,
        MAX_SMALL_DOCUMENT_BYTES,
        "DMG submission receipt",
    )
    result, _ = _load_strict_json(directory / result_name, MAX_SMALL_DOCUMENT_BYTES)
    if set(result) != {"id", "status"} or result != {
        "id": submission_id,
        "status": "Accepted",
    }:
        raise ArtifactSetError("DMG notarization result is not the sealed Accepted result")
    log, _ = _load_strict_json(directory / log_name, MAX_EVIDENCE_BYTES)
    try:
        validate_normalized_documents(
            result,
            log,
            archive_filename=dmg_name,
            archive_sha256=pre_staple_sha256,
        )
    except NotaryLogError as error:
        raise ArtifactSetError("DMG notarization log is not bound to the submitted DMG") from error
    submission, _ = _load_strict_json(directory / submission_name, MAX_SMALL_DOCUMENT_BYTES)
    submission = _validate_dmg_submission(
        submission,
        version=version,
        build_number=build_number,
        dmg_name=dmg_name,
        pre_staple_sha256=pre_staple_sha256,
    )
    if submission["submission_id"] != submission_id:
        raise ArtifactSetError("DMG submission receipt differs from its release seal")
    gatekeeper, _ = _load_strict_json(directory / gatekeeper_name, MAX_EVIDENCE_BYTES)
    try:
        gatekeeper = validate_gatekeeper_evidence(
            gatekeeper,
            expected_assessment_type="open",
            expected_primary_signature_context=True,
        )
    except (GatekeeperEvidenceError, ValueError) as error:
        raise ArtifactSetError("DMG Gatekeeper evidence is invalid") from error
    if gatekeeper["target_signed_app_tree_sha256"] != dmg_record["sha256"]:
        raise ArtifactSetError("DMG Gatekeeper evidence targets different final bytes")
    manifest, manifest_data = _load_strict_json(
        directory / manifest_name, MAX_SMALL_DOCUMENT_BYTES
    )
    expected_manifest = build_manifest(
        directory / dmg_name,
        metadata=_dmg_manifest_metadata(
            version=version,
            build_number=build_number,
            pre_staple_sha256=pre_staple_sha256,
            prepackage_manifest_sha256=str(prepackage["manifest"]["sha256"]),
            source_identity=source_identity,
        ),
        algorithm="sha256-tree-v2",
    )
    if manifest != expected_manifest:
        raise ArtifactSetError("DMG artifact manifest differs from the final DMG")
    _require_canonical_document(
        directory / manifest_name, manifest, manifest_data, "DMG artifact manifest"
    )
    candidate_app = _validate_candidate_app_binding(
        seal["candidate_app"],
        repository,
        version=version,
        source_identity=source_identity,
        expected_build_number=build_number,
    )
    dmg_before = _artifact_record(directory / dmg_name, MAX_DMG_BYTES)
    packaged_app = packaged_app_manifest_reader(directory / dmg_name)
    _validate_packaged_app_manifest(
        packaged_app, candidate_app, "DMG-contained application"
    )
    if (
        _artifact_record(directory / dmg_name, MAX_DMG_BYTES) != dmg_before
        or dmg_before != dmg_record
    ):
        raise ArtifactSetError("DMG changed during byte-proof verification")
    _validate_candidate_app_binding(
        seal["candidate_app"],
        repository,
        version=version,
        source_identity=source_identity,
        expected_build_number=build_number,
    )
    if _reopen_prepackage_binding(repository, prepackage_stage_verifier) != prepackage:
        raise ArtifactSetError("GA prepackage stage changed during DMG verification")
    return seal


def _publication_bundle_name(version: str) -> str:
    return f"Clash.for.Mac_{version}_publication.tar.gz"


def _publication_bundle_root(version: str) -> str:
    return f"Clash.for.Mac_{version}_publication"


def _gatekeeper_public_projection_name(version: str) -> str:
    return f"Clash.for.Mac_{version}_arm64.gatekeeper.public.json"


def _private_gatekeeper_material(
    package_root: Path, version: str
) -> tuple[dict[str, Any], bytes, Path, tuple[bytes, ...]]:
    dmg_directory = package_root / "dmg" / f"v{version}"
    dmg_name, _manifest, _result, _log, gatekeeper_name, _submission = (
        _dmg_names(version)
    )
    private_path = dmg_directory / gatekeeper_name
    private_record_before = _artifact_record(private_path, MAX_EVIDENCE_BYTES)
    private_evidence, private_bytes = _load_strict_json(
        private_path, MAX_EVIDENCE_BYTES
    )
    try:
        private_evidence = validate_gatekeeper_evidence(
            private_evidence,
            expected_assessment_type="open",
            expected_primary_signature_context=True,
        )
    except (GatekeeperEvidenceError, ValueError) as error:
        raise ArtifactSetError("private DMG Gatekeeper evidence is invalid") from error
    assessed_target = Path(private_evidence["assessed_target"])
    final_dmg_record = _artifact_record(dmg_directory / dmg_name, MAX_DMG_BYTES)
    if (
        private_evidence["target_identity_algorithm"] != "sha256-file"
        or private_evidence["target_signed_app_tree_sha256"]
        != final_dmg_record["sha256"]
    ):
        raise ArtifactSetError(
            "private Gatekeeper evidence targets different final DMG bytes"
        )
    private_record_after = _artifact_record(private_path, MAX_EVIDENCE_BYTES)
    if (
        private_record_after != private_record_before
        or hashlib.sha256(private_bytes).hexdigest()
        != private_record_before["sha256"]
    ):
        raise ArtifactSetError(
            "private Gatekeeper evidence changed while preparing its public projection"
        )
    assessed_target_text = str(assessed_target)
    encoded_target = json.dumps(
        assessed_target_text, ensure_ascii=True, separators=(",", ":")
    )[1:-1].encode("utf-8")
    forbidden_paths = tuple(
        sorted({assessed_target_text.encode("utf-8"), encoded_target})
    )
    return (
        private_evidence,
        private_bytes,
        assessed_target,
        forbidden_paths,
    )


def _reject_gatekeeper_path_leak(
    data: bytes, forbidden_paths: tuple[bytes, ...], label: str
) -> None:
    if any(path in data for path in forbidden_paths):
        raise ArtifactSetError(f"{label} leaks a private Gatekeeper target path")


def _contains_private_release_marker(value: object) -> bool:
    if isinstance(value, dict):
        if value.get("visibility") in PRIVATE_PUBLICATION_VISIBILITIES:
            return True
        return any(_contains_private_release_marker(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_private_release_marker(child) for child in value)
    return isinstance(value, str) and value in PRIVATE_PUBLICATION_SOURCE_IDS


def _reject_private_public_source(data: bytes, path: Path) -> None:
    if path.name in PRIVATE_PUBLICATION_FILENAMES:
        raise ArtifactSetError(
            f"private evidence filename is forbidden from public sources: {path.name}"
        )
    if path.suffix.casefold() != ".json":
        return
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateFieldError,
    ) as error:
        raise ArtifactSetError(
            f"public JSON source is not strict JSON: {path.name}"
        ) from error
    if _contains_private_release_marker(value):
        raise ArtifactSetError(
            f"private release evidence is forbidden from public sources: {path.name}"
        )


def _validate_gatekeeper_public_projection(
    directory: Path, package_root: Path, version: str
) -> tuple[dict[str, Any], tuple[bytes, ...]]:
    projection_path = directory / _gatekeeper_public_projection_name(version)
    projection, projection_bytes = _load_strict_json(
        projection_path, MAX_SMALL_DOCUMENT_BYTES
    )
    _require_canonical_document(
        projection_path,
        projection,
        projection_bytes,
        "public Gatekeeper projection",
    )
    private_evidence, private_bytes, assessed_target, forbidden_paths = (
        _private_gatekeeper_material(package_root, version)
    )
    try:
        projection = validate_gatekeeper_public_projection(
            projection,
            private_evidence,
            private_bytes,
            assessed_target,
            expected_assessment_type="open",
            expected_primary_signature_context=True,
        )
    except (GatekeeperEvidenceError, ValueError) as error:
        raise ArtifactSetError(
            "public Gatekeeper projection is not bound to its private evidence"
        ) from error
    _reject_gatekeeper_path_leak(
        projection_bytes, forbidden_paths, "public Gatekeeper projection"
    )
    return projection, forbidden_paths


def _write_gatekeeper_public_projection(
    directory: Path, package_root: Path, version: str
) -> tuple[Path, tuple[bytes, ...]]:
    private_evidence, private_bytes, assessed_target, forbidden_paths = (
        _private_gatekeeper_material(package_root, version)
    )
    try:
        projection = build_gatekeeper_public_projection(
            private_evidence,
            private_bytes,
            assessed_target,
            expected_assessment_type="open",
            expected_primary_signature_context=True,
        )
    except (GatekeeperEvidenceError, ValueError) as error:
        raise ArtifactSetError(
            "cannot derive public Gatekeeper projection from real target evidence"
        ) from error
    path = directory / _gatekeeper_public_projection_name(version)
    _write_canonical_new(path, projection)
    written, written_bytes = _load_strict_json(path, MAX_SMALL_DOCUMENT_BYTES)
    _require_canonical_document(
        path, written, written_bytes, "public Gatekeeper projection"
    )
    if written != projection:
        raise ArtifactSetError(
            "public Gatekeeper projection changed while it was written"
        )
    _reject_gatekeeper_path_leak(
        written_bytes, forbidden_paths, "public Gatekeeper projection"
    )
    return path, forbidden_paths


def _admit_publication_source_archive(path: Path) -> None:
    if not os.path.lexists(path):
        raise ArtifactSetError(
            "public publication evidence omits CCS, SBOM, or manifest inputs"
        )
    try:
        stream, opened = open_regular(path)
    except PublicationError as error:
        raise ArtifactSetError(
            "corresponding-source archive is not a single-link regular file"
        ) from error
    with stream:
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size <= 0
            or opened.st_size > MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES
        ):
            raise ArtifactSetError(
                "corresponding-source archive size is outside "
                f"1..={MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES}"
            )


def _assert_public_source_inventory(
    sources: dict[str, tuple[str, Path, int]],
    *,
    package_root: Path,
    distribution_directory: Path,
    version: str,
    forbidden_paths: tuple[bytes, ...],
) -> None:
    root = _publication_bundle_root(version)
    public_name = _gatekeeper_public_projection_name(version)
    public_bundle_path = f"{root}/verification/{public_name}"
    public_source = distribution_directory / public_name
    expected_public_source_path = (
        f"{GA_PACKAGE_RELATIVE}/distribution/v{version}/{public_name}"
    )
    if sources.get(public_bundle_path) != (
        expected_public_source_path,
        public_source,
        MAX_SMALL_DOCUMENT_BYTES,
    ):
        raise ArtifactSetError(
            "public release bundle omits its canonical Gatekeeper projection"
        )
    private_gatekeeper = (
        package_root / "dmg" / f"v{version}" / _dmg_names(version)[4]
    )
    for source_path, path, maximum in sources.values():
        if path == private_gatekeeper or source_path.endswith(
            f"/{private_gatekeeper.name}"
        ):
            raise ArtifactSetError(
                "private Gatekeeper evidence is forbidden from public sources"
            )
        if path.name == "corresponding-source.tar.gz":
            continue
        try:
            source_bytes = read_regular(path, maximum)
        except PublicationError as error:
            raise ArtifactSetError(
                f"cannot inspect public release source: {path.name}"
            ) from error
        _reject_gatekeeper_path_leak(
            source_bytes, forbidden_paths, f"public release source {path.name}"
        )
        _reject_private_public_source(source_bytes, path)


def _publication_bundle_sources(
    repository: Path,
    package_root: Path,
    distribution_directory: Path,
    version: str,
    *,
    forbidden_paths: tuple[bytes, ...] | None = None,
) -> dict[str, tuple[str, Path, int]]:
    root = _publication_bundle_root(version)
    publication = _raw_publication_root(repository)
    source_archive = publication / "corresponding-source.tar.gz"
    _admit_publication_source_archive(source_archive)
    if forbidden_paths is None:
        _projection, forbidden_paths = _validate_gatekeeper_public_projection(
            distribution_directory, package_root, version
        )
    public_name = _gatekeeper_public_projection_name(version)
    fixed = {
        f"{root}/LICENSE": ("LICENSE", repository / "LICENSE", MAX_SMALL_DOCUMENT_BYTES),
        f"{root}/MODIFICATIONS.md": (
            "CHANGELOG.md",
            repository / "CHANGELOG.md",
            MAX_PUBLICATION_DOCUMENT_BYTES,
        ),
        f"{root}/verification/{public_name}": (
            f"{GA_PACKAGE_RELATIVE}/distribution/v{version}/{public_name}",
            distribution_directory / public_name,
            MAX_SMALL_DOCUMENT_BYTES,
        ),
    }
    try:
        publication_entries = enumerate_tree(publication)
    except PublicationError as error:
        raise ArtifactSetError("cannot enumerate public publication evidence") from error
    publication_files = [
        entry for entry in publication_entries if entry["type"] == "file"
    ]
    observed = {str(entry["path"]) for entry in publication_files}
    required = {
        "corresponding-source.manifest.json",
        "corresponding-source.tar.gz",
        "evidence-manifest.json",
        "inventory.json",
        "machine-closure.json",
        "sbom.cyclonedx.json",
        "sbom.spdx.json",
    }
    if not required.issubset(observed):
        raise ArtifactSetError(
            "public publication evidence omits CCS, SBOM, or manifest inputs"
        )
    if not any(path.startswith("licenses/") for path in observed):
        raise ArtifactSetError("public publication evidence omits license/NOTICE inputs")
    if len(publication_files) > MAX_PUBLICATION_BUNDLE_FILES:
        raise ArtifactSetError("public publication evidence file count exceeds its bound")
    for entry in publication_files:
        relative = str(entry["path"])
        if relative == "legal-review.json":
            continue
        bundle_path = f"{root}/publication/{relative}"
        source_relative = (
            f"{GA_CANDIDATE_RELATIVE}/stage-inputs/publication/{relative}"
        )
        if bundle_path in fixed:
            raise ArtifactSetError("public release bundle contains a path collision")
        fixed[bundle_path] = (
            source_relative,
            publication.joinpath(*PurePosixPath(relative).parts),
            (
                MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES
                if relative == "corresponding-source.tar.gz"
                else MAX_PUBLICATION_PUBLIC_FILE_BYTES
            ),
        )
    if len(fixed) > MAX_PUBLICATION_BUNDLE_FILES:
        raise ArtifactSetError("public release bundle file count exceeds its bound")
    _assert_public_source_inventory(
        fixed,
        package_root=package_root,
        distribution_directory=distribution_directory,
        version=version,
        forbidden_paths=forbidden_paths,
    )
    return fixed


def _build_publication_bundle_manifest(
    repository: Path,
    package_root: Path,
    distribution_directory: Path,
    version: str,
    *,
    forbidden_paths: tuple[bytes, ...] | None = None,
) -> tuple[dict[str, Any], dict[str, tuple[str, Path, int]]]:
    sources = _publication_bundle_sources(
        repository,
        package_root,
        distribution_directory,
        version,
        forbidden_paths=forbidden_paths,
    )
    entries: list[dict[str, object]] = []
    auxiliary_bytes = 0
    source_archive_path = (
        f"{_publication_bundle_root(version)}/publication/"
        "corresponding-source.tar.gz"
    )
    for bundle_path, (source_path, path, maximum) in sorted(sources.items()):
        record = _artifact_record(path, maximum)
        if bundle_path != source_archive_path:
            auxiliary_bytes += int(record["size"])
            if auxiliary_bytes > MAX_PUBLICATION_BUNDLE_AUXILIARY_BYTES:
                raise ArtifactSetError(
                    "public release bundle auxiliary bytes exceed their bound"
                )
        entries.append(
            {
                "bundle_path": bundle_path,
                "sha256": record["sha256"],
                "size": record["size"],
                "source_path": source_path,
            }
        )
    manifest = {
        "document": "cfw-publication-upload-bundle-manifest-v1",
        "entries": entries,
        "excluded_private_documents": [
            f"{GA_PACKAGE_RELATIVE}/dmg/v{version}/"
            f"{_dmg_names(version)[4]}",
            f"{GA_CANDIDATE_RELATIVE}/stage-inputs/publication/legal-review.json",
        ],
        "product": PRODUCT,
        "root": _publication_bundle_root(version),
        "schema_version": 1,
        "version": version,
    }
    return manifest, sources


def _tar_info(name: str, *, directory: bool, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = 0o755 if directory else 0o644
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.size = 0 if directory else size
    return info


def _write_publication_bundle(
    directory: Path,
    repository: Path,
    package_root: Path,
    version: str,
    *,
    forbidden_paths: tuple[bytes, ...] | None = None,
) -> tuple[Path, Path]:
    if forbidden_paths is None:
        _projection, forbidden_paths = _validate_gatekeeper_public_projection(
            directory, package_root, version
        )
    manifest, sources = _build_publication_bundle_manifest(
        repository,
        package_root,
        directory,
        version,
        forbidden_paths=forbidden_paths,
    )
    manifest_path = directory / PUBLICATION_BUNDLE_MANIFEST_NAME
    _write_canonical_new(manifest_path, manifest)
    manifest_bytes = canonical_json(manifest)
    root = _publication_bundle_root(version)
    manifest_bundle_path = f"{root}/PUBLICATION-MANIFEST.json"
    file_names = {manifest_bundle_path, *sources}
    directories: set[str] = set()
    for name in file_names:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(parent.as_posix())
            parent = parent.parent
    if len(directories) + len(file_names) > MAX_PUBLICATION_BUNDLE_ENTRIES:
        raise ArtifactSetError("public release bundle entry count exceeds its bound")
    archive_path = directory / _publication_bundle_name(version)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(archive_path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            descriptor = -1
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    for name in sorted(directories):
                        archive.addfile(_tar_info(name, directory=True))
                    archive.addfile(
                        _tar_info(
                            manifest_bundle_path,
                            directory=False,
                            size=len(manifest_bytes),
                        ),
                        io.BytesIO(manifest_bytes),
                    )
                    for bundle_path, (_source_path, source, maximum) in sorted(
                        sources.items()
                    ):
                        record = _artifact_record(source, maximum)
                        stream, opened = open_regular(source)
                        with stream:
                            archive.addfile(
                                _tar_info(
                                    bundle_path,
                                    directory=False,
                                    size=int(record["size"]),
                                ),
                                stream,
                            )
                            after = os.fstat(stream.fileno())
                        if (
                            opened.st_size != record["size"]
                            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                            != (
                                after.st_dev,
                                after.st_ino,
                                after.st_size,
                                after.st_mtime_ns,
                            )
                        ):
                            raise ArtifactSetError(
                                "public release source changed while bundling"
                            )
            raw.flush()
            os.fsync(raw.fileno())
    except BaseException:
        archive_path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        _build_publication_bundle_manifest(
            repository,
            package_root,
            directory,
            version,
            forbidden_paths=forbidden_paths,
        )[0]
        != manifest
    ):
        raise ArtifactSetError("public release inputs changed while bundling")
    _validate_publication_bundle(
        directory, repository=repository, package_root=package_root, version=version
    )
    return archive_path, manifest_path


def _validate_publication_bundle(
    directory: Path,
    *,
    repository: Path,
    package_root: Path,
    version: str,
) -> tuple[dict[str, object], dict[str, object], tuple[bytes, ...]]:
    _projection, forbidden_paths = _validate_gatekeeper_public_projection(
        directory, package_root, version
    )
    archive_path = directory / _publication_bundle_name(version)
    manifest_path = directory / PUBLICATION_BUNDLE_MANIFEST_NAME
    archive_record_before = _artifact_record(
        archive_path, MAX_PUBLICATION_BUNDLE_BYTES
    )
    manifest_record_before = _artifact_record(
        manifest_path, MAX_PUBLICATION_DOCUMENT_BYTES
    )
    try:
        validate_strict_tar_gzip_stream(
            str(archive_path),
            maximum_stream=MAX_GITHUB_RELEASE_ASSET_BYTES_EXCLUSIVE,
            maximum_entries=MAX_PUBLICATION_BUNDLE_RAW_ENTRIES,
            maximum_total_extension_bytes=MAX_PUBLICATION_BUNDLE_EXTENSION_BYTES,
        )
    except (ArchiveContractError, OSError, tarfile.TarError) as error:
        raise ArtifactSetError(
            "public release bundle has an invalid gzip/tar termination boundary"
        ) from error
    manifest, manifest_data = _load_strict_json(
        manifest_path, MAX_PUBLICATION_DOCUMENT_BYTES
    )
    _reject_gatekeeper_path_leak(
        manifest_data, forbidden_paths, "public release bundle manifest"
    )
    expected_manifest, _sources = _build_publication_bundle_manifest(
        repository,
        package_root,
        directory,
        version,
        forbidden_paths=forbidden_paths,
    )
    if manifest != expected_manifest or manifest_data != canonical_json(manifest):
        raise ArtifactSetError(
            "public release bundle manifest differs from its required inputs"
        )
    expected_files = {
        str(entry["bundle_path"]): {
            "sha256": entry["sha256"],
            "size": entry["size"],
        }
        for entry in manifest["entries"]
    }
    root = _publication_bundle_root(version)
    expected_files[f"{root}/PUBLICATION-MANIFEST.json"] = {
        "sha256": hashlib.sha256(manifest_data).hexdigest(),
        "size": len(manifest_data),
    }
    expected_directories: set[str] = set()
    for name in expected_files:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    seen_files: set[str] = set()
    seen_directories: set[str] = set()
    stream, opened = open_regular(archive_path)
    if opened.st_size != archive_record_before["size"]:
        stream.close()
        raise ArtifactSetError("public release bundle size changed while opening")
    try:
        with stream, tarfile.open(fileobj=stream, mode="r|gz") as archive:
            member_count = 0
            for member in archive:
                member_count += 1
                if member_count > MAX_PUBLICATION_BUNDLE_ENTRIES:
                    raise ArtifactSetError(
                        "public release bundle contains too many entries"
                    )
                if member.pax_headers and set(member.pax_headers) != {"path"}:
                    raise ArtifactSetError(
                        "public release bundle has unexpected extended metadata"
                    )
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                ):
                    raise ArtifactSetError(
                        "public release bundle metadata is not deterministic"
                    )
                if member.isdir():
                    if (
                        member.name not in expected_directories
                        or member.name in seen_directories
                        or member.mode != 0o755
                        or member.size != 0
                    ):
                        raise ArtifactSetError(
                            "public release bundle directory inventory differs"
                        )
                    seen_directories.add(member.name)
                    continue
                expected = expected_files.get(member.name)
                if (
                    not member.isreg()
                    or expected is None
                    or member.name in seen_files
                    or member.mode != 0o644
                    or member.size != expected["size"]
                ):
                    raise ArtifactSetError(
                        "public release bundle file inventory differs"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ArtifactSetError("public release bundle file is unreadable")
                digest = hashlib.sha256()
                remaining = member.size
                leak_tail = b""
                maximum_forbidden_length = max(map(len, forbidden_paths))
                while remaining:
                    chunk = extracted.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ArtifactSetError("public release bundle file is truncated")
                    remaining -= len(chunk)
                    digest.update(chunk)
                    leak_window = leak_tail + chunk
                    _reject_gatekeeper_path_leak(
                        leak_window,
                        forbidden_paths,
                        f"public release bundle member {member.name}",
                    )
                    leak_tail = leak_window[-(maximum_forbidden_length - 1) :]
                if extracted.read(1) or digest.hexdigest() != expected["sha256"]:
                    raise ArtifactSetError(
                        "public release bundle file differs from its manifest"
                    )
                seen_files.add(member.name)
    except (OSError, tarfile.TarError) as error:
        raise ArtifactSetError("public release bundle cannot be parsed") from error
    if seen_files != set(expected_files) or seen_directories != expected_directories:
        raise ArtifactSetError("public release bundle is partial or contains extras")
    archive_record_after = _artifact_record(
        archive_path, MAX_PUBLICATION_BUNDLE_BYTES
    )
    manifest_record_after = _artifact_record(
        manifest_path, MAX_PUBLICATION_DOCUMENT_BYTES
    )
    if (
        archive_record_after != archive_record_before
        or manifest_record_after != manifest_record_before
        or _build_publication_bundle_manifest(
            repository,
            package_root,
            directory,
            version,
            forbidden_paths=forbidden_paths,
        )[0]
        != manifest
    ):
        raise ArtifactSetError("public release bundle changed during verification")
    return archive_record_after, manifest_record_after, forbidden_paths


def _release_asset_paths(
    package_root: Path,
    version: str,
    *,
    distribution_directory: Path | None = None,
) -> dict[str, tuple[Path, int]]:
    updater = package_root / "updater" / f"v{version}"
    dmg = package_root / "dmg" / f"v{version}"
    archive_name, signature_name, latest_name = _updater_names(version)
    (
        dmg_name,
        dmg_manifest_name,
        result_name,
        log_name,
        _gatekeeper_name,
        submission_name,
    ) = _dmg_names(version)
    assets = {
        "dmg": (dmg / dmg_name, MAX_DMG_BYTES),
        "dmg_manifest": (dmg / dmg_manifest_name, MAX_SMALL_DOCUMENT_BYTES),
        "dmg_notarization_log": (dmg / log_name, MAX_EVIDENCE_BYTES),
        "dmg_notarization_result": (
            dmg / result_name,
            MAX_SMALL_DOCUMENT_BYTES,
        ),
        "dmg_submission_receipt": (
            dmg / submission_name,
            MAX_SMALL_DOCUMENT_BYTES,
        ),
        "updater_archive": (
            updater / archive_name,
            MAX_UPDATER_ARCHIVE_BYTES,
        ),
        "updater_embedded_public_key_verification": (
            updater / UPDATER_VERIFICATION_NAME,
            MAX_SMALL_DOCUMENT_BYTES,
        ),
        "updater_manifest": (updater / latest_name, MAX_SMALL_DOCUMENT_BYTES),
        "updater_signature": (updater / signature_name, MAX_SIGNATURE_BYTES),
    }
    if distribution_directory is not None:
        assets.update(
            {
                "publication_bundle": (
                    distribution_directory / _publication_bundle_name(version),
                    MAX_PUBLICATION_BUNDLE_BYTES,
                ),
                "publication_bundle_manifest": (
                    distribution_directory / PUBLICATION_BUNDLE_MANIFEST_NAME,
                    MAX_PUBLICATION_DOCUMENT_BYTES,
                ),
                "dmg_gatekeeper_public_projection": (
                    distribution_directory
                    / _gatekeeper_public_projection_name(version),
                    MAX_SMALL_DOCUMENT_BYTES,
                ),
            }
        )
    return assets


def _publication_binding(
    repository: Path,
    stage_verifier: PublicationStageVerifier | None,
) -> dict[str, Any]:
    if stage_verifier is None:
        raise ArtifactSetError("fixed GA publication stage verifier is unavailable")
    publication = _raw_publication_root(repository)
    _require_real_directory(publication, "raw GA publication evidence directory")
    bound_documents = {
        "corresponding_source_manifest": "corresponding-source.manifest.json",
        "cyclonedx_sbom": "sbom.cyclonedx.json",
        "evidence_manifest": "evidence-manifest.json",
        "inventory": "inventory.json",
        "legal_review": "legal-review.json",
        "machine_closure": "machine-closure.json",
        "spdx_sbom": "sbom.spdx.json",
    }
    try:
        before = enumerate_tree(publication)
    except PublicationError as error:
        raise ArtifactSetError("cannot enumerate publication evidence") from error
    artifacts = {
        key: _artifact_record(
            publication / filename, MAX_PUBLICATION_DOCUMENT_BYTES
        )
        for key, filename in bound_documents.items()
    }
    stage_authorization = stage_verifier(repository)
    try:
        after = enumerate_tree(publication)
    except PublicationError as error:
        raise ArtifactSetError("cannot re-enumerate publication evidence") from error
    if after != before:
        raise ArtifactSetError("publication evidence changed while sealing")
    return {
        "artifacts": artifacts,
        "entry_count": len(after),
        "path": str(publication.relative_to(repository)),
        "stage_authorization": stage_authorization,
        "tree_algorithm": "sha256-inventory-v1",
        "tree_sha256": tree_digest(after),
    }


def _authorized_publication_binding(
    repository: Path,
    verifier: PublicationSemanticVerifier,
    stage_verifier: PublicationStageVerifier,
) -> dict[str, Any]:
    before = _publication_binding(repository, stage_verifier)
    app, _manifest = _candidate_app_paths(repository)
    verifier(repository, _raw_publication_root(repository), app)
    after = _publication_binding(repository, stage_verifier)
    if after != before:
        raise ArtifactSetError(
            "publication evidence changed across semantic authorization"
        )
    return after


def _validate_publication_binding(
    value: object,
    repository: Path,
    verifier: PublicationSemanticVerifier,
    stage_verifier: PublicationStageVerifier,
) -> dict[str, Any]:
    value = _require_exact_keys(
        value,
        {
            "artifacts",
            "entry_count",
            "path",
            "stage_authorization",
            "tree_algorithm",
            "tree_sha256",
        },
        "publication closure binding",
    )
    if (
        value["path"]
        != str(_raw_publication_root(repository).relative_to(repository))
        or value["tree_algorithm"] != "sha256-inventory-v1"
        or not isinstance(value["entry_count"], int)
        or isinstance(value["entry_count"], bool)
        or value["entry_count"] <= 0
    ):
        raise ArtifactSetError("publication closure binding identity is inconsistent")
    stage_authorization = _require_exact_keys(
        value["stage_authorization"],
        {
            "legal_source",
            "prepackage_manifest",
            "prepackage_manifest_path",
            "publication_manifest",
            "publication_manifest_path",
        },
        "GA publication stage authorization",
    )
    if (
        stage_authorization["prepackage_manifest_path"]
        != str(
            (_ga_candidate_root(repository) / "prepackage/manifest.json").relative_to(
                repository
            )
        )
        or stage_authorization["publication_manifest_path"]
        != str(
            (_sealed_publication_root(repository) / "manifest.json").relative_to(
                repository
            )
        )
    ):
        raise ArtifactSetError("GA publication stage paths are inconsistent")
    _require_sha256(value["tree_sha256"], "publication evidence tree digest")
    actual = _authorized_publication_binding(
        repository, verifier, stage_verifier
    )
    if value != actual:
        raise ArtifactSetError(
            "publication evidence, CCS, SBOM, or legal closure differs from its seal"
        )
    return actual


def _build_distribution_seal(
    repository: Path,
    distribution_directory: Path,
    *,
    version: str,
    source_identity: dict[str, str],
    sealed_at: str,
    packaged_app_manifest_reader: PackagedAppManifestReader,
    publication_semantic_verifier: PublicationSemanticVerifier,
    publication_stage_verifier: PublicationStageVerifier,
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> dict[str, Any]:
    package_root = _package_root(repository)
    source = _source_identity(source_identity)
    updater_directory = _updater_set_root(repository)
    dmg_directory = _dmg_set_root(repository)
    updater = verify_updater_set(
        updater_directory,
        repository=repository,
        version=version,
        expected_source_identity=source,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )
    dmg = verify_dmg_set(
        dmg_directory,
        repository=repository,
        version=version,
        expected_source_identity=source,
        packaged_app_manifest_reader=packaged_app_manifest_reader,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )
    if updater["candidate_app"] != dmg["candidate_app"]:
        raise ArtifactSetError("DMG and updater sets bind different signed applications")
    if updater["prepackage"] != dmg["prepackage"]:
        raise ArtifactSetError("DMG and updater sets bind different prepackage stages")
    candidate_app = _validate_candidate_app_binding(
        updater["candidate_app"],
        repository,
        version=version,
        source_identity=source,
        expected_build_number=dmg["build_number"],
    )
    release_assets = {
        key: _artifact_record(path, maximum)
        for key, (path, maximum) in _release_asset_paths(
            package_root,
            version,
            distribution_directory=distribution_directory,
        ).items()
    }
    set_seals = {
        "dmg": _artifact_record(
            dmg_directory / DMG_SEAL_NAME, MAX_SMALL_DOCUMENT_BYTES
        ),
        "updater": _artifact_record(
            updater_directory / UPDATER_SEAL_NAME, MAX_SMALL_DOCUMENT_BYTES
        ),
    }
    publication = _authorized_publication_binding(
        repository,
        publication_semantic_verifier,
        publication_stage_verifier,
    )
    return {
        "build_number": candidate_app["build_number"],
        "candidate_app": candidate_app,
        "document": DISTRIBUTION_SEAL_DOCUMENT,
        "product": PRODUCT,
        "publication_closure": publication,
        "release_assets": release_assets,
        "repository": source,
        "schema_version": 1,
        "sealed_at": _require_utc_timestamp(
            sealed_at, "distribution seal time"
        ),
        "set_seals": set_seals,
        "version": version,
    }


def verify_distribution_set(
    directory: Path,
    *,
    repository: Path,
    version: str,
    expected_source_identity: dict[str, str] | None = None,
    packaged_app_manifest_reader: PackagedAppManifestReader = read_dmg_app_manifest,
    publication_semantic_verifier: PublicationSemanticVerifier = verify_publication_semantics,
    publication_stage_verifier: PublicationStageVerifier | None = None,
    prepackage_stage_verifier: PrepackageStageVerifier | None = None,
    require_version_directory: bool = True,
) -> dict[str, Any]:
    version = _require_active_version(version)
    package_root = _package_root(repository)
    if require_version_directory and directory != _distribution_set_root(repository):
        raise ArtifactSetError("distribution set is not at the fixed GA package path")
    if (
        not require_version_directory
        and (
            directory.parent != _distribution_set_root(repository).parent
            or not directory.name.startswith("distribution-stage.")
            or directory.name == "distribution-stage."
        )
    ):
        raise ArtifactSetError("distribution staging is not inside the fixed GA package path")
    if _inventory(directory) != {
        DISTRIBUTION_SEAL_NAME,
        PUBLICATION_BUNDLE_MANIFEST_NAME,
        _gatekeeper_public_projection_name(version),
        _publication_bundle_name(version),
    }:
        raise ArtifactSetError("distribution set is partial or contains extras")
    seal_path = directory / DISTRIBUTION_SEAL_NAME
    seal_record_before = _artifact_record(seal_path, MAX_SMALL_DOCUMENT_BYTES)
    seal, seal_data = _load_strict_json(seal_path, MAX_SMALL_DOCUMENT_BYTES)
    seal = _require_exact_keys(
        seal,
        {
            "build_number",
            "candidate_app",
            "document",
            "product",
            "publication_closure",
            "release_assets",
            "repository",
            "schema_version",
            "sealed_at",
            "set_seals",
            "version",
        },
        "distribution release seal",
    )
    _require_canonical_document(
        seal_path, seal, seal_data, "distribution release seal"
    )
    if (
        type(seal["schema_version"]) is not int
        or seal["schema_version"] != 1
        or seal["document"] != DISTRIBUTION_SEAL_DOCUMENT
        or seal["product"] != PRODUCT
        or seal["version"] != version
    ):
        raise ArtifactSetError("distribution release seal identity is inconsistent")
    source = _source_identity(seal["repository"])
    if (
        expected_source_identity is not None
        and source != _source_identity(expected_source_identity)
    ):
        raise ArtifactSetError(
            "distribution seal differs from the expected source identity"
        )
    build_number = _require_positive_decimal(
        seal["build_number"], "distribution build number"
    )
    if build_number != CANDIDATE_BUILD_NUMBER:
        raise ArtifactSetError("distribution set is not the active GA build")
    _require_utc_timestamp(seal["sealed_at"], "distribution seal time")
    _archive_record, _manifest_record, forbidden_paths = _validate_publication_bundle(
        directory,
        repository=repository,
        package_root=package_root,
        version=version,
    )
    _reject_gatekeeper_path_leak(
        seal_data, forbidden_paths, "distribution release seal"
    )
    updater_directory = _updater_set_root(repository)
    dmg_directory = _dmg_set_root(repository)
    updater = verify_updater_set(
        updater_directory,
        repository=repository,
        version=version,
        expected_source_identity=source,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )
    dmg = verify_dmg_set(
        dmg_directory,
        repository=repository,
        version=version,
        expected_source_identity=source,
        packaged_app_manifest_reader=packaged_app_manifest_reader,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )
    candidate_app = _validate_candidate_app_binding(
        seal["candidate_app"],
        repository,
        version=version,
        source_identity=source,
        expected_build_number=build_number,
    )
    if (
        updater["candidate_app"] != candidate_app
        or dmg["candidate_app"] != candidate_app
        or dmg["build_number"] != build_number
        or updater["prepackage"] != dmg["prepackage"]
    ):
        raise ArtifactSetError(
            "distribution, DMG, and updater sets do not bind one exact application"
        )
    expected_asset_paths = _release_asset_paths(
        package_root, version, distribution_directory=directory
    )
    release_assets = _require_exact_keys(
        seal["release_assets"], set(expected_asset_paths), "distribution assets"
    )
    for key, (path, maximum) in expected_asset_paths.items():
        _validate_artifact_record(
            release_assets[key], path, maximum, f"distribution asset {key}"
        )
        if key not in {"dmg", "publication_bundle", "updater_archive"}:
            try:
                public_metadata = read_regular(path, maximum)
            except PublicationError as error:
                raise ArtifactSetError(
                    f"cannot inspect public metadata asset: {path.name}"
                ) from error
            _reject_gatekeeper_path_leak(
                public_metadata,
                forbidden_paths,
                f"public metadata asset {path.name}",
            )
    set_seals = _require_exact_keys(
        seal["set_seals"], {"dmg", "updater"}, "distribution component seals"
    )
    _validate_artifact_record(
        set_seals["dmg"],
        dmg_directory / DMG_SEAL_NAME,
        MAX_SMALL_DOCUMENT_BYTES,
        "distribution DMG set seal",
    )
    _validate_artifact_record(
        set_seals["updater"],
        updater_directory / UPDATER_SEAL_NAME,
        MAX_SMALL_DOCUMENT_BYTES,
        "distribution updater set seal",
    )
    _validate_publication_binding(
        seal["publication_closure"],
        repository,
        publication_semantic_verifier,
        publication_stage_verifier,
    )
    # Semantic closure verification can be materially slower than hashing one
    # package set. Reopen every package/seal binding and the candidate once more
    # so a concurrent mutation cannot hide inside that interval.
    for key, (path, maximum) in expected_asset_paths.items():
        _validate_artifact_record(
            release_assets[key], path, maximum, f"distribution asset {key}"
        )
    _validate_artifact_record(
        set_seals["dmg"],
        dmg_directory / DMG_SEAL_NAME,
        MAX_SMALL_DOCUMENT_BYTES,
        "distribution DMG set seal",
    )
    _validate_artifact_record(
        set_seals["updater"],
        updater_directory / UPDATER_SEAL_NAME,
        MAX_SMALL_DOCUMENT_BYTES,
        "distribution updater set seal",
    )
    _validate_candidate_app_binding(
        seal["candidate_app"],
        repository,
        version=version,
        source_identity=source,
        expected_build_number=build_number,
    )
    _validate_publication_bundle(
        directory,
        repository=repository,
        package_root=package_root,
        version=version,
    )
    if _artifact_record(seal_path, MAX_SMALL_DOCUMENT_BYTES) != seal_record_before:
        raise ArtifactSetError("distribution seal changed during verification")
    return seal


def _remove_private_distribution_stage(stage: Path) -> None:
    if not os.path.lexists(stage):
        return
    _require_real_directory(stage, "distribution staging directory")
    for entry in stage.iterdir():
        metadata = entry.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ArtifactSetError(
                "distribution staging contains an unsafe unexpected entry"
            )
        entry.unlink()
    stage.rmdir()


def seal_distribution_set(
    repository: Path,
    *,
    version: str,
    source_identity: dict[str, str],
    sealed_at: str,
    publisher: Publisher = publish_exclusive,
    packaged_app_manifest_reader: PackagedAppManifestReader = read_dmg_app_manifest,
    publication_semantic_verifier: PublicationSemanticVerifier = verify_publication_semantics,
    publication_stage_verifier: PublicationStageVerifier | None = None,
    prepackage_stage_verifier: PrepackageStageVerifier | None = None,
) -> Path:
    """Atomically publish the final seal joining every release evidence lane."""
    version = _require_active_version(version)
    package_root = _package_root(repository)
    _require_real_directory(package_root, "GA package root")
    distribution_root = package_root / "distribution"
    try:
        distribution_root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _require_real_directory(distribution_root, "distribution release root")
    destination = distribution_root / f"v{version}"
    if os.path.lexists(destination):
        verify_distribution_set(
            destination,
            repository=repository,
            version=version,
            expected_source_identity=source_identity,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            publication_semantic_verifier=publication_semantic_verifier,
            publication_stage_verifier=publication_stage_verifier,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        _confirm_existing_release_set_durable(
            destination, "distribution release set"
        )
        verify_distribution_set(
            destination,
            repository=repository,
            version=version,
            expected_source_identity=source_identity,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            publication_semantic_verifier=publication_semantic_verifier,
            publication_stage_verifier=publication_stage_verifier,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        return destination
    if any(distribution_root.iterdir()):
        raise ArtifactSetError(
            "distribution release root contains an orphan or unexpected entry"
        )
    stage = Path(
        tempfile.mkdtemp(prefix="distribution-stage.", dir=distribution_root)
    )
    os.chmod(stage, 0o700)
    try:
        _projection_path, forbidden_paths = _write_gatekeeper_public_projection(
            stage, package_root, version
        )
        _write_publication_bundle(
            stage,
            repository,
            package_root,
            version,
            forbidden_paths=forbidden_paths,
        )
        seal = _build_distribution_seal(
            repository,
            stage,
            version=version,
            source_identity=source_identity,
            sealed_at=sealed_at,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            publication_semantic_verifier=publication_semantic_verifier,
            publication_stage_verifier=publication_stage_verifier,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        _write_canonical_new(stage / DISTRIBUTION_SEAL_NAME, seal)
        verify_distribution_set(
            stage,
            repository=repository,
            version=version,
            expected_source_identity=source_identity,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            publication_semantic_verifier=publication_semantic_verifier,
            publication_stage_verifier=publication_stage_verifier,
            prepackage_stage_verifier=prepackage_stage_verifier,
            require_version_directory=False,
        )
        _fsync_release_set(stage, "distribution release set")
        try:
            publisher(stage, destination)
        except Exception as error:
            if not os.path.lexists(stage) and os.path.lexists(destination):
                try:
                    verify_distribution_set(
                        destination,
                        repository=repository,
                        version=version,
                        expected_source_identity=source_identity,
                        packaged_app_manifest_reader=packaged_app_manifest_reader,
                        publication_semantic_verifier=publication_semantic_verifier,
                        publication_stage_verifier=publication_stage_verifier,
                        prepackage_stage_verifier=prepackage_stage_verifier,
                    )
                    _confirm_release_set_durable(
                        stage, destination, "distribution release set"
                    )
                    verify_distribution_set(
                        destination,
                        repository=repository,
                        version=version,
                        expected_source_identity=source_identity,
                        packaged_app_manifest_reader=packaged_app_manifest_reader,
                        publication_semantic_verifier=publication_semantic_verifier,
                        publication_stage_verifier=publication_stage_verifier,
                        prepackage_stage_verifier=prepackage_stage_verifier,
                    )
                except (ArtifactSetError, OSError, ValueError) as recovery_error:
                    raise ArtifactSetError(
                        "distribution release set exists but its durability is unconfirmed"
                    ) from recovery_error
                return destination
            raise ArtifactSetError(
                "cannot atomically publish distribution release set"
            ) from error
        if os.path.lexists(stage) or not os.path.lexists(destination):
            raise ArtifactSetError("distribution publisher returned an ambiguous result")
        _confirm_release_set_durable(
            stage, destination, "distribution release set"
        )
        verify_distribution_set(
            destination,
            repository=repository,
            version=version,
            expected_source_identity=source_identity,
            packaged_app_manifest_reader=packaged_app_manifest_reader,
            publication_semantic_verifier=publication_semantic_verifier,
            publication_stage_verifier=publication_stage_verifier,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        return destination
    except BaseException:
        _remove_private_distribution_stage(stage)
        raise


def verify_release_sets(
    repository: Path,
    *,
    version: str,
    expected_source_identity: dict[str, str] | None = None,
    packaged_app_manifest_reader: PackagedAppManifestReader = read_dmg_app_manifest,
    publication_semantic_verifier: PublicationSemanticVerifier = verify_publication_semantics,
    publication_stage_verifier: PublicationStageVerifier | None = None,
    prepackage_stage_verifier: PrepackageStageVerifier | None = None,
) -> tuple[Path, ...]:
    """Return only files admitted by the complete final distribution seal."""
    version = _require_active_version(version)
    package_root = _package_root(repository)
    updater = _updater_set_root(repository)
    dmg = _dmg_set_root(repository)
    archive_name, signature_name, latest_name = _updater_names(version)
    dmg_names = _dmg_names(version)
    forbidden_legacy = {
        archive_name,
        signature_name,
        latest_name,
        *dmg_names,
    }
    for name in forbidden_legacy:
        if os.path.lexists(package_root / name):
            raise ArtifactSetError(
                f"legacy unsealed release asset is present at the release root: {name}"
            )
    distribution_root = package_root / "distribution"
    _require_real_directory(distribution_root, "distribution release root")
    try:
        distribution_entries = list(distribution_root.iterdir())
    except OSError as error:
        raise ArtifactSetError("cannot enumerate distribution release root") from error
    if len(distribution_entries) != 1 or distribution_entries[0].name != f"v{version}":
        raise ArtifactSetError(
            "distribution release root is partial or contains an orphan"
        )
    distribution = distribution_entries[0]
    verify_distribution_set(
        distribution,
        repository=repository,
        version=version,
        expected_source_identity=expected_source_identity,
        packaged_app_manifest_reader=packaged_app_manifest_reader,
        publication_semantic_verifier=publication_semantic_verifier,
        publication_stage_verifier=publication_stage_verifier,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )
    paths = [
        *(
            path
            for path, _maximum in _release_asset_paths(
                package_root,
                version,
                distribution_directory=distribution,
            ).values()
        ),
        dmg / DMG_SEAL_NAME,
        updater / UPDATER_SEAL_NAME,
        distribution / DISTRIBUTION_SEAL_NAME,
    ]
    return tuple(sorted(paths, key=str))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def self_check() -> None:
    if MAX_UPDATER_ARCHIVE_BYTES != 192 * 1024 * 1024:
        raise ArtifactSetError("updater archive bound drifted")
    if MAX_DMG_BYTES != 512 * 1024 * 1024:
        raise ArtifactSetError("DMG bound drifted")
    if MAX_PUBLICATION_BUNDLE_BYTES != 2 * 1024 * 1024 * 1024 - 1:
        raise ArtifactSetError("public release bundle bound drifted")
    if (
        MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES
        + MAX_PUBLICATION_BUNDLE_AUXILIARY_BYTES
        + MAX_PUBLICATION_DOCUMENT_BYTES
        >= MAX_PUBLICATION_BUNDLE_BYTES
    ):
        raise ArtifactSetError("public release bundle has no container overhead reserve")
    if DISTRIBUTION_SEAL_DOCUMENT != "cfw-ga-distribution-package-set-seal-v1":
        raise ArtifactSetError("distribution seal contract drifted")
    if UPDATER_SEAL_DOCUMENT != "cfw-updater-release-set-seal-v2":
        raise ArtifactSetError("updater seal contract drifted")
    if DMG_SEAL_DOCUMENT != "cfw-dmg-release-set-seal-v2":
        raise ArtifactSetError("DMG seal contract drifted")
    if _official_url("0.4.0", _updater_names("0.4.0")[0]) != (
        "https://github.com/billlza/cfw-rs/releases/download/v0.4.0/"
        "Clash.for.Mac_0.4.0_aarch64.app.tar.gz"
    ):
        raise ArtifactSetError("official release URL contract drifted")
    print("release artifact set self-check ok")


def main(
    *,
    prepackage_stage_verifier: PrepackageStageVerifier | None = None,
    publication_stage_verifier: PublicationStageVerifier | None = None,
) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("self-check")

    seal_updater = commands.add_parser("seal-updater")
    seal_updater.add_argument("--staging", type=Path, required=True)
    seal_updater.add_argument("--destination", type=Path, required=True)
    seal_updater.add_argument(
        "--version", choices=(CANDIDATE_VERSION,), required=True
    )
    seal_updater.add_argument("--repository", type=Path, required=True)

    for name in ("verify-updater", "verify-dmg"):
        command = commands.add_parser(name)
        command.add_argument("--directory", type=Path, required=True)
        command.add_argument(
            "--version", choices=(CANDIDATE_VERSION,), required=True
        )
        command.add_argument("--repository", type=Path, required=True)

    for name in ("seal-release", "verify-release"):
        command = commands.add_parser(name)
        command.add_argument("--repository", type=Path, required=True)
        command.add_argument(
            "--version", choices=(CANDIDATE_VERSION,), required=True
        )

    arguments = parser.parse_args()
    try:
        if arguments.command == "self-check":
            self_check()
        elif arguments.command == "seal-updater":
            identity = _canonical_source_identity(
                current_identity(arguments.repository, require_clean=True)
            )
            destination = seal_updater_set(
                arguments.staging,
                arguments.destination,
                version=arguments.version,
                source_identity=identity,
                sealed_at=_utc_now(),
                repository=arguments.repository,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            print(f"updater release set published: {destination}")
        elif arguments.command == "verify-updater":
            identity = _canonical_source_identity(
                current_identity(arguments.repository, require_clean=True)
            )
            verify_updater_set(
                arguments.directory,
                repository=arguments.repository,
                version=arguments.version,
                expected_source_identity=identity,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            print(f"updater release set verified: {arguments.directory}")
        elif arguments.command == "verify-dmg":
            identity = _canonical_source_identity(
                current_identity(arguments.repository, require_clean=True)
            )
            verify_dmg_set(
                arguments.directory,
                repository=arguments.repository,
                version=arguments.version,
                expected_source_identity=identity,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            print(f"DMG release set verified: {arguments.directory}")
        elif arguments.command == "seal-release":
            identity = _canonical_source_identity(
                current_identity(arguments.repository, require_clean=True)
            )
            destination = seal_distribution_set(
                arguments.repository,
                version=arguments.version,
                source_identity=identity,
                sealed_at=_utc_now(),
                publication_stage_verifier=publication_stage_verifier,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            print(f"distribution release set published: {destination}")
        elif arguments.command == "verify-release":
            identity = _canonical_source_identity(
                current_identity(arguments.repository, require_clean=True)
            )
            for path in verify_release_sets(
                arguments.repository,
                version=arguments.version,
                expected_source_identity=identity,
                publication_stage_verifier=publication_stage_verifier,
                prepackage_stage_verifier=prepackage_stage_verifier,
            ):
                print(path)
        else:
            raise ArtifactSetError("unsupported release artifact set command")
    except (
        ArtifactSetError,
        OSError,
        PublicationError,
        SourceIdentityError,
        ValueError,
    ) as error:
        raise SystemExit(f"error: release artifact set: {error}") from error
