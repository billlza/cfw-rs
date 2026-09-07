#!/usr/bin/env python3
"""Bind candidate application trees to source and unsigned-CI toolchain evidence.

The canonical toolchain identity remains owned by ``publication.ci_lanes``.
This module only projects its release-tree digests into artifact-manifest
metadata and verifies that a concrete application tree, its manifest, the CI
lane document, and the saved toolchain identity all describe one build.
"""

from __future__ import annotations

import argparse
from enum import Enum
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

if __package__:
    from .hash_artifact import SUPPORTED_ALGORITHMS, build_manifest
    from .publication.ci_lanes import (
        TOOLCHAIN_BINDING_KIND,
        derive_toolchain_binding,
        toolchain_sha256,
    )
    from .publication.common import PublicationError, canonical_json
    from .publication.bounded_process import BoundedProcessError, run_bounded_process
    from .publication.graph_model import load_pins
    from .publication.release_environment import release_tool_environment
    from .publication.sealed_manifest import _ci_lane_document
    from .release_python_runtime import require_closed_release_runtime
    from .repository_source_identity import SourceIdentityError, current_identity
else:
    from hash_artifact import SUPPORTED_ALGORITHMS, build_manifest
    from publication.ci_lanes import (
        TOOLCHAIN_BINDING_KIND,
        derive_toolchain_binding,
        toolchain_sha256,
    )
    from publication.common import PublicationError, canonical_json
    from publication.bounded_process import BoundedProcessError, run_bounded_process
    from publication.graph_model import load_pins
    from publication.release_environment import release_tool_environment
    from publication.sealed_manifest import _ci_lane_document
    from release_python_runtime import require_closed_release_runtime
    from repository_source_identity import SourceIdentityError, current_identity


MAX_BINDING_DOCUMENT_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# The names on the left are the canonical constituent keys in
# ``derive_toolchain_identity()['release_tree_sha256']``.  The names on the
# right are the stable artifact-manifest metadata contract.
RELEASE_TREE_METADATA = {
    "cargo-workspace-sources": "cargoWorkspaceSourcesTreeSha256",
    "go": "goToolchainTreeSha256",
    "go-module-cache": "goModuleCacheTreeSha256",
    "go-release-tools": "goToolsTreeSha256",
    "node": "nodeToolchainTreeSha256",
    "tauri-cli": "tauriToolchainTreeSha256",
    "ui-dependencies": "uiDependenciesTreeSha256",
    "xcodegen": "xcodegenToolchainTreeSha256",
}
TOOLCHAIN_METADATA_ORDER = (
    "toolchainSha256",
    *(RELEASE_TREE_METADATA[key] for key in sorted(RELEASE_TREE_METADATA)),
)


class CandidateBindingError(ValueError):
    """A candidate artifact is not bound to its source and CI evidence."""


class ArtifactToolchainError(CandidateBindingError):
    """The frozen artifact source could not verify its own toolchain."""

    def __init__(
        self, code: str, message: str, *, exit_code: int | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


class _DuplicateFieldError(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateFieldError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_regular(path: Path, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise CandidateBindingError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise CandidateBindingError(f"{label} must be a single-link regular file")
    if before.st_size <= 0 or before.st_size > MAX_BINDING_DOCUMENT_BYTES:
        raise CandidateBindingError(f"{label} size is outside the accepted range")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CandidateBindingError(f"cannot open {label}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise CandidateBindingError(f"{label} changed while opening")
        data = bytearray()
        while len(data) <= MAX_BINDING_DOCUMENT_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_BINDING_DOCUMENT_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(data) != opened.st_size
    ):
        raise CandidateBindingError(f"{label} changed while reading")
    if len(data) > MAX_BINDING_DOCUMENT_BYTES:
        raise CandidateBindingError(f"{label} exceeds the accepted size")
    return bytes(data)


def load_strict_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_regular(path, label).decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateFieldError) as error:
        raise CandidateBindingError(f"{label} is not strict JSON: {error}") from error
    if not isinstance(value, dict):
        raise CandidateBindingError(f"{label} must be a JSON object")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise CandidateBindingError(f"{label} is not a lowercase SHA-256")
    return value


def _commit(value: object, label: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        raise CandidateBindingError(f"{label} is not a lowercase 40-hex commit")
    return value


def toolchain_manifest_metadata(
    digest: object, identity: dict[str, Any]
) -> dict[str, str]:
    canonical_digest = _sha256(digest, "toolchain_sha256")
    if identity.get("document") != TOOLCHAIN_BINDING_KIND:
        raise CandidateBindingError("toolchain binding has the wrong document kind")
    if toolchain_sha256(identity) != canonical_digest:
        raise CandidateBindingError("toolchain binding digest does not match its identity")
    trees = identity.get("release_tree_sha256")
    if not isinstance(trees, dict) or set(trees) != set(RELEASE_TREE_METADATA):
        raise CandidateBindingError("toolchain binding has an unexpected release-tree set")
    metadata = {"toolchainSha256": canonical_digest}
    for constituent, metadata_key in RELEASE_TREE_METADATA.items():
        metadata[metadata_key] = _sha256(
            trees[constituent], f"release_tree_sha256.{constituent}"
        )
    return metadata


def validate_ci_toolchain_evidence(
    ci_evidence: Path,
    toolchain_binding: Path,
    expected_commit: str,
    expected_release_source_sha256: str,
) -> dict[str, str]:
    commit = _commit(expected_commit, "repositoryCommit")
    release_source_sha256 = _sha256(
        expected_release_source_sha256, "releaseSourceSha256"
    )
    ci_document = load_strict_json(ci_evidence, "unsigned CI evidence")
    try:
        validated_ci, failures = _ci_lane_document(
            ci_document, commit, release_source_sha256
        )
    except PublicationError as error:
        # The gate owns the detailed schema; expose one stable candidate boundary.
        raise CandidateBindingError(f"unsigned CI evidence is invalid: {error}") from error
    if failures:
        raise CandidateBindingError(f"unsigned CI evidence has non-passing lanes: {failures}")
    identity = load_strict_json(toolchain_binding, "CI toolchain binding")
    metadata = toolchain_manifest_metadata(validated_ci["toolchain_sha256"], identity)
    if metadata["toolchainSha256"] != validated_ci["toolchain_sha256"]:
        raise CandidateBindingError("CI lanes and toolchain binding use different digests")
    return metadata


def validate_candidate_app_manifest(
    manifest_path: Path,
    app: Path,
    *,
    artifact_kind: str,
    build_number: str,
    source_identity: dict[str, str],
    toolchain_metadata: dict[str, str],
    team_id: str,
) -> dict[str, Any]:
    if not app.is_dir() or app.is_symlink():
        raise CandidateBindingError("candidate app must be a real directory")
    document = load_strict_json(manifest_path, "candidate app manifest")
    algorithm = document.get("algorithm")
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise CandidateBindingError("candidate app manifest uses an unsupported algorithm")
    top_level = {"algorithm", "root", "sha256", "entries", "metadata"}
    if algorithm == "sha256-tree-v2":
        top_level.add("rootMode")
    if set(document) != top_level:
        raise CandidateBindingError("candidate app manifest has an unexpected field set")
    actual = build_manifest(app, algorithm=algorithm)
    compared = {"root", "sha256", "entries"}
    if algorithm == "sha256-tree-v2":
        compared.add("rootMode")
    if any(document.get(key) != actual.get(key) for key in compared):
        raise CandidateBindingError("candidate app manifest does not match the actual app tree")

    expected_source = {
        "repositoryCommit": _commit(
            source_identity.get("repositoryCommit"), "source repositoryCommit"
        ),
        "releaseSourceSha256": _sha256(
            source_identity.get("releaseSourceSha256"), "source releaseSourceSha256"
        ),
    }
    if set(toolchain_metadata) != set(TOOLCHAIN_METADATA_ORDER):
        raise CandidateBindingError("candidate toolchain metadata has an unexpected field set")
    expected_metadata = {
        "artifactKind": artifact_kind,
        "architecture": "arm64",
        "buildNumber": build_number,
        "deploymentTarget": "15.0",
        **expected_source,
        **toolchain_metadata,
        "teamID": team_id,
        "version": "0.4.0",
    }
    if document.get("metadata") != dict(sorted(expected_metadata.items())):
        raise CandidateBindingError(
            "candidate app manifest metadata is not the exact source/toolchain/build binding"
        )
    return document


def derive_candidate_toolchain_metadata(
    repository: Path, *, unsigned_validation: bool = False
) -> dict[str, str]:
    repository = repository.resolve(strict=True)
    environment = None
    if unsigned_validation:
        pins = load_pins(repository / "scripts/dependency_pins.env")
        environment = release_tool_environment(
            repository,
            pins,
            dict(os.environ),
            role="unsigned-validation",
        )
    digest, identity = derive_toolchain_binding(repository, environment)
    return toolchain_manifest_metadata(digest, identity)


def derive_artifact_toolchain_metadata(repository: Path) -> dict[str, str]:
    """Run the artifact's own policy in the existing isolated child launcher.

    Post-freeze operators must not import their newer pin policy into the
    artifact source. Both notarization and dormant installation use this one
    read-only adapter; the fixed nine-field metadata format is unchanged.
    """
    output_bytes = _run_artifact_toolchain_verifier(repository, _ArtifactToolchainOperation.METADATA)
    try:
        output = output_bytes.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ArtifactToolchainError(
            "artifact_toolchain_output_invalid",
            "the frozen source's toolchain verifier returned non-ASCII identities",
        ) from error
    values = output.removesuffix("\n").split(" ")
    if (
        len(values) != len(TOOLCHAIN_METADATA_ORDER)
        or output != " ".join(values) + "\n"
        or any(SHA256_RE.fullmatch(value) is None for value in values)
    ):
        raise ArtifactToolchainError(
            "artifact_toolchain_output_invalid",
            "the frozen source's toolchain verifier returned malformed identities",
        )
    return dict(zip(TOOLCHAIN_METADATA_ORDER, values, strict=True))


class _ArtifactToolchainOperation(Enum):
    METADATA = "metadata"
    CI_BINDING = "ci-binding"


def _artifact_source_identity(repository: Path, environment: dict[str, str]) -> dict[str, str]:
    try:
        return current_identity(repository, require_clean=True, environment=environment)
    except (OSError, SourceIdentityError) as error:
        raise ArtifactToolchainError(
            "artifact_toolchain_source_invalid",
            "the frozen toolchain source is not one clean readable identity",
        ) from error


def _run_artifact_toolchain_verifier(
    repository: Path,
    operation: _ArtifactToolchainOperation,
    release_environment: dict[str, str] | None = None,
) -> bytes:
    """Run one of the two fixed read-only operations through the artifact launcher."""
    require_closed_release_runtime()
    try:
        metadata = repository.lstat()
        if (
            not repository.is_absolute()
            or repository.resolve(strict=True) != repository
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ArtifactToolchainError(
                "artifact_toolchain_repository_invalid",
                "artifact toolchain verification requires one canonical owned repository",
            )
    except OSError as error:
        raise ArtifactToolchainError(
            "artifact_toolchain_repository_invalid",
            "artifact toolchain repository is unavailable",
        ) from error
    if operation is _ArtifactToolchainOperation.METADATA:
        entry = '"$1/scripts/candidate_artifact_binding.py" --repository "$1"'
    elif operation is _ArtifactToolchainOperation.CI_BINDING:
        entry = '"$1/scripts/sealed_evidence_manifest.py" ci-toolchain-binding'
    else:
        raise ArtifactToolchainError(
            "artifact_toolchain_operation_invalid", "unknown artifact toolchain verification operation"
        )
    environment = dict(os.environ) if release_environment is None else dict(release_environment)
    source_identity = (
        _artifact_source_identity(repository, environment)
        if operation is _ArtifactToolchainOperation.CI_BINDING else None
    )
    command = [
        "/bin/bash",
        "-p",
        "-c",
        'set -euo pipefail; source "$1/scripts/release_python_launcher.sh"; '
        'cfw_run_release_python_script "$1" ' + entry,
        "artifact-toolchain-verification",
        str(repository),
    ]
    try:
        result = run_bounded_process(
            command,
            cwd=repository,
            environment=environment,
            timeout=1800,
            output_limit=4 * 1024 * 1024,
        )
    except BoundedProcessError as error:
        raise ArtifactToolchainError(
            "artifact_toolchain_execution_failed",
            f"the frozen source's toolchain verifier did not complete ({error.reason})",
        ) from error
    except OSError as error:
        raise ArtifactToolchainError(
            "artifact_toolchain_execution_failed",
            "the frozen source's toolchain verifier encountered an operating-system error",
        ) from error
    if result.returncode != 0 or result.stderr:
        raise ArtifactToolchainError(
            "artifact_toolchain_verification_failed",
            "the frozen source's toolchain verifier failed or emitted diagnostics",
            exit_code=result.returncode,
        )
    if source_identity is not None and _artifact_source_identity(repository, environment) != source_identity:
        raise ArtifactToolchainError(
            "artifact_toolchain_source_changed",
            "the frozen source changed while its toolchain binding was being derived",
        )
    return result.stdout


def _binding_string_map(value: object, fields: set[str], label: str) -> None:
    if type(value) is not dict or set(value) != fields:
        raise CandidateBindingError(f"{label} has an unexpected field set")
    if any(
        type(item) is not str or not item or len(item) > 16 * 1024
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item)
        for item in value.values()
    ):
        raise CandidateBindingError(f"{label} must contain bounded single-line identities")


def derive_artifact_ci_toolchain_binding(
    repository: Path,
    release_environment: dict[str, str] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Read the frozen v1 binding without importing the executor's source policy."""
    output = _run_artifact_toolchain_verifier(
        repository, _ArtifactToolchainOperation.CI_BINDING, release_environment
    )
    try:
        lines = output.split(b"\n")
        if len(lines) != 3 or lines[2] != b"" or not lines[1].startswith(b"toolchain_sha256: "):
            raise CandidateBindingError("artifact CI binding must contain exactly two complete lines")
        identity = json.loads(lines[0].decode("utf-8"), object_pairs_hook=_strict_object)
        digest = _sha256(lines[1][len(b"toolchain_sha256: "):].decode("ascii"), "artifact CI toolchain digest")
        if type(identity) is not dict or canonical_json(identity) != lines[0] + b"\n":
            raise CandidateBindingError("artifact CI binding is not canonical JSON")
        if set(identity) != {
            "document", "pins_path", "pins_sha256", "toolchain_versions", "toolchain_digests",
            "release_tree_sha256", "apple_toolchain", "resolved",
        } or identity["pins_path"] != "scripts/dependency_pins.env":
            raise CandidateBindingError("artifact CI binding has an unexpected schema")
        _binding_string_map(identity["toolchain_versions"], {
            "go", "gomobile", "govulncheck", "node", "rust", "sing_box",
        }, "artifact toolchain versions")
        _binding_string_map(identity["toolchain_digests"], {
            "go_darwin_arm64_sha256", "gomobile_module_sum", "govulncheck_module_sum",
            "node_darwin_arm64_sha256", "rust_release_toolchain_surface_sha256",
        }, "artifact toolchain digests")
        _binding_string_map(identity["apple_toolchain"], {
            "macos_deployment_target", "xcode_build_version", "xcode_version",
        }, "artifact Apple toolchain")
        _binding_string_map(identity["resolved"], {
            "bash", "cargo", "cargo-audit", "cargo-deny", "cargo-tauri", "git", "go",
            "gomobile", "govulncheck", "node", "npm", "python3", "rust-toolchain-surface",
            "rustc", "swift", "xcodebuild", "xcodegen", "zsh",
        }, "artifact resolved toolchains")
        pins_payload = _read_regular(repository / "scripts/dependency_pins.env", "artifact dependency pins")
        if identity["pins_sha256"] != hashlib.sha256(pins_payload).hexdigest():
            raise CandidateBindingError("artifact CI binding names different dependency pins")
        toolchain_manifest_metadata(digest, identity)
    except (CandidateBindingError, UnicodeError, json.JSONDecodeError, _DuplicateFieldError) as error:
        raise ArtifactToolchainError(
            "artifact_toolchain_output_invalid",
            f"the frozen source's CI toolchain binding is invalid: {error}",
        ) from error
    return digest, identity


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    parser.add_argument("--unsigned-validation-toolchain", action="store_true")
    arguments = parser.parse_args()
    try:
        metadata = derive_candidate_toolchain_metadata(
            arguments.repository,
            unsigned_validation=arguments.unsigned_validation_toolchain,
        )
    except (CandidateBindingError, OSError, PublicationError, ValueError) as error:
        raise SystemExit(f"error: candidate toolchain binding failed: {error}") from error
    # Every value is a validated lowercase SHA-256.  The fixed positional form
    # is consumed by bash without eval or generated shell source.
    print(" ".join(metadata[key] for key in TOOLCHAIN_METADATA_ORDER))


if __name__ == "__main__":
    main()
