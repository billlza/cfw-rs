#!/usr/bin/env python3
"""Bind physical validation to one notarized candidate build before final rebuild."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any

if __package__:
    from .candidate_artifact_binding import (
        CandidateBindingError,
        load_strict_json,
        validate_candidate_app_manifest,
        validate_ci_toolchain_evidence,
    )
    from .release_build_identity import canonical_build_version, require_newer_build
    from .release_runtime_evidence import load_runtime_evidence
    from .repository_source_identity import SourceIdentityError, current_identity
else:
    from candidate_artifact_binding import (
        CandidateBindingError,
        load_strict_json,
        validate_candidate_app_manifest,
        validate_ci_toolchain_evidence,
    )
    from release_build_identity import canonical_build_version, require_newer_build
    from release_runtime_evidence import load_runtime_evidence
    from repository_source_identity import SourceIdentityError, current_identity


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidatedCandidateError(ValueError):
    """The installed-candidate review is absent, stale, or incomplete."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValidatedCandidateError(f"{label} has an unexpected field set")
    return value


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValidatedCandidateError(f"{label} is not a lowercase SHA-256")
    return value


def _relative_file(repository: Path, value: Any, expected: PurePosixPath, label: str) -> Path:
    if not isinstance(value, str):
        raise ValidatedCandidateError(f"{label} path is not a string")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or relative != expected:
        raise ValidatedCandidateError(f"{label} path is not the fixed candidate path")
    path = repository.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():
        raise ValidatedCandidateError(f"{label} is absent or is a symlink")
    return path


def _reviewed_at(value: Any) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidatedCandidateError("reviewed_at must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValidatedCandidateError("reviewed_at is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValidatedCandidateError("reviewed_at must use UTC")
    return value


def validate_candidate_review(
    repository: Path,
    review_path: Path,
    final_build_number: str | None = None,
    *,
    expected_source_identity: dict[str, str] | None = None,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    expected_review = repository / "target/candidates/0.4.0/review/validated-candidate.json"
    if review_path.is_symlink() or review_path.resolve(strict=True) != expected_review:
        raise ValidatedCandidateError("validated-candidate review path is not fixed")
    try:
        document = load_strict_json(review_path, "validated-candidate review")
    except CandidateBindingError as error:
        raise ValidatedCandidateError(str(error)) from error
    document = _exact(
        document,
        {
            "schema_version",
            "decision",
            "reviewer",
            "reviewed_at",
            "product",
            "candidate",
        },
        "validated-candidate review",
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["decision"] != "approved"
    ):
        raise ValidatedCandidateError("validated candidate is not explicitly approved")
    if not isinstance(document["reviewer"], str) or not document["reviewer"].strip():
        raise ValidatedCandidateError("validated candidate has no reviewer")
    _reviewed_at(document["reviewed_at"])
    product = _exact(document["product"], {"version", "build_number"}, "product")
    if product["version"] != "0.4.0":
        raise ValidatedCandidateError("validated candidate is not version 0.4.0")
    build = canonical_build_version(product["build_number"], "validated candidate build_number")
    if final_build_number is not None:
        require_newer_build(final_build_number, build)
    candidate = _exact(
        document["candidate"],
        {
            "app_manifest_path",
            "app_manifest_sha256",
            "ci_evidence_path",
            "ci_evidence_sha256",
            "notarization_result_path",
            "notarization_result_sha256",
            "runtime_evidence_path",
            "runtime_evidence_sha256",
            "toolchain_binding_path",
            "toolchain_binding_sha256",
        },
        "candidate",
    )
    prefix = PurePosixPath(f"target/candidates/0.4.0/validation/{build}")
    app_manifest = _relative_file(
        repository,
        candidate["app_manifest_path"],
        prefix / "signed/Clash for Mac.app.manifest.json",
        "candidate app manifest",
    )
    notarization = _relative_file(
        repository,
        candidate["notarization_result_path"],
        prefix / "signed/notarization.json",
        "candidate notarization result",
    )
    runtime = _relative_file(
        repository,
        candidate["runtime_evidence_path"],
        prefix / "evidence/runtime-recovery.json",
        "candidate runtime evidence",
    )
    ci_evidence = _relative_file(
        repository,
        candidate["ci_evidence_path"],
        prefix / "evidence/unsigned-ci-lanes.json",
        "candidate unsigned CI evidence",
    )
    toolchain_binding = _relative_file(
        repository,
        candidate["toolchain_binding_path"],
        prefix / "evidence/toolchain-binding.json",
        "candidate toolchain binding",
    )
    for path, field, label in (
        (app_manifest, "app_manifest_sha256", "candidate app manifest"),
        (ci_evidence, "ci_evidence_sha256", "candidate unsigned CI evidence"),
        (notarization, "notarization_result_sha256", "candidate notarization result"),
        (runtime, "runtime_evidence_sha256", "candidate runtime evidence"),
        (toolchain_binding, "toolchain_binding_sha256", "candidate toolchain binding"),
    ):
        if _digest(path) != _sha(candidate[field], field):
            raise ValidatedCandidateError(f"{label} digest differs from review")
    source_identity = expected_source_identity
    if source_identity is None:
        try:
            source_identity = current_identity(repository)
        except (OSError, SourceIdentityError) as error:
            raise ValidatedCandidateError(
                f"cannot derive current release source identity: {error}"
            ) from error
    try:
        toolchain_metadata = validate_ci_toolchain_evidence(
            ci_evidence,
            toolchain_binding,
            source_identity["repositoryCommit"],
            source_identity["releaseSourceSha256"],
        )
        validate_candidate_app_manifest(
            app_manifest,
            app_manifest.parent / "Clash for Mac.app",
            artifact_kind="notarized-validation-candidate-v1",
            build_number=build,
            source_identity=source_identity,
            toolchain_metadata=toolchain_metadata,
            team_id="YKUPL7Z869",
        )
        notary_document = load_strict_json(notarization, "candidate notarization evidence")
    except (CandidateBindingError, KeyError) as error:
        raise ValidatedCandidateError(f"candidate source/toolchain binding failed: {error}") from error
    if (
        not isinstance(notary_document, dict)
        or notary_document.get("status") != "Accepted"
        or not isinstance(notary_document.get("id"), str)
        or not notary_document["id"]
    ):
        raise ValidatedCandidateError("candidate notarization was not accepted")
    runtime_document = load_runtime_evidence(runtime)
    if runtime_document["product"] != {"version": "0.4.0", "build_number": build}:
        raise ValidatedCandidateError("runtime evidence build differs from the installed candidate")
    if runtime_document["app_manifest_sha256"] != _digest(app_manifest):
        raise ValidatedCandidateError("runtime evidence is not bound to the candidate app manifest")
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("review", type=Path)
    parser.add_argument("--final-build-number")
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        document = validate_candidate_review(
            repository, arguments.review, arguments.final_build_number
        )
    except (ValidatedCandidateError, OSError, ValueError) as error:
        raise SystemExit(f"error: validated candidate evidence failed: {error}") from error
    print(
        "validated install candidate accepted: "
        f"0.4.0 ({document['product']['build_number']})"
    )


if __name__ == "__main__":
    main()
