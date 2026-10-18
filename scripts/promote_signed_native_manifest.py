#!/usr/bin/env python3
"""Re-hash one signed native product from its verified pre-sign manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Sequence

if __package__:
    from .hash_artifact import build_manifest, write_new_manifest
    from .release_regular_file import (
        ReleaseRegularFileError,
        read_bounded_regular_file,
    )
else:
    from hash_artifact import build_manifest, write_new_manifest
    from release_regular_file import (
        ReleaseRegularFileError,
        read_bounded_regular_file,
    )


MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_ERROR_DETAIL_CHARACTERS = 512


class SignedNativeManifestError(ValueError):
    """A pre-sign manifest cannot authorize one signed product manifest."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SignedNativeManifestError(f"native manifest repeats field {key!r}")
        result[key] = value
    return result


def _read_regular(path: Path, *, label: str) -> bytes:
    try:
        return read_bounded_regular_file(
            path,
            label=label,
            maximum_bytes=MAX_MANIFEST_BYTES,
            allowed_owner_uids=frozenset({os.geteuid()}),
        )
    except ReleaseRegularFileError as error:
        raise SignedNativeManifestError(str(error)) from error


def _bounded_error_detail(error: BaseException) -> str:
    detail = " ".join(str(error).split())
    if not detail:
        detail = type(error).__name__
    if len(detail) > MAX_ERROR_DETAIL_CHARACTERS:
        return detail[: MAX_ERROR_DETAIL_CHARACTERS - 3] + "..."
    return detail


def _build_artifact_manifest(
    artifact: Path,
    *,
    metadata: dict[str, str],
    algorithm: str,
    label: str,
) -> dict[str, object]:
    try:
        return build_manifest(
            artifact,
            metadata=metadata,
            algorithm=algorithm,
        )
    except ValueError as error:
        raise SignedNativeManifestError(
            f"{label} is invalid: {_bounded_error_detail(error)}"
        ) from error


def _load_manifest(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    data = _read_regular(path, label=label)
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except SignedNativeManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SignedNativeManifestError(f"{label} is not strict JSON") from error
    if type(value) is not dict:
        raise SignedNativeManifestError(f"{label} is not an object")
    return value, data


def _reject_constant(token: str) -> Any:
    raise SignedNativeManifestError(f"pre-sign native manifest contains {token}")


def promote_manifest(
    unsigned_artifact: Path,
    unsigned_manifest: Path,
    signed_artifact: Path,
) -> dict[str, object]:
    value, manifest_bytes = _load_manifest(
        unsigned_manifest, label="pre-sign native manifest"
    )
    expected_fields = {"algorithm", "entries", "metadata", "root", "sha256"}
    if value.get("algorithm") == "sha256-tree-v2":
        expected_fields.add("rootMode")
    if set(value) != expected_fields:
        raise SignedNativeManifestError("pre-sign native manifest field set is invalid")
    algorithm = value["algorithm"]
    if algorithm not in {"sha256-tree-v1", "sha256-tree-v2"}:
        raise SignedNativeManifestError("pre-sign native manifest algorithm is unsupported")
    metadata = value["metadata"]
    if (
        type(metadata) is not dict
        or not metadata
        or any(not isinstance(key, str) or not isinstance(item, str) for key, item in metadata.items())
        or metadata.get("signingMode") != "pre-sign"
        or "preSignArtifactSha256" in metadata
        or "preSignManifestSha256" in metadata
    ):
        raise SignedNativeManifestError("pre-sign native metadata is invalid")
    observed_unsigned = _build_artifact_manifest(
        unsigned_artifact,
        metadata=dict(metadata),
        algorithm=algorithm,
        label="pre-sign native artifact",
    )
    if observed_unsigned != value:
        raise SignedNativeManifestError("unsigned native artifact differs from its manifest")
    if signed_artifact.name != unsigned_artifact.name:
        raise SignedNativeManifestError("signed native product name differs from pre-sign input")
    signed_metadata = dict(metadata)
    signed_metadata.update(
        {
            "preSignArtifactSha256": str(value["sha256"]),
            "preSignManifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "signingMode": "developer-id",
        }
    )
    return _build_artifact_manifest(
        signed_artifact,
        metadata=signed_metadata,
        algorithm=algorithm,
        label="signed native artifact",
    )


def verify_promoted_manifest(
    unsigned_artifact: Path,
    unsigned_manifest: Path,
    signed_artifact: Path,
    signed_manifest: Path,
) -> dict[str, object]:
    """Re-derive and verify one exact pre-sign to Developer ID promotion."""

    expected = promote_manifest(
        unsigned_artifact,
        unsigned_manifest,
        signed_artifact,
    )
    observed, _manifest_bytes = _load_manifest(
        signed_manifest, label="signed native manifest"
    )
    if observed != expected:
        raise SignedNativeManifestError(
            "signed native manifest differs from the exact pre-sign promotion"
        )
    return observed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unsigned_artifact", type=Path)
    parser.add_argument("unsigned_manifest", type=Path)
    parser.add_argument("signed_artifact", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        manifest = promote_manifest(
            arguments.unsigned_artifact,
            arguments.unsigned_manifest,
            arguments.signed_artifact,
        )
        try:
            write_new_manifest(
                arguments.output,
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            )
        except ValueError as error:
            raise SignedNativeManifestError(
                "signed native manifest output is invalid: "
                f"{_bounded_error_detail(error)}"
            ) from error
    except (OSError, SignedNativeManifestError) as error:
        raise SystemExit(f"error: signed native manifest: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
