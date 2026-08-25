#!/usr/bin/env python3
"""Re-hash one signed native product from its verified pre-sign manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Sequence

if __package__:
    from .hash_artifact import build_manifest, write_new_manifest
else:
    from hash_artifact import build_manifest, write_new_manifest


MAX_MANIFEST_BYTES = 64 * 1024 * 1024


class SignedNativeManifestError(ValueError):
    """A pre-sign manifest cannot authorize one signed product manifest."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SignedNativeManifestError(f"native manifest repeats field {key!r}")
        result[key] = value
    return result


def _read_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise SignedNativeManifestError(f"native manifest is unavailable: {path}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > MAX_MANIFEST_BYTES
    ):
        raise SignedNativeManifestError("pre-sign native manifest is not a bounded regular file")
    try:
        data = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise SignedNativeManifestError("cannot read pre-sign native manifest") from error
    if before != after or len(data) != before.st_size:
        raise SignedNativeManifestError("pre-sign native manifest changed while reading")
    return data


def _load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    data = _read_regular(path)
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except SignedNativeManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SignedNativeManifestError("pre-sign native manifest is not strict JSON") from error
    if type(value) is not dict:
        raise SignedNativeManifestError("pre-sign native manifest is not an object")
    return value, data


def _reject_constant(token: str) -> Any:
    raise SignedNativeManifestError(f"pre-sign native manifest contains {token}")


def promote_manifest(
    unsigned_artifact: Path,
    unsigned_manifest: Path,
    signed_artifact: Path,
) -> dict[str, object]:
    value, manifest_bytes = _load_manifest(unsigned_manifest)
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
    ):
        raise SignedNativeManifestError("pre-sign native metadata is invalid")
    observed_unsigned = build_manifest(
        unsigned_artifact,
        metadata=dict(metadata),
        algorithm=algorithm,
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
    return build_manifest(
        signed_artifact,
        metadata=signed_metadata,
        algorithm=algorithm,
    )


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
        write_new_manifest(
            arguments.output,
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        )
    except (OSError, SignedNativeManifestError, ValueError) as error:
        raise SystemExit(f"error: signed native manifest: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
