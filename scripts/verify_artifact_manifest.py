#!/usr/bin/env python3
"""Verify a sha256-tree-v1 artifact and its required metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

if __package__:
    from .hash_artifact import build_manifest, parse_metadata
else:
    from hash_artifact import build_manifest, parse_metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--metadata", action="append", default=[])
    arguments = parser.parse_args()

    if arguments.manifest.is_symlink() or not arguments.manifest.is_file():
        raise SystemExit("error: artifact manifest must be a regular non-symlink file")
    try:
        expected = json.loads(arguments.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"error: cannot parse artifact manifest: {error}") from error
    if not isinstance(expected, dict) or expected.get("algorithm") != "sha256-tree-v1":
        raise SystemExit("error: unsupported artifact manifest")

    actual = build_manifest(arguments.artifact)
    for key in ("root", "sha256", "entries"):
        if expected.get(key) != actual.get(key):
            raise SystemExit(f"error: artifact manifest {key} mismatch")
    metadata = expected.get("metadata")
    if not isinstance(metadata, dict):
        raise SystemExit("error: artifact manifest has no metadata object")
    for key, value in parse_metadata(arguments.metadata).items():
        if metadata.get(key) != value:
            raise SystemExit(f"error: artifact metadata {key} mismatch")
    print(f"artifact manifest verified: {arguments.artifact}")


if __name__ == "__main__":
    main()
