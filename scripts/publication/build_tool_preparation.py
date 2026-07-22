from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from typing import Any

from .common import PublicationError, require_sha256
from .graph_model import ComponentSeed
from .license_resolution import canonical_spdx_expression
from .source_preparation import source_input_evidence


def _external_file_identity(path: Path) -> tuple[int, str]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise PublicationError(f"build-tool executable is not a regular file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise PublicationError(f"build-tool executable changed while opening: {path}")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise PublicationError(f"build-tool executable changed while hashing: {path}")
    return opened.st_size, digest.hexdigest()


def _license_provenance(seed: ComponentSeed, resolution: dict[str, Any]) -> dict[str, Any]:
    expression = resolution.get("expression") or seed.declared_license
    if not isinstance(expression, str):
        raise PublicationError(f"external build tool lacks a license reference: {seed.identifier}")
    expression = canonical_spdx_expression(expression)
    metadata = resolution.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != {"path", "sha256"}:
        raise PublicationError(f"external build tool lacks identity metadata: {seed.identifier}")
    metadata_sha256 = require_sha256(
        metadata["sha256"], f"external build-tool metadata for {seed.identifier}"
    )
    raw_files = resolution.get("files")
    if not isinstance(raw_files, list):
        raise PublicationError(f"external build-tool license evidence is malformed: {seed.identifier}")
    evidence = []
    for item in raw_files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "supports"}:
            raise PublicationError(
                f"external build-tool license evidence is malformed: {seed.identifier}"
            )
        path = Path(item["path"])
        evidence.append(
            {
                "name": path.name,
                "sha256": require_sha256(
                    item["sha256"], f"external build-tool license for {seed.identifier}"
                ),
            }
        )
    return {
        "license_reference": expression,
        "license_evidence": sorted(
            evidence, key=lambda item: (item["name"], item["sha256"])
        ),
        "identity_metadata_sha256": metadata_sha256,
    }


def build_tool_specs(
    repository: Path,
    seeds: dict[str, ComponentSeed],
    reviews: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    output = []
    for identifier in sorted(seeds):
        seed = seeds[identifier]
        if not seed.external_build_tool:
            continue
        review = reviews[identifier]
        expected_source = source_input_evidence(repository, seed, seed.source_root)
        if review["source_evidence"] != expected_source:
            raise PublicationError(f"external build-tool evidence drifted: {identifier}")
        executables = []
        for index, path in enumerate(seed.provenance_paths):
            size, digest = _external_file_identity(path)
            executables.append(
                {
                    "name": f"executable-{index}-{path.name}",
                    "size": size,
                    "sha256": digest,
                }
            )
        if not executables:
            raise PublicationError(f"external build tool has no executable provenance: {identifier}")
        output.append(
            {
                "id": identifier,
                "name": seed.name,
                "version": seed.version,
                "ecosystem": seed.ecosystem,
                "scope": seed.scope,
                "purl": seed.purl,
                "distribution": "external-build-tool-not-distributed",
                **_license_provenance(seed, review["license_resolution"]),
                "executables": executables,
            }
        )
    return output
