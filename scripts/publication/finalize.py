from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from .closure import MAX_GRAPH_BYTES, build_machine_closure, prepared_path
from .common import (
    PublicationError,
    canonical_json,
    enumerate_tree,
    read_regular,
    sha256_bytes,
    sha256_file,
    tree_digest,
    write_new,
)
from .legal_review import legal_review
from .release_contract import evidence_root, require_fixed_path
from .sbom import build_cyclonedx, build_spdx
from .source_archive import write_source_archive


def _copy_evidence_file(prepared: Path, staging: Path, relative: str, prefix: str) -> None:
    source = prepared_path(prepared, relative, prefix)
    destination = staging.joinpath(*Path(relative).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_new(destination, read_regular(source, MAX_GRAPH_BYTES))


def finalize(
    prepared: Path,
    app: Path,
    review_path: Path,
    output: Path,
    fixture: bool,
    *,
    repository: Path | None = None,
) -> None:
    if not fixture:
        if repository is None:
            raise PublicationError("production finalization requires an explicit artifact repository")
        require_fixed_path(
            output, evidence_root(repository), "publication evidence", repository=repository
        )
    machine = build_machine_closure(prepared, app, fixture, repository=repository)
    machine_bytes = canonical_json(machine)
    closure_digest = sha256_bytes(machine_bytes)
    component_ids = [item["id"] for item in machine["components"]]
    review = legal_review(review_path, closure_digest, component_ids, fixture)
    if output.exists() or output.is_symlink():
        raise PublicationError(f"refusing to replace publication evidence: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink():
        raise PublicationError("publication evidence output parent is a symlink")
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        write_new(staging / "machine-closure.json", machine_bytes)
        write_new(staging / "legal-review.json", canonical_json(review))
        for component in machine["components"]:
            for license_file in component["license_files"]:
                _copy_evidence_file(prepared, staging, license_file["path"], "licenses")
        for collection_name in ("artifacts", "graphs"):
            for item in machine[collection_name]:
                _copy_evidence_file(prepared, staging, item["path"], collection_name)

        source_manifest = machine["corresponding_source"]
        write_new(staging / "corresponding-source.manifest.json", canonical_json(source_manifest))
        write_source_archive(prepared / "source", staging / "corresponding-source.tar.gz")
        write_new(
            staging / "sbom.spdx.json",
            canonical_json(
                build_spdx(
                    machine["product"],
                    machine["components"],
                    machine["build_tools"],
                    machine["relationships"],
                )
            ),
        )
        write_new(
            staging / "sbom.cyclonedx.json",
            canonical_json(
                build_cyclonedx(
                    machine["product"],
                    machine["components"],
                    machine["build_tools"],
                    machine["relationships"],
                )
            ),
        )
        inventory = {
            "schema_version": 1,
            "fixture": fixture,
            "product": machine["product"],
            "bundle_build_number": machine["product"]["build_number"],
            "machine_closure_sha256": closure_digest,
            "app_tree_sha256": machine["app"]["sha256"],
            "corresponding_source_archive_sha256": sha256_file(
                staging / "corresponding-source.tar.gz"
            ),
            "corresponding_source_tree_sha256": source_manifest["sha256"],
            "spdx_sha256": sha256_file(staging / "sbom.spdx.json"),
            "cyclonedx_sha256": sha256_file(staging / "sbom.cyclonedx.json"),
            "legal_review_sha256": sha256_file(staging / "legal-review.json"),
        }
        write_new(staging / "inventory.json", canonical_json(inventory))
        entries = enumerate_tree(staging)
        write_new(
            staging / "evidence-manifest.json",
            canonical_json(
                {
                    "schema_version": 1,
                    "algorithm": "sha256-tree-v1",
                    "root": "publication-evidence",
                    "entries": entries,
                    "sha256": tree_digest(entries),
                }
            ),
        )
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
