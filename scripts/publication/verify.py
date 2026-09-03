from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from .closure import (
    MAX_GRAPH_BYTES,
    product,
    scan_app_code,
    validate_bound_files,
    validate_production_sets,
)
from .artifact_preparation import _artifact_sources
from .common import (
    PublicationError,
    canonical_json,
    enumerate_artifact_tree,
    enumerate_tree,
    load_json,
    read_regular,
    require_exact_keys,
    require_sha256,
    safe_relative,
    sha256_bytes,
    sha256_file,
    tree_digest,
)
from .legal_review import legal_review
from .release_contract import evidence_root, require_fixed_path, signed_app
from .sbom import (
    build_cyclonedx,
    build_spdx,
    reject_unreviewed_values,
    validate_build_tools,
    validate_components,
    validate_relationships,
)
from .source_archive import verify_source_archive
if __package__.startswith("scripts."):
    from scripts.release_build_identity import bundle_build_identity
else:
    from release_build_identity import bundle_build_identity


def _verify_evidence_manifest(root: Path) -> None:
    manifest = require_exact_keys(
        load_json(root / "evidence-manifest.json"),
        {"schema_version", "algorithm", "root", "entries", "sha256"},
        "publication evidence manifest",
    )
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["algorithm"] != "sha256-tree-v1"
        or manifest["root"] != "publication-evidence"
    ):
        raise PublicationError("unsupported publication evidence manifest")
    expected = manifest["entries"]
    if not isinstance(expected, list):
        raise PublicationError("publication evidence manifest entries are invalid")
    actual = [entry for entry in enumerate_tree(root) if entry["path"] != "evidence-manifest.json"]
    if actual != expected or tree_digest(actual) != require_sha256(manifest["sha256"], "evidence digest"):
        raise PublicationError("publication evidence was added, removed, or modified")


def _verify_component_sources(
    components: list[dict[str, Any]], source_manifest: dict[str, Any]
) -> None:
    entries = source_manifest.get("entries")
    if not isinstance(entries, list):
        raise PublicationError("corresponding-source manifest entries are invalid")
    directories = {
        str(entry.get("path"))
        for entry in entries
        if isinstance(entry, dict) and entry.get("type") == "directory"
    }
    for component in components:
        source_path = safe_relative(component["source_path"], "component source path")
        if source_path.parts[0] != "source" or len(source_path.parts) < 2:
            raise PublicationError("component source path escaped corresponding-source root")
        root = PurePosixPath(*source_path.parts[1:]).as_posix()
        if root not in directories:
            raise PublicationError(f"component source root is absent: {component['id']}")
        prefix = root + "/"
        subtree = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise PublicationError("corresponding-source manifest entry is invalid")
            path = entry.get("path")
            if not isinstance(path, str) or not path.startswith(prefix):
                continue
            copied = dict(entry)
            copied["path"] = path[len(prefix) :]
            subtree.append(copied)
        subtree.sort(key=lambda item: item["path"])
        if tree_digest(subtree) != component["source_sha256"]:
            raise PublicationError(f"component source digest is not bound to its archive: {component['id']}")


def _verify_artifact_inputs(
    repository: Path,
    root: Path,
    artifacts: list[dict[str, Any]],
    app: Path,
    build_number: str,
) -> None:
    from .release_contract import native_products_root

    expected = _artifact_sources(
        repository,
        native_products_root(repository, build_number),
        app,
        build_number,
        # This argument controls release_git reads. None selects that adapter's
        # fixed minimal environment, never the caller's ambient Git state.
        None,
    )
    by_kind = {item["kind"]: item for item in artifacts}
    if set(by_kind) != set(expected):
        raise PublicationError("native/libbox artifact manifest set is incomplete")
    for kind, current_path in expected.items():
        evidence_path = root.joinpath(*safe_relative(by_kind[kind]["path"]).parts)
        if read_regular(current_path, MAX_GRAPH_BYTES) != read_regular(evidence_path, MAX_GRAPH_BYTES):
            raise PublicationError(f"current {kind} differs from publication evidence")


def _verify_inventory(
    root: Path,
    inventory: dict[str, Any],
    machine: dict[str, Any],
    identity: dict[str, str],
    closure_digest: str,
    fixture: bool,
) -> None:
    app_manifest = machine["app"]
    if (
        type(inventory["schema_version"]) is not int
        or inventory["schema_version"] != 1
        or inventory["fixture"] is not fixture
        or inventory["product"] != identity
        or inventory["bundle_build_number"] != identity["build_number"]
        or inventory["machine_closure_sha256"] != closure_digest
        or inventory["app_tree_sha256"] != app_manifest["sha256"]
        or inventory["corresponding_source_tree_sha256"]
        != machine["corresponding_source"]["sha256"]
        or inventory["spdx_sha256"] != sha256_file(root / "sbom.spdx.json")
        or inventory["cyclonedx_sha256"] != sha256_file(root / "sbom.cyclonedx.json")
        or inventory["legal_review_sha256"] != sha256_file(root / "legal-review.json")
    ):
        raise PublicationError("publication inventory binding mismatch")


def verify_evidence(
    root: Path, app: Path, fixture: bool, *, repository: Path | None = None
) -> None:
    _verify_evidence_manifest(root)
    machine = require_exact_keys(
        load_json(root / "machine-closure.json"),
        {
            "schema_version",
            "fixture",
            "product",
            "app",
            "components",
            "build_tools",
            "relationships",
            "artifacts",
            "graphs",
            "corresponding_source",
        },
        "machine closure",
    )
    if (
        type(machine["schema_version"]) is not int
        or machine["schema_version"] != 1
        or machine["fixture"] is not fixture
    ):
        raise PublicationError("machine closure mode/version mismatch")
    identity = product(machine["product"], fixture)
    if not fixture:
        app_identity = bundle_build_identity(app)
        if (
            app_identity.product_version != identity["version"]
            or app_identity.build_version != identity["build_number"]
        ):
            raise PublicationError("signed app build identity differs from publication evidence")
    components = validate_components(machine["components"])
    build_tools = validate_build_tools(machine["build_tools"])
    component_ids = {item["id"] for item in [*components, *build_tools]}
    relationships = validate_relationships(machine["relationships"], component_ids)
    closure_digest = sha256_bytes(canonical_json(machine))
    legal_review(
        root / "legal-review.json", closure_digest, [item["id"] for item in components], fixture
    )
    app_entries = enumerate_artifact_tree(app)
    app_manifest = require_exact_keys(machine["app"], {"root", "entries", "sha256"}, "app closure")
    if (
        app_manifest["root"] != app.name
        or app_entries != app_manifest["entries"]
        or tree_digest(app_entries) != require_sha256(app_manifest["sha256"], "app tree digest")
    ):
        raise PublicationError("signed app differs from publication evidence")
    scan_app_code(app, fixture)
    for component in components:
        for license_file in component["license_files"]:
            path = root.joinpath(*safe_relative(license_file["path"]).parts)
            if sha256_file(path) != license_file["sha256"]:
                raise PublicationError("license text differs from its component binding")
    artifacts = validate_bound_files(machine["artifacts"], "artifacts", component_ids)
    graphs = validate_bound_files(machine["graphs"], "graphs", component_ids)
    if not fixture:
        validate_production_sets(components, build_tools, artifacts, graphs)
    for collection_name, collection in (("artifacts", artifacts), ("graphs", graphs)):
        for item in collection:
            path = root.joinpath(*safe_relative(item["path"]).parts)
            if sha256_file(path) != item["sha256"]:
                raise PublicationError(f"{collection_name} evidence differs from its binding")
    if not fixture:
        if repository is None:
            repository = Path(__file__).resolve().parent.parent.parent
        _verify_artifact_inputs(
            repository,
            root,
            artifacts,
            app,
            identity["build_number"],
        )

    spdx = load_json(root / "sbom.spdx.json")
    cyclonedx = load_json(root / "sbom.cyclonedx.json")
    reject_unreviewed_values(spdx)
    reject_unreviewed_values(cyclonedx)
    if spdx != build_spdx(identity, components, build_tools, relationships):
        raise PublicationError("SPDX SBOM differs from the reviewed machine closure")
    if cyclonedx != build_cyclonedx(identity, components, build_tools, relationships):
        raise PublicationError("CycloneDX SBOM differs from the reviewed machine closure")
    inventory = require_exact_keys(
        load_json(root / "inventory.json"),
        {
            "schema_version",
            "fixture",
            "product",
            "bundle_build_number",
            "machine_closure_sha256",
            "app_tree_sha256",
            "corresponding_source_archive_sha256",
            "corresponding_source_tree_sha256",
            "spdx_sha256",
            "cyclonedx_sha256",
            "legal_review_sha256",
        },
        "publication inventory",
    )
    _verify_inventory(root, inventory, machine, identity, closure_digest, fixture)
    source_manifest = load_json(root / "corresponding-source.manifest.json")
    if source_manifest != machine["corresponding_source"]:
        raise PublicationError("corresponding-source manifest differs from the machine closure")
    _verify_component_sources(components, source_manifest)
    verify_source_archive(
        root / "corresponding-source.tar.gz",
        source_manifest,
        inventory["corresponding_source_archive_sha256"],
    )


def verify(
    root: Path, app: Path, fixture: bool, *, repository: Path | None = None
) -> None:
    root = root.resolve(strict=True)
    app = app.resolve(strict=True)
    if not fixture:
        if repository is None:
            repository = Path(__file__).resolve().parent.parent.parent
        require_fixed_path(root, evidence_root(repository), "publication evidence")
        require_fixed_path(app, signed_app(repository), "signed app")
    verify_evidence(root, app, fixture, repository=repository)
