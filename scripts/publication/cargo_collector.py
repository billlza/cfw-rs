from __future__ import annotations

import os
from collections import deque
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import quote

from .common import PublicationError
from .graph_model import ComponentSeed, merge_seed, run_json, seed

if __package__ and __package__.startswith("scripts."):
    from scripts.release_cargo_inputs import (
        CRATES_IO_SOURCE,
        ReleaseCargoInputsError,
        create_runtime_cargo_home,
        verify_runtime_cargo_home,
        verify_workspace_cargo_inputs,
    )
else:
    from release_cargo_inputs import (
        CRATES_IO_SOURCE,
        ReleaseCargoInputsError,
        create_runtime_cargo_home,
        verify_runtime_cargo_home,
        verify_workspace_cargo_inputs,
    )


CollectorResult = tuple[
    dict[str, ComponentSeed],
    set[tuple[str, str, str]],
    dict[str, dict[str, Any]],
    dict[str, set[str]],
]


def _cargo_seed(package: dict[str, Any], repository: Path, scope: str) -> ComponentSeed:
    name = str(package["name"])
    version = str(package["version"])
    checksum = package.get("checksum")
    qualifier = f"?checksum={checksum}" if isinstance(checksum, str) and checksum else ""
    purl = f"pkg:cargo/{quote(name, safe='')}@{quote(version, safe='.+-')}{qualifier}"
    manifest = Path(str(package["manifest_path"])).resolve(strict=True)
    source_root = manifest.parent
    try:
        source_root.relative_to(repository)
        repository_source = True
    except ValueError:
        repository_source = False
    return seed(
        name,
        version,
        "cargo",
        scope,
        purl,
        source_root,
        repository_source,
        license_root=repository if repository_source else source_root,
        metadata_path=manifest,
        declared_license=package.get("license"),
    )


def collect_cargo(
    repository: Path, release_environment: dict[str, str]
) -> CollectorResult:
    repository = repository.resolve(strict=True)
    environment = dict(release_environment)
    environment["CARGO_NET_OFFLINE"] = "true"
    try:
        cargo = Path(environment["CFW_RELEASE_CARGO_EXECUTABLE"])
    except KeyError as error:
        raise PublicationError("release environment omitted its Cargo executable") from error
    if not cargo.exists() or not os.access(cargo, os.X_OK):
        raise PublicationError("trusted Cargo executable is unavailable")
    try:
        workspace_inputs = verify_workspace_cargo_inputs(
            repository,
            Path(environment["CFW_RELEASE_CARGO_INPUT_ROOT"]),
        )
        with tempfile.TemporaryDirectory(prefix="cfw-cargo-collector.") as temporary:
            cargo_home = Path(temporary) / "cargo-home"
            cargo_home.mkdir(mode=0o700)
            create_runtime_cargo_home(repository, workspace_inputs, cargo_home)
            cargo_environment = dict(environment)
            cargo_environment["CARGO_HOME"] = str(cargo_home)
            cargo_environment["CARGO_NET_OFFLINE"] = "true"
            metadata = run_json(
                [
                    str(cargo),
                    "metadata",
                    "--locked",
                    "--offline",
                    "--filter-platform",
                    "aarch64-apple-darwin",
                    "--format-version",
                    "1",
                ],
                repository,
                cargo_environment,
            )
            verify_runtime_cargo_home(repository, workspace_inputs, cargo_home)
            ending_inputs = verify_workspace_cargo_inputs(
                repository,
                Path(environment["CFW_RELEASE_CARGO_INPUT_ROOT"]),
            )
        if ending_inputs != workspace_inputs:
            raise PublicationError(
                "verified Cargo workspace inputs changed during metadata collection"
            )
    except (KeyError, OSError, ReleaseCargoInputsError) as error:
        raise PublicationError(
            "Cargo metadata did not use the verified workspace input boundary"
        ) from error
    raw_packages = metadata.get("packages", [])
    if not isinstance(raw_packages, list):
        raise PublicationError("Cargo metadata package inventory is malformed")
    for package in raw_packages:
        if not isinstance(package, dict):
            raise PublicationError("Cargo metadata contains a malformed package")
        try:
            manifest = Path(str(package["manifest_path"])).resolve(strict=True)
        except (KeyError, OSError) as error:
            raise PublicationError("Cargo metadata package manifest is unavailable") from error
        source = package.get("source")
        expected_root = repository if source is None else workspace_inputs.vendor
        if source is not None and source != CRATES_IO_SOURCE:
            raise PublicationError("Cargo metadata contains an unverified external source")
        try:
            manifest.relative_to(expected_root)
        except ValueError as error:
            label = "repository" if source is None else "verified vendor"
            raise PublicationError(
                f"Cargo metadata package escaped the {label} source root"
            ) from error
    packages = {str(package["id"]): package for package in raw_packages}
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict):
        raise PublicationError("Cargo metadata has no resolved graph")
    nodes = {str(node["id"]): node for node in resolve.get("nodes", [])}
    roots = [
        identifier
        for identifier, package in packages.items()
        if package.get("name") == "cfw-tauri-shell"
    ]
    if len(roots) != 1:
        raise PublicationError("Cargo graph does not have exactly one cfw-tauri-shell root")
    root = roots[0]
    contexts: dict[str, set[str]] = {}
    edges: set[tuple[str, str, str]] = set()
    queue: deque[tuple[str, str]] = deque([(root, "runtime")])
    while queue:
        package_id, context = queue.popleft()
        if package_id not in packages or package_id not in nodes:
            raise PublicationError("Cargo resolve graph references an absent package")
        known = contexts.setdefault(package_id, set())
        if context in known:
            continue
        known.add(context)
        for dependency in nodes[package_id].get("deps", []):
            child = str(dependency.get("pkg"))
            if child not in packages:
                raise PublicationError("Cargo dependency references an absent package")
            kinds = dependency.get("dep_kinds") or [{"kind": None}]
            for kind_entry in kinds:
                kind = kind_entry.get("kind")
                if kind == "dev":
                    continue
                child_is_macro = any(
                    "proc-macro" in target.get("kind", [])
                    for target in packages[child].get("targets", [])
                )
                child_context = (
                    "build"
                    if context == "build" or kind == "build" or child_is_macro
                    else "runtime"
                )
                edges.add((package_id, child, child_context))
                queue.append((child, child_context))

    components: dict[str, ComponentSeed] = {}
    package_to_component: dict[str, str] = {}
    for package_id, package_contexts in contexts.items():
        scope = "runtime" if "runtime" in package_contexts else "build"
        candidate = _cargo_seed(packages[package_id], repository, scope)
        merge_seed(components, candidate)
        package_to_component[package_id] = candidate.identifier

    relationships: set[tuple[str, str, str]] = set()
    graph_edges: dict[str, set[tuple[str, str]]] = {"runtime": set(), "build": set()}
    for parent, child, context in edges:
        parent_component = package_to_component[parent]
        child_component = package_to_component[child]
        graph_edges[context].add((parent_component, child_component))
        relation = (
            (parent_component, child_component, "DEPENDS_ON")
            if context == "runtime"
            else (child_component, parent_component, "BUILD_DEPENDENCY_OF")
        )
        relationships.add(relation)

    graphs: dict[str, dict[str, Any]] = {}
    graph_components: dict[str, set[str]] = {}
    for context, kind in (("runtime", "cargo-runtime-graph"), ("build", "cargo-build-graph")):
        component_ids = {
            package_to_component[package_id]
            for package_id, package_contexts in contexts.items()
            if context in package_contexts
        }
        graphs[kind] = {
            "schema_version": 1,
            "target": "aarch64-apple-darwin",
            "root": package_to_component[root],
            "nodes": sorted(component_ids),
            "edges": [
                {"source": source, "target": target}
                for source, target in sorted(graph_edges[context])
            ],
        }
        graph_components[kind] = component_ids
    return components, relationships, graphs, graph_components
