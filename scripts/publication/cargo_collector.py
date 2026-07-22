from __future__ import annotations

import os
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .common import PublicationError
from .graph_model import ComponentSeed, merge_seed, run_json, seed


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


def collect_cargo(repository: Path) -> CollectorResult:
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    metadata = run_json(
        [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--filter-platform",
            "aarch64-apple-darwin",
            "--format-version",
            "1",
        ],
        repository,
        environment,
    )
    packages = {str(package["id"]): package for package in metadata.get("packages", [])}
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
