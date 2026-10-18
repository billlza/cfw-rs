from __future__ import annotations

from pathlib import Path
from typing import Any

from .cargo_collector import collect_cargo
from .common import PublicationError
from .go_collector import collect_go
from .graph_model import (
    RELEASE_VERSION,
    CollectedGraphs,
    ComponentSeed,
    canonical_graph_bytes,
    load_pins,
    merge_seed,
)
from .native_collector import collect_native, collect_toolchains
from .npm_collector import collect_npm


def collect_all(
    repository: Path,
    libbox_source: Path,
    release_environment: dict[str, str],
) -> CollectedGraphs:
    pins = load_pins(repository / "scripts/dependency_pins.env")
    components: dict[str, ComponentSeed] = {}
    relationships: set[tuple[str, str, str]] = set()
    graphs: dict[str, dict[str, Any]] = {}
    graph_components: dict[str, set[str]] = {}
    for result in (
        collect_cargo(repository, release_environment),
        collect_npm(repository),
        collect_go(repository, libbox_source, pins, release_environment),
        collect_native(repository, pins, release_environment),
    ):
        result_components, result_relationships, result_graphs, result_bindings = result
        for candidate in result_components.values():
            merge_seed(components, candidate)
        relationships.update(result_relationships)
        for kind, graph in result_graphs.items():
            if kind in graphs:
                raise PublicationError(f"duplicate collected graph kind: {kind}")
            graphs[kind] = graph
            graph_components[kind] = result_bindings[kind]
    toolchains, toolchain_relationships = collect_toolchains(
        repository, pins, release_environment
    )
    for candidate in toolchains.values():
        merge_seed(components, candidate)
    relationships.update(toolchain_relationships)
    return CollectedGraphs(components, relationships, graphs, graph_components)


__all__ = [
    "RELEASE_VERSION",
    "CollectedGraphs",
    "ComponentSeed",
    "canonical_graph_bytes",
    "collect_all",
    "collect_cargo",
    "collect_go",
    "collect_native",
    "collect_npm",
    "collect_toolchains",
    "load_pins",
]
