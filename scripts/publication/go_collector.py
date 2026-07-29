from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import quote

from .cargo_collector import CollectorResult
from .common import PublicationError
from .graph_model import ComponentSeed, MAX_COMMAND_BYTES, merge_seed, run, seed
from .release_toolchains import verified_release_toolchain_trees


_PINNED_GO_LICENSES = {
    ("github.com/klauspost/compress", "v1.18.0"): (
        "BSD-3-Clause AND Apache-2.0 AND MIT"
    ),
}


def _decode_json_stream(payload: bytes) -> list[dict[str, Any]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PublicationError("Go package graph is not UTF-8") from error
    decoder = json.JSONDecoder()
    offset = 0
    values: list[dict[str, Any]] = []
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError as error:
            raise PublicationError("Go package graph is not a JSON object stream") from error
        if not isinstance(value, dict):
            raise PublicationError("Go package graph contains a non-object")
        values.append(value)
    return values


def _module_identity(
    module: dict[str, Any], pins: dict[str, str]
) -> tuple[str, str, Path, Path]:
    effective = module.get("Replace") if isinstance(module.get("Replace"), dict) else module
    path = str(effective.get("Path") or module.get("Path") or "")
    version = str(effective.get("Version") or module.get("Version") or "")
    if module.get("Main") is True:
        path = str(module.get("Path"))
        version = pins["SING_BOX_VERSION"]
    if not path or not version:
        raise PublicationError("Go linked module lacks a versioned effective identity")
    directory = effective.get("Dir") or module.get("Dir")
    go_mod = effective.get("GoMod") or module.get("GoMod")
    if not isinstance(directory, str):
        raise PublicationError(f"Go linked module has no source directory: {path}")
    if not isinstance(go_mod, str):
        raise PublicationError(f"Go linked module has no identity metadata: {path}")
    return path, version, Path(directory).resolve(strict=True), Path(go_mod).resolve(strict=True)


def _environment(
    repository: Path,
    pins: dict[str, str],
    go_cache: Path,
) -> tuple[Path, dict[str, str]]:
    toolchain_root, _tree_digests = verified_release_toolchain_trees(repository, pins)
    go_bin = toolchain_root / f"go-{pins['GO_VERSION']}" / "bin/go"
    if not go_bin.is_file() or go_bin.is_symlink():
        raise PublicationError("pinned Go toolchain is unavailable for linked-package collection")
    environment = os.environ.copy()
    for key in list(environment):
        if key.startswith("GO") or key in {"AR", "CC", "CXX", "PKG_CONFIG", "SDKROOT"}:
            environment.pop(key, None)
    go_workspace = toolchain_root / "go-workspace"
    environment.update(
        {
            "GOARCH": "arm64",
            "GOENV": "off",
            "GOFLAGS": "-mod=readonly -trimpath",
            "GOOS": "darwin",
            "GOPATH": str(go_workspace),
            "GOMODCACHE": str(go_workspace / "pkg/mod"),
            "GOCACHE": str(go_cache),
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOTELEMETRY": "off",
            "GOWORK": "off",
            "GOVCS": "*:off",
        }
    )
    return go_bin, environment


def collect_go(repository: Path, libbox_source: Path, pins: dict[str, str]) -> CollectorResult:
    cache_parent = repository / "target/release-build-cache"
    cache_parent.mkdir(parents=True, exist_ok=True)
    if cache_parent.is_symlink() or not cache_parent.is_dir():
        raise PublicationError("Go collector cache parent must be a real directory")
    with tempfile.TemporaryDirectory(prefix="go-collector.", dir=cache_parent) as temporary:
        go_bin, environment = _environment(repository, pins, Path(temporary))
        payload = run(
            [
                str(go_bin),
                "list",
                "-deps",
                "-json",
                f"-tags={pins['LIBBOX_BUILD_TAGS']}",
                "./experimental/libbox",
            ],
            libbox_source,
            environment,
        )
    verified_release_toolchain_trees(repository, pins)
    if len(payload) > MAX_COMMAND_BYTES:
        raise PublicationError("Go linked-package graph exceeded its fixed bound")
    packages = _decode_json_stream(payload)
    components: dict[str, ComponentSeed] = {}
    package_to_component: dict[str, str] = {}
    module_records: dict[str, dict[str, Any]] = {}
    main_source: Path | None = None
    for package in packages:
        import_path = package.get("ImportPath")
        module = package.get("Module")
        if not isinstance(import_path, str):
            raise PublicationError("Go package graph lacks an import path")
        if not isinstance(module, dict):
            continue
        module_path, version, source_root, metadata_path = _module_identity(module, pins)
        purl = f"pkg:golang/{quote(module_path, safe='/')}@{quote(version, safe='.+-')}"
        candidate = seed(
            module_path,
            version,
            "go",
            "runtime",
            purl,
            source_root,
            license_root=source_root,
            metadata_path=metadata_path,
            declared_license=_PINNED_GO_LICENSES.get((module_path, version)),
        )
        merge_seed(components, candidate)
        package_to_component[import_path] = candidate.identifier
        module_records[candidate.identifier] = {
            "id": candidate.identifier,
            "path": module_path,
            "version": version,
        }
        if module.get("Main") is True:
            main_source = source_root
    if main_source != libbox_source.resolve(strict=True):
        raise PublicationError("Go linked graph main module is not the supplied pinned libbox source")

    relationships: set[tuple[str, str, str]] = set()
    package_records = []
    for package in packages:
        import_path = package.get("ImportPath")
        imports = package.get("Imports") or []
        if not isinstance(import_path, str) or not isinstance(imports, list):
            raise PublicationError("Go linked package graph is malformed")
        component = package_to_component.get(import_path)
        linked_imports = sorted(value for value in imports if isinstance(value, str))
        if component is not None:
            for dependency in linked_imports:
                dependency_component = package_to_component.get(dependency)
                if dependency_component is not None and dependency_component != component:
                    relationships.add((component, dependency_component, "DEPENDS_ON"))
        package_records.append(
            {"import_path": import_path, "module_id": component, "imports": linked_imports}
        )
    graph = {
        "schema_version": 1,
        "target": "darwin-arm64",
        "tags": pins["LIBBOX_BUILD_TAGS"].split(","),
        "modules": [module_records[key] for key in sorted(module_records)],
        "packages": sorted(package_records, key=lambda item: item["import_path"]),
    }
    component_ids = set(components)
    return (
        components,
        relationships,
        {"go-linked-packages": graph},
        {"go-linked-packages": component_ids},
    )
