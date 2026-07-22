from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from .cargo_collector import CollectorResult
from .common import PublicationError, load_json
from .graph_model import ComponentSeed, RELEASE_VERSION, merge_seed, seed


def _package_name(input_path: str) -> str | None:
    parts = PurePosixPath(input_path).parts
    indexes = [index for index, part in enumerate(parts) if part == "node_modules"]
    if not indexes:
        return None
    index = indexes[-1] + 1
    if index >= len(parts):
        return None
    if parts[index].startswith("@"):
        if index + 1 >= len(parts):
            return None
        return f"{parts[index]}/{parts[index + 1]}"
    return parts[index]


def _npm_seed(name: str, package: dict[str, Any], shell_root: Path, scope: str) -> ComponentSeed:
    version = str(package.get("version") or RELEASE_VERSION)
    purl = f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='.+-')}"
    source_root = (
        shell_root
        if name == "cfw-tauri-shell-ui"
        else shell_root / "node_modules" / name
    ).resolve(strict=True)
    external_build_tool = name in {"esbuild", "@esbuild/darwin-arm64"}
    corresponding_source = None if external_build_tool else source_root
    license_root = (
        shell_root / "node_modules/esbuild"
        if name == "@esbuild/darwin-arm64"
        else (shell_root.parent.parent if name == "cfw-tauri-shell-ui" else source_root)
    )
    return seed(
        name,
        version,
        "npm",
        scope,
        purl,
        corresponding_source,
        name == "cfw-tauri-shell-ui",
        license_root=license_root,
        metadata_path=source_root / "package.json",
        declared_license=package.get("license"),
        external_build_tool=external_build_tool,
        provenance_paths=((source_root / "bin/esbuild",) if external_build_tool else ()),
    )


def collect_npm(repository: Path) -> CollectorResult:
    shell_root = repository / "apps/cfw-tauri-shell"
    lock = load_json(shell_root / "package-lock.json")
    metadata = load_json(repository / "target/ui-build/esbuild-meta.json")
    if not isinstance(lock, dict) or lock.get("lockfileVersion") != 3:
        raise PublicationError("npm release graph requires package-lock v3")
    if not isinstance(metadata, dict) or set(metadata) != {"schemaVersion", "tool", "metafile"}:
        raise PublicationError("esbuild metadata wrapper is invalid")
    if metadata["schemaVersion"] != 1 or not isinstance(metadata["metafile"], dict):
        raise PublicationError("esbuild metadata version is invalid")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise PublicationError("npm lockfile has no package inventory or root")
    tool = metadata["tool"]
    esbuild_locked = packages.get("node_modules/esbuild")
    if (
        not isinstance(tool, dict)
        or tool.get("name") != "esbuild"
        or not isinstance(esbuild_locked, dict)
        or tool.get("version") != esbuild_locked.get("version")
    ):
        raise PublicationError("esbuild metadata does not match the exact npm lock")
    inputs = metadata["metafile"].get("inputs")
    if not isinstance(inputs, dict) or not inputs:
        raise PublicationError("esbuild metadata has no bundled inputs")
    runtime_names = {_package_name(path) for path in inputs}
    runtime_names.discard(None)
    build_names = {"esbuild", "@esbuild/darwin-arm64"}
    names = {"cfw-tauri-shell-ui"} | runtime_names | build_names
    components: dict[str, ComponentSeed] = {}
    name_to_id: dict[str, str] = {}
    for name in sorted(names):
        key = "" if name == "cfw-tauri-shell-ui" else f"node_modules/{name}"
        package = packages.get(key)
        if not isinstance(package, dict):
            raise PublicationError(f"npm exact bundle references an unlocked package: {name}")
        scope = "runtime" if name == "cfw-tauri-shell-ui" or name in runtime_names else "build"
        candidate = _npm_seed(name, package, shell_root, scope)
        merge_seed(components, candidate)
        name_to_id[name] = candidate.identifier
    root_id = name_to_id["cfw-tauri-shell-ui"]
    relationships = {
        (
            root_id if name in runtime_names else name_to_id[name],
            name_to_id[name] if name in runtime_names else root_id,
            "DEPENDS_ON" if name in runtime_names else "BUILD_DEPENDENCY_OF",
        )
        for name in names
        if name != "cfw-tauri-shell-ui"
    }
    component_ids = set(name_to_id.values())
    return (
        components,
        relationships,
        {"npm-esbuild-meta": metadata, "npm-lock": lock},
        {"npm-esbuild-meta": component_ids, "npm-lock": component_ids},
    )
