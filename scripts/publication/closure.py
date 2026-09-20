from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from .common import (
    PublicationError,
    enumerate_artifact_tree,
    enumerate_tree,
    load_json,
    read_prefix,
    require_exact_keys,
    require_sha256,
    safe_identifier,
    safe_relative,
    sha256_file,
    tree_digest,
)
from .release_contract import (
    PRODUCT_NAME,
    RELEASE_VERSION,
    prepared_root,
    require_fixed_path,
    signed_app,
)
from .sbom import (
    ALLOWED_ECOSYSTEMS,
    ALLOWED_SCOPES,
    EXPECTED_BUILD_TOOLS,
    validate_build_tools,
    validate_components,
    validate_relationships,
)
from .source_archive import build_source_manifest
if __package__.startswith("scripts."):
    from scripts.release_build_identity import bundle_build_identity, canonical_build_version
else:
    from release_build_identity import bundle_build_identity, canonical_build_version


MAX_COMPONENTS = 10_000
MAX_GRAPH_BYTES = 256 * 1024 * 1024
REQUIRED_ECOSYSTEMS = {"application", "cargo", "npm", "go", "swift", "native"}
REQUIRED_GRAPH_KINDS = {
    "cargo-runtime-graph",
    "cargo-build-graph",
    "npm-esbuild-meta",
    "npm-lock",
    "go-linked-packages",
    "swift-package",
    "xcode-modules",
}
REQUIRED_ARTIFACT_KINDS = {
    "candidate-freeze-intent",
    "ga-product-input",
    "libbox-manifest",
    "legacy-tombstone-manifest",
    "native-host-bridge-manifest",
    "native-proxy-agent-manifest",
    "native-packet-tunnel-manifest",
    "notarization-result",
    "notarization-submission-manifest",
    "signed-app-manifest",
    "signing-transformation",
    "hosted-ci-receipt",
}
ALLOWED_CODE_PATHS = {
    "Contents/MacOS/clash-for-mac",
    "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/CFWNativeBridge",
    "Contents/Library/HelperTools/CFWGlobalAuthority",
    "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent",
    "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension/Contents/MacOS/CFWPacketTunnel",
    "Contents/Library/HelperTools/cfw-helper-tombstone",
}
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


def product(value: object, fixture: bool) -> dict[str, str]:
    identity = require_exact_keys(
        value, {"name", "version", "build_number"}, "publication product"
    )
    if not all(isinstance(identity[field], str) and identity[field] for field in identity):
        raise PublicationError("publication product identity is invalid")
    canonical_build_version(identity["build_number"], "publication product build_number")
    if not fixture and (
        identity["name"] != PRODUCT_NAME or identity["version"] != RELEASE_VERSION
    ):
        raise PublicationError("publication evidence is not for the fixed 0.4.0 product")
    return {
        "name": identity["name"],
        "version": identity["version"],
        "build_number": identity["build_number"],
    }


def prepared_path(root: Path, relative: str, prefix: str) -> Path:
    parsed = safe_relative(relative)
    if parsed.parts[0] != prefix:
        raise PublicationError(f"prepared path must live under {prefix}/: {relative}")
    candidate = root.joinpath(*parsed.parts)
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise PublicationError("prepared path escaped its root") from error
    return candidate


def _normalize_components(prepared: Path, raw_components: object) -> list[dict[str, Any]]:
    if not isinstance(raw_components, list) or not raw_components or len(raw_components) > MAX_COMPONENTS:
        raise PublicationError("prepared component set is empty or exceeds its bound")
    normalized = []
    fields = {
        "id",
        "name",
        "version",
        "ecosystem",
        "scope",
        "purl",
        "license_expression",
        "copyright_text",
        "license_files",
        "source_path",
    }
    for index, raw in enumerate(raw_components):
        item = require_exact_keys(raw, fields, f"prepared component[{index}]")
        component_id = safe_identifier(item["id"], f"prepared component[{index}].id")
        if item["ecosystem"] not in ALLOWED_ECOSYSTEMS or item["scope"] not in ALLOWED_SCOPES:
            raise PublicationError(f"prepared component {component_id} has invalid classification")
        source_path = safe_identifier(item["source_path"], f"prepared component {component_id}.source_path")
        source_entries = enumerate_tree(prepared_path(prepared, source_path, "source"))
        license_paths = item["license_files"]
        if not isinstance(license_paths, list) or not license_paths:
            raise PublicationError(f"prepared component {component_id} has no license files")
        licenses = []
        for license_path in license_paths:
            bounded = safe_identifier(license_path, f"prepared component {component_id} license path")
            licenses.append(
                {
                    "path": bounded,
                    "sha256": sha256_file(prepared_path(prepared, bounded, "licenses")),
                }
            )
        normalized.append(
            {
                **{key: item[key] for key in fields - {"license_files", "source_path"}},
                "license_files": sorted(licenses, key=lambda value: value["path"]),
                "source_path": source_path,
                "source_sha256": tree_digest(source_entries),
            }
        )
    return validate_components(sorted(normalized, key=lambda value: value["id"]))


def _normalize_files(prepared: Path, value: object, prefix: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise PublicationError(f"{prefix} inputs are not an array")
    normalized = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        item = require_exact_keys(raw, {"id", "kind", "path", "component_ids"}, f"{prefix}[{index}]")
        identifier = safe_identifier(item["id"], f"{prefix}[{index}].id")
        kind = safe_identifier(item["kind"], f"{prefix}[{index}].kind")
        path = safe_identifier(item["path"], f"{prefix}[{index}].path")
        if any(part.casefold() == "reverse" for part in safe_relative(path).parts):
            raise PublicationError("reference-only reverse payload is forbidden")
        component_ids = item["component_ids"]
        if not isinstance(component_ids, list) or not component_ids:
            raise PublicationError(f"{prefix} input has no component binding")
        component_ids = sorted(
            safe_identifier(component_id, f"{prefix}[{index}].component_id")
            for component_id in component_ids
        )
        if identifier in seen:
            raise PublicationError(f"duplicate {prefix} input: {identifier}")
        seen.add(identifier)
        normalized.append(
            {
                "id": identifier,
                "kind": kind,
                "path": path,
                "sha256": sha256_file(prepared_path(prepared, path, prefix)),
                "component_ids": component_ids,
            }
        )
    return sorted(normalized, key=lambda item: item["id"])


def validate_production_sets(
    components: list[dict[str, Any]],
    build_tools: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    graphs: list[dict[str, Any]],
) -> None:
    ecosystems = {item["ecosystem"] for item in components}
    if ecosystems != REQUIRED_ECOSYSTEMS:
        raise PublicationError(
            "production ecosystem closure is incomplete or unknown; "
            f"missing={sorted(REQUIRED_ECOSYSTEMS - ecosystems)}, "
            f"extra={sorted(ecosystems - REQUIRED_ECOSYSTEMS)}"
        )
    build_tool_names = {item["name"] for item in build_tools}
    if build_tool_names != EXPECTED_BUILD_TOOLS or len(build_tools) != len(EXPECTED_BUILD_TOOLS):
        raise PublicationError("external build-tool provenance closure is incomplete or duplicated")
    artifact_kinds = [item["kind"] for item in artifacts]
    if len(artifact_kinds) != len(REQUIRED_ARTIFACT_KINDS) or set(artifact_kinds) != REQUIRED_ARTIFACT_KINDS:
        raise PublicationError("production native/libbox artifact closure is incomplete or duplicated")
    graph_kinds = [item["kind"] for item in graphs]
    if len(graph_kinds) != len(REQUIRED_GRAPH_KINDS) or set(graph_kinds) != REQUIRED_GRAPH_KINDS:
        raise PublicationError("production build graph closure is incomplete or duplicated")


def scan_app_code(app: Path, fixture: bool) -> None:
    if fixture:
        return
    observed: set[str] = set()
    for current, directories, files in os.walk(app, topdown=True, followlinks=False):
        for name in directories:
            if name.casefold() == "reverse":
                raise PublicationError("reference-only reverse payload is present in the app")
        directories[:] = sorted(name for name in directories if not (Path(current) / name).is_symlink())
        for name in sorted(files):
            path = Path(current) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise PublicationError(f"unsupported app entry type: {path}")
            relative = path.relative_to(app).as_posix()
            magic = read_prefix(path, 4)
            is_binary = magic in MACHO_MAGICS or magic.startswith(b"MZ") or magic == b"\x7fELF"
            if is_binary or metadata.st_mode & 0o111:
                if relative not in ALLOWED_CODE_PATHS:
                    raise PublicationError(f"unknown executable or binary in signed app: {relative}")
                observed.add(relative)
    if observed != ALLOWED_CODE_PATHS:
        raise PublicationError(f"signed app code closure is incomplete: {sorted(ALLOWED_CODE_PATHS - observed)}")


def build_machine_closure(
    prepared: Path, app: Path, fixture: bool, *, repository: Path | None = None
) -> dict[str, Any]:
    if not fixture:
        if repository is None:
            raise PublicationError("production closure requires an explicit artifact repository")
        require_fixed_path(
            prepared, prepared_root(repository), "prepared evidence", repository=repository
        )
        require_fixed_path(app, signed_app(repository), "signed app", repository=repository)
    specification = require_exact_keys(
        load_json(prepared / "closure-components.json"),
        {
            "schema_version",
            "fixture",
            "product",
            "components",
            "build_tools",
            "relationships",
            "artifacts",
            "graphs",
        },
        "prepared publication closure",
    )
    if (
        type(specification["schema_version"]) is not int
        or specification["schema_version"] != 1
        or specification["fixture"] is not fixture
    ):
        raise PublicationError("prepared publication closure mode/version mismatch")
    identity = product(specification["product"], fixture)
    components = _normalize_components(prepared, specification["components"])
    build_tools = validate_build_tools(specification["build_tools"])
    component_ids = {item["id"] for item in [*components, *build_tools]}
    relationships = validate_relationships(specification["relationships"], component_ids)
    artifacts = _normalize_files(prepared, specification["artifacts"], "artifacts")
    graphs = _normalize_files(prepared, specification["graphs"], "graphs")
    for item in artifacts + graphs:
        if not set(item["component_ids"]).issubset(component_ids):
            raise PublicationError("publication input binds an absent component")
    if not fixture:
        validate_production_sets(components, build_tools, artifacts, graphs)
        current_identity = bundle_build_identity(app)
        if (
            current_identity.product_version != identity["version"]
            or current_identity.build_version != identity["build_number"]
        ):
            raise PublicationError("signed app bundle identity differs from publication product")
    scan_app_code(app, fixture)
    app_entries = enumerate_artifact_tree(app)
    return {
        "schema_version": 1,
        "fixture": fixture,
        "product": identity,
        "app": {"root": app.name, "entries": app_entries, "sha256": tree_digest(app_entries)},
        "components": components,
        "build_tools": build_tools,
        "relationships": relationships,
        "artifacts": artifacts,
        "graphs": graphs,
        "corresponding_source": build_source_manifest(prepared / "source"),
    }


def validate_bound_files(
    value: object, prefix: str, component_ids: set[str]
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise PublicationError(f"{prefix} closure is invalid")
    normalized: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, raw in enumerate(value):
        item = require_exact_keys(
            raw, {"id", "kind", "path", "sha256", "component_ids"}, f"{prefix}[{index}]"
        )
        identifier = safe_identifier(item["id"], f"{prefix}[{index}].id")
        if identifier in identifiers:
            raise PublicationError(f"duplicate {prefix} input: {identifier}")
        identifiers.add(identifier)
        kind = safe_identifier(item["kind"], f"{prefix}[{index}].kind")
        path = safe_identifier(item["path"], f"{prefix}[{index}].path")
        parsed = safe_relative(path, f"{prefix}[{index}].path")
        if parsed.parts[0] != prefix:
            raise PublicationError(f"{prefix} evidence escaped its canonical directory")
        digest = require_sha256(item["sha256"], f"{prefix}[{index}].sha256")
        bound_ids = item["component_ids"]
        if not isinstance(bound_ids, list) or not bound_ids:
            raise PublicationError(f"{prefix}[{index}] has no component binding")
        canonical_ids = [
            safe_identifier(component_id, f"{prefix}[{index}].component_id")
            for component_id in bound_ids
        ]
        if canonical_ids != sorted(set(canonical_ids)) or not set(canonical_ids).issubset(component_ids):
            raise PublicationError(f"{prefix}[{index}] component binding is not canonical")
        normalized.append(
            {"id": identifier, "kind": kind, "path": path, "sha256": digest, "component_ids": canonical_ids}
        )
    if normalized != sorted(normalized, key=lambda item: item["id"]):
        raise PublicationError(f"{prefix} closure is not canonically sorted")
    return normalized
