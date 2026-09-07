from __future__ import annotations

import re
from typing import Any

from .common import (
    PublicationError,
    bounded_text,
    require_exact_keys,
    require_sha256,
    safe_identifier,
    safe_relative,
)
from .license_resolution import canonical_spdx_expression


FORBIDDEN_LICENSE_VALUES = {"", "NONE", "NOASSERTION", "UNKNOWN", "UNLICENSED"}
FORBIDDEN_COPYRIGHT_VALUES = {"", "NONE", "UNKNOWN", "UNLICENSED"}
ALLOWED_ECOSYSTEMS = {"cargo", "npm", "go", "swift", "native", "application", "toolchain"}
ALLOWED_SCOPES = {"runtime", "build", "toolchain"}
ALLOWED_RELATIONSHIPS = {"DEPENDS_ON", "BUILD_DEPENDENCY_OF", "CONTAINS"}
EXPECTED_BUILD_TOOLS = {
    "@esbuild/darwin-arm64",
    "esbuild",
    "go",
    "gomobile",
    "node",
    "rust",
    "swift",
    "tauri-cli",
    "xcode",
    "xcodegen",
}


def _license_expression(value: object, component_id: str) -> str:
    if not isinstance(value, str) or value.strip() != value or value.upper() in FORBIDDEN_LICENSE_VALUES:
        raise PublicationError(f"component {component_id} has an unreviewed license expression")
    if "NOASSERTION" in value.upper() or "UNKNOWN" in value.upper():
        raise PublicationError(f"component {component_id} has an unreviewed license expression")
    try:
        return canonical_spdx_expression(value)
    except PublicationError as error:
        raise PublicationError(
            f"component {component_id} has an invalid SPDX license expression"
        ) from error


def validate_components(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise PublicationError("publication component inventory is empty")
    components: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        component = require_exact_keys(
            raw,
            {
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
                "source_sha256",
            },
            f"component[{index}]",
        )
        component_id = safe_identifier(component["id"], f"component[{index}].id")
        if component_id in seen:
            raise PublicationError(f"duplicate publication component: {component_id}")
        seen.add(component_id)
        bounded_text(component["name"], f"component {component_id}.name", 512)
        safe_identifier(component["version"], f"component {component_id}.version")
        purl = bounded_text(component["purl"], f"component {component_id}.purl", 2048)
        if not purl.startswith("pkg:") or any(character.isspace() for character in purl):
            raise PublicationError(f"component {component_id}.purl is not canonical")
        source_path = safe_relative(component["source_path"], f"component {component_id}.source_path")
        if source_path.parts[0] != "source":
            raise PublicationError(f"component {component_id}.source_path escaped source/")
        if component["ecosystem"] not in ALLOWED_ECOSYSTEMS:
            raise PublicationError(f"component {component_id} has an unsupported ecosystem")
        if component["scope"] not in ALLOWED_SCOPES:
            raise PublicationError(f"component {component_id} has an unsupported scope")
        component["license_expression"] = _license_expression(
            component["license_expression"], component_id
        )
        copyright_text = bounded_text(
            component["copyright_text"], f"component {component_id}.copyright_text", 4096
        )
        if (
            copyright_text != "NOASSERTION"
            and copyright_text.upper()
            in FORBIDDEN_COPYRIGHT_VALUES | {"NOASSERTION"}
        ):
            raise PublicationError(f"component {component_id} lacks reviewed copyright text")
        require_sha256(component["source_sha256"], f"component {component_id}.source_sha256")
        license_files = component["license_files"]
        if not isinstance(license_files, list) or not license_files:
            raise PublicationError(f"component {component_id} has no bound license text")
        seen_licenses: set[str] = set()
        for license_index, item in enumerate(license_files):
            license_file = require_exact_keys(
                item, {"path", "sha256"}, f"component {component_id}.license_files[{license_index}]"
            )
            path = safe_identifier(
                license_file["path"], f"component {component_id}.license_files[{license_index}].path"
            )
            parsed_path = safe_relative(
                path, f"component {component_id}.license_files[{license_index}].path"
            )
            if parsed_path.parts[0] != "licenses":
                raise PublicationError(f"component {component_id} license escaped licenses/")
            if path in seen_licenses:
                raise PublicationError(f"component {component_id} repeats a license file")
            seen_licenses.add(path)
            require_sha256(license_file["sha256"], f"license digest for {component_id}")
        components.append(component)
    if components != sorted(components, key=lambda item: item["id"]):
        raise PublicationError("publication components are not canonically sorted")
    return components


def validate_relationships(value: object, component_ids: set[str]) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise PublicationError("publication relationships are not an array")
    relationships: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(value):
        relation = require_exact_keys(raw, {"source", "target", "type"}, f"relationship[{index}]")
        source = safe_identifier(relation["source"], f"relationship[{index}].source")
        target = safe_identifier(relation["target"], f"relationship[{index}].target")
        kind = relation["type"]
        if source not in component_ids or target not in component_ids:
            raise PublicationError("publication relationship names an absent component")
        if kind not in ALLOWED_RELATIONSHIPS:
            raise PublicationError("publication relationship has an unsupported type")
        identity = (source, target, kind)
        if identity in seen:
            raise PublicationError("duplicate publication relationship")
        seen.add(identity)
        relationships.append({"source": source, "target": target, "type": kind})
    if relationships != sorted(
        relationships, key=lambda item: (item["source"], item["target"], item["type"])
    ):
        raise PublicationError("publication relationships are not canonically sorted")
    return relationships


def validate_build_tools(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise PublicationError("build-tool inventory is not an array")
    output = []
    seen: set[str] = set()
    fields = {
        "id",
        "name",
        "version",
        "ecosystem",
        "scope",
        "purl",
        "distribution",
        "license_reference",
        "license_evidence",
        "identity_metadata_sha256",
        "executables",
    }
    for index, raw in enumerate(value):
        item = require_exact_keys(raw, fields, f"build_tools[{index}]")
        identifier = safe_identifier(item["id"], f"build_tools[{index}].id")
        if identifier in seen:
            raise PublicationError(f"duplicate build tool: {identifier}")
        seen.add(identifier)
        bounded_text(item["name"], f"build tool {identifier}.name", 512)
        safe_identifier(item["version"], f"build tool {identifier}.version")
        purl = bounded_text(item["purl"], f"build tool {identifier}.purl", 2048)
        if not purl.startswith("pkg:") or any(character.isspace() for character in purl):
            raise PublicationError(f"build tool {identifier} has an invalid purl")
        if item["ecosystem"] not in {"npm", "toolchain"}:
            raise PublicationError(f"build tool {identifier} has an invalid ecosystem")
        if item["scope"] not in {"build", "toolchain"}:
            raise PublicationError(f"build tool {identifier} has an invalid scope")
        if item["distribution"] != "external-build-tool-not-distributed":
            raise PublicationError(f"build tool {identifier} has an invalid distribution class")
        item["license_reference"] = _license_expression(
            item["license_reference"], identifier
        )
        require_sha256(
            item["identity_metadata_sha256"], f"build tool {identifier} metadata digest"
        )
        for field in ("license_evidence", "executables"):
            entries = item[field]
            if not isinstance(entries, list):
                raise PublicationError(f"build tool {identifier}.{field} is not an array")
            if field == "executables" and not entries:
                raise PublicationError(f"build tool {identifier} has no executable evidence")
            for entry_index, entry in enumerate(entries):
                expected = {"name", "sha256"} | ({"size"} if field == "executables" else set())
                require_exact_keys(
                    entry, expected, f"build tool {identifier}.{field}[{entry_index}]"
                )
                safe_identifier(
                    entry["name"], f"build tool {identifier}.{field}[{entry_index}].name"
                )
                require_sha256(
                    entry["sha256"], f"build tool {identifier}.{field}[{entry_index}].sha256"
                )
                if field == "executables" and (
                    not isinstance(entry["size"], int)
                    or isinstance(entry["size"], bool)
                    or entry["size"] <= 0
                ):
                    raise PublicationError(f"build tool {identifier} executable size is invalid")
        output.append(item)
    if output != sorted(output, key=lambda item: item["id"]):
        raise PublicationError("build tools are not canonically sorted")
    return output


def _spdx_id(component_id: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", component_id)


def build_spdx(
    product: dict[str, str],
    components: list[dict[str, Any]],
    build_tools: list[dict[str, Any]],
    relationships: list[dict[str, str]],
) -> dict[str, Any]:
    namespace = (
        f"https://github.com/billlza/cfw-rs/releases/{product['version']}/"
        f"build-{product['build_number']}/sbom"
    )
    packages = []
    for component in components:
        packages.append(
            {
                "SPDXID": _spdx_id(component["id"]),
                "name": component["name"],
                "versionInfo": component["version"],
                "downloadLocation": component["purl"],
                "filesAnalyzed": False,
                "licenseConcluded": component["license_expression"],
                "licenseDeclared": component["license_expression"],
                "copyrightText": component["copyright_text"],
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": component["source_sha256"]}
                ],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": component["purl"],
                    }
                ],
                "annotations": [
                    {
                        "annotationType": "OTHER",
                        "annotator": "Organization: Clash for Mac Contributors",
                        "annotationDate": "1970-01-01T00:00:00Z",
                        "comment": "license evidence: "
                        + ",".join(item["path"] for item in component["license_files"]),
                    }
                ],
            }
        )
    for tool in build_tools:
        packages.append(
            {
                "SPDXID": _spdx_id(tool["id"]),
                "name": tool["name"],
                "versionInfo": tool["version"],
                "downloadLocation": tool["purl"],
                "filesAnalyzed": False,
                "primaryPackagePurpose": "BUILD_TOOL",
                "licenseConcluded": tool["license_reference"],
                "licenseDeclared": tool["license_reference"],
                "copyrightText": "NOASSERTION",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": entry["sha256"]}
                    for entry in tool["executables"]
                ],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": tool["purl"],
                    }
                ],
                "annotations": [
                    {
                        "annotationType": "OTHER",
                        "annotator": "Organization: Clash for Mac Contributors",
                        "annotationDate": "1970-01-01T00:00:00Z",
                        "comment": (
                            "external build tool; executable and identity hashes retained; "
                            "not distributed in the application"
                        ),
                    }
                ],
            }
        )
    spdx_relationships = [
        {
            "spdxElementId": _spdx_id(relation["source"]),
            "relationshipType": relation["type"],
            "relatedSpdxElement": _spdx_id(relation["target"]),
        }
        for relation in relationships
    ]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{product['name']}-{product['version']}-build-{product['build_number']}",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Organization: Clash for Mac Contributors"],
            "comment": f"macOS CFBundleVersion={product['build_number']}",
        },
        "packages": packages,
        "relationships": spdx_relationships,
    }


def build_cyclonedx(
    product: dict[str, str],
    components: list[dict[str, Any]],
    build_tools: list[dict[str, Any]],
    relationships: list[dict[str, str]],
) -> dict[str, Any]:
    dependencies: dict[str, set[str]] = {
        item["id"]: set() for item in [*components, *build_tools]
    }
    for relation in relationships:
        if relation["type"] in {"DEPENDS_ON", "CONTAINS"}:
            dependencies[relation["source"]].add(relation["target"])
        elif relation["type"] == "BUILD_DEPENDENCY_OF":
            dependencies[relation["target"]].add(relation["source"])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "product",
                "name": product["name"],
                "version": product["version"],
                "properties": [
                    {"name": "cfw:macos-cf-bundle-version", "value": product["build_number"]}
                ],
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "bom-ref": tool["id"],
                        "name": tool["name"],
                        "version": tool["version"],
                        "scope": "excluded",
                        "purl": tool["purl"],
                        "hashes": [
                            {"alg": "SHA-256", "content": entry["sha256"]}
                            for entry in tool["executables"]
                        ],
                        "licenses": [{"expression": tool["license_reference"]}],
                        "properties": [
                            {
                                "name": "cfw:distribution",
                                "value": "external-build-tool-not-distributed",
                            },
                            {
                                "name": "cfw:identity-metadata-sha256",
                                "value": tool["identity_metadata_sha256"],
                            },
                        ],
                    }
                    for tool in build_tools
                ]
            },
        },
        "components": [
            {
                "type": "application" if item["ecosystem"] == "application" else "library",
                "bom-ref": item["id"],
                "name": item["name"],
                "version": item["version"],
                "scope": "required" if item["scope"] == "runtime" else "excluded",
                "purl": item["purl"],
                "hashes": [{"alg": "SHA-256", "content": item["source_sha256"]}],
                "licenses": [{"expression": item["license_expression"]}],
                **(
                    {}
                    if item["copyright_text"] == "NOASSERTION"
                    else {"copyright": item["copyright_text"]}
                ),
                "properties": [
                    {"name": "cfw:ecosystem", "value": item["ecosystem"]},
                    {"name": "cfw:scope", "value": item["scope"]},
                    {"name": "cfw:source-path", "value": item["source_path"]},
                    {
                        "name": "cfw:license-evidence",
                        "value": ",".join(entry["path"] for entry in item["license_files"]),
                    },
                ],
            }
            for item in components
        ],
        "dependencies": [
            {"ref": component_id, "dependsOn": sorted(targets)}
            for component_id, targets in sorted(dependencies.items())
        ],
    }


def reject_unreviewed_values(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "copyrightText" and child == "NOASSERTION":
                continue
            reject_unreviewed_values(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_unreviewed_values(child, f"{path}[{index}]")
    elif isinstance(value, str) and value.upper() in {
        "NONE",
        "NOASSERTION",
        "UNKNOWN",
        "UNLICENSED",
    }:
        raise PublicationError(f"unreviewed SBOM value at {path}")
