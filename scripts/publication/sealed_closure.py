"""Sealed-release source, license, vulnerability, and SBOM closure (Task 12.1).

This module extends the existing offline publication tooling (it reuses
``publication.common`` and ``publication.sbom`` and the pinned-input verifier in
``scripts/verify_pinned_build_inputs.py``) with a single content-addressed
supply-chain closure that binds, in one canonical document, the exact:

* GPL complete corresponding source (CCS) archive and tree digests;
* GPL modification notice and third-party notices;
* reviewed license nodes and the merged SPDX and CycloneDX SBOMs;
* pinned Go/vulnerability tool identities and the govulncheck reports;
* the patched sing-box source (upstream commit + three patch digests + the
  combined diff digest + verified Go module inputs);
* the source-built ``Libbox.xcframework`` digest;
* the signed application tree digest;
* the exact artifact-hash manifest.

The closure is bound to Requirements 4.1, 5.1, and 6.5 (see design "Evidence and
Completion Model", "GPL corresponding-source", and "Release Gates and Evidence
Manifest"). It is *fail closed*: the validator rejects missing source/tool
inputs, unreviewed license nodes, partial patches, inconsistent package graphs,
and SBOM/artifact-hash mismatches. Where the physical or signed artifacts (the
signed app tree, the XCFramework, or the govulncheck reports) are unavailable in
the current environment, the closure is *environment-gated*: it reports status
``blocked`` and can never be promoted to ``sealed``. It never fabricates
acceptance and never reads or reports the contents of the workspace updater key.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .common import (
    PublicationError,
    canonical_json,
    require_exact_keys,
    require_sha256,
    safe_identifier,
    safe_relative,
    sha256_bytes,
    tree_digest,
)
from .sbom import (
    build_cyclonedx,
    build_spdx,
    reject_unreviewed_values,
    validate_build_tools,
    validate_components,
    validate_relationships,
)

if __package__ and __package__.startswith("scripts."):
    from scripts import verify_pinned_build_inputs as pinned
else:  # pragma: no cover - exercised via both invocation styles
    import verify_pinned_build_inputs as pinned


SCHEMA_VERSION = 1
DOCUMENT_KIND = "sealed-source-license-vulnerability-sbom-closure-v1"
SEALED = "sealed"
BLOCKED = "blocked"
STATUSES = {SEALED, BLOCKED}

# The physical/signed inputs that only exist on the release machine. When any of
# these is absent the closure is environment-gated to ``blocked`` and can never
# be promoted to ``sealed``.
PHYSICAL_INPUTS = ("signed_app", "xcframework", "vulnerability_reports")

# Toolchain identities the design pins (Requirement 5.1). These are the exact
# content-addressed inputs the sealed closure must bind, in addition to the
# versions carried by the pinned-input manifest.
TOOLCHAIN_DIGEST_KEYS = {
    "node_darwin_arm64_sha256": "NODE_DARWIN_ARM64_SHA256",
    "go_darwin_arm64_sha256": "GO_DARWIN_ARM64_SHA256",
    "gomobile_module_sum": "GOMOBILE_MODULE_SUM",
    "govulncheck_module_sum": "GOVULNCHECK_MODULE_SUM",
}
GO_MODULE_INPUT_KEYS = (
    "SING_BOX_UPSTREAM_GO_MOD_SHA256",
    "SING_BOX_UPSTREAM_GO_SUM_SHA256",
    "SING_BOX_PATCHED_GO_MOD_SHA256",
    "SING_BOX_PATCHED_GO_SUM_SHA256",
)
MODULE_SUM_RE = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# The sole vulnerability-scan target the release pipeline produces
# (scripts/scan_libbox_vulnerabilities.sh scans ./experimental/libbox).
REQUIRED_VULN_TARGETS = frozenset({"libbox-macos-arm64"})


def _require_str(value: object, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise PublicationError(f"{label} is not a bounded string")
    return value


def _require_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        raise PublicationError(f"{label} is not a 40-hex commit hash")
    return value


def _require_module_sum(value: str, label: str) -> str:
    if not MODULE_SUM_RE.fullmatch(value):
        raise PublicationError(f"{label} is not an h1: module checksum")
    return value


# --------------------------------------------------------------------------
# Supply-chain (toolchain + patched source) derivation
# --------------------------------------------------------------------------


def derive_supply_chain(repository: Path) -> dict[str, Any]:
    """Derive the canonical, content-addressed toolchain and patched-source graph.

    This first runs the fail-closed pinned-input verifier so a missing tool
    input, a partial/legacy patch digest, or a combined diff that collapses to a
    single patch digest is rejected before anything is bound. It then extracts
    the exact pinned identities into a canonical structure.
    """
    try:
        pinned.verify(repository)
    except pinned.PinnedInputError as error:
        raise PublicationError(f"pinned supply-chain inputs failed: {error}") from error

    manifest = pinned._load_manifest(repository)
    env = pinned._parse_env(
        pinned._read_text(
            repository / manifest.get("dependencyPinsPath", "scripts/dependency_pins.env"),
            "dependency_pins.env",
        )
    )

    tools = manifest["tools"]
    toolchain_versions = {
        "rust": _require_str(tools["RUST_VERSION"], "rust version", 64),
        "node": _require_str(tools["NODE_VERSION"], "node version", 64),
        "go": _require_str(tools["GO_VERSION"], "go version", 64),
        "gomobile": _require_str(tools["GOMOBILE_VERSION"], "gomobile version", 64),
        "govulncheck": _require_str(tools["GOVULNCHECK_VERSION"], "govulncheck version", 64),
        "sing_box": _require_str(tools["SING_BOX_VERSION"], "sing-box version", 64),
    }
    toolchain_digests: dict[str, str] = {}
    for field, key in TOOLCHAIN_DIGEST_KEYS.items():
        value = pinned._require_env(env, key)
        if field.endswith("_module_sum"):
            toolchain_digests[field] = _require_module_sum(value, f"toolchain {field}")
        else:
            toolchain_digests[field] = require_sha256(value, f"toolchain {field}")

    patch_digests = sorted(
        require_sha256(patch["sha256"], f"patch digest {patch.get('name')}")
        for patch in manifest["patches"]
    )
    combined = require_sha256(manifest["combinedDiffSha256"], "combined diff digest")
    if combined in patch_digests:
        raise PublicationError("combined diff digest equals a single patch digest")
    rejected = sorted(
        require_sha256(digest, "rejected patch digest")
        for digest in (manifest.get("rejectedPatchDigests") or [])
    )
    for digest in patch_digests:
        if digest in rejected:
            raise PublicationError("a bound patch digest is a rejected/legacy digest")

    go_module_inputs = {}
    for key in GO_MODULE_INPUT_KEYS:
        value = pinned._require_env(env, key)
        go_module_inputs[key] = require_sha256(value, f"Go module input {key}")

    patched_source = {
        "upstream_commit": _require_commit(manifest["singBoxCommit"], "sing-box upstream commit"),
        "patch_digests": patch_digests,
        "combined_diff_sha256": combined,
        "rejected_patch_digests": rejected,
        "go_module_inputs": go_module_inputs,
    }
    return {
        "toolchain_versions": toolchain_versions,
        "toolchain_digests": toolchain_digests,
        "patched_source": patched_source,
    }


# --------------------------------------------------------------------------
# SBOM / license graph
# --------------------------------------------------------------------------


def _sbom_graph(sbom_request: object) -> dict[str, Any]:
    request = require_exact_keys(
        sbom_request, {"components", "build_tools", "relationships"}, "sbom graph"
    )
    components = validate_components(request["components"])
    build_tools = validate_build_tools(request["build_tools"])
    component_ids = {item["id"] for item in [*components, *build_tools]}
    relationships = validate_relationships(request["relationships"], component_ids)
    return {
        "components": components,
        "build_tools": build_tools,
        "relationships": relationships,
        "component_ids": component_ids,
    }


def _cross_consistent_graph(spdx: dict[str, Any], cyclonedx: dict[str, Any]) -> None:
    """Reject a package graph that is inconsistent across the two SBOM formats."""
    spdx_packages = {package["name"] + "@" + package["versionInfo"] for package in spdx["packages"]}
    cyclonedx_nodes = {component["bom-ref"] for component in cyclonedx["components"]}
    cyclonedx_tools = {
        tool["bom-ref"] for tool in cyclonedx["metadata"]["tools"]["components"]
    }
    cyclonedx_all = cyclonedx_nodes | cyclonedx_tools
    dependency_refs = {entry["ref"] for entry in cyclonedx["dependencies"]}
    if dependency_refs != cyclonedx_all:
        raise PublicationError("CycloneDX dependency graph does not cover every component")
    if len(spdx_packages) != len(spdx["packages"]):
        raise PublicationError("SPDX package graph contains duplicate name/version nodes")
    # SPDX relationships and CycloneDX dependencies must describe the same edge count.
    spdx_edges = len(spdx["relationships"])
    cyclonedx_edges = sum(len(entry["dependsOn"]) for entry in cyclonedx["dependencies"])
    if spdx_edges != cyclonedx_edges:
        raise PublicationError("SPDX and CycloneDX package graphs disagree on dependency edges")


def build_sbom_documents(
    product: dict[str, str], graph: dict[str, Any]
) -> dict[str, Any]:
    spdx = build_spdx(product, graph["components"], graph["build_tools"], graph["relationships"])
    cyclonedx = build_cyclonedx(
        product, graph["components"], graph["build_tools"], graph["relationships"]
    )
    reject_unreviewed_values(spdx)
    reject_unreviewed_values(cyclonedx)
    _cross_consistent_graph(spdx, cyclonedx)
    return {
        "spdx": spdx,
        "cyclonedx": cyclonedx,
        "spdx_sha256": sha256_bytes(canonical_json(spdx)),
        "cyclonedx_sha256": sha256_bytes(canonical_json(cyclonedx)),
    }


# --------------------------------------------------------------------------
# Content-addressed evidence files
# --------------------------------------------------------------------------


def _digest_reference(value: object, label: str, extra: set[str] | None = None) -> dict[str, Any]:
    fields = {"sha256"} | (extra or set())
    reference = require_exact_keys(value, fields, label)
    result = {"sha256": require_sha256(reference["sha256"], f"{label}.sha256")}
    for field in sorted(extra or set()):
        result[field] = reference[field]
    return result


def _artifact_hash_manifest(value: object) -> dict[str, Any]:
    manifest = require_exact_keys(value, {"entries", "sha256"}, "artifact hash manifest")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        raise PublicationError("artifact hash manifest is empty")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(entries):
        entry = require_exact_keys(raw, {"path", "sha256"}, f"artifact hash entry[{index}]")
        path = safe_identifier(entry["path"], f"artifact hash entry[{index}].path")
        safe_relative(path, f"artifact hash entry[{index}].path")
        if path in seen:
            raise PublicationError(f"artifact hash manifest repeats a path: {path}")
        seen.add(path)
        normalized.append(
            {"path": path, "sha256": require_sha256(entry["sha256"], f"artifact hash for {path}")}
        )
    normalized.sort(key=lambda item: item["path"])
    digest = tree_digest(normalized)
    if digest != require_sha256(manifest["sha256"], "artifact hash manifest sha256"):
        raise PublicationError("artifact hash manifest digest does not bind its entries")
    return {"entries": normalized, "sha256": digest}


def _vulnerability_reports(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise PublicationError("vulnerability report set is empty or missing")
    reports: list[dict[str, Any]] = []
    seen: set[str] = set()
    targets: set[str] = set()
    for index, raw in enumerate(value):
        report = require_exact_keys(
            raw, {"id", "tool", "tool_version", "target", "sha256"}, f"vulnerability report[{index}]"
        )
        identifier = safe_identifier(report["id"], f"vulnerability report[{index}].id")
        if identifier in seen:
            raise PublicationError(f"duplicate vulnerability report: {identifier}")
        seen.add(identifier)
        tool = _require_str(report["tool"], f"vulnerability report {identifier}.tool", 128)
        if tool != "govulncheck":
            raise PublicationError(f"vulnerability report {identifier} is not a govulncheck report")
        tool_version = _require_str(
            report["tool_version"], f"vulnerability report {identifier}.tool_version", 64
        )
        target = safe_identifier(report["target"], f"vulnerability report {identifier}.target")
        targets.add(target)
        reports.append(
            {
                "id": identifier,
                "tool": tool,
                "tool_version": tool_version,
                "target": target,
                "sha256": require_sha256(
                    report["sha256"], f"vulnerability report {identifier}.sha256"
                ),
            }
        )
    if not REQUIRED_VULN_TARGETS.issubset(targets):
        raise PublicationError(
            "vulnerability report closure is missing the libbox scan target: "
            f"{sorted(REQUIRED_VULN_TARGETS - targets)}"
        )
    return sorted(reports, key=lambda item: item["id"])


# --------------------------------------------------------------------------
# Build + validate
# --------------------------------------------------------------------------


def _product(value: object) -> dict[str, str]:
    identity = require_exact_keys(value, {"name", "version", "build_number"}, "product")
    return {
        "name": _require_str(identity["name"], "product.name", 128),
        "version": _require_str(identity["version"], "product.version", 64),
        "build_number": _require_str(identity["build_number"], "product.build_number", 64),
    }


def _closure_body(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "closure_sha256"}


def build_sealed_closure(
    repository: Path, request: object, *, fixture: bool
) -> dict[str, Any]:
    """Assemble the canonical sealed closure from reviewed inputs.

    ``request`` provides the product identity, the repository commit, the SBOM
    component graph, and the content-addressed references to the CCS archive,
    the modification/third-party notices, the artifact-hash manifest, and the
    physical/signed inputs (signed app tree, XCFramework, vulnerability reports).
    A missing physical input environment-gates the closure to ``blocked``.
    """
    fields = {
        "product",
        "commit",
        "sbom",
        "ccs",
        "modification_notice",
        "third_party_notices",
        "artifact_hash_manifest",
        "signed_app",
        "xcframework",
        "vulnerability_reports",
    }
    payload = require_exact_keys(request, fields, "sealed closure request")
    product = _product(payload["product"])
    commit = _require_commit(payload["commit"], "repository commit")
    supply_chain = derive_supply_chain(repository)
    graph = _sbom_graph(payload["sbom"])
    sbom = build_sbom_documents(product, graph)

    ccs = _digest_reference(payload["ccs"], "corresponding source", {"archive_sha256"})
    require_sha256(ccs["archive_sha256"], "corresponding-source archive digest")
    modification_notice = _digest_reference(payload["modification_notice"], "modification notice")
    third_party_notices = _digest_reference(payload["third_party_notices"], "third-party notices")
    artifact_hash_manifest = _artifact_hash_manifest(payload["artifact_hash_manifest"])

    # Environment-gated physical/signed inputs. ``None`` means "not available in
    # this environment" and must block the seal rather than fabricate it.
    missing: list[str] = []
    signed_app = None
    xcframework = None
    vulnerability_reports = None
    if payload["signed_app"] is None:
        missing.append("signed_app")
    else:
        signed_app = _digest_reference(payload["signed_app"], "signed app")
    if payload["xcframework"] is None:
        missing.append("xcframework")
    else:
        xcframework = _digest_reference(payload["xcframework"], "libbox xcframework")
    if payload["vulnerability_reports"] is None:
        missing.append("vulnerability_reports")
    else:
        vulnerability_reports = _vulnerability_reports(payload["vulnerability_reports"])

    status = SEALED if not missing else BLOCKED

    body = {
        "schema_version": SCHEMA_VERSION,
        "document": DOCUMENT_KIND,
        "fixture": bool(fixture),
        "status": status,
        "blocked_inputs": sorted(missing),
        "product": product,
        "commit": commit,
        "supply_chain": supply_chain,
        "sbom": {
            "spdx_sha256": sbom["spdx_sha256"],
            "cyclonedx_sha256": sbom["cyclonedx_sha256"],
            "component_ids": sorted(graph["component_ids"]),
            "components": graph["components"],
            "build_tools": graph["build_tools"],
            "relationships": graph["relationships"],
        },
        "corresponding_source": ccs,
        "modification_notice": modification_notice,
        "third_party_notices": third_party_notices,
        "artifact_hash_manifest": artifact_hash_manifest,
        "signed_app": signed_app,
        "xcframework": xcframework,
        "vulnerability_reports": vulnerability_reports,
    }
    body["closure_sha256"] = sha256_bytes(canonical_json(body))
    return body


def validate_sealed_closure(
    repository: Path, document: object, *, fixture: bool, require_sealed: bool = False
) -> dict[str, Any]:
    """Fail-closed validation of a sealed closure document.

    Rejects missing source/tool inputs, unreviewed license nodes, partial
    patches, inconsistent package graphs, and SBOM/artifact-hash mismatches. When
    ``require_sealed`` is set, a ``blocked`` (environment-gated) closure is also
    rejected so an incomplete environment can never be promoted.
    """
    fields = {
        "schema_version",
        "document",
        "fixture",
        "status",
        "blocked_inputs",
        "product",
        "commit",
        "supply_chain",
        "sbom",
        "corresponding_source",
        "modification_notice",
        "third_party_notices",
        "artifact_hash_manifest",
        "signed_app",
        "xcframework",
        "vulnerability_reports",
    }
    parsed = require_exact_keys(document, fields | {"closure_sha256"}, "sealed closure")
    if (
        type(parsed["schema_version"]) is not int
        or parsed["schema_version"] != SCHEMA_VERSION
        or parsed["document"] != DOCUMENT_KIND
    ):
        raise PublicationError("sealed closure has an unsupported schema/document kind")
    if parsed["fixture"] is not bool(fixture):
        raise PublicationError("sealed closure fixture mode mismatch")
    status = parsed["status"]
    if status not in STATUSES:
        raise PublicationError("sealed closure status is not sealed/blocked")

    product = _product(parsed["product"])
    commit = _require_commit(parsed["commit"], "repository commit")

    # Re-derive the toolchain/patched-source graph from the repository and bind
    # it exactly; this rejects any tampered, partial, or drifted supply chain.
    expected_supply_chain = derive_supply_chain(repository)
    if parsed["supply_chain"] != expected_supply_chain:
        raise PublicationError("sealed closure supply chain does not bind the repository pins")

    sbom_block = require_exact_keys(
        parsed["sbom"],
        {"spdx_sha256", "cyclonedx_sha256", "component_ids", "components", "build_tools", "relationships"},
        "sealed closure sbom",
    )
    graph = _sbom_graph(
        {
            "components": sbom_block["components"],
            "build_tools": sbom_block["build_tools"],
            "relationships": sbom_block["relationships"],
        }
    )
    if sbom_block["component_ids"] != sorted(graph["component_ids"]):
        raise PublicationError("sealed closure component id set is inconsistent")
    sbom = build_sbom_documents(product, graph)
    if (
        sbom_block["spdx_sha256"] != sbom["spdx_sha256"]
        or sbom_block["cyclonedx_sha256"] != sbom["cyclonedx_sha256"]
    ):
        raise PublicationError("sealed closure SBOM digests do not match the reviewed graph")

    ccs = _digest_reference(parsed["corresponding_source"], "corresponding source", {"archive_sha256"})
    require_sha256(ccs["archive_sha256"], "corresponding-source archive digest")
    _digest_reference(parsed["modification_notice"], "modification notice")
    _digest_reference(parsed["third_party_notices"], "third-party notices")
    _artifact_hash_manifest(parsed["artifact_hash_manifest"])

    missing: list[str] = []
    if parsed["signed_app"] is None:
        missing.append("signed_app")
    else:
        _digest_reference(parsed["signed_app"], "signed app")
    if parsed["xcframework"] is None:
        missing.append("xcframework")
    else:
        _digest_reference(parsed["xcframework"], "libbox xcframework")
    if parsed["vulnerability_reports"] is None:
        missing.append("vulnerability_reports")
    else:
        _vulnerability_reports(parsed["vulnerability_reports"])

    if sorted(parsed["blocked_inputs"]) != sorted(missing):
        raise PublicationError("sealed closure blocked-input set is inconsistent")
    expected_status = SEALED if not missing else BLOCKED
    if status != expected_status:
        raise PublicationError("sealed closure status disagrees with its bound inputs")

    body = _closure_body(parsed)
    if sha256_bytes(canonical_json(body)) != require_sha256(
        parsed["closure_sha256"], "sealed closure digest"
    ):
        raise PublicationError("sealed closure content digest mismatch")

    if require_sealed and status != SEALED:
        raise PublicationError(
            "sealed closure is environment-gated (blocked) and cannot be promoted: "
            f"{sorted(missing)}"
        )
    return parsed
