#!/usr/bin/env python3
"""Validate the complete, source-bound v0.4.0 release capability inventory.

The generic inner Evidence_Manifest format intentionally supports arbitrary
capability names.  A production v0.4.0 outer seal must not inherit that
generality: omitting a difficult capability would otherwise make a smaller
subset appear fully sealed.  This module binds the release to one fixed
capability per numbered requirements section and proves that every numbered
requirement is covered exactly once.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

if __package__:
    from .evidence_manifest import KIND_LEVEL, LEVEL_ORDER
    from .publication.common import (
        PublicationError,
        canonical_json,
        read_regular,
        require_exact_keys,
        safe_identifier,
    )
else:
    from evidence_manifest import KIND_LEVEL, LEVEL_ORDER
    from publication.common import (
        PublicationError,
        canonical_json,
        read_regular,
        require_exact_keys,
        safe_identifier,
    )


INVENTORY_PATH = "scripts/release_capability_inventory.json"
REQUIREMENTS_PATH = "docs/release/macos15-network-extension-migration/requirements.md"
DOCUMENT_KIND = "cfw-release-capability-inventory-v1"

CAPABILITY_SECTION: tuple[tuple[str, str], ...] = (
    ("platform-command-boundary", "1"),
    ("provisioning-entitlement-contract", "2"),
    ("global-authority-peer-authentication", "3"),
    ("state-recovery-failure-semantics", "4"),
    ("ticket-only-packet-tunnel", "5"),
    ("authority-owned-system-proxy", "6"),
    ("secret-lifecycle-diagnostics", "7"),
    ("signed-publication-evidence", "8"),
    ("stable-fail-closed-ui", "9"),
)
CAPABILITY_IDS = tuple(identifier for identifier, _section in CAPABILITY_SECTION)

CAPABILITY_SOURCE_PATH: dict[str, str] = {
    "platform-command-boundary": "crates/cfw-application/src/lib.rs",
    "provisioning-entitlement-contract": "scripts/release_entitlement_contract.py",
    "global-authority-peer-authentication": (
        "native/macos/Sources/CFWGlobalAuthority/RoleScopedConnectionAuthorization.swift"
    ),
    "state-recovery-failure-semantics": (
        "native/macos/Sources/CFWGlobalAuthority/AuthorityJournal.swift"
    ),
    "ticket-only-packet-tunnel": (
        "native/macos/Sources/CFWPacketTunnel/TunnelTicketStartCoordinator.swift"
    ),
    "authority-owned-system-proxy": (
        "native/macos/Sources/CFWProxyAgent/ProxyAuthorityOwnership.swift"
    ),
    "secret-lifecycle-diagnostics": (
        "native/macos/Sources/CFWGlobalAuthority/TunnelSecretLifecycle.swift"
    ),
    "signed-publication-evidence": "scripts/release_publication_gate.sh",
    "stable-fail-closed-ui": "apps/cfw-tauri-shell/ui/src/app.js",
}

EVIDENCE_LEVEL_ORDER = tuple(LEVEL_ORDER)

# Every capability receives its own immutable report IDs. Paths may intentionally
# point at the same release gate because those gates are global, but no capability
# can borrow another capability's IDs or replace its source anchor.
LEVEL_REPORT_POLICY: dict[str, tuple[tuple[str, str, str], ...]] = {
    "Source_Implemented": (
        ("source", "source_hash", "{source}"),
        (
            "boundary",
            "boundary_scan",
            "target/candidates/0.4.0/release/evidence-inputs/p0-source-gates.json",
        ),
    ),
    "Unsigned_CI_Verified": (
        (
            "unsigned-artifact",
            "unsigned_artifact",
            "target/candidates/0.4.0/validation/40026/signed/Clash for Mac.app.manifest.json",
        ),
        (
            "deterministic-ci",
            "deterministic_test",
            "target/candidates/0.4.0/validation/40026/evidence/unsigned-ci-lanes.json",
        ),
    ),
    "Signed_Installed_Verified": (
        (
            "signed-identity",
            "signed_identity",
            "target/candidates/0.4.0/signed/Clash for Mac.app.manifest.json",
        ),
        (
            "physical-machine",
            "physical_machine",
            "target/candidates/0.4.0/release/final-candidate/physical-evidence.json",
        ),
        (
            "packet-evidence",
            "packet_evidence",
            "target/candidates/0.4.0/release/final-candidate/physical-evidence.json",
        ),
    ),
    "Sealed_Release_Evidence": (
        (
            "notarization",
            "notarization",
            "target/candidates/0.4.0/signed/notarization-log.json",
        ),
        (
            "publication",
            "publication",
            "target/candidates/0.4.0/release/publication/evidence-manifest.json",
        ),
        (
            "spdx-sbom",
            "sbom",
            "target/candidates/0.4.0/release/publication/sbom.spdx.json",
        ),
        (
            "cyclonedx-sbom",
            "sbom",
            "target/candidates/0.4.0/release/publication/sbom.cyclonedx.json",
        ),
    ),
}

SECTION_RE = re.compile(r"^## ([0-9]+)\.(?:[ \t]+|$)")
ITEM_RE = re.compile(r"^([1-9][0-9]*)\. ")


def _strict_json(path: Path) -> Any:
    data = read_regular(path, 256 * 1024)
    try:
        value = json.loads(data, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"capability inventory is not valid UTF-8 JSON: {error}") from error
    if canonical_json(value) != data:
        raise PublicationError("capability inventory bytes are not canonical JSON")
    return value


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicationError(f"capability inventory repeats the field {key!r}")
        result[key] = value
    return result


def _requirements_by_section(path: Path) -> dict[str, list[str]]:
    data = read_regular(path, 1024 * 1024)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PublicationError("release requirements are not valid UTF-8") from error
    current: str | None = None
    requirements: dict[str, list[str]] = {
        section: [] for _identifier, section in CAPABILITY_SECTION
    }
    for line in text.splitlines():
        heading = SECTION_RE.match(line)
        if heading is not None:
            current = heading.group(1)
            if current not in requirements:
                raise PublicationError(
                    f"release requirements contain unknown numbered section {current}"
                )
            continue
        if current is None:
            continue
        item = ITEM_RE.match(line)
        if item is None:
            continue
        identifier = f"{current}.{item.group(1)}"
        if identifier in requirements[current]:
            raise PublicationError(f"release requirements repeat {identifier}")
        requirements[current].append(identifier)
    missing_sections = [section for section, items in requirements.items() if not items]
    if missing_sections:
        raise PublicationError(
            f"release requirements omit numbered sections: {missing_sections}"
        )
    return requirements


def validate_inventory(repository: Path) -> dict[str, tuple[str, ...]]:
    """Return the fixed capability mapping after re-reading its source spec."""
    repository = repository.resolve(strict=True)
    if set(CAPABILITY_SOURCE_PATH) != set(CAPABILITY_IDS):
        raise PublicationError("release capability source-anchor policy drifted")
    if set(LEVEL_REPORT_POLICY) != set(EVIDENCE_LEVEL_ORDER):
        raise PublicationError("release capability evidence-level policy drifted")
    for level, contracts in LEVEL_REPORT_POLICY.items():
        if any(KIND_LEVEL.get(kind) != level for _suffix, kind, _path in contracts):
            raise PublicationError(
                "release capability report kind is assigned to the wrong evidence level"
            )
    raw = require_exact_keys(
        _strict_json(repository / INVENTORY_PATH),
        {"schema_version", "document", "source", "capabilities"},
        "release capability inventory",
    )
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or raw["document"] != DOCUMENT_KIND
    ):
        raise PublicationError("release capability inventory has an unsupported schema")
    if raw["source"] != REQUIREMENTS_PATH:
        raise PublicationError("release capability inventory names a different requirements source")
    capabilities = raw["capabilities"]
    if not isinstance(capabilities, list):
        raise PublicationError("release capability inventory capabilities are not an array")
    if len(capabilities) != len(CAPABILITY_SECTION):
        raise PublicationError(
            "release capability inventory does not contain exactly nine capabilities"
        )

    requirements = _requirements_by_section(repository / REQUIREMENTS_PATH)
    normalized: dict[str, tuple[str, ...]] = {}
    covered: set[str] = set()
    for index, ((expected_id, section), value) in enumerate(
        zip(CAPABILITY_SECTION, capabilities, strict=True)
    ):
        entry = require_exact_keys(value, {"id", "requirements"}, f"capability[{index}]")
        identifier = safe_identifier(entry["id"], f"capability[{index}].id")
        if identifier != expected_id:
            raise PublicationError(
                f"release capability inventory order/identity drifted at section {section}"
            )
        expected_requirements = requirements[section]
        if entry["requirements"] != expected_requirements:
            raise PublicationError(
                f"capability {identifier!r} does not exactly cover requirements section {section}"
            )
        overlap = covered.intersection(expected_requirements)
        if overlap:
            raise PublicationError(
                "release capability inventory covers requirements more than once: "
                f"{sorted(overlap)}"
            )
        covered.update(expected_requirements)
        normalized[identifier] = tuple(expected_requirements)

    expected_all = {
        requirement
        for section_requirements in requirements.values()
        for requirement in section_requirements
    }
    if covered != expected_all:
        raise PublicationError(
            "release capability inventory does not cover every numbered requirement exactly once"
        )
    for identifier, relative in CAPABILITY_SOURCE_PATH.items():
        path = repository / relative
        if path.is_symlink() or not path.is_file():
            raise PublicationError(
                f"release capability source anchor is unavailable: {identifier}"
            )
    return normalized


def expected_report_contracts(
    through_level: str | None = None,
    *,
    capabilities: tuple[str, ...] = CAPABILITY_IDS,
) -> tuple[dict[str, str], ...]:
    """Return the exact capability-owned report identities, kinds, and paths."""
    if through_level is None:
        included_levels = EVIDENCE_LEVEL_ORDER
    elif through_level in EVIDENCE_LEVEL_ORDER:
        included_levels = EVIDENCE_LEVEL_ORDER[
            : EVIDENCE_LEVEL_ORDER.index(through_level) + 1
        ]
    else:
        raise PublicationError(f"unknown fixed evidence level: {through_level!r}")
    if len(capabilities) != len(set(capabilities)) or not set(capabilities).issubset(
        CAPABILITY_SOURCE_PATH
    ):
        raise PublicationError("fixed report contract capability selection is invalid")
    contracts: list[dict[str, str]] = []
    for capability in capabilities:
        source = CAPABILITY_SOURCE_PATH[capability]
        for level in included_levels:
            for suffix, kind, path_template in LEVEL_REPORT_POLICY[level]:
                contracts.append(
                    {
                        "id": f"{capability}-{suffix}",
                        "kind": kind,
                        "path": source if path_template == "{source}" else path_template,
                    }
                )
    return tuple(contracts)


def expected_capability_levels(
    capability: str,
    through_level: str | None = None,
) -> dict[str, dict[str, list[str]]]:
    if capability not in CAPABILITY_SOURCE_PATH:
        raise PublicationError(f"unknown fixed release capability: {capability!r}")
    if through_level is None:
        included_levels = EVIDENCE_LEVEL_ORDER
    elif through_level in EVIDENCE_LEVEL_ORDER:
        included_levels = EVIDENCE_LEVEL_ORDER[
            : EVIDENCE_LEVEL_ORDER.index(through_level) + 1
        ]
    else:
        raise PublicationError(f"unknown fixed evidence level: {through_level!r}")
    return {
        level: {
            "report_ids": [
                f"{capability}-{suffix}"
                for suffix, _kind, _path in LEVEL_REPORT_POLICY[level]
            ]
        }
        for level in included_levels
    }


def require_fixed_evidence_mapping(value: object) -> None:
    """Reject report or capability mappings not derived from the fixed policy."""
    if not isinstance(value, dict):
        raise PublicationError("inner Evidence_Manifest must be an object")
    reports = value.get("reports")
    capabilities = value.get("capabilities")
    if not isinstance(reports, list) or not isinstance(capabilities, list):
        raise PublicationError("inner Evidence_Manifest report mapping is malformed")

    actual_reports: dict[str, tuple[str, str]] = {}
    for report in reports:
        if not isinstance(report, dict):
            raise PublicationError("inner Evidence_Manifest contains a malformed report")
        identifier = report.get("id")
        kind = report.get("kind")
        path = report.get("path")
        if not all(isinstance(item, str) for item in (identifier, kind, path)):
            raise PublicationError("inner Evidence_Manifest report contract is malformed")
        if identifier in actual_reports:
            raise PublicationError(f"inner Evidence_Manifest repeats report {identifier!r}")
        actual_reports[identifier] = (kind, path)
    actual_capabilities: dict[str, object] = {}
    for capability in capabilities:
        if not isinstance(capability, dict) or not isinstance(capability.get("id"), str):
            raise PublicationError("inner Evidence_Manifest contains a malformed capability")
        identifier = capability["id"]
        if identifier in actual_capabilities:
            raise PublicationError(f"inner Evidence_Manifest repeats capability {identifier!r}")
        actual_capabilities[identifier] = capability.get("levels")
    expected_ids = set(CAPABILITY_IDS)
    if set(actual_capabilities) != expected_ids:
        raise PublicationError("inner Evidence_Manifest capability policy is incomplete")
    expected_reports: dict[str, tuple[str, str]] = {}
    for identifier in CAPABILITY_IDS:
        levels = actual_capabilities[identifier]
        if not isinstance(levels, dict) or not levels:
            raise PublicationError(
                f"inner Evidence_Manifest capability report policy drifted: {identifier}"
            )
        declared = set(levels)
        if not declared.issubset(EVIDENCE_LEVEL_ORDER):
            raise PublicationError(
                f"inner Evidence_Manifest capability report policy drifted: {identifier}"
            )
        deepest = max(declared, key=EVIDENCE_LEVEL_ORDER.index)
        expected_levels = expected_capability_levels(identifier, deepest)
        if levels != expected_levels:
            raise PublicationError(
                f"inner Evidence_Manifest capability report policy drifted: {identifier}"
            )
        for contract in expected_report_contracts(deepest, capabilities=(identifier,)):
            expected_reports[contract["id"]] = (contract["kind"], contract["path"])
    if actual_reports != expected_reports:
        raise PublicationError("inner Evidence_Manifest report policy drifted")


def require_complete_capability_set(repository: Path, identifiers: object) -> None:
    """Reject any production inner manifest with an omitted/extra capability."""
    inventory = validate_inventory(repository)
    if not isinstance(identifiers, list) or any(not isinstance(item, str) for item in identifiers):
        raise PublicationError("inner Evidence_Manifest capability identifiers are invalid")
    if len(identifiers) != len(set(identifiers)):
        raise PublicationError("inner Evidence_Manifest repeats a release capability")
    actual = set(identifiers)
    expected = set(inventory)
    if actual != expected:
        raise PublicationError(
            "inner Evidence_Manifest capability inventory is incomplete or unknown: "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def main() -> None:
    repository = Path(__file__).resolve().parent.parent
    try:
        inventory = validate_inventory(repository)
    except (OSError, PublicationError) as error:
        raise SystemExit(f"error: release capability inventory: {error}") from error
    print(
        "release capability inventory verified: "
        f"capabilities={len(inventory)} requirements={sum(map(len, inventory.values()))}"
    )


if __name__ == "__main__":
    main()
