#!/usr/bin/env python3
"""Validate the canonical Evidence_Manifest that binds capability evidence levels.

The Evidence_Manifest is the machine-verifiable document required by Requirement
4.1: it assigns every capability exactly one highest achieved level from
``Source_Implemented``, ``Unsigned_CI_Verified``, ``Signed_Installed_Verified``,
and ``Sealed_Release_Evidence`` and refuses to promote a capability when a
predecessor, an exact artifact or environment binding, a content hash, a raw
report, an identity proof, a physical-machine proof, or a publication artifact
is absent, stale, skipped, masked, malformed, or unsuccessful (Requirements 4.1,
6.5, 7.5).

The validator is deliberately fail-closed:

* parsing is canonical - duplicate JSON keys, unknown fields, and non-object
  documents are rejected before any interpretation;
* every capability level references content-addressed reports whose ``status``
  must be exactly ``passed`` (``skipped``, ``masked``, ``timeout``, ``malformed``,
  ``failed`` and every other value fail the level);
* each report is bound to the manifest identity (commit, toolchain, signed app)
  appropriate for its level, so a Source_Implemented or Unsigned_CI_Verified
  report can never be reused to justify an installed or sealed claim;
* levels must form an unbroken prefix of the level order (predecessor closure)
  and the declared ``highest_level`` must equal the deepest satisfied level
  (no over-promotion);
* when a reports root is supplied, each raw report file must exist as a regular
  non-symlink file whose SHA-256 equals the manifest binding (missing raw report
  and content-address mismatch both fail closed).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

SCHEMA_VERSION = 1
MANIFEST_VERSION = "evidence-manifest-v1"

# The four evidence levels in strict ascending order. A capability's achieved
# level is the deepest contiguous prefix of this list that is fully satisfied.
LEVEL_ORDER = (
    "Source_Implemented",
    "Unsigned_CI_Verified",
    "Signed_Installed_Verified",
    "Sealed_Release_Evidence",
)
LEVEL_INDEX = {level: index for index, level in enumerate(LEVEL_ORDER)}

# Content-addressed report kinds and the single evidence level each one belongs
# to. A report may only satisfy the level of its kind, so a lower-level report
# can never be promoted into an installed or sealed claim.
KIND_LEVEL = {
    "source_hash": "Source_Implemented",
    "boundary_scan": "Source_Implemented",
    "unsigned_artifact": "Unsigned_CI_Verified",
    "deterministic_test": "Unsigned_CI_Verified",
    "signed_identity": "Signed_Installed_Verified",
    "physical_machine": "Signed_Installed_Verified",
    "packet_evidence": "Signed_Installed_Verified",
    "notarization": "Sealed_Release_Evidence",
    "publication": "Sealed_Release_Evidence",
    "sbom": "Sealed_Release_Evidence",
}

# The minimum set of report kinds a level must reference before it may be
# considered satisfied. A missing kind is skipped evidence and fails closed.
REQUIRED_KINDS = {
    "Source_Implemented": frozenset({"source_hash", "boundary_scan"}),
    "Unsigned_CI_Verified": frozenset({"unsigned_artifact", "deterministic_test"}),
    "Signed_Installed_Verified": frozenset({"signed_identity", "physical_machine"}),
    "Sealed_Release_Evidence": frozenset({"notarization", "publication", "sbom"}),
}

# Identity/environment bindings each report must carry and match against the
# manifest identity, keyed by the report's level. Higher levels inherit and
# extend the bindings of lower levels.
REQUIRED_BINDINGS = {
    "Source_Implemented": ("commit",),
    "Unsigned_CI_Verified": ("commit", "toolchain_sha256"),
    "Signed_Installed_Verified": ("commit", "toolchain_sha256", "signed_app_sha256"),
    "Sealed_Release_Evidence": ("commit", "toolchain_sha256", "signed_app_sha256"),
}

# The only report status that contributes evidence. Every other value - skipped,
# masked, suppressed, timed-out, malformed, or unsuccessful - fails the level.
ACCEPTED_STATUS = "passed"

MAX_REPORTS = 512
MAX_CAPABILITIES = 256
MAX_REPORT_IDS_PER_LEVEL = 64
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


class EvidenceManifestError(ValueError):
    """The Evidence_Manifest is malformed, incomplete, or over-promoted."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceManifestError(f"manifest has a duplicate field: {key!r}")
        result[key] = value
    return result


def _canonical_loads(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise EvidenceManifestError("Evidence_Manifest is not canonical JSON") from error


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceManifestError(f"{label} must be a JSON object")
    actual = set(value)
    missing = fields - actual
    unknown = actual - fields
    if missing:
        raise EvidenceManifestError(f"{label} is missing required fields: {sorted(missing)}")
    if unknown:
        raise EvidenceManifestError(f"{label} has unknown fields: {sorted(unknown)}")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise EvidenceManifestError(f"{label} is not a lowercase SHA-256")
    return value


def _commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        raise EvidenceManifestError(f"{label} is not a 40-character commit hash")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise EvidenceManifestError(f"{label} is not a canonical identifier")
    return value


def _relative_posix(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise EvidenceManifestError(f"{label} path is not a non-empty string")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise EvidenceManifestError(f"{label} path is not a safe relative path")
    return relative


def _identity(value: Any) -> dict[str, str]:
    identity = _exact(value, {"commit", "toolchain_sha256", "signed_app_sha256"}, "identity")
    return {
        "commit": _commit(identity["commit"], "identity.commit"),
        "toolchain_sha256": _sha256(identity["toolchain_sha256"], "identity.toolchain_sha256"),
        "signed_app_sha256": _sha256(identity["signed_app_sha256"], "identity.signed_app_sha256"),
    }


def _report(raw: Any, index: int, identity: dict[str, str]) -> dict[str, Any]:
    report = _exact(
        raw,
        {"id", "kind", "path", "sha256", "status", "bindings"},
        f"reports[{index}]",
    )
    report_id = _identifier(report["id"], f"reports[{index}].id")
    kind = report["kind"]
    if kind not in KIND_LEVEL:
        raise EvidenceManifestError(f"{report_id} has an unknown report kind: {kind!r}")
    level = KIND_LEVEL[kind]
    _relative_posix(report["path"], f"{report_id} path")
    _sha256(report["sha256"], f"{report_id} sha256")
    status = report["status"]
    if status != ACCEPTED_STATUS:
        # skipped, masked, suppressed, timeout, malformed, failed, "|| true", ...
        raise EvidenceManifestError(
            f"{report_id} status is {status!r}; only {ACCEPTED_STATUS!r} evidence is accepted"
        )
    required = REQUIRED_BINDINGS[level]
    bindings = _exact(report["bindings"], set(required), f"{report_id} bindings")
    for field in required:
        expected = identity[field]
        actual = bindings[field]
        matcher = _commit if field == "commit" else _sha256
        matcher(actual, f"{report_id} bindings.{field}")
        if actual != expected:
            # A stale commit, foreign toolchain, or foreign signed app cannot
            # bind evidence to this candidate.
            raise EvidenceManifestError(
                f"{report_id} bindings.{field} does not match the manifest identity"
            )
    return {"id": report_id, "kind": kind, "level": level, "path": report["path"], "sha256": report["sha256"]}


def _achieved_level(levels: dict[str, Any]) -> str:
    declared = set(levels)
    unknown = declared - set(LEVEL_ORDER)
    if unknown:
        raise EvidenceManifestError(f"capability declares unknown levels: {sorted(unknown)}")
    if not declared:
        raise EvidenceManifestError("capability declares no evidence levels")
    depth = max(LEVEL_INDEX[name] for name in declared)
    # Predecessor closure: the declared levels must be exactly the contiguous
    # prefix of the level order up to the deepest declared level.
    expected_prefix = set(LEVEL_ORDER[: depth + 1])
    if declared != expected_prefix:
        missing = sorted(expected_prefix - declared, key=lambda name: LEVEL_INDEX[name])
        raise EvidenceManifestError(
            f"capability skips predecessor evidence levels: missing {missing}"
        )
    return LEVEL_ORDER[depth]


def _validate_level(
    capability_id: str,
    level_name: str,
    raw: Any,
    reports_by_id: dict[str, dict[str, Any]],
    referenced: set[str],
) -> None:
    entry = _exact(raw, {"report_ids"}, f"{capability_id}.{level_name}")
    report_ids = entry["report_ids"]
    if not isinstance(report_ids, list) or not report_ids:
        raise EvidenceManifestError(
            f"{capability_id}.{level_name} must reference at least one report"
        )
    if len(report_ids) > MAX_REPORT_IDS_PER_LEVEL:
        raise EvidenceManifestError(f"{capability_id}.{level_name} references too many reports")
    seen: set[str] = set()
    kinds: set[str] = set()
    for report_id in report_ids:
        if not isinstance(report_id, str) or report_id not in reports_by_id:
            raise EvidenceManifestError(
                f"{capability_id}.{level_name} references a missing raw report: {report_id!r}"
            )
        if report_id in seen:
            raise EvidenceManifestError(
                f"{capability_id}.{level_name} references a duplicate report: {report_id!r}"
            )
        seen.add(report_id)
        report = reports_by_id[report_id]
        if report["level"] != level_name:
            # A lower-level report cannot be promoted to satisfy a higher level.
            raise EvidenceManifestError(
                f"{capability_id}.{level_name} binds a {report['level']} report: {report_id!r}"
            )
        kinds.add(report["kind"])
    missing_kinds = REQUIRED_KINDS[level_name] - kinds
    if missing_kinds:
        raise EvidenceManifestError(
            f"{capability_id}.{level_name} skips required evidence kinds: {sorted(missing_kinds)}"
        )
    referenced.update(seen)


def _capability(
    raw: Any, index: int, reports_by_id: dict[str, dict[str, Any]], referenced: set[str]
) -> dict[str, Any]:
    capability = _exact(raw, {"id", "highest_level", "levels"}, f"capabilities[{index}]")
    capability_id = _identifier(capability["id"], f"capabilities[{index}].id")
    levels = capability["levels"]
    if not isinstance(levels, dict):
        raise EvidenceManifestError(f"{capability_id}.levels must be a JSON object")
    achieved = _achieved_level(levels)
    highest = capability["highest_level"]
    if highest not in LEVEL_ORDER:
        raise EvidenceManifestError(f"{capability_id}.highest_level is not a known level")
    if highest != achieved:
        # Reject over-promotion in either direction: the recorded highest level
        # must equal the deepest fully satisfied level.
        raise EvidenceManifestError(
            f"{capability_id}.highest_level {highest!r} does not match the achieved level "
            f"{achieved!r}"
        )
    for level_name in LEVEL_ORDER:
        if level_name in levels:
            _validate_level(capability_id, level_name, levels[level_name], reports_by_id, referenced)
    return {"id": capability_id, "highest_level": highest}


def validate_evidence_manifest(value: Any) -> dict[str, Any]:
    """Validate a parsed Evidence_Manifest document and return a summary."""
    document = _exact(
        value,
        {"schema_version", "manifest_version", "identity", "reports", "capabilities"},
        "Evidence_Manifest",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise EvidenceManifestError(f"Evidence_Manifest schema_version must be {SCHEMA_VERSION}")
    if document["manifest_version"] != MANIFEST_VERSION:
        raise EvidenceManifestError(f"Evidence_Manifest manifest_version must be {MANIFEST_VERSION!r}")
    identity = _identity(document["identity"])

    reports = document["reports"]
    if not isinstance(reports, list) or not reports:
        raise EvidenceManifestError("Evidence_Manifest must declare at least one report")
    if len(reports) > MAX_REPORTS:
        raise EvidenceManifestError("Evidence_Manifest declares too many reports")
    reports_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(reports):
        report = _report(raw, index, identity)
        if report["id"] in reports_by_id:
            raise EvidenceManifestError(f"duplicate report id: {report['id']!r}")
        reports_by_id[report["id"]] = report

    capabilities = document["capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        raise EvidenceManifestError("Evidence_Manifest must declare at least one capability")
    if len(capabilities) > MAX_CAPABILITIES:
        raise EvidenceManifestError("Evidence_Manifest declares too many capabilities")
    referenced: set[str] = set()
    seen_capabilities: set[str] = set()
    summary: list[dict[str, Any]] = []
    for index, raw in enumerate(capabilities):
        capability = _capability(raw, index, reports_by_id, referenced)
        if capability["id"] in seen_capabilities:
            raise EvidenceManifestError(f"duplicate capability id: {capability['id']!r}")
        seen_capabilities.add(capability["id"])
        summary.append(capability)

    unused = set(reports_by_id) - referenced
    if unused:
        # Every content-addressed report must be bound to a capability level so
        # the manifest cannot smuggle unaudited or masked evidence.
        raise EvidenceManifestError(f"Evidence_Manifest declares unbound reports: {sorted(unused)}")

    return {"identity": identity, "capabilities": summary, "reports": reports_by_id}


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_raw_reports(reports_root: Path, reports_by_id: dict[str, dict[str, Any]]) -> None:
    root = reports_root.resolve(strict=True)
    for report in reports_by_id.values():
        relative = _relative_posix(report["path"], f"{report['id']} path")
        path = root.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise EvidenceManifestError(
                f"{report['id']} raw report is missing or is a symlink: {report['path']}"
            )
        if _digest_file(path) != report["sha256"]:
            raise EvidenceManifestError(
                f"{report['id']} raw report content hash does not match the manifest binding"
            )


def load_evidence_manifest(path: Path, reports_root: Path | None = None) -> dict[str, Any]:
    """Load, canonically parse, and validate an Evidence_Manifest file."""
    if path.is_symlink() or not path.is_file():
        raise EvidenceManifestError("Evidence_Manifest must be a regular non-symlink file")
    data = path.read_bytes()
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise EvidenceManifestError("Evidence_Manifest size is outside the accepted range")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceManifestError("Evidence_Manifest is not valid UTF-8") from error
    result = validate_evidence_manifest(_canonical_loads(text))
    if reports_root is not None:
        _verify_raw_reports(reports_root, result["reports"])
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a canonical Evidence_Manifest.")
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--reports-root",
        type=Path,
        default=None,
        help="verify each raw report file exists and content-addresses to its manifest hash",
    )
    arguments = parser.parse_args()
    try:
        result = load_evidence_manifest(arguments.manifest, arguments.reports_root)
    except (EvidenceManifestError, OSError) as error:
        raise SystemExit(f"error: evidence manifest validation failed: {error}") from error
    lines = "; ".join(
        f"{capability['id']}={capability['highest_level']}" for capability in result["capabilities"]
    )
    print(f"evidence manifest verified: {len(result['capabilities'])} capabilities [{lines}]")


if __name__ == "__main__":
    main()
