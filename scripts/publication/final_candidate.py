"""Bind notarization and installed evidence to one final candidate (Task 12.2).

This module extends the existing offline ``scripts/publication`` release-
validation tooling with a single fail-closed *final-candidate binder*. It does
not create a competing framework: it consumes the wave-11 physical-evidence
aggregate (``harness.physical_evidence_aggregator``) as a black box for the
installed lifecycle matrix, unique-token packet evidence, performance/soak
gates, and the adversarial/security matrix, and it consumes the path/name-only
updater-key release blocker (``updater_key_release_blocker``) unchanged.

On top of those, the binder requires — for exactly one unchanged signed app
tree — accepted notarization, a stapled ticket, a Gatekeeper assessment, the
final inside-out signing identities (the app plus the embedded Network
Extension, the Global Authority daemon, and the ProxyAgent XPC owner) together
with the exact source-built libbox XCFramework every one of those identities was
linked against, the physical matrix hashes, and the packet / performance /
security-adversarial / soak raw reports, all pinned to the exact final artifact
hashes.

It is *fail closed* and invalidates the candidate on:

* a post-verification mutation — the final signed app-tree hash is not bound
  into the exact final artifact-hash manifest, the manifest digest drifts from
  its entries, the physical evidence describes a different app tree, or the
  app-tree hash re-observed *after* every verification step differs from the
  hash all of that evidence was bound to;
* a stale report — any notarization/staple/Gatekeeper/physical capture that
  predates the candidate build, a physical aggregate whose build time or
  identity does not match the final candidate, a report set bound to a
  different (superseded) final artifact-hash manifest, or a raw report the
  operator has recorded as superseded;
* an identity mismatch — a wrong Team ID, an unexpected/absent inside-out
  bundle identity, an inside-out component linked against a different libbox
  XCFramework, an XCFramework that is not the pinned patched-source build, or a
  target that does not name the final app tree;
* missing raw evidence — an absent inside-out identity, a missing final
  artifact hash, a missing installed-matrix / packet / performance / security /
  soak report for either required macOS run set, or any missing
  physical/notarization/post-verification input; and
* the updater-key release blocker — if any updater-key file exists in the
  workspace (for example ``.tauri/cfw-rs.key``), the candidate is invalid.
  The key is referenced by path/name only and is never opened (Requirement 8.1).

Where the physical, signed, or notarized artifacts are unavailable in this
environment, the binding is environment-gated: it reports ``blocked`` and can
never be promoted to ``verified``. It never fabricates acceptance.

Bindings: Requirements 4.1, 5.1, 6.1, 6.2, 6.3, 6.4, 6.5, 8.1 (see design
"Release Gates and Evidence Manifest", the EvidenceManifestV1 schema, and the
evidence hierarchy).
"""

from __future__ import annotations

import re
from datetime import datetime
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

# The physical-evidence aggregator uses parent-relative imports, so it must be
# imported under the ``scripts`` package (as ``scripts.harness...``) for its own
# ``..release_build_identity`` import to resolve. Import the dependencies under
# the ``scripts`` package, adding the repository root to ``sys.path`` when this
# module is loaded via the CLI front end (where ``scripts`` is not yet on path).
try:  # pragma: no cover - import shim exercised by both invocation styles
    from scripts.harness.physical_evidence_aggregator import (
        REQUIRED_OS,
        PhysicalEvidenceError,
        validate_physical_evidence,
    )
    from scripts.release_build_identity import canonical_build_version
    from scripts.updater_key_release_blocker import (
        UpdaterKeyReleaseBlock,
        evaluate_workspace,
    )
except ImportError:  # pragma: no cover - CLI invocation style
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from scripts.harness.physical_evidence_aggregator import (
        REQUIRED_OS,
        PhysicalEvidenceError,
        validate_physical_evidence,
    )
    from scripts.release_build_identity import canonical_build_version
    from scripts.updater_key_release_blocker import (
        UpdaterKeyReleaseBlock,
        evaluate_workspace,
    )

# The sealed source/supply-chain closure (Task 12.1) already derives and verifies
# the pinned patched sing-box source. Reuse it as a black box so the final
# candidate's XCFramework identity can never drift from the pinned build inputs
# and so this task adds no competing supply-chain logic.
from scripts.publication.sealed_closure import derive_supply_chain  # noqa: E402
from scripts.gatekeeper_assessment import (  # noqa: E402
    GatekeeperEvidenceError,
    validate_evidence as validate_gatekeeper_evidence,
)
from scripts.repository_source_identity import (  # noqa: E402
    SourceIdentityError,
    repository_commit,
    require_clean_repository,
)


SCHEMA_VERSION = 2
DOCUMENT_KIND = "final-candidate-notarization-installed-binding-v2"
VERIFIED = "verified"
BLOCKED = "blocked"
STATUSES = {VERIFIED, BLOCKED}

PRODUCT_VERSION = "0.4.0"
TEAM_ID = "YKUPL7Z869"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CDHASH_RE = re.compile(r"^[0-9a-f]{40}$")

# The final inside-out signing identities that must all be present in one
# unchanged app tree: the app itself plus the embedded Network Extension
# (Provider), the Global Authority daemon, and the ProxyAgent XPC owner. A
# missing role is missing raw evidence and fails closed; an unexpected bundle
# identity is an identity mismatch and fails closed.
REQUIRED_NESTED_CODE: dict[str, str] = {
    "host": "com.bill.clashformac",
    "packet-tunnel": "com.bill.clashformac.packet-tunnel",
    "global-authority": "com.bill.clashformac.global-authority",
    "proxy-agent": "com.bill.clashformac.proxy-agent",
}

# The fifth final identity: the one source-built libbox XCFramework every
# inside-out component is linked against. It is statically linked (``embed:
# false`` in the native project), so it carries no nested bundle identity of its
# own; it is bound by exact content digest plus the pinned patched-source
# identity derived by the sealed closure (Task 12.1).
XCFRAMEWORK_NAME = "Libbox.xcframework"

# The five report families that must exist for *every* required macOS run set:
# the installed lifecycle matrix (Requirement 6.1), unique-token packet evidence
# (6.2), the performance/weak-network gates and the 24-hour soak (6.3), and the
# separately signed adversarial/security matrix (6.4).
REPORT_CATEGORIES = ("installed_matrix", "packet", "performance", "security", "soak")

# Report family -> wave-11 harness that produces its raw report. ``soak`` has no
# separate harness: Requirement 6.3 keeps the 24-hour zero-crash result inside
# the performance document, so its hash is content-addressed from that section.
HARNESS_BY_CATEGORY: dict[str, str] = {
    "installed_matrix": "lifecycle",
    "packet": "packet",
    "performance": "performance",
    "security": "adversarial",
}
SOAK_CATEGORY = "soak"

# The environment-gated physical/signed/notarized inputs. A ``None`` value means
# "not available in this environment" and blocks the binding (never fabricated).
# ``post_verification`` is the app-tree hash re-observed after every other
# verification step; without it a post-verification mutation could go unnoticed,
# so its absence blocks the candidate too.
PHYSICAL_INPUTS = (
    "notarization",
    "staple",
    "gatekeeper",
    "physical_evidence",
    "post_verification",
)

# The synthetic blocked marker recorded when the updater-key release blocker
# fires. The candidate is always invalid while any updater-key file is present.
UPDATER_KEY_BLOCK = "updater_key_release_blocker"


def _require_str(value: object, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise PublicationError(f"{label} is not a bounded string")
    return value


def _require_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        raise PublicationError(f"{label} is not a 40-hex commit hash")
    return value


def _require_current_repository_commit(
    repository: Path, declared_commit: str, *, require_clean: bool
) -> None:
    try:
        current_commit = repository_commit(repository)
        if require_clean:
            require_clean_repository(repository)
    except SourceIdentityError as error:
        raise PublicationError(f"cannot verify the final-candidate repository: {error}") from error
    if declared_commit != current_commit:
        raise PublicationError("final candidate repository commit does not match current HEAD")


def _require_cdhash(value: object, label: str) -> str:
    if not isinstance(value, str) or not CDHASH_RE.fullmatch(value):
        raise PublicationError(f"{label} is not a 40-hex code-directory hash")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PublicationError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PublicationError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PublicationError(f"{label} must use UTC")
    return parsed


# --------------------------------------------------------------------------
# Product, final artifacts, and inside-out identities
# --------------------------------------------------------------------------


def _product(value: object) -> dict[str, str]:
    identity = require_exact_keys(value, {"version", "build_number"}, "product")
    if identity["version"] != PRODUCT_VERSION:
        raise PublicationError(f"final candidate product.version must be {PRODUCT_VERSION}")
    return {
        "version": PRODUCT_VERSION,
        "build_number": canonical_build_version(
            identity["build_number"], "final candidate build_number"
        ),
    }


def _artifact_hash_manifest(value: object) -> dict[str, Any]:
    manifest = require_exact_keys(value, {"entries", "sha256"}, "final artifact hash manifest")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        raise PublicationError("final artifact hash manifest is empty")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(entries):
        entry = require_exact_keys(raw, {"path", "sha256"}, f"artifact hash entry[{index}]")
        path = safe_identifier(entry["path"], f"artifact hash entry[{index}].path")
        safe_relative(path, f"artifact hash entry[{index}].path")
        if path in seen:
            raise PublicationError(f"final artifact hash manifest repeats a path: {path}")
        seen.add(path)
        normalized.append(
            {"path": path, "sha256": require_sha256(entry["sha256"], f"artifact hash for {path}")}
        )
    normalized.sort(key=lambda item: item["path"])
    digest = tree_digest(normalized)
    # A post-verification mutation of the manifest (any drift in an entry) breaks
    # this self-binding digest and fails closed.
    if digest != require_sha256(manifest["sha256"], "final artifact hash manifest sha256"):
        raise PublicationError("final artifact hash manifest digest does not bind its entries")
    return {"entries": normalized, "sha256": digest}


def _final_artifacts(value: object) -> dict[str, Any]:
    artifacts = require_exact_keys(
        value,
        {"signed_app_tree_sha256", "app_manifest_sha256", "built_at", "artifact_hash_manifest"},
        "final artifacts",
    )
    signed_app_tree = require_sha256(
        artifacts["signed_app_tree_sha256"], "final_artifacts.signed_app_tree_sha256"
    )
    app_manifest = require_sha256(
        artifacts["app_manifest_sha256"], "final_artifacts.app_manifest_sha256"
    )
    built_at_raw = artifacts["built_at"]
    built_at = _timestamp(built_at_raw, "final_artifacts.built_at")
    manifest = _artifact_hash_manifest(artifacts["artifact_hash_manifest"])
    exact_hashes = {entry["sha256"] for entry in manifest["entries"]}
    # The exact final artifact hashes must pin one unchanged app tree: both the
    # signed app-tree hash and the app manifest hash must appear as exact final
    # artifact hashes. A drifted tree changes its hash and is rejected here.
    if signed_app_tree not in exact_hashes:
        raise PublicationError(
            "final artifact hash manifest does not bind the signed app-tree hash"
        )
    if app_manifest not in exact_hashes:
        raise PublicationError(
            "final artifact hash manifest does not bind the app-manifest hash"
        )
    return {
        "signed_app_tree_sha256": signed_app_tree,
        "app_manifest_sha256": app_manifest,
        "built_at": built_at_raw,
        "built_at_dt": built_at,
        "artifact_hash_manifest": manifest,
    }


def _xcframework(value: object, repository: Path, exact_hashes: set[str]) -> dict[str, Any]:
    """Validate the fifth final identity: the source-built libbox XCFramework.

    The XCFramework is statically linked into every inside-out component, so its
    identity is its exact content digest plus the pinned patched-source identity.
    Both must be present in the exact final artifact hashes, and the declared
    upstream commit / combined diff digest must equal the repository pins the
    sealed closure derives. A drifted or foreign XCFramework fails closed.
    """
    xcframework = require_exact_keys(
        value,
        {
            "path",
            "xcframework_sha256",
            "manifest_sha256",
            "upstream_commit",
            "combined_diff_sha256",
        },
        "xcframework",
    )
    path = _require_str(xcframework["path"], "xcframework.path", 512)
    safe_relative(path, "xcframework.path")
    if not path.endswith(XCFRAMEWORK_NAME):
        raise PublicationError(f"xcframework.path does not name {XCFRAMEWORK_NAME}")
    digest = require_sha256(xcframework["xcframework_sha256"], "xcframework.xcframework_sha256")
    manifest = require_sha256(xcframework["manifest_sha256"], "xcframework.manifest_sha256")
    # The XCFramework digest and its artifact manifest must both be pinned by the
    # exact final artifact hashes; otherwise the shipped data plane is unbound.
    if digest not in exact_hashes:
        raise PublicationError(
            "final artifact hash manifest does not bind the libbox XCFramework digest"
        )
    if manifest not in exact_hashes:
        raise PublicationError(
            "final artifact hash manifest does not bind the libbox XCFramework manifest digest"
        )
    pinned = derive_supply_chain(repository)["patched_source"]
    commit = _require_commit(xcframework["upstream_commit"], "xcframework.upstream_commit")
    combined = require_sha256(
        xcframework["combined_diff_sha256"], "xcframework.combined_diff_sha256"
    )
    if commit != pinned["upstream_commit"]:
        raise PublicationError("xcframework upstream commit is not the pinned sing-box commit")
    if combined != pinned["combined_diff_sha256"]:
        raise PublicationError("xcframework combined diff digest is not the pinned patch closure")
    return {
        "path": path,
        "xcframework_sha256": digest,
        "manifest_sha256": manifest,
        "upstream_commit": commit,
        "combined_diff_sha256": combined,
    }


def _nested_code(value: object, xcframework_sha256: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise PublicationError("final candidate declares no inside-out signing identities")
    by_role: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(value):
        entry = require_exact_keys(
            raw,
            {
                "role",
                "path",
                "bundle_id",
                "team_id",
                "cdhash",
                "designated_requirement_sha256",
                "entitlements_sha256",
                "provisioning",
                "libbox_xcframework_sha256",
            },
            f"nested_code[{index}]",
        )
        role = entry["role"]
        if role not in REQUIRED_NESTED_CODE:
            raise PublicationError(f"nested_code[{index}] declares an unknown role: {role!r}")
        if role in by_role:
            raise PublicationError(f"nested_code duplicates the {role!r} identity")
        path = _require_str(entry["path"], f"nested_code[{role}].path", 512)
        safe_relative(path, f"nested_code[{role}].path")
        bundle_id = _require_str(entry["bundle_id"], f"nested_code[{role}].bundle_id", 256)
        if bundle_id != REQUIRED_NESTED_CODE[role]:
            raise PublicationError(
                f"nested_code[{role}].bundle_id {bundle_id!r} is not the expected identity"
            )
        team_id = _require_str(entry["team_id"], f"nested_code[{role}].team_id", 32)
        if team_id != TEAM_ID:
            raise PublicationError(f"nested_code[{role}].team_id is not {TEAM_ID}")
        provisioning = _require_str(entry["provisioning"], f"nested_code[{role}].provisioning", 128)
        linked = require_sha256(
            entry["libbox_xcframework_sha256"],
            f"nested_code[{role}].libbox_xcframework_sha256",
        )
        if linked != xcframework_sha256:
            # A component linked against a different libbox build is an identity
            # mismatch: the app tree would not be one coherent candidate.
            raise PublicationError(
                f"nested_code[{role}] is linked against a different libbox XCFramework"
            )
        by_role[role] = {
            "role": role,
            "path": path,
            "bundle_id": bundle_id,
            "team_id": team_id,
            "cdhash": _require_cdhash(entry["cdhash"], f"nested_code[{role}].cdhash"),
            "designated_requirement_sha256": require_sha256(
                entry["designated_requirement_sha256"],
                f"nested_code[{role}].designated_requirement_sha256",
            ),
            "entitlements_sha256": require_sha256(
                entry["entitlements_sha256"], f"nested_code[{role}].entitlements_sha256"
            ),
            "provisioning": provisioning,
            "libbox_xcframework_sha256": linked,
        }
    missing = set(REQUIRED_NESTED_CODE) - set(by_role)
    if missing:
        # A missing inside-out identity is missing raw evidence and fails closed.
        raise PublicationError(
            f"final candidate is missing inside-out signing identities: {sorted(missing)}"
        )
    return [by_role[role] for role in sorted(by_role)]


# --------------------------------------------------------------------------
# Notarization / staple / Gatekeeper (each bound to the final app tree)
# --------------------------------------------------------------------------


def _check_target(target: object, signed_app_tree: str, label: str) -> str:
    tree = require_sha256(target, f"{label}.target_signed_app_tree_sha256")
    if tree != signed_app_tree:
        raise PublicationError(f"{label} does not target the final signed app tree")
    return tree


def _check_not_stale(captured_at: object, built_at: datetime, label: str) -> str:
    parsed = _timestamp(captured_at, f"{label}.captured_at")
    if parsed < built_at:
        raise PublicationError(f"{label} is stale: captured before the final candidate was built")
    return captured_at  # type: ignore[return-value]


def _notarization(value: object, signed_app_tree: str, built_at: datetime) -> dict[str, Any]:
    notarization = require_exact_keys(
        value,
        {"status", "id", "submission_sha256", "target_signed_app_tree_sha256", "captured_at"},
        "notarization",
    )
    if notarization["status"] != "Accepted":
        raise PublicationError("notarization was not accepted")
    identifier = _require_str(notarization["id"], "notarization.id", 128)
    return {
        "status": "Accepted",
        "id": identifier,
        "submission_sha256": require_sha256(
            notarization["submission_sha256"], "notarization.submission_sha256"
        ),
        "target_signed_app_tree_sha256": _check_target(
            notarization["target_signed_app_tree_sha256"], signed_app_tree, "notarization"
        ),
        "captured_at": _check_not_stale(notarization["captured_at"], built_at, "notarization"),
    }


def _staple(value: object, signed_app_tree: str, built_at: datetime) -> dict[str, Any]:
    staple = require_exact_keys(
        value,
        {"stapled", "target_signed_app_tree_sha256", "captured_at"},
        "staple",
    )
    if staple["stapled"] is not True:
        raise PublicationError("notarization ticket is not stapled to the candidate")
    return {
        "stapled": True,
        "target_signed_app_tree_sha256": _check_target(
            staple["target_signed_app_tree_sha256"], signed_app_tree, "staple"
        ),
        "captured_at": _check_not_stale(staple["captured_at"], built_at, "staple"),
    }


def _gatekeeper(value: object, signed_app_tree: str, built_at: datetime) -> dict[str, Any]:
    try:
        gatekeeper = validate_gatekeeper_evidence(value)
    except GatekeeperEvidenceError as error:
        raise PublicationError(f"Gatekeeper evidence is invalid: {error}") from error
    gatekeeper["target_signed_app_tree_sha256"] = _check_target(
        gatekeeper["target_signed_app_tree_sha256"], signed_app_tree, "gatekeeper"
    )
    gatekeeper["captured_at"] = _check_not_stale(
        gatekeeper["captured_at"], built_at, "gatekeeper"
    )
    return gatekeeper


def _physical_evidence(value: object, final: dict[str, Any]) -> dict[str, Any]:
    """Validate the physical aggregate and bind it to the final candidate.

    The aggregate carries the installed lifecycle matrix hashes and the
    packet/performance/security/soak reports; it is consumed as a black box and
    then cross-checked against the exact final artifact hashes and product
    identity so a stale or foreign aggregate cannot be smuggled in.
    """
    if not isinstance(value, dict):
        raise PublicationError("physical evidence aggregate must be a JSON object")
    try:
        summary = validate_physical_evidence(value)
    except PhysicalEvidenceError as error:
        raise PublicationError(f"physical evidence aggregate is invalid: {error}") from error
    candidate = summary["candidate"]
    if candidate["version"] != final["product"]["version"]:
        raise PublicationError("physical evidence version does not match the final candidate")
    if candidate["build_number"] != final["product"]["build_number"]:
        raise PublicationError("physical evidence build number does not match the final candidate")
    if candidate["signed_app_tree_sha256"] != final["signed_app_tree_sha256"]:
        # A different signed app tree is a post-verification mutation / identity
        # mismatch: the installed evidence does not describe this final tree.
        raise PublicationError("physical evidence signed app tree does not match the final candidate")
    if candidate["app_manifest_sha256"] != final["app_manifest_sha256"]:
        raise PublicationError("physical evidence app manifest does not match the final candidate")
    # The aggregate's own candidate build time must equal the final build time so
    # a stale run set from an earlier build cannot be reused.
    built_at = value.get("candidate", {}).get("built_at")
    _timestamp(built_at, "physical_evidence.candidate.built_at")
    if built_at != final["built_at"]:
        raise PublicationError("physical evidence build time does not match the final candidate")
    return summary


# --------------------------------------------------------------------------
# Physical matrix / packet / performance / security / soak report bindings
# --------------------------------------------------------------------------


def _derive_report_bindings(aggregate: dict[str, Any]) -> dict[str, Any]:
    """Extract the exact raw-report hashes the final candidate must bind.

    Called only after :func:`validate_physical_evidence` has accepted the
    aggregate, so every run/report field is already canonical. The result is
    derived, never operator-supplied: the installed lifecycle matrix, packet,
    performance, security-adversarial, and soak report hashes for *each* required
    macOS run set. A missing family or run set is missing raw evidence.
    """
    bindings: list[dict[str, Any]] = []
    installed_runs: list[dict[str, Any]] = []
    for run in aggregate["runs"]:
        os_label = run["os"]
        reports = run["reports"]
        run_hashes: list[str] = []
        for category in REPORT_CATEGORIES:
            if category == SOAK_CATEGORY:
                performance = reports["performance"]
                soak = performance["document"].get("soak")
                if not isinstance(soak, dict):
                    raise PublicationError(
                        f"physical evidence run[{os_label}] carries no soak report"
                    )
                # Content-address the soak section itself so a mutated duration or
                # crash count breaks this binding. Two clean runs can legitimately
                # produce the same soak section, so this hash is not required to be
                # unique across runs (the raw report hashes above already are).
                entry = {
                    "os": os_label,
                    "category": category,
                    "tool_version": performance["tool_version"],
                    "report_sha256": sha256_bytes(canonical_json(soak)),
                    "captured_at": performance["captured_at"],
                }
            else:
                report = reports[HARNESS_BY_CATEGORY[category]]
                entry = {
                    "os": os_label,
                    "category": category,
                    "tool_version": report["tool_version"],
                    "report_sha256": report["report_sha256"],
                    "captured_at": report["captured_at"],
                }
            bindings.append(entry)
            run_hashes.append(entry["report_sha256"])
        installed_runs.append(
            {
                "os": os_label,
                "macos_build": run["macos_build"],
                "machine_sha256": run["machine_sha256"],
                "report_hashes": sorted(set(run_hashes)),
            }
        )
    expected = {(os_label, category) for os_label in REQUIRED_OS for category in REPORT_CATEGORIES}
    actual = {(entry["os"], entry["category"]) for entry in bindings}
    if actual != expected:
        raise PublicationError(
            "final candidate is missing raw physical reports: "
            f"{sorted(expected - actual)}"
        )
    bindings.sort(key=lambda entry: (entry["os"], entry["category"]))
    installed_runs.sort(key=lambda entry: entry["os"])
    return {"report_bindings": bindings, "installed_runs": installed_runs}


def _evidence_binding(
    value: object, artifact_manifest_sha256: str, bound_hashes: set[str]
) -> dict[str, Any]:
    """Bind the whole report set to the exact final artifact hashes.

    ``artifact_hash_manifest_sha256`` is the digest of the exact final
    artifact-hash manifest the reports were captured against. If it names a
    different (earlier, superseded) manifest, the reports are stale for this
    candidate. ``superseded_report_hashes`` records raw reports the operator has
    explicitly retired; binding any of them fails closed.
    """
    binding = require_exact_keys(
        value,
        {"artifact_hash_manifest_sha256", "superseded_report_hashes"},
        "evidence_binding",
    )
    declared = require_sha256(
        binding["artifact_hash_manifest_sha256"],
        "evidence_binding.artifact_hash_manifest_sha256",
    )
    if declared != artifact_manifest_sha256:
        raise PublicationError(
            "bound reports are stale: they are bound to a superseded final artifact-hash manifest"
        )
    raw = binding["superseded_report_hashes"]
    if not isinstance(raw, list):
        raise PublicationError("evidence_binding.superseded_report_hashes must be a list")
    superseded: list[str] = []
    for index, item in enumerate(raw):
        digest = require_sha256(item, f"evidence_binding.superseded_report_hashes[{index}]")
        if digest in superseded:
            raise PublicationError("evidence_binding repeats a superseded report hash")
        superseded.append(digest)
    collision = sorted(set(superseded) & bound_hashes)
    if collision:
        raise PublicationError(
            f"final candidate binds superseded raw reports: {collision}"
        )
    return {
        "artifact_hash_manifest_sha256": declared,
        "superseded_report_hashes": sorted(superseded),
    }


def _post_verification(
    value: object, signed_app_tree: str, latest_evidence_at: datetime | None
) -> dict[str, Any]:
    """Re-check the app tree *after* every verification step.

    Requirement 4.1/6.5: a candidate may not be mutated once its notarization,
    Gatekeeper, and physical evidence are captured. The operator re-hashes the
    signed app tree after the last verification step; any drift from the hash all
    of that evidence is bound to invalidates the candidate.
    """
    recheck = require_exact_keys(
        value, {"app_tree_sha256", "observed_at"}, "post_verification"
    )
    observed = require_sha256(recheck["app_tree_sha256"], "post_verification.app_tree_sha256")
    observed_at = _timestamp(recheck["observed_at"], "post_verification.observed_at")
    if observed != signed_app_tree:
        raise PublicationError(
            "app tree hash drifted after verification: the candidate was mutated post-verification"
        )
    if latest_evidence_at is not None and observed_at < latest_evidence_at:
        raise PublicationError(
            "post-verification re-check precedes bound evidence and cannot prove immutability"
        )
    return {"app_tree_sha256": observed, "observed_at": recheck["observed_at"]}


# --------------------------------------------------------------------------
# Updater-key release blocker (path/name only, never opened)
# --------------------------------------------------------------------------


def _updater_key_responses(workspace_root: Path) -> list[Any]:
    """Return the atomic updater-key security responses for the workspace.

    Delegates to the path/name-only blocker; it never opens or reads a key.
    Fails closed: an unreadable/symlinked/malformed workspace raises.
    """
    try:
        return list(evaluate_workspace(workspace_root))
    except UpdaterKeyReleaseBlock as error:
        raise PublicationError(f"updater-key release blocker failed closed: {error}") from error


def _updater_key_blocked(workspace_root: Path) -> bool:
    """Return True when an updater-key file exists in the workspace."""
    return bool(_updater_key_responses(workspace_root))


# --------------------------------------------------------------------------
# Environment status (which final-candidate inputs exist at all)
# --------------------------------------------------------------------------

# Where the release pipeline stages the environment-gated final-candidate inputs
# (alongside the existing 0.4.0 candidate/publication layout).
DEFAULT_EVIDENCE_DIRECTORY = "target/candidates/0.4.0/release/final-candidate"

ENVIRONMENT_INPUT_FILES: dict[str, str] = {
    "notarization": "notarization.json",
    "staple": "staple.json",
    "gatekeeper": "gatekeeper.json",
    "physical_evidence": "physical-evidence.json",
    "post_verification": "post-verification.json",
}

NOT_RUN = "not-run"
PRESENT = "present"


def environment_status(
    repository: Path,
    *,
    evidence_directory: Path | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    """Report which final-candidate inputs exist, without fabricating any.

    Every environment-gated input is reported as ``present`` or ``not-run`` from
    path/type metadata alone, and the updater-key blocker is reported by
    path/name only. An input that is absent, a symlink, or not a regular file is
    ``not-run`` and blocks the candidate; nothing here can grant acceptance.
    """
    directory = (
        repository / DEFAULT_EVIDENCE_DIRECTORY
        if evidence_directory is None
        else evidence_directory
    )
    root = repository if workspace_root is None else workspace_root
    inputs: dict[str, dict[str, str]] = {}
    blocked: list[str] = []
    for name in PHYSICAL_INPUTS:
        candidate = directory / ENVIRONMENT_INPUT_FILES[name]
        present = candidate.is_file() and not candidate.is_symlink()
        inputs[name] = {"path": str(candidate), "state": PRESENT if present else NOT_RUN}
        if not present:
            blocked.append(name)
    updater_key_blocks = [
        {
            "path": response.detected_path,
            "name": response.detected_name,
            "relocation_target": response.relocation_target,
            "exposure_plausible": response.exposure_plausible,
            "rotation_required": response.rotation_required,
            "trust_migration_required": response.trust_migration_required,
        }
        for response in _updater_key_responses(root)
    ]
    if updater_key_blocks:
        blocked.append(UPDATER_KEY_BLOCK)
    return {
        "evidence_directory": str(directory),
        "inputs": inputs,
        "updater_key_blocks": updater_key_blocks,
        "blocked_inputs": sorted(blocked),
        # ``inputs-present`` means only that the files exist; acceptance still
        # requires build + validate over their contents.
        "status": BLOCKED if blocked else "inputs-present",
    }


# --------------------------------------------------------------------------
# Build + validate
# --------------------------------------------------------------------------


def _binding_body(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "binding_sha256"}


def build_final_candidate_binding(
    repository: Path, request: object, *, fixture: bool, workspace_root: Path | None = None
) -> dict[str, Any]:
    """Assemble the canonical final-candidate binding from reviewed inputs.

    ``workspace_root`` is scanned by the updater-key blocker (path/name only);
    it defaults to ``repository``. A present updater-key file always blocks.
    """
    root = repository if workspace_root is None else workspace_root
    fields = {
        "product",
        "commit",
        "final_artifacts",
        "xcframework",
        "nested_code",
        "evidence_binding",
        "notarization",
        "staple",
        "gatekeeper",
        "physical_evidence",
        "post_verification",
    }
    payload = require_exact_keys(request, fields, "final candidate binding request")
    product = _product(payload["product"])
    commit = _require_commit(payload["commit"], "repository commit")
    _require_current_repository_commit(repository, commit, require_clean=not fixture)
    final_artifacts = _final_artifacts(payload["final_artifacts"])
    exact_hashes = {
        entry["sha256"] for entry in final_artifacts["artifact_hash_manifest"]["entries"]
    }
    xcframework = _xcframework(payload["xcframework"], repository, exact_hashes)
    nested_code = _nested_code(payload["nested_code"], xcframework["xcframework_sha256"])

    final = {
        "product": product,
        "signed_app_tree_sha256": final_artifacts["signed_app_tree_sha256"],
        "app_manifest_sha256": final_artifacts["app_manifest_sha256"],
        "built_at": final_artifacts["built_at"],
    }
    signed_app_tree = final_artifacts["signed_app_tree_sha256"]
    built_at = final_artifacts["built_at_dt"]

    missing: list[str] = []
    notarization = None
    staple = None
    gatekeeper = None
    physical_evidence = None
    post_verification = None
    report_bindings: list[dict[str, Any]] = []
    installed_runs: list[dict[str, Any]] = []
    evidence_timestamps: list[datetime] = []
    if payload["notarization"] is None:
        missing.append("notarization")
    else:
        notarization = _notarization(payload["notarization"], signed_app_tree, built_at)
        evidence_timestamps.append(_timestamp(notarization["captured_at"], "notarization"))
    if payload["staple"] is None:
        missing.append("staple")
    else:
        staple = _staple(payload["staple"], signed_app_tree, built_at)
        evidence_timestamps.append(_timestamp(staple["captured_at"], "staple"))
    if payload["gatekeeper"] is None:
        missing.append("gatekeeper")
    else:
        gatekeeper = _gatekeeper(payload["gatekeeper"], signed_app_tree, built_at)
        evidence_timestamps.append(_timestamp(gatekeeper["captured_at"], "gatekeeper"))
    if payload["physical_evidence"] is None:
        missing.append("physical_evidence")
    else:
        # Validate the aggregate and bind it to the final candidate, but store
        # the raw aggregate verbatim so validation is idempotent under rebuild.
        _physical_evidence(payload["physical_evidence"], final)
        physical_evidence = payload["physical_evidence"]
        derived = _derive_report_bindings(physical_evidence)
        report_bindings = derived["report_bindings"]
        installed_runs = derived["installed_runs"]
        evidence_timestamps.extend(
            _timestamp(entry["captured_at"], f"report[{entry['os']}.{entry['category']}]")
            for entry in report_bindings
        )

    # Bind the whole raw-report set to the exact final artifact hashes and reject
    # superseded reports. This is checked whether or not the physical aggregate is
    # available, so a wrong manifest binding is caught in every environment.
    evidence_binding = _evidence_binding(
        payload["evidence_binding"],
        final_artifacts["artifact_hash_manifest"]["sha256"],
        {entry["report_sha256"] for entry in report_bindings},
    )

    latest_evidence_at = max(evidence_timestamps) if evidence_timestamps else None
    if payload["post_verification"] is None:
        missing.append("post_verification")
    else:
        post_verification = _post_verification(
            payload["post_verification"], signed_app_tree, latest_evidence_at
        )

    # The updater-key release blocker always invalidates the candidate while any
    # updater-key file is present in the workspace (Requirement 8.1).
    if _updater_key_blocked(root):
        missing.append(UPDATER_KEY_BLOCK)

    blocked_inputs = sorted(set(missing))
    status = VERIFIED if not blocked_inputs else BLOCKED

    body = {
        "schema_version": SCHEMA_VERSION,
        "document": DOCUMENT_KIND,
        "fixture": bool(fixture),
        "status": status,
        "blocked_inputs": blocked_inputs,
        "product": product,
        "commit": commit,
        "final_artifacts": {
            "signed_app_tree_sha256": final_artifacts["signed_app_tree_sha256"],
            "app_manifest_sha256": final_artifacts["app_manifest_sha256"],
            "built_at": final_artifacts["built_at"],
            "artifact_hash_manifest": final_artifacts["artifact_hash_manifest"],
        },
        "xcframework": xcframework,
        "nested_code": nested_code,
        "evidence_binding": evidence_binding,
        "notarization": notarization,
        "staple": staple,
        "gatekeeper": gatekeeper,
        "physical_evidence": physical_evidence,
        "report_bindings": report_bindings,
        "installed_runs": installed_runs,
        "post_verification": post_verification,
    }
    body["binding_sha256"] = sha256_bytes(canonical_json(body))
    return body


def validate_final_candidate_binding(
    repository: Path,
    document: object,
    *,
    fixture: bool,
    workspace_root: Path | None = None,
    require_verified: bool = False,
) -> dict[str, Any]:
    """Fail-closed validation of a final-candidate binding document.

    Re-derives the binding from the embedded evidence, re-runs the updater-key
    scan, and rejects any post-verification mutation, stale report, identity
    mismatch, missing raw evidence, or updater-key blocker. With
    ``require_verified`` a ``blocked`` (environment-gated) binding is rejected so
    an incomplete environment can never be promoted.
    """
    root = repository if workspace_root is None else workspace_root
    fields = {
        "schema_version",
        "document",
        "fixture",
        "status",
        "blocked_inputs",
        "product",
        "commit",
        "final_artifacts",
        "xcframework",
        "nested_code",
        "evidence_binding",
        "notarization",
        "staple",
        "gatekeeper",
        "physical_evidence",
        "report_bindings",
        "installed_runs",
        "post_verification",
    }
    parsed = require_exact_keys(document, fields | {"binding_sha256"}, "final candidate binding")
    if parsed["schema_version"] != SCHEMA_VERSION or parsed["document"] != DOCUMENT_KIND:
        raise PublicationError("final candidate binding has an unsupported schema/document kind")
    if parsed["fixture"] is not bool(fixture):
        raise PublicationError("final candidate binding fixture mode mismatch")
    status = parsed["status"]
    if status not in STATUSES:
        raise PublicationError("final candidate binding status is not verified/blocked")

    # Re-derive the binding body from the embedded evidence. This recomputes the
    # artifact-hash manifest digest, re-validates the physical aggregate, and
    # re-runs the notarization/staple/Gatekeeper checks, so any drift, stale
    # report, or identity mismatch is caught independently of the stored status.
    request = {
        "product": parsed["product"],
        "commit": parsed["commit"],
        "final_artifacts": parsed["final_artifacts"],
        "xcframework": parsed["xcframework"],
        "nested_code": parsed["nested_code"],
        "evidence_binding": parsed["evidence_binding"],
        "notarization": parsed["notarization"],
        "staple": parsed["staple"],
        "gatekeeper": parsed["gatekeeper"],
        "physical_evidence": parsed["physical_evidence"],
        "post_verification": parsed["post_verification"],
    }
    rebuilt = build_final_candidate_binding(
        repository, request, fixture=fixture, workspace_root=root
    )

    if sorted(parsed["blocked_inputs"]) != rebuilt["blocked_inputs"]:
        raise PublicationError("final candidate binding blocked-input set is inconsistent")
    if status != rebuilt["status"]:
        raise PublicationError("final candidate binding status disagrees with its bound inputs")
    # The stored report bindings and installed-run summary are derived, never
    # asserted: any hand-edited report hash or run summary is rejected here.
    if parsed["report_bindings"] != rebuilt["report_bindings"]:
        raise PublicationError(
            "final candidate report bindings do not match the raw physical evidence"
        )
    if parsed["installed_runs"] != rebuilt["installed_runs"]:
        raise PublicationError(
            "final candidate installed-run summary does not match the raw physical evidence"
        )
    if parsed["binding_sha256"] != rebuilt["binding_sha256"]:
        raise PublicationError("final candidate binding content digest mismatch")

    if require_verified and status != VERIFIED:
        raise PublicationError(
            "final candidate binding is environment-gated (blocked) and cannot be promoted: "
            f"{rebuilt['blocked_inputs']}"
        )
    return rebuilt


def self_check() -> None:
    """Verify the binder's internal wiring without any evidence file.

    Lets a static boundary gate confirm the final-candidate binder is wired to
    the physical aggregator and the updater-key blocker and requires the full
    inside-out identity set, without needing signed/notarized/physical inputs.
    """
    if set(REQUIRED_NESTED_CODE) != {
        "host",
        "packet-tunnel",
        "global-authority",
        "proxy-agent",
    }:
        raise PublicationError("inside-out identity wiring is inconsistent")
    if PHYSICAL_INPUTS != (
        "notarization",
        "staple",
        "gatekeeper",
        "physical_evidence",
        "post_verification",
    ):
        raise PublicationError("environment-gated input wiring is inconsistent")
    if set(REPORT_CATEGORIES) != set(HARNESS_BY_CATEGORY) | {SOAK_CATEGORY}:
        raise PublicationError("report family wiring is inconsistent")
    if set(ENVIRONMENT_INPUT_FILES) != set(PHYSICAL_INPUTS):
        raise PublicationError("environment-gated input file wiring is inconsistent")
    if len(REQUIRED_OS) != 2:
        raise PublicationError("final candidate must bind both required macOS run sets")
    if validate_physical_evidence is None or evaluate_workspace is None:
        raise PublicationError("final candidate binder is not wired to its dependencies")
    if derive_supply_chain is None:
        raise PublicationError("final candidate binder is not wired to the sealed closure pins")
