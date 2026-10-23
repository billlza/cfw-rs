"""Carry the approved component license decisions of the last shipped release forward.

docs/supply-chain.md: a new component-review template does not invalidate an
existing human decision. A decision of the last shipped release is reused only
when its approval chain still verifies and the current template item keeps the
same component identity, the complete license-file set and bytes, the declared
expression, identity metadata (apart from other tools' version pins) and
source scope. Every other manual item is left ``manual-required`` for a new
human decision, which ``record_decisions`` takes at an interactive terminal.

The trust root of a shipped release is its owner approval record: it binds the
exact finalized machine closure and legal review, the legal review names the
reviewed component input, and that input's manual decisions are exactly the
ones the approved closure carries.

None of this approves the new closure; ``record_legal_review`` records that
human approval separately, and ``run_publication_evidence.sh finalize`` stays
the authority that revalidates the review (scripts/publication/legal_review.py).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Final

from .common import PublicationError
from .legal_review import legal_review
from .license_resolution import CARGO_LICENSE_DONOR_SHA256, license_identifiers

PRODUCT_NAME: Final = "Clash for Mac"
MAX_JSON_BYTES: Final = 64 * 1024 * 1024
TOOL_PIN_PREFIXES: Final = {
    "node": ("NODE_",),
    "swift": ("XCODE_", "SWIFT_"),
    "xcode": ("XCODE_", "SWIFT_"),
}
REVIEW_FLAG: Final = "<-- review"

COMPARISON: Final = "component-review-comparison.json"
PENDING: Final = "component-review-pending.json"
DECISIONS: Final = "component-decisions.json"
REVIEWED: Final = "component-review-reviewed.json"
APPROVAL: Final = "approval.json"


class CarryoverRefused(PublicationError):
    """The approval chain or the current evidence cannot be proven."""


def _require(value: object, message: str) -> None:
    if not value:
        raise CarryoverRefused(message)


def _digest(path: Path) -> str:
    _require(stat.S_ISREG(path.lstat().st_mode), f"expected a regular file: {path}")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _read_bytes(path: Path) -> bytes:
    metadata = path.lstat()
    _require(
        stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_JSON_BYTES,
        f"expected a bounded regular JSON file: {path}",
    )
    return path.read_bytes()


def _read_json(path: Path) -> Any:
    return json.loads(_read_bytes(path).decode("utf-8"))


def _canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _pretty(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_exclusive(path: Path, data: bytes) -> None:
    """Create ``path`` once, durably, owner-only; never replace an existing file."""

    parent = path.parent
    _require(stat.S_ISDIR(parent.lstat().st_mode), f"output parent is not a real directory: {parent}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _pins(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            _require("=" in line, f"unclassified pin line: {line}")
            key, value = line.split("=", 1)
            _require(key not in entries, f"duplicate pin: {key}")
            entries[key] = value
    return entries


def _evidence_items(resolution: dict[str, Any]) -> list[dict[str, Any]]:
    return ([resolution["metadata"]] if resolution["metadata"] else []) + list(resolution["files"])


def _bounded_line(value: str, label: str, maximum: int) -> str:
    _require(
        value
        and value.strip() == value
        and len(value) <= maximum
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value),
        f"{label} must be one non-empty line of at most {maximum} characters",
    )
    return value


@dataclass(frozen=True)
class Release:
    """One release's frozen artifact checkout and private review directory."""

    version: str
    build: str
    artifact: Path
    review: Path

    @property
    def stage_inputs(self) -> Path:
        return self.artifact / f"target/candidates/{self.version}/ga/{self.build}/stage-inputs"

    def _named(self, generic: str) -> Path:
        # Releases before the release driver suffixed each file with the build.
        legacy = self.review / generic.replace(".json", f"-{self.build}.json")
        return legacy if os.path.lexists(legacy) else self.review / generic


@dataclass(frozen=True)
class ShippedDecisions:
    """The verified manual decisions of a shipped release."""

    release: Release
    approval_sha256: str
    closure_sha256: str
    legal_review_sha256: str
    comparison_sha256: str
    reviewed_sha256: str
    reviewed: dict[str, dict[str, Any]]


def shipped_decisions(shipped: Release) -> ShippedDecisions:
    """Verify a shipped release's approval chain and return its reviewed decisions."""

    approval_path = shipped._named(APPROVAL)
    approval = _read_json(approval_path)
    legal_path = shipped.stage_inputs / "legal-review.json"
    legal = _read_json(legal_path)
    closure_path = shipped.stage_inputs / "publication/machine-closure.json"
    closure_sha256 = _digest(closure_path)
    _require(approval["approved_closure_sha256"] == closure_sha256, f"{shipped.build} approval does not bind its closure")
    _require(approval["review_sha256"] == _digest(legal_path), f"{shipped.build} legal review bytes drifted")
    _require(
        legal["decision"] == "approved"
        and legal["closure_sha256"] == closure_sha256
        and legal["license_texts_reviewed"] is True
        and legal["source_scope_reviewed"] is True,
        f"{shipped.build} legal review is not an approval of its closure",
    )
    _require(
        _read_json(shipped.stage_inputs / "publication/legal-review.json") == legal,
        f"{shipped.build} finalized legal review differs from its input",
    )
    reviewed_sha256 = approval["reviewed_components_sha256"]
    candidates = [
        path
        for path in sorted(shipped.review.glob("component-review-*.json"))
        if "comparison" not in path.name and "pending" not in path.name and _digest(path) == reviewed_sha256
    ]
    _require(len(candidates) == 1, f"{shipped.build} reviewed component input is not unique in {shipped.review}")
    comparison_path = shipped._named(COMPARISON)
    comparison_sha256 = _digest(comparison_path)
    _require(
        comparison_sha256 in legal["notes"] and reviewed_sha256 in legal["notes"],
        f"{shipped.build} legal review does not name its component comparison and reviewed input",
    )
    document = _read_json(candidates[0])
    reviewed = {item["id"]: item for item in document["components"]}
    _require(len(reviewed) == len(document["components"]), f"{shipped.build} reviewed input repeats an id")
    closure = _read_json(closure_path)
    closure_components = {(item["name"], item["version"]): item for item in closure["components"]}
    closure_tools = {(item["name"], item["version"]): item for item in closure["build_tools"]}
    for key, record in reviewed.items():
        resolution = record["license_resolution"]
        if resolution["status"] != "manual-reviewed":
            continue
        texts = sorted(item["sha256"] for item in resolution["files"])
        identity = (record["name"], record["version"])
        if identity in closure_components:
            entry = closure_components[identity]
            _require(entry["license_expression"] == resolution["expression"], f"approved closure expression differs: {key}")
            _require(sorted(item["sha256"] for item in entry["license_files"]) == texts, f"approved closure texts differ: {key}")
        else:
            entry = closure_tools.get(identity)
            _require(entry is not None, f"reviewed decision is absent from the approved closure: {key}")
            _require(entry["license_reference"] == resolution["expression"], f"approved tool license differs: {key}")
            _require(sorted(item["sha256"] for item in entry["license_evidence"]) == texts, f"approved tool texts differ: {key}")
    return ShippedDecisions(
        release=shipped,
        approval_sha256=_digest(approval_path),
        closure_sha256=closure_sha256,
        legal_review_sha256=approval["review_sha256"],
        comparison_sha256=comparison_sha256,
        reviewed_sha256=reviewed_sha256,
        reviewed=reviewed,
    )


def compare(shipped: Release, candidate: Release, executor: Path, tooling_root: Path) -> dict[str, Any]:
    """Write the comparison and the reviewed (or pending) component input for ``candidate``."""

    comparison_output = candidate.review / COMPARISON
    reviewed_output = candidate.review / REVIEWED
    pending_output = candidate.review / PENDING
    for output in (comparison_output, reviewed_output, pending_output):
        _require(not os.path.lexists(output), f"refusing to replace an existing output: {output}")
    prior = shipped_decisions(shipped)
    roots = (str(shipped.artifact), str(candidate.artifact))
    workspace_re = re.compile(re.escape(str(tooling_root)) + r"/cargo-workspace-[0-9a-f]{64}(?=/|\Z)")

    def normalize(value: object) -> object:
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, str):
            for root in roots:
                if value == root or value.startswith(root + "/"):
                    return "<artifact>" + value[len(root):]
            match = workspace_re.match(value)
            if match:
                return "<cargo-workspace>" + value[match.end():]
        return value

    def file_set(resolution: dict[str, Any]) -> list[tuple[object, str]]:
        return [(normalize(item["path"]), item["sha256"]) for item in resolution["files"]]

    template_path = candidate.stage_inputs / "component-review.json"
    template_sha256 = _digest(template_path)
    template = _read_json(template_path)
    _require(
        template["schema_version"] == 1 and template["product"] == {"name": PRODUCT_NAME, "version": candidate.version},
        f"the template is not the {candidate.version} component review",
    )
    current = {item["id"]: item for item in template["components"]}
    _require(len(current) == len(template["components"]), "the template repeats a component id")
    old_pins_path = shipped.artifact / "scripts/dependency_pins.env"
    new_pins_path = candidate.artifact / "scripts/dependency_pins.env"
    old_pins, new_pins = _pins(old_pins_path), _pins(new_pins_path)
    changed_pins = sorted(key for key in old_pins.keys() | new_pins.keys() if old_pins.get(key) != new_pins.get(key))
    manual_by_name: dict[str, list[dict[str, Any]]] = {}
    for record in prior.reviewed.values():
        if record["license_resolution"]["status"] == "manual-reviewed":
            manual_by_name.setdefault(record["name"], []).append(record)

    review = copy.deepcopy(template)
    rows: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for record in review["components"]:
        key = record["id"]
        resolution = record["license_resolution"]
        for item in _evidence_items(resolution):
            _require(_digest(Path(item["path"])) == item["sha256"], f"current evidence bytes drifted: {item['path']}")
        if resolution["status"] == "automatic":
            continue
        _require(resolution["status"] == "manual-required", f"unexpected template state: {key}")
        reasons, metadata_changed = _reuse_obstacles(
            record, prior.reviewed.get(key), shipped.build, normalize, file_set,
            changed_pins, old_pins_path, new_pins_path,
        )
        if reasons:
            pending.append(_pending_item(record, reasons, manual_by_name, file_set))
            continue
        previous = prior.reviewed[key]["license_resolution"]
        reason = (
            f"Retains the release owner's approved component decision from the approved {shipped.build} closure "
            "after fresh checks of component identity, complete license-file bytes, declared expression and "
            "source scope. This is reuse of an existing decision, not a new human legal review or closure approval."
        )
        if metadata_changed:
            reason += (
                " The pin file changed only outside this tool's version pins ("
                + ", ".join(changed_pins)
                + "); its version, license files and distribution scope are unchanged."
            )
        resolution.update(expression=previous["expression"], method="human-legal-review",
                          status="manual-reviewed", reason=reason)
        for item, approved in zip(resolution["files"], previous["files"]):
            item["supports"] = approved["supports"]
        rows.append({"id": key, "name": record["name"], "version": record["version"],
                     "expression": resolution["expression"], "metadata_changed": metadata_changed})

    def describe(identifiers: list[str], source: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {"id": key, "name": source[key]["name"], "version": source[key]["version"],
             "status": source[key]["license_resolution"]["status"],
             "expression": source[key]["license_resolution"]["expression"]}
            for key in identifiers
        ]

    added = sorted(set(current) - set(prior.reviewed))
    removed = sorted(set(prior.reviewed) - set(current))
    automatic_changed = sorted(
        key
        for key in set(current) & set(prior.reviewed)
        if current[key]["license_resolution"]["status"] == "automatic"
        and normalize(current[key]) != normalize(prior.reviewed[key])
    )
    donor_resolved = _donor_resolved(current, prior.reviewed)
    review_output = pending_output if pending else reviewed_output
    encoded = _canonical(review)
    comparison = {
        "document": "cfm-component-review-comparison-v2",
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "shipped": {"version": shipped.version, "build": shipped.build},
        "candidate": {"version": candidate.version, "build": candidate.build},
        "component_count": len(current),
        "reused_disposition_count": len(rows),
        "pending_decision_count": len(pending),
        "review_kind": "pending" if pending else "complete",
        "review_file": review_output.name,
        "review_sha256": hashlib.sha256(encoded).hexdigest(),
        "current_template_sha256": template_sha256,
        "shipped_approval_sha256": prior.approval_sha256,
        "shipped_closure_sha256": prior.closure_sha256,
        "shipped_legal_review_sha256": prior.legal_review_sha256,
        "shipped_comparison_sha256": prior.comparison_sha256,
        "shipped_reviewed_sha256": prior.reviewed_sha256,
        "resolver_sha256": _digest(executor / "scripts/publication/license_resolution.py"),
        "changed_pins": changed_pins,
        "rows": rows,
        "pending_human_decisions": pending,
        "added_components": describe(added, current),
        "removed_components": describe(removed, prior.reviewed),
        "automatic_components_changed": describe(automatic_changed, current),
        "donor_resolved_components": donor_resolved,
        "final_publication_closure_approved": False,
    }
    write_exclusive(review_output, encoded)
    write_exclusive(comparison_output, _pretty(comparison))
    return {
        "components": len(current),
        "reused_decisions": [row["name"] for row in rows],
        "pending_human_decisions": [
            {"name": item["name"], "version": item["version"], "reasons": item["reasons"]} for item in pending
        ],
        "added": [(item["name"], item["version"], item["status"]) for item in comparison["added_components"]],
        "removed": [(item["name"], item["version"], item["status"]) for item in comparison["removed_components"]],
        "automatic_changed": [(item["name"], item["version"]) for item in comparison["automatic_components_changed"]],
        "donor_not_in_shipped": [
            (item["name"], item["version"]) for item in donor_resolved if not item["same_donor_text_in_shipped"]
        ],
        "changed_pins": changed_pins,
        "review_kind": comparison["review_kind"],
        "review_file": str(review_output),
        "comparison": str(comparison_output),
    }


def _reuse_obstacles(
    record: dict[str, Any],
    previous_record: dict[str, Any] | None,
    shipped_build: str,
    normalize: Callable[[object], object],
    file_set: Callable[[dict[str, Any]], list[tuple[object, str]]],
    changed_pins: list[str],
    old_pins_path: Path,
    new_pins_path: Path,
) -> tuple[list[str], bool]:
    """Why a shipped decision cannot be reused for ``record`` (empty when it can)."""

    resolution = record["license_resolution"]
    if previous_record is None:
        return [f"no approved {shipped_build} decision has this component id"], False
    previous = previous_record["license_resolution"]
    if previous["status"] != "manual-reviewed":
        return [f"the {shipped_build} record of this id was {previous['status']}, not a manual decision"], False
    # The approved digests come from the reviewed input that the shipped
    # approval binds; the current bytes were hashed above. Equal digests are
    # the whole proof, so the shipped build's own caches need not be retained.
    reasons: list[str] = []
    for field in ("name", "version", "purl", "copyright_text", "source_override"):
        if record[field] != previous_record[field]:
            reasons.append(f"{field} changed: {previous_record[field]!r} -> {record[field]!r}")
    if normalize(record["source_evidence"]) != normalize(previous_record["source_evidence"]):
        reasons.append("source scope changed")
    if file_set(resolution) != file_set(previous):
        reasons.append("license file set or bytes changed")
    if resolution["expression"] not in ("", previous["expression"]):
        reasons.append(f"declared license expression changed: {previous['expression']} -> {resolution['expression']}")
    metadata_changed = False
    if normalize(resolution["metadata"]) != normalize(previous["metadata"]):
        prefixes = TOOL_PIN_PREFIXES.get(record["name"])
        if prefixes is None:
            reasons.append("identity metadata changed")
        elif not (
            resolution["metadata"] is not None
            and previous["metadata"] is not None
            and resolution["metadata"]["path"] == str(new_pins_path)
            and previous["metadata"]["path"] == str(old_pins_path)
        ):
            reasons.append("tool identity metadata is not the pin file")
        else:
            tool_pins = [pin for pin in changed_pins if pin.startswith(prefixes)]
            if tool_pins:
                reasons.append("tool version pins changed: " + ", ".join(tool_pins))
            else:
                metadata_changed = True
    return reasons, metadata_changed


def _pending_item(
    record: dict[str, Any],
    reasons: list[str],
    manual_by_name: dict[str, list[dict[str, Any]]],
    file_set: Callable[[dict[str, Any]], list[tuple[object, str]]],
) -> dict[str, Any]:
    resolution = record["license_resolution"]
    same_name = sorted(manual_by_name.get(record["name"], []), key=lambda item: item["id"])
    return {
        "id": record["id"],
        "name": record["name"],
        "version": record["version"],
        "purl": record["purl"],
        "template_expression": resolution["expression"],
        "template_reason": resolution["reason"],
        "metadata": resolution["metadata"],
        "files": [{"path": item["path"], "sha256": item["sha256"]} for item in resolution["files"]],
        "reasons": reasons,
        "approved_decisions_with_same_name": [
            {
                "id": item["id"],
                "name": item["name"],
                "version": item["version"],
                "expression": item["license_resolution"]["expression"],
                "reason": item["license_resolution"]["reason"],
                "same_license_bytes": sorted(sha for _path, sha in file_set(item["license_resolution"]))
                == sorted(sha for _path, sha in file_set(resolution)),
            }
            for item in same_name
        ],
    }


def _donor_resolved(current: dict[str, dict[str, Any]], shipped: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    def donor_texts(component: dict[str, Any]) -> list[dict[str, Any]]:
        resolution = component["license_resolution"]
        source = component["source_evidence"]
        if resolution["status"] != "automatic" or not isinstance(source, dict) or source.get("path") is None:
            return []
        root = Path(source["path"])
        return [
            item for item in resolution["files"]
            if item["sha256"] in CARGO_LICENSE_DONOR_SHA256 and not Path(item["path"]).is_relative_to(root)
        ]

    shipped_by_name: dict[str, set[str]] = {}
    for record in shipped.values():
        shipped_by_name.setdefault(record["name"], set()).update(item["sha256"] for item in donor_texts(record))
    resolved = []
    for key in sorted(current):
        texts = donor_texts(current[key])
        if texts:
            resolved.append({
                "id": key,
                "name": current[key]["name"],
                "version": current[key]["version"],
                "expression": current[key]["license_resolution"]["expression"],
                "donor_texts": [{"path": item["path"], "sha256": item["sha256"]} for item in texts],
                "same_donor_text_in_shipped": {item["sha256"] for item in texts}
                <= shipped_by_name.get(current[key]["name"], set()),
            })
    return resolved


# --- new human component decisions ---------------------------------------------------


def record_decisions(candidate: Release, ask: Callable[[str], str], show: Callable[[str], None]) -> dict[str, Any]:
    """Take a human decision for every pending item and write the reviewed input."""

    reviewed_output = candidate.review / REVIEWED
    decisions_output = candidate.review / DECISIONS
    for output in (reviewed_output, decisions_output):
        _require(not os.path.lexists(output), f"refusing to replace an existing output: {output}")
    comparison_bytes = _read_bytes(candidate.review / COMPARISON)
    comparison = json.loads(comparison_bytes)
    pending_path = candidate.review / PENDING
    pending_bytes = _read_bytes(pending_path)
    pending_sha256 = hashlib.sha256(pending_bytes).hexdigest()
    template_path = candidate.stage_inputs / "component-review.json"
    template_bytes = _read_bytes(template_path)
    template_sha256 = hashlib.sha256(template_bytes).hexdigest()
    _require(
        comparison.get("candidate") == {"version": candidate.version, "build": candidate.build}
        and comparison.get("review_kind") == "pending"
        and comparison.get("review_file") == PENDING
        and comparison.get("review_sha256") == pending_sha256,
        "the pending review copy is not the one the comparison recorded",
    )
    _require(comparison.get("current_template_sha256") == template_sha256,
             "the component-review template changed after the comparison")
    template = {item["id"]: item for item in json.loads(template_bytes)["components"]}
    document = json.loads(pending_bytes)
    listed = {item["id"]: item for item in comparison["pending_human_decisions"]}
    unresolved = [item for item in document["components"] if item["license_resolution"]["status"] == "manual-required"]
    _require({item["id"] for item in unresolved} == set(listed) and len(unresolved) == len(listed),
             "the pending review copy does not match the comparison's pending list")
    shipped_build = comparison["shipped"]["build"]
    show(f"New human license decisions for {PRODUCT_NAME} {candidate.version} build {candidate.build}")
    show(f"pending review copy: {pending_path} (sha256 {pending_sha256})")
    show(f"reused {shipped_build} decisions: "
         + ("; ".join(f"{row['name']} {row['version']}: {row['expression']}" for row in comparison["rows"]) or "none"))
    show(f"items that need a new decision: {len(unresolved)}")
    reviewer = _bounded_line(ask("Reviewer identity for the decision record: ").strip(), "reviewer identity", 200)
    _require(not any(marker in reviewer.casefold() for marker in ("fixture", "test")),
             "a fixture reviewer identity is forbidden in production evidence")
    decided = copy.deepcopy(document)
    by_id = {item["id"]: item for item in decided["components"]}
    decisions = []
    for index, item in enumerate(sorted(unresolved, key=lambda value: value["id"]), start=1):
        decisions.append(_decide(candidate, item, template.get(item["id"]), listed[item["id"]],
                                 by_id[item["id"]], reviewer, shipped_build, index, len(unresolved), ask, show))
    _require(all(item["license_resolution"]["status"] != "manual-required" for item in decided["components"]),
             "an item is still unresolved")
    reviewed_bytes = _canonical(decided)
    record = {
        "document": "cfm-component-license-decisions-v2",
        "version": candidate.version,
        "build": candidate.build,
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reviewer": reviewer,
        "confirmation": "typed each license expression, the supported identifiers of each bound license file and "
        "the rationale, and confirmed each decision at an interactive terminal",
        "template_sha256": template_sha256,
        "comparison_sha256": hashlib.sha256(comparison_bytes).hexdigest(),
        "pending_review_sha256": pending_sha256,
        "reviewed_components_sha256": hashlib.sha256(reviewed_bytes).hexdigest(),
        "reviewed_components_file": REVIEWED,
        "decisions": decisions,
        "scope": f"New human component license decisions for {candidate.version} build {candidate.build}. "
        "They are not the approval of the build's machine closure.",
    }
    write_exclusive(reviewed_output, reviewed_bytes)
    write_exclusive(decisions_output, _pretty(record))
    return record


def _decide(
    candidate: Release,
    item: dict[str, Any],
    template_record: dict[str, Any] | None,
    context: dict[str, Any],
    decided_record: dict[str, Any],
    reviewer: str,
    shipped_build: str,
    index: int,
    total: int,
    ask: Callable[[str], str],
    show: Callable[[str], None],
) -> dict[str, Any]:
    _require(template_record is not None and template_record == item, f"pending item differs from the template: {item['id']}")
    resolution = item["license_resolution"]
    for evidence in _evidence_items(resolution):
        _require(_digest(Path(evidence["path"])) == evidence["sha256"], f"evidence bytes changed: {evidence['path']}")
    _require(resolution["files"], f"no candidate license file exists for {item['id']}; a decision cannot bind text")
    show("")
    show(f"[{index}/{total}] {item['name']} {item['version']} ({item['purl']})")
    show(f"  why no approved decision is reused: {'; '.join(context['reasons'])}")
    show(f"  declared expression: {resolution['expression'] or '(none; the reviewer concludes one)'}")
    for previous in context["approved_decisions_with_same_name"]:
        show(f"  approved {shipped_build} decision of the same name: {previous['name']} {previous['version']} -> "
             f"{previous['expression']} (license bytes {'identical' if previous['same_license_bytes'] else 'DIFFERENT'})")
    show("  candidate license files:")
    for number, evidence in enumerate(resolution["files"], start=1):
        show(f"    [{number}] {evidence['path']} sha256 {evidence['sha256']}")
    typed = ask("  Type the license expression for this component: ").strip()
    _require(not resolution["expression"] or typed == resolution["expression"],
             f"the release tool requires the declared expression {resolution['expression']}; nothing was written")
    expression = _bounded_line(typed, "license expression", 1024)
    expression_ids = license_identifiers(expression)
    _require(expression_ids, "the license expression names no license; nothing was written")
    bound = []
    for number, evidence in enumerate(resolution["files"], start=1):
        answer = ask(f"  License identifiers that file [{number}] supports, separated by spaces "
                     "('all' for every identifier, Enter to leave the file out): ").strip()
        if not answer:
            continue
        supports = sorted(expression_ids) if answer == "all" else sorted(set(answer.split()))
        _require(set(supports) <= expression_ids, f"file [{number}] names an identifier outside the expression")
        bound.append({"path": evidence["path"], "sha256": evidence["sha256"], "supports": supports})
    covered = {identifier for entry in bound for identifier in entry["supports"]}
    _require(bound and covered == expression_ids, "the bound license files do not cover the exact expression")
    rationale = _bounded_line(ask("  Rationale for this decision (one line): ").strip(), "decision rationale", 3000)
    stop = "" if rationale.endswith((".", "!", "?", "。")) else "."
    decided_record["license_resolution"] = {
        "status": "manual-reviewed",
        "expression": expression,
        "method": "human-legal-review",
        "reason": f"{rationale}{stop} Recorded as a new human license decision for {candidate.version} build "
        f"{candidate.build} by {reviewer}; it is not reused from build {shipped_build}.",
        "metadata": resolution["metadata"],
        "files": bound,
    }
    _require(ask(f"  Record this decision for {item['name']} {item['version']}? Type yes: ").strip() == "yes",
             "the decision was not confirmed; nothing was written")
    return {
        "id": item["id"],
        "name": item["name"],
        "version": item["version"],
        "purl": item["purl"],
        "license_resolution": decided_record["license_resolution"],
        "reasons_for_new_decision": context["reasons"],
    }


# --- closure difference and legal review ------------------------------------------------


def closure_difference(shipped: Release, draft_path: Path) -> list[str]:
    """Reviewer aid: what the draft closure changes against the shipped approved closure."""

    prior = shipped_decisions(shipped)
    approved_path = shipped.stage_inputs / "publication/machine-closure.json"
    approved = _read_json(approved_path)
    draft = _read_json(draft_path)
    lines = [
        f"approved {shipped.build} closure: {prior.closure_sha256}",
        f"draft closure: {_digest(draft_path)}",
    ]

    def index(entries: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
        indexed = {item["id"]: item for item in entries}
        _require(len(indexed) == len(entries), f"closure repeats a {label} id")
        return indexed

    def texts(entry: dict[str, Any], field: str) -> list[str]:
        return sorted(item["sha256"] for item in entry[field])

    for label, license_field, text_field, field in (
        ("component", "license_expression", "license_files", "components"),
        ("build tool", "license_reference", "license_evidence", "build_tools"),
    ):
        old, new = index(approved[field], label), index(draft[field], label)
        lines.append(f"{label}s: approved {len(old)} -> draft {len(new)}")

        def describe(entry: dict[str, Any]) -> str:
            return f"{entry['name']} {entry['version']} [{entry[license_field]}]"

        def by_name(entries: dict[str, dict[str, Any]], ids: set[str]) -> dict[tuple[str, str], list[dict[str, Any]]]:
            groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for identifier in sorted(ids):
                entry = entries[identifier]
                groups.setdefault((entry.get("ecosystem", ""), entry["name"]), []).append(entry)
            return groups

        removed, added = by_name(old, set(old) - set(new)), by_name(new, set(new) - set(old))
        for key in sorted(removed.keys() | added.keys()):
            before, after = removed.get(key, []), added.get(key, [])
            if len(before) == 1 and len(after) == 1:
                same_license = before[0][license_field] == after[0][license_field]
                same_texts = texts(before[0], text_field) == texts(after[0], text_field)
                flag = "" if same_license and same_texts else f"  LICENSE CHANGED {REVIEW_FLAG}"
                lines.append(f"{label} version change: {describe(before[0])} -> {describe(after[0])}; license "
                             f"{'same' if same_license else 'DIFFERENT'}, texts {'same' if same_texts else 'DIFFERENT'}{flag}")
                continue
            lines.extend(f"{label} ADDED: {describe(entry)}  new, review license and source {REVIEW_FLAG}" for entry in after)
            lines.extend(f"{label} REMOVED: {describe(entry)}" for entry in before)
        for identifier in sorted(set(old) & set(new)):
            before, after = old[identifier], new[identifier]
            if before == after:
                continue
            changed = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
            if before[license_field] != after[license_field] or texts(before, text_field) != texts(after, text_field):
                lines.append(f"{label} LICENSE CHANGED: {describe(before)} -> {describe(after)}; fields {changed}  {REVIEW_FLAG}")
            else:
                lines.append(f"{label} same license, changed fields {changed}: {describe(after)}")
    old_source, new_source = approved.get("corresponding_source", {}), draft.get("corresponding_source", {})
    lines.append(f"corresponding source: approved {old_source.get('sha256')} ({old_source.get('total_file_bytes')} bytes) "
                 f"-> draft {new_source.get('sha256')} ({new_source.get('total_file_bytes')} bytes)")
    lines.append(f"review flags: {sum(line.endswith(REVIEW_FLAG) for line in lines)}")
    return lines


def record_legal_review(
    shipped: Release, candidate: Release, ask: Callable[[str], str], show: Callable[[str], None]
) -> dict[str, Any]:
    """Record the human approval of the exact draft closure and its private approval record."""

    review_output = candidate.stage_inputs / "legal-review.json"
    approval_output = candidate.review / APPROVAL
    for output in (review_output, approval_output):
        _require(not os.path.lexists(output), f"refusing to replace an existing output: {output}")
    draft_path = candidate.stage_inputs / "machine-closure.draft.json"
    draft_bytes = _read_bytes(draft_path)
    closure_sha256 = hashlib.sha256(draft_bytes).hexdigest()
    closure = json.loads(draft_bytes)
    _require(
        closure.get("product") == {"build_number": candidate.build, "name": PRODUCT_NAME, "version": candidate.version}
        and closure.get("fixture") is False,
        f"the draft is not the production closure of {candidate.version} build {candidate.build}",
    )
    component_ids = [item["id"] for item in closure["components"]]
    tools = closure["build_tools"]
    reviewed_path = candidate.review / REVIEWED
    reviewed_bytes = _read_bytes(reviewed_path)
    reviewed_sha256 = hashlib.sha256(reviewed_bytes).hexdigest()
    reviewed = {item["id"]: item for item in json.loads(reviewed_bytes)["components"]}
    entries = {item["id"]: item for item in closure["components"]}
    entries.update({item["id"]: item for item in tools})
    _require(set(reviewed) == set(entries), "the reviewed component input does not cover exactly the draft closure")
    manual_ids: set[str] = set()
    manual_lines = []
    for identifier, item in sorted(reviewed.items()):
        resolution = item["license_resolution"]
        if resolution["status"] == "automatic":
            continue
        _require(resolution["status"] == "manual-reviewed", f"an item is still unresolved: {identifier}")
        entry = entries[identifier]
        _require(entry.get("license_expression", entry.get("license_reference")) == resolution["expression"],
                 f"the draft closure does not carry the reviewed decision: {identifier}")
        manual_ids.add(identifier)
        manual_lines.append(f"{item['name']} {item['version']}: {resolution['expression']}")
    provenance = _decision_provenance(candidate, reviewed_sha256, manual_ids)
    show(f"product: {PRODUCT_NAME} {candidate.version} build {candidate.build}")
    for line in closure_difference(shipped, draft_path):
        show(line)
    show(f"reviewed component input: {reviewed_path} (sha256 {reviewed_sha256})")
    show("manual license decisions: " + ("; ".join(manual_lines) or "none"))
    typed = ask("Type the full closure sha256 to approve this exact closure (anything else aborts): ").strip()
    _require(typed == closure_sha256, "the closure digest was not confirmed; nothing was written")
    _require(ask("Have you reviewed every license text of this closure? Type yes: ").strip() == "yes",
             "license texts were not confirmed as reviewed; nothing was written")
    _require(ask("Have you reviewed the corresponding-source scope? Type yes: ").strip() == "yes",
             "corresponding-source scope was not confirmed as reviewed; nothing was written")
    reviewer = _bounded_line(ask("Reviewer identity for legal-review.json: ").strip(), "reviewer identity", 200)
    extra = ask("Optional one-line reviewer note (Enter for none): ").strip()
    reviewed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    notes = (
        f"The reviewer approved the exact {candidate.version} build {candidate.build} machine closure "
        f"{closure_sha256}, its {len(component_ids)} components, {len(tools)} external build tools, license texts "
        "and corresponding-source scope by typing the closure digest at the release Mac's terminal. The reviewed "
        f"component input has sha256 {reviewed_sha256}.{provenance['sentence']}"
    )
    if extra:
        notes += f" Reviewer note: {_bounded_line(extra, 'reviewer note', 1000)}"
    review = {
        "schema_version": 1,
        "decision": "approved",
        "reviewer": reviewer,
        "reviewed_at": reviewed_at,
        "closure_sha256": closure_sha256,
        "component_ids": component_ids,
        "license_texts_reviewed": True,
        "source_scope_reviewed": True,
        "notes": notes,
    }
    review_bytes = _pretty(review)
    # The release tool's own validator is the authority over the file. It reads
    # a private pending copy, so a refused review never appears under its final
    # name; the link then publishes it without replacing anything.
    pending = review_output.with_name(f".{review_output.name}.pending")
    _require(not os.path.lexists(pending), f"an earlier legal review attempt left {pending}; inspect and remove it")
    write_exclusive(pending, review_bytes)
    try:
        legal_review(pending, closure_sha256, component_ids, False)
        os.link(pending, review_output)
    finally:
        os.unlink(pending)
    approval = {
        "recorded_at": reviewed_at,
        "reviewer": reviewer,
        "confirmation": "typed the exact closure sha256 and confirmed license-text and source-scope review "
        "at an interactive terminal",
        "approved_closure_sha256": closure_sha256,
        "component_count": len(component_ids),
        "build_tool_count": len(tools),
        "reviewed_components_sha256": reviewed_sha256,
        "component_comparison_sha256": provenance["comparison_sha256"],
        "component_decisions_sha256": provenance["decisions_sha256"],
        "review_sha256": hashlib.sha256(review_bytes).hexdigest(),
        "scope": f"Exact closure approval for the {candidate.version} build {candidate.build} publication evidence.",
    }
    write_exclusive(approval_output, _pretty(approval))
    return approval


def _decision_provenance(candidate: Release, reviewed_sha256: str, manual_ids: set[str]) -> dict[str, Any]:
    comparison_bytes = _read_bytes(candidate.review / COMPARISON)
    comparison = json.loads(comparison_bytes)
    comparison_sha256 = hashlib.sha256(comparison_bytes).hexdigest()
    _require(comparison.get("candidate") == {"version": candidate.version, "build": candidate.build},
             "the component comparison belongs to another build")
    reused_ids = {row["id"] for row in comparison["rows"]}
    shipped_build = comparison["shipped"]["build"]
    if comparison.get("review_kind") == "complete" and comparison.get("review_sha256") == reviewed_sha256:
        _require(reused_ids == manual_ids, "the comparison's reused decisions are not the manual decisions of the input")
        return {
            "comparison_sha256": comparison_sha256,
            "decisions_sha256": None,
            "sentence": f" Its {len(manual_ids)} manual decisions reuse the approved {shipped_build} decisions after "
            f"the exact identity, license-byte, declared-expression and source-scope rechecks recorded in {COMPARISON} "
            f"(sha256 {comparison_sha256}).",
        }
    decisions_path = candidate.review / DECISIONS
    _require(comparison.get("review_kind") == "pending" and os.path.lexists(decisions_path),
             "the reviewed component input is not the comparison's complete reviewed copy")
    decisions_bytes = _read_bytes(decisions_path)
    decisions = json.loads(decisions_bytes)
    decisions_sha256 = hashlib.sha256(decisions_bytes).hexdigest()
    decided_ids = {item["id"] for item in decisions["decisions"]}
    _require(
        decisions.get("build") == candidate.build
        and decisions.get("reviewed_components_sha256") == reviewed_sha256
        and decisions.get("pending_review_sha256") == comparison.get("review_sha256")
        and decisions.get("comparison_sha256") == comparison_sha256
        and not decided_ids & reused_ids
        and decided_ids | reused_ids == manual_ids,
        "the reviewed component input is not bound by the comparison and decision record",
    )
    return {
        "comparison_sha256": comparison_sha256,
        "decisions_sha256": decisions_sha256,
        "sentence": f" {len(reused_ids)} of its {len(manual_ids)} manual decisions reuse the approved {shipped_build} "
        f"decisions after the rechecks recorded in {COMPARISON} (sha256 {comparison_sha256}); the other "
        f"{len(decided_ids)} are new human license decisions recorded in {DECISIONS} (sha256 {decisions_sha256}).",
    }
