#!/usr/bin/env python3
"""Source-pinned proof-to-byte physical-evidence aggregation gate.

The aggregate contains descriptors for four source-pinned harness reports, never embedded
claim-only documents. Each report is reopened and hashed beneath the aggregate's
evidence root; each harness then reopens and validates its own raw artifacts.
Finally, a source-pinned external collector key verifies a canonical receipt
covering the candidate, run identity, report descriptors, and complete raw set.

Without a configured release trust policy this gate fails closed. Filesystem
checks and hashes do not claim to defend against a malicious operator who owns
the collector signing key or the collection host.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Callable

if __package__:
    from .adversarial_clients import (
        HARNESS_VERSION as ADVERSARIAL_VERSION,
        AdversarialMatrixError,
        validate_adversarial_matrix,
    )
    from .lifecycle_matrix import (
        HARNESS_VERSION as LIFECYCLE_VERSION,
        MACOS_BUILD_RE,
        LifecycleMatrixError,
        validate_lifecycle_matrix,
    )
    from .packet_evidence import (
        HARNESS_VERSION as PACKET_VERSION,
        PacketEvidenceError,
        validate_packet_evidence,
    )
    from .performance_gates import (
        HARNESS_VERSION as PERFORMANCE_VERSION,
        PerformanceGateError,
        validate_performance_evidence,
    )
    from .raw_artifacts import (
        ArtifactReader,
        CollectorTrustNotConfiguredError,
        CollectorTrustPolicy,
        RELEASE_TRUST_POLICY_SHA256,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        load_release_trust_policy,
        parse_descriptor,
        parse_proof_binding,
        read_regular_file_bytes,
        require_identifier,
        require_sha256,
        read_release_trust_policy_bytes,
        verify_rs256,
    )
    from ..evidence_manifest import LEVEL_ORDER
    from ..release_build_identity import BuildIdentityError, canonical_build_version
else:  # pragma: no cover - direct-script import path
    import sys

    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    sys.path.insert(0, str(here.parent))
    from adversarial_clients import (  # type: ignore
        HARNESS_VERSION as ADVERSARIAL_VERSION,
        AdversarialMatrixError,
        validate_adversarial_matrix,
    )
    from lifecycle_matrix import (  # type: ignore
        HARNESS_VERSION as LIFECYCLE_VERSION,
        MACOS_BUILD_RE,
        LifecycleMatrixError,
        validate_lifecycle_matrix,
    )
    from packet_evidence import (  # type: ignore
        HARNESS_VERSION as PACKET_VERSION,
        PacketEvidenceError,
        validate_packet_evidence,
    )
    from performance_gates import (  # type: ignore
        HARNESS_VERSION as PERFORMANCE_VERSION,
        PerformanceGateError,
        validate_performance_evidence,
    )
    from raw_artifacts import (  # type: ignore
        ArtifactReader,
        CollectorTrustNotConfiguredError,
        CollectorTrustPolicy,
        RELEASE_TRUST_POLICY_SHA256,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        load_release_trust_policy,
        parse_descriptor,
        parse_proof_binding,
        read_regular_file_bytes,
        require_identifier,
        require_sha256,
        read_release_trust_policy_bytes,
        verify_rs256,
    )
    from evidence_manifest import LEVEL_ORDER  # type: ignore
    from release_build_identity import BuildIdentityError, canonical_build_version  # type: ignore


SCHEMA_VERSION = 2
AGGREGATOR_VERSION = "physical-evidence-aggregator-v2"
PRODUCT_VERSION = "0.4.0"
GRANTED_LEVEL = "Signed_Installed_Verified"
if GRANTED_LEVEL not in LEVEL_ORDER:
    raise RuntimeError("physical evidence level is absent from Evidence_Manifest")

REQUIRED_OS = frozenset({"macos15", "current-macos"})
# Reviewed stable release matrix, source-pinned on 2026-07-29 from Apple's
# 2026-07-27 security-release list. Updating "current" is a release-source
# change, never an inference from whichever host happens to run the collector.
REQUIRED_MACOS_VERSIONS = {
    "macos15": "15.7.8",
    "current-macos": "26.6",
}
REQUIRED_MACOS_BUILDS = {
    "macos15": "24G824",
    "current-macos": "25G72",
}
STABLE_MATRIX_GENERAL_AVAILABILITY = datetime(
    2026, 7, 27, tzinfo=timezone.utc
)
REQUIRED_HARNESSES = frozenset({"lifecycle", "packet", "performance", "adversarial"})
EXPECTED_TOOL_VERSIONS = {
    "lifecycle": LIFECYCLE_VERSION,
    "packet": PACKET_VERSION,
    "performance": PERFORMANCE_VERSION,
    "adversarial": ADVERSARIAL_VERSION,
}
REPORT_KINDS = {
    "lifecycle": "lifecycle-report",
    "packet": "packet-report",
    "performance": "performance-report",
    "adversarial": "adversarial-report",
}
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024

CANDIDATE_FIELDS = {
    "version",
    "build_number",
    "app_manifest_sha256",
    "signed_app_tree_sha256",
    "built_at",
}
RUN_FIELDS = {
    "os",
    "macos_version",
    "macos_build",
    "machine_sha256",
    "clean_install",
    "captured_at",
    "completed_at",
    "signed_at",
    "run_id",
    "run_nonce",
    "collector",
    "reports",
}
COLLECTOR_FIELDS = {
    "version",
    "source_sha256",
    "executable_sha256",
    "key_id",
    "algorithm",
    "signature",
}
REPORT_FIELDS = {"tool_version", "captured_at", "completed_at", "signed_at", "artifact"}


class PhysicalEvidenceError(ValueError):
    """Physical evidence is incomplete, byte-drifted, replayed, or untrusted."""


def _resolve_trust_policy(
    trust_policy: CollectorTrustPolicy | None, *, fixture: bool
) -> CollectorTrustPolicy:
    """Keep test-key injection out of every production validation path."""

    if fixture:
        return load_release_trust_policy() if trust_policy is None else trust_policy
    if trust_policy is not None and not trust_policy.release_source_pinned:
        raise RawArtifactError(
            "caller-supplied collector trust policies require fixture mode"
        )
    canonical = load_release_trust_policy()
    if trust_policy is not None and trust_policy != canonical:
        raise RawArtifactError(
            "collector trust policy does not exactly match the source-pinned policy"
        )
    return canonical


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PhysicalEvidenceError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PhysicalEvidenceError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PhysicalEvidenceError(f"{label} must use UTC")
    return parsed


def _bounded_text(value: Any, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PhysicalEvidenceError(f"{label} must be bounded printable text")
    return value


def _candidate(value: Any) -> tuple[dict[str, Any], datetime]:
    candidate = exact_object(value, CANDIDATE_FIELDS, "candidate")
    if candidate["version"] != PRODUCT_VERSION:
        raise PhysicalEvidenceError(f"candidate.version must be {PRODUCT_VERSION}")
    try:
        build_number = canonical_build_version(candidate["build_number"], "candidate.build_number")
    except BuildIdentityError as error:
        raise PhysicalEvidenceError(str(error)) from error
    parsed = {
        "version": PRODUCT_VERSION,
        "build_number": build_number,
        "app_manifest_sha256": require_sha256(
            candidate["app_manifest_sha256"], "candidate.app_manifest_sha256"
        ),
        "signed_app_tree_sha256": require_sha256(
            candidate["signed_app_tree_sha256"], "candidate.signed_app_tree_sha256"
        ),
        "built_at": candidate["built_at"],
    }
    return parsed, _timestamp(candidate["built_at"], "candidate.built_at")


def _collector(value: Any, policy: CollectorTrustPolicy, label: str) -> dict[str, Any]:
    collector = exact_object(value, COLLECTOR_FIELDS, label)
    parsed = {
        "version": require_identifier(collector["version"], f"{label}.version"),
        "source_sha256": require_sha256(collector["source_sha256"], f"{label}.source_sha256"),
        "executable_sha256": require_sha256(
            collector["executable_sha256"], f"{label}.executable_sha256"
        ),
        "key_id": require_identifier(collector["key_id"], f"{label}.key_id"),
        "algorithm": collector["algorithm"],
        "signature": collector["signature"],
    }
    expected = {
        "version": policy.collector_version,
        "source_sha256": policy.collector_source_sha256,
        "executable_sha256": policy.collector_executable_sha256,
        "key_id": policy.key_id,
        "algorithm": "RS256",
    }
    for field, wanted in expected.items():
        if parsed[field] != wanted:
            raise PhysicalEvidenceError(f"{label}.{field} differs from the source-pinned policy")
    if not isinstance(parsed["signature"], str):
        raise PhysicalEvidenceError(f"{label}.signature must be an RS256 base64url string")
    return parsed


def _proof_expected(
    candidate: dict[str, Any], run: dict[str, Any], collector: dict[str, Any]
) -> dict[str, Any]:
    return {
        "run_id": run["run_id"],
        "run_nonce": run["run_nonce"],
        "candidate": {key: candidate[key] for key in sorted(CANDIDATE_FIELDS - {"built_at"})},
        "collector": {
            "version": collector["version"],
            "source_sha256": collector["source_sha256"],
            "executable_sha256": collector["executable_sha256"],
        },
    }


def _identity_check(
    harness: str,
    result: dict[str, Any],
    run: dict[str, Any],
    label: str,
) -> None:
    document = result["document"]
    if harness == "lifecycle":
        environment = result["environment"]
        if environment["machine_sha256"] != run["machine_sha256"]:
            raise PhysicalEvidenceError(f"{label} machine identity differs from its run")
        if environment["macos_build"] != run["macos_build"]:
            raise PhysicalEvidenceError(f"{label} macOS build differs from its run")
    elif harness == "packet":
        if document["platform"]["macos_version"] != run["macos_version"]:
            raise PhysicalEvidenceError(f"{label} macOS version differs from its run")
    elif harness == "performance":
        machine = result["parameters"]["machine"]
        expected = {
            "macos_version": run["macos_version"],
            "macos_build": run["macos_build"],
            "machine_sha256": run["machine_sha256"],
        }
        for field, wanted in expected.items():
            if machine[field] != wanted:
                raise PhysicalEvidenceError(f"{label} machine.{field} differs from its run")
    elif harness == "adversarial":
        if document["platform"]["macos_version"] != run["macos_version"]:
            raise PhysicalEvidenceError(f"{label} macOS version differs from its run")
    else:
        raise PhysicalEvidenceError(f"unknown harness identity check: {harness}")


def _validate_lifecycle(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    return validate_lifecycle_matrix(value, artifacts)


def _validate_packet(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    return validate_packet_evidence(value, artifacts)


def _validate_performance(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    return validate_performance_evidence(value, artifacts)


def _validate_adversarial(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    return validate_adversarial_matrix(value, artifacts)


HARNESS_VALIDATORS: dict[str, Callable[[Any, ArtifactReader], dict[str, Any]]] = {
    "lifecycle": _validate_lifecycle,
    "packet": _validate_packet,
    "performance": _validate_performance,
    "adversarial": _validate_adversarial,
}

HARNESS_ERRORS = (
    LifecycleMatrixError,
    PacketEvidenceError,
    PerformanceGateError,
    AdversarialMatrixError,
)


def _validate_report(
    harness: str,
    value: Any,
    *,
    candidate: dict[str, Any],
    built_at: datetime,
    run: dict[str, Any],
    collector: dict[str, Any],
    artifacts: ArtifactReader,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    label = f"run[{run['os']}].reports.{harness}"
    report = exact_object(value, REPORT_FIELDS, label)
    if report["tool_version"] != EXPECTED_TOOL_VERSIONS[harness]:
        raise PhysicalEvidenceError(
            f"{label}.tool_version differs from the source-pinned harness"
        )
    captured_at = _timestamp(report["captured_at"], f"{label}.captured_at")
    completed_at = _timestamp(report["completed_at"], f"{label}.completed_at")
    signed_at = _timestamp(report["signed_at"], f"{label}.signed_at")
    if not (
        built_at <= run["captured_at_dt"] <= captured_at <= completed_at <= signed_at
        and completed_at <= run["completed_at_dt"]
        and signed_at <= run["signed_at_dt"]
    ):
        raise PhysicalEvidenceError(f"{label} timestamps are stale, reversed, or after its run")
    descriptor, document = artifacts.read_json(
        report["artifact"], expected_kind=REPORT_KINDS[harness], label=f"{label}.artifact"
    )
    try:
        result = HARNESS_VALIDATORS[harness](document, artifacts)
    except HARNESS_ERRORS as error:
        raise PhysicalEvidenceError(f"{label} harness validation failed: {error}") from error
    expected_proof = _proof_expected(candidate, run, collector)
    if parse_proof_binding(result["proof"], f"{label}.proof") != expected_proof:
        raise PhysicalEvidenceError(f"{label} candidate/run/collector proof differs")
    if document.get("harness_version") != report["tool_version"]:
        raise PhysicalEvidenceError(f"{label} report wrapper/tool version differs from its bytes")
    for field in ("captured_at", "completed_at", "signed_at"):
        if document.get(field) != report[field]:
            raise PhysicalEvidenceError(f"{label} {field} differs from its report bytes")
    _identity_check(harness, result, run, label)
    report_binding = {
        "harness": harness,
        "tool_version": report["tool_version"],
        "captured_at": report["captured_at"],
        "completed_at": report["completed_at"],
        "signed_at": report["signed_at"],
        "descriptor": descriptor.as_dict(),
    }
    raw_bindings = [
        {
            "harness": harness,
            "subject": binding["subject"],
            "descriptor": binding["descriptor"],
        }
        for binding in result["artifacts"]
    ]
    return result, report_binding, raw_bindings


def _receipt_payload(
    *,
    policy_sha256: str,
    candidate: dict[str, Any],
    run: dict[str, Any],
    collector: dict[str, Any],
    report_bindings: list[dict[str, Any]],
    raw_bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "trust_policy_sha256": policy_sha256,
        "candidate": candidate,
        "run": {
            key: run[key]
            for key in (
                "os",
                "macos_version",
                "macos_build",
                "machine_sha256",
                "clean_install",
                "captured_at",
                "completed_at",
                "signed_at",
                "run_id",
                "run_nonce",
            )
        },
        "collector": {
            key: collector[key]
            for key in ("version", "source_sha256", "executable_sha256", "key_id", "algorithm")
        },
        "reports": sorted(report_bindings, key=lambda entry: entry["harness"]),
        "raw_artifacts": sorted(
            raw_bindings, key=lambda entry: (entry["harness"], entry["subject"])
        ),
    }


def _validate_run(
    value: Any,
    index: int,
    *,
    policy: CollectorTrustPolicy,
    candidate: dict[str, Any],
    built_at: datetime,
    artifacts: ArtifactReader,
    seen_os: set[str],
    seen_run_ids: set[str],
    seen_nonces: set[str],
    seen_machines: set[str],
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], str]:
    raw = exact_object(value, RUN_FIELDS, f"runs[{index}]")
    os_label = raw["os"]
    if os_label not in REQUIRED_OS or os_label in seen_os:
        raise PhysicalEvidenceError(f"runs[{index}].os is unknown or duplicated")
    seen_os.add(os_label)
    macos_version = _bounded_text(raw["macos_version"], f"runs[{index}].macos_version")
    expected_version = REQUIRED_MACOS_VERSIONS[os_label]
    if macos_version != expected_version:
        raise PhysicalEvidenceError(
            f"runs[{index}].macos_version must be the source-pinned stable "
            f"version {expected_version!r} for {os_label!r}"
        )
    macos_build = raw["macos_build"]
    if not isinstance(macos_build, str) or not MACOS_BUILD_RE.fullmatch(macos_build):
        raise PhysicalEvidenceError(f"runs[{index}].macos_build is invalid")
    expected_build = REQUIRED_MACOS_BUILDS[os_label]
    if macos_build != expected_build:
        raise PhysicalEvidenceError(
            f"runs[{index}].macos_build must be the source-pinned stable build "
            f"{expected_build!r} for {os_label!r}"
        )
    machine = require_sha256(raw["machine_sha256"], f"runs[{index}].machine_sha256")
    if machine in seen_machines:
        raise PhysicalEvidenceError("physical runs reuse a machine identity")
    seen_machines.add(machine)
    if raw["clean_install"] is not True:
        raise PhysicalEvidenceError(f"runs[{index}] is not a clean physical install")
    captured_at_dt = _timestamp(raw["captured_at"], f"runs[{index}].captured_at")
    completed_at_dt = _timestamp(raw["completed_at"], f"runs[{index}].completed_at")
    signed_at_dt = _timestamp(raw["signed_at"], f"runs[{index}].signed_at")
    if not (
        max(built_at, STABLE_MATRIX_GENERAL_AVAILABILITY)
        <= captured_at_dt
        <= completed_at_dt
        <= signed_at_dt
    ) or signed_at_dt > datetime.now(timezone.utc):
        raise PhysicalEvidenceError(
            f"runs[{index}] predates stable GA, has reversed completion/signing "
            "timestamps, or is dated in the future"
        )
    run_id = require_identifier(raw["run_id"], f"runs[{index}].run_id")
    if run_id in seen_run_ids:
        raise PhysicalEvidenceError("physical runs reuse a run_id")
    seen_run_ids.add(run_id)
    run_nonce = require_sha256(raw["run_nonce"], f"runs[{index}].run_nonce")
    if run_nonce in seen_nonces:
        raise PhysicalEvidenceError("physical runs reuse a run nonce")
    seen_nonces.add(run_nonce)
    run = {
        "os": os_label,
        "macos_version": macos_version,
        "macos_build": macos_build,
        "machine_sha256": machine,
        "clean_install": True,
        "captured_at": raw["captured_at"],
        "captured_at_dt": captured_at_dt,
        "completed_at": raw["completed_at"],
        "completed_at_dt": completed_at_dt,
        "signed_at": raw["signed_at"],
        "signed_at_dt": signed_at_dt,
        "run_id": run_id,
        "run_nonce": run_nonce,
    }
    collector = _collector(raw["collector"], policy, f"runs[{index}].collector")
    reports = exact_object(raw["reports"], set(REQUIRED_HARNESSES), f"runs[{index}].reports")
    report_bindings: list[dict[str, Any]] = []
    raw_bindings: list[dict[str, Any]] = []
    results: dict[str, dict[str, Any]] = {}
    for harness in sorted(REQUIRED_HARNESSES):
        result, report_binding, harness_raw = _validate_report(
            harness,
            reports[harness],
            candidate=candidate,
            built_at=built_at,
            run=run,
            collector=collector,
            artifacts=artifacts,
        )
        results[harness] = result
        report_bindings.append(report_binding)
        raw_bindings.extend(harness_raw)
    payload = _receipt_payload(
        policy_sha256=policy.policy_sha256,
        candidate=candidate,
        run=run,
        collector=collector,
        report_bindings=report_bindings,
        raw_bindings=raw_bindings,
    )
    try:
        verify_rs256(
            canonical_json(payload),
            collector["signature"],
            modulus=policy.modulus,
            exponent=policy.exponent,
        )
    except RawArtifactError as error:
        raise PhysicalEvidenceError(f"runs[{index}] collector receipt failed: {error}") from error
    receipt_sha256 = hashlib.sha256(canonical_json(payload)).hexdigest()

    # Final-candidate publication binds five categories. Soak is bound directly
    # to the raw performance-samples bytes; performance itself is bound to its
    # report document bytes.
    publication_bindings: list[dict[str, Any]] = []
    category_map = {
        "lifecycle": "installed_matrix",
        "packet": "packet",
        "performance": "performance",
        "adversarial": "security",
    }
    for binding in report_bindings:
        descriptor = binding["descriptor"]
        publication_bindings.append(
            {
                "os": os_label,
                "category": category_map[binding["harness"]],
                "tool_version": binding["tool_version"],
                "captured_at": binding["captured_at"],
                "completed_at": binding["completed_at"],
                "signed_at": binding["signed_at"],
                "report_sha256": descriptor["sha256"],
                "artifact_path": descriptor["path"],
            }
        )
    performance_raw = [
        entry for entry in raw_bindings if entry["harness"] == "performance"
    ]
    if len(performance_raw) != 1:
        raise PhysicalEvidenceError("performance harness must bind exactly one raw sample artifact")
    soak_descriptor = performance_raw[0]["descriptor"]
    performance_report = next(
        binding for binding in report_bindings if binding["harness"] == "performance"
    )
    publication_bindings.append(
        {
            "os": os_label,
            "category": "soak",
            "tool_version": performance_report["tool_version"],
            "captured_at": performance_report["captured_at"],
            "completed_at": performance_report["completed_at"],
            "signed_at": performance_report["signed_at"],
            "report_sha256": soak_descriptor["sha256"],
            "artifact_path": soak_descriptor["path"],
        }
    )
    return os_label, publication_bindings, raw_bindings, receipt_sha256


def _validate(
    value: Any,
    *,
    artifacts: ArtifactReader,
    trust_policy: CollectorTrustPolicy,
    fixture: bool,
) -> dict[str, Any]:
    initial_artifact_count = artifacts.artifact_count
    initial_artifact_bytes = artifacts.total_bytes
    if not trust_policy.release_source_pinned and not fixture:
        raise PhysicalEvidenceError(
            "collector trust policy is not pinned by release source; "
            "test policies require fixture mode"
        )
    document = exact_object(
        value,
        {
            "schema_version",
            "aggregator_version",
            "granted_level",
            "trust_policy_sha256",
            "candidate",
            "runs",
        },
        "physical evidence aggregate",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise PhysicalEvidenceError(f"aggregate schema_version must be {SCHEMA_VERSION}")
    if document["aggregator_version"] != AGGREGATOR_VERSION:
        raise PhysicalEvidenceError(
            f"aggregate aggregator_version must be {AGGREGATOR_VERSION!r}"
        )
    if document["granted_level"] != GRANTED_LEVEL:
        raise PhysicalEvidenceError("aggregate may grant only Signed_Installed_Verified")
    declared_policy = require_sha256(
        document["trust_policy_sha256"], "aggregate.trust_policy_sha256"
    )
    if declared_policy != trust_policy.policy_sha256:
        raise PhysicalEvidenceError("aggregate trust policy differs from the source-pinned policy")
    candidate, built_at = _candidate(document["candidate"])
    runs = document["runs"]
    if not isinstance(runs, list) or len(runs) != len(REQUIRED_OS):
        raise PhysicalEvidenceError("aggregate must contain both required physical run sets")
    seen_os: set[str] = set()
    seen_run_ids: set[str] = set()
    seen_nonces: set[str] = set()
    seen_machines: set[str] = set()
    report_bindings: list[dict[str, Any]] = []
    raw_bindings: list[dict[str, Any]] = []
    receipt_hashes: list[str] = []
    installed_runs: list[dict[str, Any]] = []
    for index, raw_run in enumerate(runs):
        _os, publication, raw_artifacts, receipt_sha256 = _validate_run(
            raw_run,
            index,
            policy=trust_policy,
            candidate=candidate,
            built_at=built_at,
            artifacts=artifacts,
            seen_os=seen_os,
            seen_run_ids=seen_run_ids,
            seen_nonces=seen_nonces,
            seen_machines=seen_machines,
        )
        report_bindings.extend(publication)
        raw_bindings.extend(raw_artifacts)
        receipt_hashes.append(receipt_sha256)
        run_value = runs[index]
        installed_runs.append(
            {
                "os": run_value["os"],
                "macos_build": run_value["macos_build"],
                "machine_sha256": run_value["machine_sha256"],
                "report_hashes": sorted(
                    entry["report_sha256"] for entry in publication
                ),
            }
        )
    artifact_count = artifacts.artifact_count - initial_artifact_count
    artifact_bytes = artifacts.total_bytes - initial_artifact_bytes
    if seen_os != set(REQUIRED_OS):
        raise PhysicalEvidenceError("aggregate is missing a required macOS run set")
    if len(set(receipt_hashes)) != len(receipt_hashes):
        raise PhysicalEvidenceError("physical runs reuse a collector receipt")
    raw_manifest_sha256 = hashlib.sha256(
        canonical_json(
            sorted(
                raw_bindings,
                key=lambda entry: (
                    entry["harness"],
                    entry["subject"],
                    entry["descriptor"]["path"],
                ),
            )
        )
    ).hexdigest()
    return {
        "granted_level": GRANTED_LEVEL,
        "trust_policy_sha256": trust_policy.policy_sha256,
        "candidate": candidate,
        "runs": sorted(seen_os),
        "reports": len(REQUIRED_OS) * len(REQUIRED_HARNESSES),
        "report_bindings": sorted(
            report_bindings, key=lambda entry: (entry["os"], entry["category"])
        ),
        "installed_runs": sorted(installed_runs, key=lambda entry: entry["os"]),
        "raw_artifact_manifest_sha256": raw_manifest_sha256,
        "collector_receipt_sha256": sorted(receipt_hashes),
        "artifact_count": artifact_count,
        "artifact_bytes": artifact_bytes,
    }


def validate_physical_evidence(
    value: Any,
    *,
    evidence_root: Path,
    trust_policy: CollectorTrustPolicy | None = None,
    fixture: bool = False,
) -> dict[str, Any]:
    """Validate a parsed aggregate only inside an explicit fixture boundary.

    Production must enter through :func:`load_physical_evidence_artifact`,
    which reopens the aggregate bytes and internally reloads the one canonical
    source-pinned policy. A parsed object can never establish release trust.
    """

    try:
        if not fixture:
            raise RawArtifactError(
                "parsed aggregate validation is fixture-only; production requires "
                "a bound aggregate artifact"
            )
        policy = _resolve_trust_policy(trust_policy, fixture=True)
        with ArtifactReader(evidence_root) as artifacts:
            summary = _validate(
                value,
                artifacts=artifacts,
                trust_policy=policy,
                fixture=True,
            )
            artifacts.verify_all_unchanged()
            return summary
    except RawArtifactError as error:
        raise PhysicalEvidenceError(str(error)) from error


def _with_private_archive_binding(
    summary: dict[str, Any], aggregate_artifact: dict[str, Any]
) -> dict[str, Any]:
    """Bind the retained private archive without publishing its raw payloads."""

    archive = {
        "visibility": "private-release-evidence",
        "aggregate_artifact": aggregate_artifact,
        "raw_artifact_manifest_sha256": summary["raw_artifact_manifest_sha256"],
        "collector_receipt_sha256": summary["collector_receipt_sha256"],
        "trust_policy_sha256": summary["trust_policy_sha256"],
        "artifact_count": summary["artifact_count"] + 1,
        "artifact_bytes": summary["artifact_bytes"] + aggregate_artifact["size"],
    }
    archive["binding_sha256"] = hashlib.sha256(canonical_json(archive)).hexdigest()
    result = dict(summary)
    result["aggregate_artifact"] = aggregate_artifact
    result["private_archive"] = archive
    result["artifact_count"] = archive["artifact_count"]
    result["artifact_bytes"] = archive["artifact_bytes"]
    return result


def load_physical_evidence_artifact(
    value: Any,
    *,
    evidence_root: Path,
    trust_policy: CollectorTrustPolicy | None = None,
    fixture: bool = False,
) -> dict[str, Any]:
    """Reopen a bound aggregate, then every report/raw byte, from one root.

    The aggregate descriptor is the root binding of a private evidence archive.
    Its exact bytes are read before validation and reopened once more after all
    descendant report/raw validation, so a summary digest alone can never grant
    the release level.
    """

    root = evidence_root.absolute()
    try:
        policy = _resolve_trust_policy(trust_policy, fixture=fixture)
        descriptor = parse_descriptor(
            value,
            expected_kinds={"physical-aggregate"},
            label="physical evidence aggregate artifact",
        )
        with ArtifactReader(root) as artifacts:
            parsed_descriptor, data = artifacts.read(
                descriptor.as_dict(),
                expected_kinds={"physical-aggregate"},
                label="physical evidence aggregate artifact",
            )
            document = load_json_bytes(data, "physical evidence aggregate")
            summary = _validate(
                document,
                artifacts=artifacts,
                trust_policy=policy,
                fixture=fixture,
            )
            # Reopen, reread, and rehash every report/raw object before checking
            # the aggregate last, all beneath the same held evidence-root fd.
            artifacts.verify_all_unchanged(final_path=parsed_descriptor.path)
        return _with_private_archive_binding(summary, parsed_descriptor.as_dict())
    except RawArtifactError as error:
        raise PhysicalEvidenceError(str(error)) from error


def load_physical_evidence(
    path: Path,
    *,
    evidence_root: Path | None = None,
    trust_policy: CollectorTrustPolicy | None = None,
    fixture: bool = False,
) -> dict[str, Any]:
    """Load an aggregate and verify artifacts relative to its explicit/root directory."""

    root = path.absolute().parent if evidence_root is None else evidence_root.absolute()
    try:
        descriptor_path = path.absolute()
        if descriptor_path.parent != root:
            # The aggregate itself may live below a separately specified root,
            # but it must still be a canonical descendant rather than an
            # unrelated path selected by cwd drift.
            try:
                descriptor_path.relative_to(root)
            except ValueError as error:
                raise PhysicalEvidenceError(
                    "aggregate path is outside its evidence root"
                ) from error
        data = read_regular_file_bytes(descriptor_path, maximum=MAX_DOCUMENT_BYTES)
        relative = descriptor_path.relative_to(root).as_posix()
        descriptor = {
            "kind": "physical-aggregate",
            "path": relative,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        return load_physical_evidence_artifact(
            descriptor,
            evidence_root=root,
            trust_policy=trust_policy,
            fixture=fixture,
        )
    except RawArtifactError as error:
        raise PhysicalEvidenceError(str(error)) from error


def self_check() -> None:
    """Verify static wiring without granting or requiring physical evidence."""

    if GRANTED_LEVEL not in LEVEL_ORDER:
        raise PhysicalEvidenceError("granted level is not in Evidence_Manifest")
    if set(HARNESS_VALIDATORS) != REQUIRED_HARNESSES:
        raise PhysicalEvidenceError("harness validator wiring is inconsistent")
    if set(EXPECTED_TOOL_VERSIONS) != REQUIRED_HARNESSES:
        raise PhysicalEvidenceError("harness version wiring is inconsistent")
    if set(REPORT_KINDS) != REQUIRED_HARNESSES:
        raise PhysicalEvidenceError("report artifact kind wiring is inconsistent")
    if len(REQUIRED_OS) != 2:
        raise PhysicalEvidenceError("physical gate must require two OS runs")
    if set(REQUIRED_MACOS_VERSIONS) != set(REQUIRED_OS) or (
        set(REQUIRED_MACOS_BUILDS) != set(REQUIRED_OS)
    ):
        raise PhysicalEvidenceError("physical macOS release-matrix wiring is inconsistent")
    try:
        policy_bytes = read_release_trust_policy_bytes()
    except (OSError, RawArtifactError) as error:
        raise PhysicalEvidenceError("release collector trust policy file is unreadable") from error
    if hashlib.sha256(policy_bytes).hexdigest() != RELEASE_TRUST_POLICY_SHA256:
        raise PhysicalEvidenceError("release collector trust policy pin drifted")
    try:
        policy = load_release_trust_policy()
    except CollectorTrustNotConfiguredError:
        # This is the expected pre-provisioning state. The parse still proved
        # canonical bytes and the exact source digest before returning here.
        return
    if not policy.release_source_pinned:
        raise PhysicalEvidenceError("configured release trust policy lost its source pin")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("aggregate", nargs="?", type=Path)
    group.add_argument("--self-check", action="store_true")
    parser.add_argument("--evidence-root", type=Path)
    arguments = parser.parse_args()
    if arguments.self_check:
        try:
            self_check()
        except PhysicalEvidenceError as error:
            raise SystemExit(f"error: physical aggregator self-check failed: {error}") from error
        print(
            "physical evidence aggregator self-check ok; production collector trust "
            "remains fail-closed until the source-pinned policy is configured"
        )
        return
    try:
        summary = load_physical_evidence(
            arguments.aggregate, evidence_root=arguments.evidence_root
        )
    except (PhysicalEvidenceError, OSError) as error:
        raise SystemExit(f"error: physical evidence aggregation failed: {error}") from error
    print(
        "physical evidence aggregated: "
        f"{summary['granted_level']} for {summary['candidate']['version']} "
        f"({summary['candidate']['build_number']}), {summary['artifact_count']} artifacts"
    )


if __name__ == "__main__":
    main()
