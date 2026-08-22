#!/usr/bin/env python3
"""Validate proof-bound performance summaries from a frozen sample ledger.

The proof-free ledger binds every metric to fixed command output, the signed
product's Unified Log state, a signed process roster, and wall/monotonic time.
Weak-network intent and restoration are separate mandatory artifacts.  This
report validator reopens all three artifacts and recomputes every summary; it
never accepts caller-declared samples or a synthetic pass flag.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import math
from pathlib import Path
from typing import Any

if __package__:
    from .performance_ledger import (
        FINAL_BUILD,
        LEDGER_KIND,
        LEDGER_SUBJECT,
        SHAPING_INTENT_SUBJECT,
        SHAPING_RESTORATION_SUBJECT,
        WEAK_NETWORK_PROFILES,
        PerformanceLedgerError,
        validate_performance_ledger,
    )
    from .raw_artifacts import (
        ArtifactReader,
        EVIDENCE_PROFILE,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        load_json_file,
        parse_proof_binding,
    )
else:  # pragma: no cover - direct-script import path
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from performance_ledger import (  # type: ignore
        FINAL_BUILD,
        LEDGER_KIND,
        LEDGER_SUBJECT,
        SHAPING_INTENT_SUBJECT,
        SHAPING_RESTORATION_SUBJECT,
        WEAK_NETWORK_PROFILES,
        PerformanceLedgerError,
        validate_performance_ledger,
    )
    from raw_artifacts import (  # type: ignore
        ArtifactReader,
        EVIDENCE_PROFILE,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        load_json_file,
        parse_proof_binding,
    )


SCHEMA_VERSION = 3
HARNESS_VERSION = "performance-gates-v3"
PRODUCT_VERSION = "0.4.0"
MAX_REPORT_BYTES = 1 * 1024 * 1024

RECOVERY_P95_MAX_MS = 10_000
CONNECT_P95_MAX_MS = 5_000
DISCONNECT_P95_MAX_MS = 3_000
ADDED_LATENCY_MAX_PERCENT = 10.0
THROUGHPUT_MIN_RATIO_PERCENT = 90.0
IDLE_CPU_MAX_PERCENT = 1.0
ACTIVE_RSS_MAX_MIB = 120.0
SWITCH_MIN_COUNT = 100
SWITCH_RSS_GROWTH_MAX_MIB = 5.0
SWITCH_FD_GROWTH_MAX = 2
SOAK_MIN_HOURS = EVIDENCE_PROFILE["soak_hours_per_run"]
SOAK_MAX_CRASHES = 0

SUMMARY_FIELDS = {"p50", "p95", "p99"}
REPORT_FIELDS = {
    "schema_version",
    "harness_version",
    "captured_at",
    "completed_at",
    "signed_at",
    "proof",
    "parameters",
    "weak_network",
    "latency",
    "throughput",
    "resources",
    "switch_cycle",
    "soak",
    "ledger_artifact",
    "shaping_intent_artifact",
    "shaping_restoration_artifact",
}


class PerformanceGateError(ValueError):
    """Performance evidence is incomplete, drifted, or outside a gate."""


def percentiles(samples: list[float]) -> dict[str, float]:
    if not samples:
        raise PerformanceGateError("cannot take percentiles of an empty sample set")
    if any(not math.isfinite(sample) for sample in samples):
        raise PerformanceGateError("cannot take percentiles of non-finite samples")
    ordered = sorted(samples)
    count = len(ordered)

    def rank(percent: float) -> float:
        index = math.ceil((percent / 100.0) * count)
        return ordered[max(1, min(index, count)) - 1]

    return {"p50": rank(50.0), "p95": rank(95.0), "p99": rank(99.0)}


def _number(value: Any, label: str, *, non_negative: bool = True) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PerformanceGateError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or (non_negative and result < 0):
        raise PerformanceGateError(f"{label} must be finite and non-negative")
    return result


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PerformanceGateError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PerformanceGateError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PerformanceGateError(f"{label} must use UTC")
    return parsed


def _summary(value: Any, expected: dict[str, float], label: str) -> None:
    declared = exact_object(value, SUMMARY_FIELDS, label)
    normalized = {field: _number(declared[field], f"{label}.{field}") for field in SUMMARY_FIELDS}
    if normalized != expected:
        raise PerformanceGateError(f"{label} differs from the retained ledger")


def _read_ledger(
    artifacts: ArtifactReader, descriptor: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    parsed, data = artifacts.read(
        descriptor,
        expected_kinds={LEDGER_KIND},
        label="performance.ledger_artifact",
    )
    value = load_json_bytes(data, "performance sample ledger")
    if not isinstance(value, dict) or canonical_json(value) + b"\n" != data:
        raise PerformanceGateError("performance sample ledger is not canonical JSON")
    return parsed.as_dict(), value


def _proof_candidate(proof: dict[str, Any]) -> dict[str, Any]:
    return {
        key: proof["candidate"][key]
        for key in (
            "version",
            "build_number",
            "app_manifest_sha256",
            "signed_app_tree_sha256",
            "artifact_hash_manifest_sha256",
        )
    }


def _validate_summaries(document: dict[str, Any], derived: dict[str, Any]) -> None:
    weak = document["weak_network"]
    if not isinstance(weak, list) or len(weak) != len(WEAK_NETWORK_PROFILES):
        raise PerformanceGateError("weak_network must contain every fixed profile")
    for index, profile_id in enumerate(sorted(WEAK_NETWORK_PROFILES)):
        entry = exact_object(
            weak[index], {"id", "control", "recovery_ms"}, f"weak_network[{index}]"
        )
        expected_control = {
            key: value
            for key, value in WEAK_NETWORK_PROFILES[profile_id].items()
            if key != "pipe_id"
        }
        if entry["id"] != profile_id or entry["control"] != expected_control:
            raise PerformanceGateError(f"weak_network[{index}] profile/control differs")
        computed = percentiles(derived["weak_network"][profile_id])
        _summary(entry["recovery_ms"], computed, f"weak_network[{index}].recovery_ms")
        if computed["p95"] > RECOVERY_P95_MAX_MS:
            raise PerformanceGateError(f"weak_network[{profile_id}] recovery p95 exceeds gate")

    latency = exact_object(
        document["latency"],
        {"connect_ms", "disconnect_ms", "added_latency_percent"},
        "latency",
    )
    latency_gates = {
        "connect_ms": CONNECT_P95_MAX_MS,
        "disconnect_ms": DISCONNECT_P95_MAX_MS,
        "added_latency_percent": ADDED_LATENCY_MAX_PERCENT,
    }
    for field, maximum in latency_gates.items():
        computed = percentiles(derived["latency"][field])
        _summary(latency[field], computed, f"latency.{field}")
        if computed["p95"] > maximum:
            raise PerformanceGateError(f"latency.{field} p95 exceeds gate")

    throughput = exact_object(
        document["throughput"],
        {"baseline_mbps", "measured_mbps", "ratio_percent"},
        "throughput",
    )
    baseline = percentiles(derived["throughput"]["baseline_mbps"])["p50"]
    measured = percentiles(derived["throughput"]["measured_mbps"])["p50"]
    if baseline <= 0:
        raise PerformanceGateError("throughput baseline p50 is not positive")
    ratio = 100.0 * measured / baseline
    expected_throughput = {
        "baseline_mbps": baseline,
        "measured_mbps": measured,
        "ratio_percent": ratio,
    }
    normalized_throughput = {
        field: _number(throughput[field], f"throughput.{field}")
        for field in expected_throughput
    }
    if normalized_throughput != expected_throughput:
        raise PerformanceGateError("throughput summary differs from the retained ledger")
    if ratio < THROUGHPUT_MIN_RATIO_PERCENT:
        raise PerformanceGateError("throughput ratio is below gate")

    resources = exact_object(
        document["resources"],
        {"active_idle_cpu_percent", "active_rss_mib"},
        "resources",
    )
    cpu = percentiles(derived["resources"]["active_idle_cpu_percent"])
    rss = percentiles(derived["resources"]["active_rss_mib"])
    _summary(resources["active_idle_cpu_percent"], cpu, "resources.active_idle_cpu_percent")
    _summary(resources["active_rss_mib"], rss, "resources.active_rss_mib")
    if not cpu["p95"] < IDLE_CPU_MAX_PERCENT:
        raise PerformanceGateError("active idle CPU p95 is not below gate")
    if rss["p95"] > ACTIVE_RSS_MAX_MIB:
        raise PerformanceGateError("active RSS p95 exceeds gate")

    switch = exact_object(
        document["switch_cycle"],
        {"switch_count", "rss_growth_mib", "fd_growth"},
        "switch_cycle",
    )
    expected_switch = {
        "switch_count": derived["switch_cycle"]["switch_count"],
        "rss_growth_mib": derived["switch_cycle"]["rss_growth_mib"],
        "fd_growth": derived["switch_cycle"]["fd_growth"],
    }
    normalized_switch = {
        "switch_count": switch["switch_count"],
        "rss_growth_mib": _number(
            switch["rss_growth_mib"], "switch_cycle.rss_growth_mib"
        ),
        "fd_growth": switch["fd_growth"],
    }
    if (
        type(switch["switch_count"]) is not int
        or type(switch["fd_growth"]) is not int
        or normalized_switch != expected_switch
    ):
        raise PerformanceGateError("switch_cycle differs from fixed ps/lsof records")
    if (
        expected_switch["switch_count"] < SWITCH_MIN_COUNT
        or expected_switch["rss_growth_mib"] > SWITCH_RSS_GROWTH_MAX_MIB
        or expected_switch["fd_growth"] > SWITCH_FD_GROWTH_MAX
    ):
        raise PerformanceGateError("switch_cycle fails count/resource growth gate")

    soak = exact_object(
        document["soak"],
        {"duration_hours", "heartbeat_count", "traffic_count", "crash_count"},
        "soak",
    )
    normalized_soak = {
        "duration_hours": _number(soak["duration_hours"], "soak.duration_hours"),
        "heartbeat_count": soak["heartbeat_count"],
        "traffic_count": soak["traffic_count"],
        "crash_count": soak["crash_count"],
    }
    if any(
        type(soak[field]) is not int
        for field in ("heartbeat_count", "traffic_count", "crash_count")
    ) or normalized_soak != {
        key: derived["soak"][key]
        for key in ("duration_hours", "heartbeat_count", "traffic_count", "crash_count")
    }:
        raise PerformanceGateError("soak declaration differs from continuous ledger")
    if (
        normalized_soak["duration_hours"] < SOAK_MIN_HOURS
        or normalized_soak["crash_count"] > SOAK_MAX_CRASHES
    ):
        raise PerformanceGateError("soak duration/crash result fails gate")


def _validate(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    document = exact_object(value, REPORT_FIELDS, "performance evidence")
    if type(document["schema_version"]) is not int or document[
        "schema_version"
    ] != SCHEMA_VERSION:
        raise PerformanceGateError(f"performance schema_version must be {SCHEMA_VERSION}")
    if document["harness_version"] != HARNESS_VERSION:
        raise PerformanceGateError(f"performance harness_version must be {HARNESS_VERSION!r}")
    proof = parse_proof_binding(document["proof"])
    if (
        proof["candidate"]["version"] != PRODUCT_VERSION
        or proof["candidate"]["build_number"] != FINAL_BUILD
    ):
        raise PerformanceGateError(
            f"performance evidence is not final 0.4.0 build {FINAL_BUILD}"
        )
    ledger_descriptor, ledger = _read_ledger(artifacts, document["ledger_artifact"])
    derived = validate_performance_ledger(ledger, artifacts=artifacts)
    if _proof_candidate(proof) != {
        key: derived["candidate"][key] for key in _proof_candidate(proof)
    } or proof["run_id"] != derived["run"]["run_id"]:
        raise PerformanceGateError("performance proof differs from proof-free ledger context")
    if document["parameters"] != derived["parameters"]:
        raise PerformanceGateError("performance parameters differ from proof-free ledger")
    artifacts_by_subject = {
        entry["subject"]: entry["descriptor"] for entry in derived["artifacts"]
    }
    if document["shaping_intent_artifact"] != artifacts_by_subject[
        SHAPING_INTENT_SUBJECT
    ] or document["shaping_restoration_artifact"] != artifacts_by_subject[
        SHAPING_RESTORATION_SUBJECT
    ]:
        raise PerformanceGateError("performance report shaping descriptors differ from ledger")
    captured_at = _timestamp(document["captured_at"], "performance.captured_at")
    completed_at = _timestamp(document["completed_at"], "performance.completed_at")
    signed_at = _timestamp(document["signed_at"], "performance.signed_at")
    if captured_at != derived["captured_at"] or completed_at != derived["completed_at"]:
        raise PerformanceGateError("performance report times differ from proof-free ledger")
    if signed_at < completed_at:
        raise PerformanceGateError("performance report was signed before collection completed")
    _validate_summaries(document, derived)
    raw_artifacts = [
        {"subject": LEDGER_SUBJECT, "descriptor": ledger_descriptor},
        *derived["artifacts"],
    ]
    if {entry["subject"] for entry in raw_artifacts} != {
        LEDGER_SUBJECT,
        SHAPING_INTENT_SUBJECT,
        SHAPING_RESTORATION_SUBJECT,
    }:
        raise PerformanceGateError("performance raw subject closure is incomplete")
    return {
        "document": document,
        "proof": proof,
        "parameters": derived["parameters"],
        "started_at": captured_at,
        "completed_at": completed_at,
        "artifacts": raw_artifacts,
    }


def validate_performance_evidence(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    try:
        return _validate(value, artifacts)
    except (PerformanceLedgerError, RawArtifactError) as error:
        raise PerformanceGateError(str(error)) from error


def load_performance_evidence(path: Path, *, evidence_root: Path) -> dict[str, Any]:
    try:
        value = load_json_file(path, maximum=MAX_REPORT_BYTES, label="performance report")
        with ArtifactReader(evidence_root) as artifacts:
            return validate_performance_evidence(value, artifacts)
    except RawArtifactError as error:
        raise PerformanceGateError(str(error)) from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = load_performance_evidence(
            arguments.report, evidence_root=arguments.evidence_root
        )
    except (PerformanceGateError, OSError) as error:
        raise SystemExit(f"error: performance evidence failed: {error}") from error
    print(
        "performance ledger/shaping evidence structurally verified "
        "(collector signature not checked): "
        f"{len(result['artifacts'])} raw artifacts"
    )


if __name__ == "__main__":
    main()
