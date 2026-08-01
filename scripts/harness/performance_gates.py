#!/usr/bin/env python3
"""Proof-to-byte weak-network, performance, switch, and soak gates.

The report contains only declared summaries. All samples, shaping-control
events, switch records, and soak timestamps/crashes live in one raw artifact
that is reopened and hashed beneath an explicit evidence root. Every summary
and threshold is recomputed from those bytes.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import math
from pathlib import Path
import re
from typing import Any

if __package__:
    from .physical_machine_identity import (
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from .raw_artifacts import (
        ArtifactReader,
        EVIDENCE_PROFILE,
        RawArtifactError,
        exact_object,
        load_json_file,
        parse_proof_binding,
        require_identifier,
        require_sha256,
    )
else:  # pragma: no cover - direct-script import path
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from physical_machine_identity import (  # type: ignore
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from raw_artifacts import (  # type: ignore
        ArtifactReader,
        EVIDENCE_PROFILE,
        RawArtifactError,
        exact_object,
        load_json_file,
        parse_proof_binding,
        require_identifier,
        require_sha256,
    )


SCHEMA_VERSION = 2
HARNESS_VERSION = "performance-gates-v2"
PRODUCT_VERSION = "0.4.0"
MAX_REPORT_BYTES = 1 * 1024 * 1024
MACOS_BUILD_RE = re.compile(r"^[0-9]{2}[A-Z][0-9]{1,5}[a-z]?$")
# Twenty observations is the smallest set whose nearest-rank p95 is not simply
# an under-sampled convenience statistic.
MIN_SERIES_SAMPLES = 20
MAX_SERIES_SAMPLES = 100_000
MAX_SWITCH_RECORDS = 10_001
MAX_CRASH_EVENTS = 1_000

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

WEAK_NETWORK_PROFILES: dict[str, dict[str, Any]] = {
    "latency-100ms-loss-1pct-10mbps": {
        "kind": "shaping",
        "latency_ms": 100,
        "loss_percent": 1.0,
        "bandwidth_mbps": 10.0,
    },
    "latency-300ms-loss-5pct-1mbps": {
        "kind": "shaping",
        "latency_ms": 300,
        "loss_percent": 5.0,
        "bandwidth_mbps": 1.0,
    },
    "outage-30s": {"kind": "outage", "outage_seconds": 30},
}

PARAMETER_FIELDS = {"machine", "network", "power"}
MACHINE_FIELDS = {
    "architecture",
    "macos_version",
    "macos_build",
    "hardware_model",
    "machine_sha256",
    "clean_install",
}
SUMMARY_FIELDS = {"p50", "p95", "p99"}


class PerformanceGateError(ValueError):
    """Performance evidence is incomplete, drifted, or outside a gate."""


def percentiles(samples: list[float]) -> dict[str, float]:
    if not samples:
        raise PerformanceGateError("cannot take percentiles of an empty sample set")
    ordered = sorted(samples)
    count = len(ordered)

    def _rank(percent: float) -> float:
        index = math.ceil((percent / 100.0) * count)
        return ordered[max(1, min(index, count)) - 1]

    return {"p50": _rank(50.0), "p95": _rank(95.0), "p99": _rank(99.0)}


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PerformanceGateError(f"{label} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise PerformanceGateError(f"{label} must be finite")
    return result


def _non_negative(value: Any, label: str) -> float:
    result = _number(value, label)
    if result < 0:
        raise PerformanceGateError(f"{label} must be non-negative")
    return result


def _positive(value: Any, label: str) -> float:
    result = _number(value, label)
    if result <= 0:
        raise PerformanceGateError(f"{label} must be positive")
    return result


def _bounded_text(value: Any, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PerformanceGateError(f"{label} must be bounded printable text")
    return value


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


def _parameters(value: Any, label: str = "parameters") -> dict[str, Any]:
    parameters = exact_object(value, PARAMETER_FIELDS, label)
    machine = exact_object(parameters["machine"], MACHINE_FIELDS, f"{label}.machine")
    if machine["architecture"] != "arm64" or machine["clean_install"] is not True:
        raise PerformanceGateError(f"{label}.machine must be a clean arm64 machine")
    _bounded_text(machine["macos_version"], f"{label}.machine.macos_version")
    macos_build = machine["macos_build"]
    if not isinstance(macos_build, str) or not MACOS_BUILD_RE.fullmatch(macos_build):
        raise PerformanceGateError(f"{label}.machine.macos_build is invalid")
    try:
        validate_physical_hardware_model(machine["hardware_model"])
    except PhysicalMachineIdentityError as error:
        raise PerformanceGateError(
            f"{label}.machine.hardware_model is invalid"
        ) from error
    require_sha256(machine["machine_sha256"], f"{label}.machine.machine_sha256")
    network = exact_object(
        parameters["network"], {"description", "uplink_mbps"}, f"{label}.network"
    )
    _bounded_text(network["description"], f"{label}.network.description")
    _positive(network["uplink_mbps"], f"{label}.network.uplink_mbps")
    power = exact_object(
        parameters["power"], {"source", "low_power_mode"}, f"{label}.power"
    )
    if power["source"] not in {"ac", "battery"}:
        raise PerformanceGateError(f"{label}.power.source is invalid")
    if not isinstance(power["low_power_mode"], bool):
        raise PerformanceGateError(f"{label}.power.low_power_mode must be boolean")
    return parameters


def _raw_series(value: Any, label: str) -> tuple[list[float], dict[str, float]]:
    if not isinstance(value, list) or not MIN_SERIES_SAMPLES <= len(value) <= MAX_SERIES_SAMPLES:
        raise PerformanceGateError(
            f"{label} must contain {MIN_SERIES_SAMPLES}..{MAX_SERIES_SAMPLES} samples"
        )
    samples = [_non_negative(sample, f"{label}[{index}]") for index, sample in enumerate(value)]
    return samples, percentiles(samples)


def _declared_summary(value: Any, label: str) -> dict[str, float]:
    summary = exact_object(value, SUMMARY_FIELDS, label)
    return {key: _number(summary[key], f"{label}.{key}") for key in sorted(SUMMARY_FIELDS)}


def _match_summary(value: Any, computed: dict[str, float], label: str) -> None:
    declared = _declared_summary(value, label)
    if declared != computed:
        raise PerformanceGateError(f"{label} does not match the raw sample bytes")


def _control(value: Any, profile_id: str, *, raw: bool, label: str) -> dict[str, Any]:
    expected = WEAK_NETWORK_PROFILES[profile_id]
    fields = {"applied", "kind"} | (set(expected) - {"kind"})
    if raw:
        fields |= {"applied_at", "command_exit_code"}
    control = exact_object(value, fields, label)
    if control["applied"] is not True or control["kind"] != expected["kind"]:
        raise PerformanceGateError(f"{label} does not prove the required shaping control")
    for key, wanted in expected.items():
        if key != "kind" and _number(control[key], f"{label}.{key}") != float(wanted):
            raise PerformanceGateError(f"{label}.{key} differs from the required profile")
    if raw:
        _timestamp(control["applied_at"], f"{label}.applied_at")
        if control["command_exit_code"] != 0:
            raise PerformanceGateError(f"{label}.command_exit_code is not zero")
    return {key: control[key] for key in fields if key not in {"applied_at", "command_exit_code"}}


def _weak_network(declared: Any, raw: Any) -> datetime:
    if not isinstance(declared, list) or not isinstance(raw, list):
        raise PerformanceGateError("weak_network must be a list")
    if len(declared) != len(WEAK_NETWORK_PROFILES) or len(raw) != len(declared):
        raise PerformanceGateError("weak_network must contain every required profile exactly once")
    declared_by_id: dict[str, dict[str, Any]] = {}
    for index, entry_value in enumerate(declared):
        entry = exact_object(
            entry_value,
            {"id", "control", "recovery_ms"},
            f"weak_network[{index}]",
        )
        profile_id = entry["id"]
        if profile_id not in WEAK_NETWORK_PROFILES or profile_id in declared_by_id:
            raise PerformanceGateError(
                f"weak_network profile is unknown/duplicated: {profile_id!r}"
            )
        declared_by_id[profile_id] = entry
    seen: set[str] = set()
    applied_times: list[datetime] = []
    for index, entry_value in enumerate(raw):
        entry = exact_object(
            entry_value, {"id", "control", "recovery_ms"}, f"raw.weak_network[{index}]"
        )
        profile_id = entry["id"]
        if profile_id not in declared_by_id or profile_id in seen:
            raise PerformanceGateError(
                f"raw weak-network profile is unknown/duplicated: {profile_id!r}"
            )
        seen.add(profile_id)
        declared_entry = declared_by_id[profile_id]
        if _control(
            declared_entry["control"],
            profile_id,
            raw=False,
            label=f"weak_network[{profile_id}].control",
        ) != _control(
            entry["control"], profile_id, raw=True, label=f"raw.weak_network[{profile_id}].control"
        ):
            raise PerformanceGateError(f"weak_network[{profile_id}] control differs from raw bytes")
        applied_times.append(
            _timestamp(
                entry["control"]["applied_at"],
                f"raw.weak_network[{profile_id}].control.applied_at",
            )
        )
        _samples, computed = _raw_series(
            entry["recovery_ms"], f"raw.weak_network[{profile_id}].recovery_ms"
        )
        _match_summary(
            declared_entry["recovery_ms"], computed, f"weak_network[{profile_id}].recovery_ms"
        )
        if computed["p95"] > RECOVERY_P95_MAX_MS:
            raise PerformanceGateError(f"weak_network[{profile_id}] recovery p95 exceeds the gate")
    if seen != set(WEAK_NETWORK_PROFILES):
        raise PerformanceGateError("raw weak_network is missing a required profile")
    return min(applied_times)


def _latency(declared: Any, raw: Any) -> None:
    fields = {"connect_ms", "disconnect_ms", "added_latency_percent"}
    declared_value = exact_object(declared, fields, "latency")
    raw_value = exact_object(raw, fields, "raw.latency")
    gates = {
        "connect_ms": CONNECT_P95_MAX_MS,
        "disconnect_ms": DISCONNECT_P95_MAX_MS,
        "added_latency_percent": ADDED_LATENCY_MAX_PERCENT,
    }
    for name, maximum in gates.items():
        _samples, computed = _raw_series(raw_value[name], f"raw.latency.{name}")
        _match_summary(declared_value[name], computed, f"latency.{name}")
        if computed["p95"] > maximum:
            raise PerformanceGateError(f"latency.{name} p95 exceeds {maximum}")


def _throughput(declared: Any, raw: Any) -> None:
    declared_value = exact_object(
        declared, {"baseline_mbps", "measured_mbps", "ratio_percent"}, "throughput"
    )
    raw_value = exact_object(
        raw, {"baseline_mbps", "measured_mbps"}, "raw.throughput"
    )
    baseline_samples, baseline_summary = _raw_series(
        raw_value["baseline_mbps"], "raw.throughput.baseline_mbps"
    )
    measured_samples, measured_summary = _raw_series(
        raw_value["measured_mbps"], "raw.throughput.measured_mbps"
    )
    if len(baseline_samples) != len(measured_samples):
        raise PerformanceGateError("throughput baseline/measured sample counts differ")
    baseline = _positive(baseline_summary["p50"], "raw throughput baseline p50")
    measured = _non_negative(measured_summary["p50"], "raw throughput measured p50")
    ratio = 100.0 * measured / baseline
    if _number(declared_value["baseline_mbps"], "throughput.baseline_mbps") != baseline:
        raise PerformanceGateError("throughput baseline declaration differs from raw samples")
    if _number(declared_value["measured_mbps"], "throughput.measured_mbps") != measured:
        raise PerformanceGateError("throughput measured declaration differs from raw samples")
    recorded = _number(declared_value["ratio_percent"], "throughput.ratio_percent")
    if not math.isclose(recorded, ratio, rel_tol=1e-12, abs_tol=1e-12):
        raise PerformanceGateError("throughput ratio declaration differs from raw samples")
    if ratio < THROUGHPUT_MIN_RATIO_PERCENT:
        raise PerformanceGateError("throughput ratio is below the gate")


def _resources(declared: Any, raw: Any) -> None:
    fields = {"active_idle_cpu_percent", "active_rss_mib"}
    declared_value = exact_object(declared, fields, "resources")
    raw_value = exact_object(raw, fields, "raw.resources")
    _samples, cpu = _raw_series(
        raw_value["active_idle_cpu_percent"], "raw.resources.active_idle_cpu_percent"
    )
    _match_summary(
        declared_value["active_idle_cpu_percent"],
        cpu,
        "resources.active_idle_cpu_percent",
    )
    if not cpu["p95"] < IDLE_CPU_MAX_PERCENT:
        raise PerformanceGateError("active idle CPU p95 is not below the gate")
    _samples, rss = _raw_series(raw_value["active_rss_mib"], "raw.resources.active_rss_mib")
    _match_summary(declared_value["active_rss_mib"], rss, "resources.active_rss_mib")
    if rss["p95"] > ACTIVE_RSS_MAX_MIB:
        raise PerformanceGateError("active RSS p95 exceeds the gate")


def _switch_cycle(declared: Any, raw: Any) -> None:
    declared_value = exact_object(
        declared, {"switch_count", "rss_growth_mib", "fd_growth"}, "switch_cycle"
    )
    raw_value = exact_object(raw, {"records"}, "raw.switch_cycle")
    records = raw_value["records"]
    if not isinstance(records, list) or not 2 <= len(records) <= MAX_SWITCH_RECORDS:
        raise PerformanceGateError("raw.switch_cycle.records count is outside the bound")
    rss_values: list[float] = []
    fd_values: list[int] = []
    for index, raw_record in enumerate(records):
        record = exact_object(
            raw_record, {"index", "rss_mib", "fd_count"}, f"raw.switch_cycle.records[{index}]"
        )
        if record["index"] != index:
            raise PerformanceGateError("raw switch record indices are not contiguous")
        rss_values.append(_non_negative(record["rss_mib"], f"raw switch[{index}].rss_mib"))
        fd_count = record["fd_count"]
        if not isinstance(fd_count, int) or isinstance(fd_count, bool) or fd_count < 0:
            raise PerformanceGateError(f"raw switch[{index}].fd_count must be non-negative integer")
        fd_values.append(fd_count)
    count = len(records) - 1
    rss_growth = max(rss_values) - rss_values[0]
    fd_growth = max(fd_values) - fd_values[0]
    expected = {"switch_count": count, "rss_growth_mib": rss_growth, "fd_growth": fd_growth}
    declared_count = declared_value["switch_count"]
    declared_fd_growth = declared_value["fd_growth"]
    if (
        not isinstance(declared_count, int)
        or isinstance(declared_count, bool)
        or not isinstance(declared_fd_growth, int)
        or isinstance(declared_fd_growth, bool)
    ):
        raise PerformanceGateError("switch_cycle count/growth declarations must be integers")
    declared_normalized = {
        "switch_count": declared_count,
        "rss_growth_mib": _number(declared_value["rss_growth_mib"], "switch_cycle.rss_growth_mib"),
        "fd_growth": declared_fd_growth,
    }
    if declared_normalized != expected:
        raise PerformanceGateError("switch_cycle declaration differs from raw records")
    if count < SWITCH_MIN_COUNT:
        raise PerformanceGateError("switch_cycle count is below the gate")
    if rss_growth > SWITCH_RSS_GROWTH_MAX_MIB or fd_growth > SWITCH_FD_GROWTH_MAX:
        raise PerformanceGateError("switch_cycle resource growth exceeds the gate")


def _soak(declared: Any, raw: Any) -> tuple[datetime, datetime]:
    declared_value = exact_object(declared, {"duration_hours", "crash_count"}, "soak")
    raw_value = exact_object(raw, {"started_at", "ended_at", "crash_events"}, "raw.soak")
    started = _timestamp(raw_value["started_at"], "raw.soak.started_at")
    ended = _timestamp(raw_value["ended_at"], "raw.soak.ended_at")
    duration_hours = (ended - started).total_seconds() / 3600.0
    if duration_hours <= 0 or duration_hours > 168:
        raise PerformanceGateError("raw soak duration is outside 0..168 hours")
    crash_events = raw_value["crash_events"]
    if not isinstance(crash_events, list) or len(crash_events) > MAX_CRASH_EVENTS:
        raise PerformanceGateError("raw soak crash event count exceeds the bound")
    previous: datetime | None = None
    for index, raw_event in enumerate(crash_events):
        event = exact_object(raw_event, {"timestamp", "code"}, f"raw.soak.crash_events[{index}]")
        timestamp = _timestamp(event["timestamp"], f"raw.soak.crash_events[{index}].timestamp")
        require_identifier(event["code"], f"raw.soak.crash_events[{index}].code")
        if (
            timestamp < started
            or timestamp > ended
            or (previous is not None and timestamp <= previous)
        ):
            raise PerformanceGateError("raw soak crash timestamps are outside/order-invalid")
        previous = timestamp
    declared_duration = _number(declared_value["duration_hours"], "soak.duration_hours")
    if not math.isclose(declared_duration, duration_hours, rel_tol=0.0, abs_tol=1e-12):
        raise PerformanceGateError("soak duration declaration differs from raw timestamps")
    crash_count = declared_value["crash_count"]
    if not isinstance(crash_count, int) or isinstance(crash_count, bool):
        raise PerformanceGateError("soak.crash_count must be an integer")
    if crash_count != len(crash_events):
        raise PerformanceGateError("soak crash_count declaration differs from raw events")
    if duration_hours < SOAK_MIN_HOURS or len(crash_events) > SOAK_MAX_CRASHES:
        raise PerformanceGateError("soak duration/crash result fails the gate")
    return started, ended


def _validate_raw(
    raw: Any,
    *,
    proof: dict[str, Any],
    parameters: dict[str, Any],
    document: dict[str, Any],
) -> tuple[datetime, datetime]:
    fields = {
        "schema_version",
        "captured_at",
        "completed_at",
        "proof",
        "parameters",
        "weak_network",
        "latency",
        "throughput",
        "resources",
        "switch_cycle",
        "soak",
    }
    raw_value = exact_object(raw, fields, "raw performance samples")
    if type(raw_value["schema_version"]) is not int or raw_value["schema_version"] != 1:
        raise PerformanceGateError("raw performance schema_version must be 1")
    if parse_proof_binding(raw_value["proof"], "raw.performance.proof") != proof:
        raise PerformanceGateError("raw performance proof differs from its report")
    if _parameters(raw_value["parameters"], "raw.parameters") != parameters:
        raise PerformanceGateError("raw performance parameters differ from its report")
    weak_started = _weak_network(document["weak_network"], raw_value["weak_network"])
    _latency(document["latency"], raw_value["latency"])
    _throughput(document["throughput"], raw_value["throughput"])
    _resources(document["resources"], raw_value["resources"])
    _switch_cycle(document["switch_cycle"], raw_value["switch_cycle"])
    soak_started, soak_ended = _soak(document["soak"], raw_value["soak"])
    raw_captured_at = _timestamp(raw_value["captured_at"], "raw.performance.captured_at")
    if raw_value["captured_at"] != document["captured_at"]:
        raise PerformanceGateError("raw performance captured_at differs from its report")
    if raw_captured_at != min(weak_started, soak_started):
        raise PerformanceGateError("performance captured_at differs from earliest raw event")
    raw_completed_at = _timestamp(raw_value["completed_at"], "raw.performance.completed_at")
    if raw_completed_at != soak_ended:
        raise PerformanceGateError("raw performance completed_at differs from soak completion")
    return raw_captured_at, raw_completed_at


def _validate(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    fields = {
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
        "samples_artifact",
    }
    document = exact_object(value, fields, "performance evidence")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise PerformanceGateError(f"performance schema_version must be {SCHEMA_VERSION}")
    if document["harness_version"] != HARNESS_VERSION:
        raise PerformanceGateError(
            f"performance harness_version must be {HARNESS_VERSION!r}"
        )
    proof = parse_proof_binding(document["proof"])
    if proof["candidate"]["version"] != PRODUCT_VERSION:
        raise PerformanceGateError("performance evidence is not for version 0.4.0")
    parameters = _parameters(document["parameters"])
    descriptor, raw = artifacts.read_json(
        document["samples_artifact"],
        expected_kind="performance-samples",
        label="performance.samples_artifact",
    )
    started_at, completed_at = _validate_raw(
        raw, proof=proof, parameters=parameters, document=document
    )
    if _timestamp(document["completed_at"], "completed_at") != completed_at:
        raise PerformanceGateError("report completed_at differs from raw completion")
    if _timestamp(document["signed_at"], "signed_at") < completed_at:
        raise PerformanceGateError("report signed_at predates raw completion")
    return {
        "document": document,
        "proof": proof,
        "parameters": parameters,
        "started_at": started_at,
        "completed_at": completed_at,
        "artifacts": [{"subject": "measurements", "descriptor": descriptor.as_dict()}],
    }


def validate_performance_evidence(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    try:
        return _validate(value, artifacts)
    except RawArtifactError as error:
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
        "performance raw evidence structurally verified (collector signature not checked): "
        f"{len(result['artifacts'])} sample artifact"
    )


if __name__ == "__main__":
    main()
