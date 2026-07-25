#!/usr/bin/env python3
"""Weak-network, performance, switch-churn, and soak gate definitions and validator.

Requirement 6.3 makes the following mandatory for a Signed_Installed_Verified
candidate, and Requirement 6.5 forbids any skip, mask, or ``|| true`` that would
turn an unavailable or failing measurement into success. This module defines the
gate thresholds and a fail-closed validator over a captured evidence document.

The live measurement requires physical Apple Silicon hardware with a configured
network-shaping control (latency, loss, bandwidth, and outage injection) and is
out of scope here. This module supplies the gate definitions, the fail-closed
result validator, and the percentile arithmetic the harness relies on. The
validator fails closed on absent shaping controls, incomplete durations,
malformed samples, or any threshold violation.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

if __package__:
    from ..release_build_identity import canonical_build_version
else:  # pragma: no cover - direct-script execution fallback
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from release_build_identity import canonical_build_version


PRODUCT_VERSION = "0.4.0"
SHA256_HEX_LENGTH = 64

# Gate definitions (Requirement 6.3). Thresholds are inclusive bounds unless the
# name says otherwise; IDLE_CPU_MAX_PERCENT is a strict upper bound.
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
SOAK_MIN_HOURS = 24
SOAK_MAX_CRASHES = 0

# The three mandatory weak-network profiles. Each is keyed by a stable id and
# describes the exact shaping control that must have been applied.
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
    "outage-30s": {
        "kind": "outage",
        "outage_seconds": 30,
    },
}


class PerformanceGateError(ValueError):
    """Performance evidence is absent, incomplete, malformed, or out of bounds."""


def percentiles(samples: list[float]) -> dict[str, float]:
    """Return nearest-rank p50/p95/p99 of a non-empty numeric sample list.

    Nearest-rank keeps every reported percentile equal to an actual observed
    sample, so recorded values must reproduce exactly rather than within a
    tolerance.
    """

    if not samples:
        raise PerformanceGateError("cannot take percentiles of an empty sample set")
    ordered = sorted(samples)
    count = len(ordered)

    def _rank(percent: float) -> float:
        index = math.ceil((percent / 100.0) * count)
        if index < 1:
            index = 1
        if index > count:
            index = count
        return ordered[index - 1]

    return {"p50": _rank(50.0), "p95": _rank(95.0), "p99": _rank(99.0)}


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise PerformanceGateError(f"{label} fields differ: {actual}")
    return value


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


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PerformanceGateError(f"{label} must be an integer")
    return value


def _non_empty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PerformanceGateError(f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PerformanceGateError(f"{label} must be a lowercase SHA-256")
    return value


def _series(value: Any, label: str) -> dict[str, float]:
    """Validate a raw-sample series and its preserved p50/p95/p99 summary."""

    series = _exact(value, {"samples", "p50", "p95", "p99"}, label)
    samples = series["samples"]
    if not isinstance(samples, list) or not samples:
        raise PerformanceGateError(f"{label}.samples must be a non-empty list")
    clean: list[float] = []
    for index, sample in enumerate(samples):
        clean.append(_non_negative(sample, f"{label}.samples[{index}]"))
    computed = percentiles(clean)
    for key in ("p50", "p95", "p99"):
        recorded = _number(series[key], f"{label}.{key}")
        if recorded != computed[key]:
            raise PerformanceGateError(
                f"{label}.{key} ({recorded}) does not match raw samples ({computed[key]})"
            )
    return computed


def _validate_parameters(value: Any) -> dict[str, Any]:
    parameters = _exact(value, {"machine", "network", "power", "build"}, "parameters")

    machine = _exact(
        parameters["machine"],
        {"architecture", "macos_version", "hardware_model"},
        "parameters.machine",
    )
    if machine["architecture"] != "arm64":
        raise PerformanceGateError("parameters.machine.architecture must be arm64")
    _non_empty_string(machine["macos_version"], "parameters.machine.macos_version")
    _non_empty_string(machine["hardware_model"], "parameters.machine.hardware_model")

    network = _exact(
        parameters["network"],
        {"description", "uplink_mbps"},
        "parameters.network",
    )
    _non_empty_string(network["description"], "parameters.network.description")
    _positive(network["uplink_mbps"], "parameters.network.uplink_mbps")

    power = _exact(
        parameters["power"],
        {"source", "low_power_mode"},
        "parameters.power",
    )
    if power["source"] not in {"ac", "battery"}:
        raise PerformanceGateError("parameters.power.source must be 'ac' or 'battery'")
    if not isinstance(power["low_power_mode"], bool):
        raise PerformanceGateError("parameters.power.low_power_mode must be boolean")

    build = _exact(
        parameters["build"],
        {"version", "build_number", "app_manifest_sha256"},
        "parameters.build",
    )
    if build["version"] != PRODUCT_VERSION:
        raise PerformanceGateError(
            f"parameters.build.version must be {PRODUCT_VERSION}"
        )
    canonical_build_version(build["build_number"], "parameters.build.build_number")
    _sha256(build["app_manifest_sha256"], "parameters.build.app_manifest_sha256")
    return parameters


def _validate_weak_network(value: Any) -> None:
    if not isinstance(value, list) or len(value) != len(WEAK_NETWORK_PROFILES):
        raise PerformanceGateError(
            "weak_network must contain each mandatory profile exactly once"
        )
    seen: set[str] = set()
    for index, raw in enumerate(value):
        profile = _exact(raw, {"id", "control", "recovery_ms"}, f"weak_network[{index}]")
        profile_id = profile["id"]
        if profile_id not in WEAK_NETWORK_PROFILES or profile_id in seen:
            raise PerformanceGateError(
                f"weak_network profile is unknown or duplicated: {profile_id!r}"
            )
        seen.add(profile_id)
        expected = WEAK_NETWORK_PROFILES[profile_id]
        _validate_control(profile["control"], expected, profile_id)
        recovery = _series(profile["recovery_ms"], f"weak_network[{profile_id}].recovery_ms")
        if recovery["p95"] > RECOVERY_P95_MAX_MS:
            raise PerformanceGateError(
                f"weak_network[{profile_id}] recovery p95 exceeds {RECOVERY_P95_MAX_MS} ms"
            )
    if seen != set(WEAK_NETWORK_PROFILES):
        raise PerformanceGateError("weak_network is missing a mandatory profile")


def _validate_control(value: Any, expected: dict[str, Any], profile_id: str) -> None:
    label = f"weak_network[{profile_id}].control"
    if expected["kind"] == "shaping":
        control = _exact(
            value,
            {"applied", "kind", "latency_ms", "loss_percent", "bandwidth_mbps"},
            label,
        )
    else:
        control = _exact(value, {"applied", "kind", "outage_seconds"}, label)
    if control["applied"] is not True:
        raise PerformanceGateError(f"{label} was not applied (absent shaping control)")
    if control["kind"] != expected["kind"]:
        raise PerformanceGateError(f"{label}.kind is not {expected['kind']!r}")
    for key, wanted in expected.items():
        if key == "kind":
            continue
        actual = _number(control[key], f"{label}.{key}")
        if actual != float(wanted):
            raise PerformanceGateError(
                f"{label}.{key} ({actual}) does not match profile ({wanted})"
            )


def _validate_latency(value: Any) -> None:
    latency = _exact(
        value,
        {"connect_ms", "disconnect_ms", "added_latency_percent"},
        "latency",
    )
    connect = _series(latency["connect_ms"], "latency.connect_ms")
    if connect["p95"] > CONNECT_P95_MAX_MS:
        raise PerformanceGateError(f"connect p95 exceeds {CONNECT_P95_MAX_MS} ms")
    disconnect = _series(latency["disconnect_ms"], "latency.disconnect_ms")
    if disconnect["p95"] > DISCONNECT_P95_MAX_MS:
        raise PerformanceGateError(f"disconnect p95 exceeds {DISCONNECT_P95_MAX_MS} ms")
    added = _series(latency["added_latency_percent"], "latency.added_latency_percent")
    if added["p95"] > ADDED_LATENCY_MAX_PERCENT:
        raise PerformanceGateError(
            f"added latency p95 exceeds {ADDED_LATENCY_MAX_PERCENT} percent"
        )


def _validate_throughput(value: Any) -> None:
    throughput = _exact(
        value,
        {"baseline_mbps", "measured_mbps", "ratio_percent"},
        "throughput",
    )
    baseline = _positive(throughput["baseline_mbps"], "throughput.baseline_mbps")
    measured = _non_negative(throughput["measured_mbps"], "throughput.measured_mbps")
    recorded = _number(throughput["ratio_percent"], "throughput.ratio_percent")
    computed = 100.0 * measured / baseline
    if not math.isclose(recorded, computed, rel_tol=1e-9, abs_tol=1e-9):
        raise PerformanceGateError(
            "throughput.ratio_percent does not match measured/baseline"
        )
    if computed < THROUGHPUT_MIN_RATIO_PERCENT:
        raise PerformanceGateError(
            f"throughput is below {THROUGHPUT_MIN_RATIO_PERCENT} percent of baseline"
        )


def _validate_resources(value: Any) -> None:
    resources = _exact(
        value,
        {"active_idle_cpu_percent", "active_rss_mib"},
        "resources",
    )
    cpu = _series(resources["active_idle_cpu_percent"], "resources.active_idle_cpu_percent")
    if not cpu["p95"] < IDLE_CPU_MAX_PERCENT:
        raise PerformanceGateError(
            f"active idle CPU p95 is not below {IDLE_CPU_MAX_PERCENT} percent"
        )
    rss = _series(resources["active_rss_mib"], "resources.active_rss_mib")
    if rss["p95"] > ACTIVE_RSS_MAX_MIB:
        raise PerformanceGateError(f"active RSS p95 exceeds {ACTIVE_RSS_MAX_MIB} MiB")


def _validate_switch_cycle(value: Any) -> None:
    switch = _exact(
        value,
        {"switch_count", "rss_growth_mib", "fd_growth"},
        "switch_cycle",
    )
    count = _integer(switch["switch_count"], "switch_cycle.switch_count")
    if count < SWITCH_MIN_COUNT:
        raise PerformanceGateError(
            f"switch_cycle only ran {count} of {SWITCH_MIN_COUNT} required switches"
        )
    rss_growth = _non_negative(switch["rss_growth_mib"], "switch_cycle.rss_growth_mib")
    if rss_growth > SWITCH_RSS_GROWTH_MAX_MIB:
        raise PerformanceGateError(
            f"switch_cycle RSS growth exceeds {SWITCH_RSS_GROWTH_MAX_MIB} MiB"
        )
    fd_growth = _integer(switch["fd_growth"], "switch_cycle.fd_growth")
    if fd_growth < 0:
        raise PerformanceGateError("switch_cycle.fd_growth must be non-negative")
    if fd_growth > SWITCH_FD_GROWTH_MAX:
        raise PerformanceGateError(
            f"switch_cycle file-descriptor growth exceeds {SWITCH_FD_GROWTH_MAX}"
        )


def _validate_soak(value: Any) -> None:
    soak = _exact(value, {"duration_hours", "crash_count"}, "soak")
    duration = _non_negative(soak["duration_hours"], "soak.duration_hours")
    if duration < SOAK_MIN_HOURS:
        raise PerformanceGateError(
            f"soak ran {duration} of {SOAK_MIN_HOURS} required hours"
        )
    crashes = _integer(soak["crash_count"], "soak.crash_count")
    if crashes < 0:
        raise PerformanceGateError("soak.crash_count must be non-negative")
    if crashes > SOAK_MAX_CRASHES:
        raise PerformanceGateError(f"soak observed {crashes} crashes")


def validate_performance_evidence(value: Any) -> dict[str, Any]:
    """Validate the whole performance evidence document, failing closed."""

    document = _exact(
        value,
        {
            "schema_version",
            "parameters",
            "weak_network",
            "latency",
            "throughput",
            "resources",
            "switch_cycle",
            "soak",
        },
        "performance evidence",
    )
    if document["schema_version"] != 1:
        raise PerformanceGateError("performance evidence schema_version must be 1")
    _validate_parameters(document["parameters"])
    _validate_weak_network(document["weak_network"])
    _validate_latency(document["latency"])
    _validate_throughput(document["throughput"])
    _validate_resources(document["resources"])
    _validate_switch_cycle(document["switch_cycle"])
    _validate_soak(document["soak"])
    return document


def load_performance_evidence(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PerformanceGateError("performance evidence must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PerformanceGateError("performance evidence is not valid UTF-8 JSON") from error
    return validate_performance_evidence(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    arguments = parser.parse_args()
    try:
        document = load_performance_evidence(arguments.evidence)
    except (PerformanceGateError, OSError) as error:
        raise SystemExit(f"error: performance gate evidence failed: {error}") from error
    print(
        "performance gate evidence verified: "
        f"{PRODUCT_VERSION} ({document['parameters']['build']['build_number']}), "
        f"{len(document['weak_network'])} weak-network profiles"
    )


if __name__ == "__main__":
    main()
