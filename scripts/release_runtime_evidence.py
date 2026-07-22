#!/usr/bin/env python3
"""Validate physical-machine bounded recovery evidence for a 0.4.0 candidate."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any

if __package__:
    from .release_build_identity import canonical_build_version
else:
    from release_build_identity import canonical_build_version


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_CASES = {
    "provider-crash": ("tunnel", "TunnelActive", True, "TunnelActive", True),
    "proxy-agent-crash": ("proxy", "ProxyActive", True, "ProxyActive", True),
    "sleep-wake": ("tunnel", "TunnelActive", True, "TunnelActive", True),
    "network-outage-30s": ("tunnel", "TunnelActive", True, "TunnelActive", True),
    "cancel-during-start": ("tunnel", "TunnelStarting", False, "Off", False),
    "late-callback-after-cancel": ("tunnel", "TunnelStarting", False, "Off", False),
}
DATA_PLANE_FIELDS = {
    "tcp_v4",
    "tcp_v6",
    "udp_quic",
    "dns_a",
    "dns_aaaa",
}


class RuntimeEvidenceError(ValueError):
    """Runtime evidence is incomplete, inconsistent, or unbounded."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise RuntimeEvidenceError(f"{label} fields differ: {actual}")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise RuntimeEvidenceError(f"{label} is not a lowercase SHA-256")
    return value


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RuntimeEvidenceError("captured_at must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise RuntimeEvidenceError("captured_at is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise RuntimeEvidenceError("captured_at must use UTC")
    return value


def _snapshot(value: Any, label: str) -> dict[str, Any]:
    snapshot = _exact(
        value,
        {"generation", "config_sha256", "ready", "state"},
        label,
    )
    generation = snapshot["generation"]
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise RuntimeEvidenceError(f"{label}.generation must be a positive integer")
    _sha256(snapshot["config_sha256"], f"{label}.config_sha256")
    if not isinstance(snapshot["ready"], bool):
        raise RuntimeEvidenceError(f"{label}.ready must be boolean")
    if snapshot["state"] not in {
        "Off",
        "ProxyStarting",
        "ProxyActive",
        "TunnelStarting",
        "TunnelActive",
    }:
        raise RuntimeEvidenceError(f"{label}.state is unsupported")
    return snapshot


def _retry_policy(value: Any) -> dict[str, Any]:
    policy = _exact(
        value,
        {"max_attempts", "initial_backoff_ms", "maximum_backoff_ms", "multiplier"},
        "retry_policy",
    )
    maximum = policy["max_attempts"]
    initial = policy["initial_backoff_ms"]
    cap = policy["maximum_backoff_ms"]
    multiplier = policy["multiplier"]
    if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 5:
        raise RuntimeEvidenceError("retry_policy.max_attempts must be between 1 and 5")
    if not isinstance(initial, int) or isinstance(initial, bool) or not 100 <= initial <= 5_000:
        raise RuntimeEvidenceError("retry_policy.initial_backoff_ms is outside 100..5000")
    if not isinstance(cap, int) or isinstance(cap, bool) or not initial <= cap <= 10_000:
        raise RuntimeEvidenceError("retry_policy.maximum_backoff_ms is invalid")
    if not isinstance(multiplier, (int, float)) or isinstance(multiplier, bool):
        raise RuntimeEvidenceError("retry_policy.multiplier must be numeric")
    if not 1.5 <= float(multiplier) <= 4.0:
        raise RuntimeEvidenceError("retry_policy.multiplier is outside 1.5..4.0")
    return policy


def _expected_backoff(policy: dict[str, Any], count: int) -> list[int]:
    return [
        min(
            policy["maximum_backoff_ms"],
            round(policy["initial_backoff_ms"] * float(policy["multiplier"]) ** index),
        )
        for index in range(count)
    ]


def validate_runtime_evidence(value: Any) -> dict[str, Any]:
    document = _exact(
        value,
        {
            "schema_version",
            "product",
            "app_manifest_sha256",
            "captured_at",
            "platform",
            "retry_policy",
            "cases",
        },
        "runtime evidence",
    )
    if document["schema_version"] != 1:
        raise RuntimeEvidenceError("runtime evidence schema_version must be 1")
    product = _exact(document["product"], {"version", "build_number"}, "product")
    if product["version"] != "0.4.0":
        raise RuntimeEvidenceError("runtime evidence is not for version 0.4.0")
    canonical_build_version(product["build_number"], "runtime evidence build_number")
    _sha256(document["app_manifest_sha256"], "app_manifest_sha256")
    _timestamp(document["captured_at"])
    platform = _exact(
        document["platform"],
        {"architecture", "macos_version", "hardware_model", "clean_install"},
        "platform",
    )
    if platform["architecture"] != "arm64" or platform["clean_install"] is not True:
        raise RuntimeEvidenceError("runtime evidence requires a clean Apple Silicon machine")
    if not all(
        isinstance(platform[key], str) and platform[key].strip()
        for key in ("macos_version", "hardware_model")
    ):
        raise RuntimeEvidenceError("runtime platform identity is incomplete")
    policy = _retry_policy(document["retry_policy"])
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(REQUIRED_CASES):
        raise RuntimeEvidenceError("runtime evidence must contain each required case exactly once")
    observed_ids: set[str] = set()
    tokens: set[str] = set()
    case_fields = {
        "id",
        "mode",
        "before",
        "after",
        "attempt_count",
        "observed_backoff_ms",
        "recovery_ms",
        "cancellation_observed",
        "late_callback_ignored",
        "data_plane",
        "busy_loop",
    }
    for index, raw in enumerate(cases):
        case = _exact(raw, case_fields, f"cases[{index}]")
        case_id = case["id"]
        if case_id not in REQUIRED_CASES or case_id in observed_ids:
            raise RuntimeEvidenceError(f"runtime case is unknown or duplicated: {case_id!r}")
        observed_ids.add(case_id)
        (
            expected_mode,
            expected_before_state,
            expected_before_ready,
            expected_after_state,
            expected_after_ready,
        ) = REQUIRED_CASES[case_id]
        is_recovery = expected_after_ready
        if case["mode"] != expected_mode:
            raise RuntimeEvidenceError(f"{case_id} has the wrong engine mode")
        before = _snapshot(case["before"], f"{case_id}.before")
        after = _snapshot(case["after"], f"{case_id}.after")
        if before["generation"] != after["generation"]:
            raise RuntimeEvidenceError(f"{case_id} changed generation during recovery")
        if before["config_sha256"] != after["config_sha256"]:
            raise RuntimeEvidenceError(f"{case_id} changed config digest during recovery")
        if (
            before["state"] != expected_before_state
            or before["ready"] is not expected_before_ready
        ):
            raise RuntimeEvidenceError(f"{case_id} has an invalid initial ready/state snapshot")
        if after["state"] != expected_after_state or after["ready"] is not expected_after_ready:
            raise RuntimeEvidenceError(f"{case_id} has an invalid final ready/state snapshot")
        attempts = case["attempt_count"]
        if not isinstance(attempts, int) or isinstance(attempts, bool) or not 1 <= attempts <= policy["max_attempts"]:
            raise RuntimeEvidenceError(f"{case_id} exceeded or omitted its retry attempt bound")
        observed_backoff = case["observed_backoff_ms"]
        expected_backoff = _expected_backoff(policy, attempts - 1)
        if observed_backoff != expected_backoff:
            raise RuntimeEvidenceError(
                f"{case_id} backoff differs: {observed_backoff!r}, expected {expected_backoff!r}"
            )
        busy_loop = _exact(
            case["busy_loop"],
            {"detected", "idle_cpu_percent", "poll_iterations", "observation_ms"},
            f"{case_id}.busy_loop",
        )
        observation = busy_loop["observation_ms"]
        polls = busy_loop["poll_iterations"]
        cpu = busy_loop["idle_cpu_percent"]
        if busy_loop["detected"] is not False:
            raise RuntimeEvidenceError(f"{case_id} reported a busy loop")
        if not isinstance(observation, int) or observation < 30_000:
            raise RuntimeEvidenceError(f"{case_id} busy-loop observation is shorter than 30 seconds")
        if not isinstance(polls, int) or polls < 0 or polls > observation // 100:
            raise RuntimeEvidenceError(f"{case_id} poll rate exceeds the 100 ms lower bound")
        if not isinstance(cpu, (int, float)) or isinstance(cpu, bool) or not 0 <= float(cpu) < 1:
            raise RuntimeEvidenceError(f"{case_id} idle CPU is not below 1 percent")
        if is_recovery:
            if not isinstance(case["recovery_ms"], int) or not 0 <= case["recovery_ms"] <= 10_000:
                raise RuntimeEvidenceError(f"{case_id} recovery exceeds 10 seconds")
            if case["cancellation_observed"] is not False:
                raise RuntimeEvidenceError(f"{case_id} incorrectly reports cancellation")
            data_plane = _exact(
                case["data_plane"], {"token", *DATA_PLANE_FIELDS}, f"{case_id}.data_plane"
            )
            token = data_plane["token"]
            if not isinstance(token, str) or len(token) < 16 or token in tokens:
                raise RuntimeEvidenceError(f"{case_id} data-plane token is absent or reused")
            tokens.add(token)
            if any(data_plane[field] is not True for field in DATA_PLANE_FIELDS):
                raise RuntimeEvidenceError(f"{case_id} lacks complete post-recovery data-plane proof")
        else:
            if case["recovery_ms"] is not None or case["data_plane"] is not None:
                raise RuntimeEvidenceError(f"{case_id} cancellation must not claim active data plane")
            if case["cancellation_observed"] is not True:
                raise RuntimeEvidenceError(f"{case_id} did not observe cancellation")
            expected_late = case_id == "late-callback-after-cancel"
            if case["late_callback_ignored"] is not expected_late:
                raise RuntimeEvidenceError(f"{case_id} late callback disposition is invalid")
    if observed_ids != set(REQUIRED_CASES):
        raise RuntimeEvidenceError("runtime evidence is missing required cases")
    return document


def load_runtime_evidence(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeEvidenceError("runtime evidence must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeEvidenceError("runtime evidence is not valid UTF-8 JSON") from error
    return validate_runtime_evidence(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    arguments = parser.parse_args()
    try:
        document = load_runtime_evidence(arguments.evidence)
    except (RuntimeEvidenceError, OSError) as error:
        raise SystemExit(f"error: runtime recovery evidence failed: {error}") from error
    print(
        "runtime recovery evidence verified: "
        f"0.4.0 ({document['product']['build_number']}), {len(document['cases'])} cases"
    )


if __name__ == "__main__":
    main()
