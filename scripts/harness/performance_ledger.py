#!/usr/bin/env python3
"""Strict proof-free performance sample-ledger validation.

The signed product owns mode/generation/terminal-state observations in Unified
Logging.  The collector owns only source-fixed OS commands and monotonic
timestamps.  This validator joins those two sources, recomputes every numeric
measurement from retained command output, and rejects a ledger with missing
continuity, shaping restoration, process identity, or crash-delta evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
from typing import Any, Final

if __package__:
    from .physical_machine_identity import (
        BOOT_DOCUMENT as BOOT_ENVIRONMENT_SCHEME,
        DOCUMENT as MACHINE_IDENTITY_SCHEME,
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from .raw_artifacts import (
        ArtifactReader,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        require_identifier,
    )
else:  # pragma: no cover - direct-script import path
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from physical_machine_identity import (  # type: ignore
        BOOT_DOCUMENT as BOOT_ENVIRONMENT_SCHEME,
        DOCUMENT as MACHINE_IDENTITY_SCHEME,
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from raw_artifacts import (  # type: ignore
        ArtifactReader,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        require_identifier,
    )


LEDGER_SCHEMA_VERSION: Final = 2
LEDGER_DOCUMENT: Final = "cfw-performance-sample-ledger-v2"
LEDGER_KIND: Final = "performance-sample-ledger"
LEDGER_SUBJECT: Final = "sample-ledger"
SHAPING_INTENT_DOCUMENT: Final = "cfw-performance-shaping-intent-v1"
SHAPING_RESTORATION_DOCUMENT: Final = "cfw-performance-shaping-restoration-v1"
SHAPING_KIND: Final = "performance-shaping-transaction"
SHAPING_INTENT_SUBJECT: Final = "shaping-intent"
SHAPING_RESTORATION_SUBJECT: Final = "shaping-restoration"
REQUIRED_PERFORMANCE_SUBJECTS: Final = frozenset(
    {LEDGER_SUBJECT, SHAPING_INTENT_SUBJECT, SHAPING_RESTORATION_SUBJECT}
)

PRODUCT_VERSION: Final = "0.4.0"
FINAL_BUILD: Final = "40025"
PRODUCT_OBSERVATION_PREFIX: Final = "cfw-release-observation-v1 "
PRODUCT_OBSERVATION_DOCUMENT: Final = "cfw-product-observation-event-v1"
PRODUCT_LOG_SUBSYSTEM: Final = "com.bill.clashformac"
PRODUCT_LOG_CATEGORY: Final = "release-observation"
PRODUCT_LOG_PREDICATE: Final = (
    'subsystem == "com.bill.clashformac" AND '
    'category == "release-observation" AND '
    'eventMessage BEGINSWITH "cfw-release-observation-v1 "'
)

INSTALLED_APP: Final = "/Applications/Clash for Mac.app"
COMPONENT_IDENTITIES: Final = {
    "host": {
        "executable": f"{INSTALLED_APP}/Contents/MacOS/clash-for-mac",
        "codesign_target": INSTALLED_APP,
        "signing_identifier": "com.bill.clashformac",
    },
    "proxy_agent": {
        "executable": (
            f"{INSTALLED_APP}/Contents/Library/LoginItems/"
            "CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
        ),
        "codesign_target": (
            f"{INSTALLED_APP}/Contents/Library/LoginItems/CFWProxyAgent.app"
        ),
        "signing_identifier": "com.bill.clashformac.proxy-agent",
    },
    "packet_tunnel": {
        "executable": (
            f"{INSTALLED_APP}/Contents/Library/SystemExtensions/"
            "com.bill.clashformac.packet-tunnel.systemextension/Contents/MacOS/"
            "CFWPacketTunnel"
        ),
        "codesign_target": (
            f"{INSTALLED_APP}/Contents/Library/SystemExtensions/"
            "com.bill.clashformac.packet-tunnel.systemextension"
        ),
        "signing_identifier": "com.bill.clashformac.packet-tunnel",
    },
}
PROCESS_NAMES: Final = {
    "host": "clash-for-mac",
    "proxy_agent": "CFWProxyAgent",
    "packet_tunnel": "CFWPacketTunnel",
}
TEAM_ID: Final = "YKUPL7Z869"

SERIES_SAMPLE_COUNT: Final = 20
SWITCH_SAMPLE_COUNT: Final = 101
SOAK_HEARTBEAT_INTERVAL_SECONDS: Final = 300
SOAK_HEARTBEAT_COUNT: Final = 37
SOAK_TRAFFIC_INTERVAL_SECONDS: Final = 900
SOAK_TRAFFIC_COUNT: Final = 13
SOAK_DURATION_SECONDS: Final = 3 * 60 * 60
INTERVAL_TOLERANCE_SECONDS: Final = 5
TRAFFIC_INTERVAL_TOLERANCE_SECONDS: Final = 15
MAX_COMMAND_OUTPUT_BYTES: Final = 1024 * 1024
MAX_LEDGER_SAMPLES: Final = 2_000
MAX_CRASH_PATHS: Final = 2_000

WEAK_NETWORK_PROFILES: Final = {
    "latency-100ms-loss-1pct-10mbps": {
        "pipe_id": "40001",
        "kind": "shaping",
        "latency_ms": 100,
        "loss_percent": 1.0,
        "bandwidth_mbps": 10.0,
        "profile_sha256": "259df2641a9a5c8be89df82303af9a25c38b189115de9d391da98ec7ffeccbaa",
    },
    "latency-300ms-loss-5pct-1mbps": {
        "pipe_id": "40002",
        "kind": "shaping",
        "latency_ms": 300,
        "loss_percent": 5.0,
        "bandwidth_mbps": 1.0,
        "profile_sha256": "85097feae3cff0695299e222f576660f310c09b458c20c6fc4573a14f85e1a29",
    },
    "outage-30s": {
        "pipe_id": "40003",
        "kind": "outage",
        "outage_seconds": 30,
        "profile_sha256": "071121d49e606b00862d36c7829711260c5d69421c64e3161359f854f9bcd7c6",
    },
}
PF_ANCHOR: Final = "com.bill.clashformac.performance"
PROFILE_DIRECTORY: Final = (
    "/Library/Application Support/Clash for Mac/ReleaseEvidence/performance-profiles"
)
PROFILE_FILES: Final = {
    profile_id: f"{PROFILE_DIRECTORY}/{profile_id}.pf"
    for profile_id in WEAK_NETWORK_PROFILES
}
NETWORK_QUALITY_MAX_SECONDS: Final = 5
CRASH_LOG_PREDICATE: Final = (
    '(processImagePath == "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac" '
    'OR processImagePath == "/Applications/Clash for Mac.app/Contents/Library/'
    'LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent" '
    'OR processImagePath == "/Applications/Clash for Mac.app/Contents/Library/'
    'SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension/'
    'Contents/MacOS/CFWPacketTunnel") AND messageType == fault'
)

COMMAND_FIELDS: Final = {
    "role",
    "argv",
    "argv_sha256",
    "started_at",
    "completed_at",
    "duration_ms",
    "exit_code",
    "stdout_size",
    "stdout_sha256",
    "stdout",
    "stderr_size",
    "stderr_sha256",
    "stderr",
    "observer_executable_sha256",
}
CANDIDATE_FIELDS: Final = {
    "version",
    "build_number",
    "app_manifest_sha256",
    "signed_app_tree_sha256",
    "artifact_hash_manifest_sha256",
    "built_at",
}
RUN_FIELDS: Final = {
    "os",
    "macos_version",
    "macos_build",
    "machine_sha256",
    "machine_identity_scheme",
    "hardware_model",
    "virtualization_present",
    "boot_environment_sha256",
    "boot_environment_scheme",
    "clean_install",
    "run_id",
}
PARAMETER_FIELDS: Final = {"machine", "network", "power"}
MACHINE_FIELDS: Final = {
    "architecture",
    "macos_version",
    "macos_build",
    "hardware_model",
    "machine_sha256",
    "clean_install",
}
LOG_ENTRY_FIELDS: Final = {
    "timestamp",
    "machTimestamp",
    "processImagePath",
    "processID",
    "subsystem",
    "category",
    "eventMessage",
}
PRODUCT_EVENT_FIELDS: Final = {
    "schema_version",
    "document",
    "component",
    "event",
    "sequence",
    "recorded_unix_ms",
    "process",
    "candidate",
    "payload",
}
PRODUCT_PROCESS_FIELDS: Final = {"pid", "start_unix_ms"}
PRODUCT_CANDIDATE_FIELDS: Final = {"version", "build_number"}
PRODUCT_STATE_FIELDS: Final = {
    "desired_mode",
    "generation",
    "config_digest",
    "phase",
    "owner",
    "ready",
    "ipv6_enabled",
}
STATE_OBSERVATION_FIELDS: Final = {"log_entry", "event", "query_command"}
SIGNING_OBSERVATION_FIELDS: Final = {"component", "identity", "command"}
SIGNING_IDENTITY_FIELDS: Final = {
    "executable",
    "team_id",
    "signing_identifier",
    "cdhash",
    "designated_requirement_sha256",
}
ROSTER_PROCESS_FIELDS: Final = {
    "component",
    "pid",
    "uid",
    "start_time",
    "executable",
    "team_id",
    "signing_identifier",
    "cdhash",
    "designated_requirement_sha256",
    "product_event_sha256",
    "signing_observation_sha256",
    "runtime_signing_command",
}
SAMPLE_FIELDS: Final = {
    "sequence",
    "kind",
    "wall_time",
    "monotonic_ns",
    "operation_id",
    "generation",
    "mode",
    "terminal_state",
    "state_observation",
    "roster",
    "roster_discovery_commands",
    "roster_command",
    "measurement",
}
LEDGER_FIELDS: Final = {
    "schema_version",
    "document",
    "candidate",
    "run",
    "parameters",
    "captured_at",
    "completed_at",
    "heartbeat_interval_seconds",
    "traffic_interval_seconds",
    "signing_observations",
    "shaping",
    "samples",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CDHASH_RE = re.compile(r"^[0-9a-f]{40}$")
_MACOS_BUILD_RE = re.compile(r"^[0-9]{2}[A-Z][0-9]{1,5}$")
_ACTIVE_OWNER = {
    "system_proxy": "proxy_agent",
    "tunnel": "packet_tunnel_system_extension",
}
_EXPECTED_ROSTER = {
    "off": ("host",),
    "system_proxy": ("host", "proxy_agent"),
    "tunnel": ("host", "packet_tunnel"),
}
_TERMINAL_PHASE = {
    "off": "off",
    "system_proxy": "proxy_active",
    "tunnel": "tunnel_active",
}
_SAMPLE_COUNTS = {
    "connect-start": SERIES_SAMPLE_COUNT,
    "connect-end": SERIES_SAMPLE_COUNT,
    "disconnect-start": SERIES_SAMPLE_COUNT,
    "disconnect-end": SERIES_SAMPLE_COUNT,
    "network-baseline": SERIES_SAMPLE_COUNT,
    "network-measured": SERIES_SAMPLE_COUNT,
    "resource": SERIES_SAMPLE_COUNT,
    "weak-recovery": SERIES_SAMPLE_COUNT * len(WEAK_NETWORK_PROFILES),
    "switch": SWITCH_SAMPLE_COUNT,
    "crash-baseline": 1,
    "soak-heartbeat": SOAK_HEARTBEAT_COUNT,
    "soak-traffic": SOAK_TRAFFIC_COUNT,
    "crash-final": 1,
}

INTENT_FIELDS: Final = {
    "schema_version",
    "document",
    "candidate",
    "run",
    "created_at",
    "privilege_preflight",
    "anchor",
    "profiles",
    "original_state",
    "transactions",
}
RESTORATION_FIELDS: Final = {
    "schema_version",
    "document",
    "candidate",
    "run",
    "intent_artifact",
    "completed_at",
    "transactions",
}
SHAPING_TRANSACTION_FIELDS: Final = {
    "index",
    "profile_id",
    "applied_monotonic_ns",
    "restored_monotonic_ns",
    "apply_commands",
    "effective_queries",
    "restore_commands",
    "restoration_queries",
}


class PerformanceLedgerError(ValueError):
    """A proof-free performance ledger is incomplete or not source-derived."""


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PerformanceLedgerError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PerformanceLedgerError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PerformanceLedgerError(f"{label} must use UTC")
    return parsed


def _oslog_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}[+]0000",
        value,
    ) is None:
        raise PerformanceLedgerError(f"{label} is not a canonical UTC OSLog timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f%z")
    except ValueError as error:
        raise PerformanceLedgerError(f"{label} is not a valid OSLog timestamp") from error


def _log_query_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}", value
    ) is None:
        raise PerformanceLedgerError(
            f"{label} is not a canonical UTC log-show boundary"
        )
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise PerformanceLedgerError(f"{label} is not a valid log-show boundary") from error


def _format_milliseconds(value: int) -> str:
    if type(value) is not int or value < 1:
        raise PerformanceLedgerError("Unix millisecond timestamp is invalid")
    seconds, milliseconds = divmod(value, 1000)
    return datetime.fromtimestamp(
        seconds, timezone.utc
    ).replace(microsecond=milliseconds * 1000).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _number(value: Any, label: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PerformanceLedgerError(f"{label} must be numeric")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0 or (positive and normalized <= 0):
        requirement = "positive" if positive else "non-negative"
        raise PerformanceLedgerError(f"{label} must be finite and {requirement}")
    return normalized


def _positive_int(value: Any, label: str, *, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise PerformanceLedgerError(f"{label} must be a bounded positive integer")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise PerformanceLedgerError(f"{label} is not a lowercase SHA-256")
    return value


def _candidate(value: Any) -> dict[str, Any]:
    candidate = exact_object(value, CANDIDATE_FIELDS, "performance ledger.candidate")
    if candidate["version"] != PRODUCT_VERSION or candidate["build_number"] != FINAL_BUILD:
        raise PerformanceLedgerError(
            f"performance ledger is not final build {FINAL_BUILD}"
        )
    for field in CANDIDATE_FIELDS - {"version", "build_number", "built_at"}:
        _sha256(candidate[field], f"performance ledger.candidate.{field}")
    _timestamp(candidate["built_at"], "performance ledger.candidate.built_at")
    return candidate


def _run(value: Any) -> dict[str, Any]:
    run = exact_object(value, RUN_FIELDS, "performance ledger.run")
    if run["machine_identity_scheme"] != MACHINE_IDENTITY_SCHEME:
        raise PerformanceLedgerError("performance ledger machine identity scheme differs")
    if run["boot_environment_scheme"] != BOOT_ENVIRONMENT_SCHEME:
        raise PerformanceLedgerError("performance ledger boot environment scheme differs")
    if run["virtualization_present"] is not False or run["clean_install"] is not True:
        raise PerformanceLedgerError("performance ledger run is not clean physical hardware")
    try:
        validate_physical_hardware_model(run["hardware_model"])
    except PhysicalMachineIdentityError as error:
        raise PerformanceLedgerError("performance ledger hardware model is invalid") from error
    _sha256(run["machine_sha256"], "performance ledger.run.machine_sha256")
    _sha256(
        run["boot_environment_sha256"],
        "performance ledger.run.boot_environment_sha256",
    )
    require_identifier(run["run_id"], "performance ledger.run.run_id")
    if not isinstance(run["macos_build"], str) or _MACOS_BUILD_RE.fullmatch(
        run["macos_build"]
    ) is None:
        raise PerformanceLedgerError("performance ledger macOS build is invalid")
    if not isinstance(run["macos_version"], str) or not run["macos_version"]:
        raise PerformanceLedgerError("performance ledger macOS version is invalid")
    if run["os"] not in {"macos15", "current-macos"}:
        raise PerformanceLedgerError("performance ledger OS label is invalid")
    return run


def _parameters(value: Any, run: dict[str, Any]) -> dict[str, Any]:
    parameters = exact_object(value, PARAMETER_FIELDS, "performance ledger.parameters")
    machine = exact_object(
        parameters["machine"], MACHINE_FIELDS, "performance ledger.parameters.machine"
    )
    expected_machine = {
        "architecture": "arm64",
        "macos_version": run["macos_version"],
        "macos_build": run["macos_build"],
        "hardware_model": run["hardware_model"],
        "machine_sha256": run["machine_sha256"],
        "clean_install": True,
    }
    if machine != expected_machine:
        raise PerformanceLedgerError("performance parameters differ from the run context")
    network = exact_object(
        parameters["network"],
        {"description", "uplink_mbps"},
        "performance ledger.parameters.network",
    )
    if (
        not isinstance(network["description"], str)
        or not network["description"].strip()
        or len(network["description"].encode("utf-8")) > 256
    ):
        raise PerformanceLedgerError("performance network description is invalid")
    _number(network["uplink_mbps"], "performance network uplink", positive=True)
    power = exact_object(
        parameters["power"],
        {"source", "low_power_mode"},
        "performance ledger.parameters.power",
    )
    if power["source"] not in {"ac", "battery"} or type(
        power["low_power_mode"]
    ) is not bool:
        raise PerformanceLedgerError("performance power parameters are invalid")
    return parameters


def _command(value: Any, label: str, *, role: str | None = None) -> dict[str, Any]:
    command = exact_object(value, COMMAND_FIELDS, label)
    if role is not None and command["role"] != role:
        raise PerformanceLedgerError(f"{label}.role differs from {role!r}")
    if not isinstance(command["role"], str) or not re.fullmatch(
        r"[a-z][a-z0-9-]{0,63}", command["role"]
    ):
        raise PerformanceLedgerError(f"{label}.role is not canonical")
    argv = command["argv"]
    if (
        not isinstance(argv, list)
        or not 1 <= len(argv) <= 64
        or any(
            not isinstance(argument, str)
            or not argument
            or "\x00" in argument
            or len(argument.encode("utf-8")) > 4096
            for argument in argv
        )
    ):
        raise PerformanceLedgerError(f"{label}.argv is not a bounded vector")
    argv_sha256 = hashlib.sha256(canonical_json(argv)).hexdigest()
    if command["argv_sha256"] != argv_sha256:
        raise PerformanceLedgerError(f"{label}.argv_sha256 differs from its argv")
    executable_sha256 = _sha256(
        command["observer_executable_sha256"], f"{label}.observer_executable_sha256"
    )
    started = _timestamp(command["started_at"], f"{label}.started_at")
    completed = _timestamp(command["completed_at"], f"{label}.completed_at")
    duration_ms = command["duration_ms"]
    if (
        type(duration_ms) is not int
        or duration_ms < 1
        or not started < completed
        or abs((completed - started).total_seconds() * 1000 - duration_ms) > 1000
    ):
        raise PerformanceLedgerError(f"{label} duration/timestamps are not causal")
    if type(command["exit_code"]) is not int or command["exit_code"] != 0:
        raise PerformanceLedgerError(f"{label} did not exit successfully")
    outputs: dict[str, str] = {}
    for stream in ("stdout", "stderr"):
        output = command[stream]
        if not isinstance(output, str) or "\x00" in output:
            raise PerformanceLedgerError(f"{label}.{stream} is not UTF-8 text")
        encoded = output.encode("utf-8")
        if len(encoded) > MAX_COMMAND_OUTPUT_BYTES:
            raise PerformanceLedgerError(f"{label}.{stream} exceeds its byte bound")
        if command[f"{stream}_size"] != len(encoded):
            raise PerformanceLedgerError(f"{label}.{stream}_size differs")
        if command[f"{stream}_sha256"] != hashlib.sha256(encoded).hexdigest():
            raise PerformanceLedgerError(f"{label}.{stream}_sha256 differs")
        outputs[stream] = output
    return {
        "role": command["role"],
        "argv": tuple(argv),
        "argv_sha256": argv_sha256,
        "observer_executable_sha256": executable_sha256,
        "started_at": started,
        "completed_at": completed,
        "duration_ms": duration_ms,
        "stdout": outputs["stdout"],
        "stderr": outputs["stderr"],
    }


def _strict_json(value: str, label: str) -> Any:
    def reject_constant(token: str) -> None:
        raise ValueError(f"non-finite token {token}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key}")
            result[key] = item
        return result

    try:
        return json.loads(
            value,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        raise PerformanceLedgerError(f"{label} is not strict JSON") from error


def _fixed_log_query(command: dict[str, Any], label: str) -> list[dict[str, Any]]:
    argv = command["argv"]
    if (
        len(argv) != 13
        or argv[:7]
        != (
            "/usr/bin/log",
            "show",
            "--style",
            "ndjson",
            "--info",
            "--timezone",
            "UTC",
        )
        or argv[7] != "--start"
        or argv[9] != "--end"
        or argv[11:] != ("--predicate", PRODUCT_LOG_PREDICATE)
    ):
        raise PerformanceLedgerError(f"{label}.argv differs from the fixed OSLog reader")
    start = _log_query_timestamp(argv[8], f"{label}.argv.start")
    end = _log_query_timestamp(argv[10], f"{label}.argv.end")
    if not start <= end <= command["completed_at"]:
        raise PerformanceLedgerError(f"{label} query window is not causal")
    entries: list[dict[str, Any]] = []
    for index, line in enumerate(command["stdout"].splitlines()):
        if not line.strip():
            continue
        value = _strict_json(line, f"{label}.stdout[{index}]")
        if not isinstance(value, dict):
            raise PerformanceLedgerError(f"{label}.stdout[{index}] is not an object")
        entries.append(value)
    if not entries:
        raise PerformanceLedgerError(f"{label} returned no signed product observations")
    return entries


def _state(value: Any, label: str) -> dict[str, Any]:
    state = exact_object(value, PRODUCT_STATE_FIELDS, label)
    mode = state["desired_mode"]
    phase = state["phase"]
    generation = state["generation"]
    if mode not in _TERMINAL_PHASE or phase != _TERMINAL_PHASE[mode]:
        raise PerformanceLedgerError(f"{label} mode/phase pair is invalid")
    if type(generation) is not int or generation < 0:
        raise PerformanceLedgerError(f"{label}.generation is invalid")
    if type(state["ready"]) is not bool or type(state["ipv6_enabled"]) is not bool:
        raise PerformanceLedgerError(f"{label} booleans are invalid")
    if mode == "off":
        if (
            state["config_digest"] is not None
            or state["owner"] is not None
            or state["ready"] is not False
        ):
            raise PerformanceLedgerError(f"{label} is not exact Off")
    else:
        if (
            generation < 1
            or _sha256(state["config_digest"], f"{label}.config_digest")
            != state["config_digest"]
            or state["owner"] != _ACTIVE_OWNER[mode]
            or state["ready"] is not True
        ):
            raise PerformanceLedgerError(f"{label} active owner is not exact and ready")
    return state


def _product_observation(
    value: Any,
    *,
    candidate: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    observation = exact_object(value, STATE_OBSERVATION_FIELDS, label)
    command = _command(
        observation["query_command"], f"{label}.query_command", role="product-observation-log"
    )
    entries = _fixed_log_query(command, f"{label}.query_command")
    log_entry = exact_object(observation["log_entry"], LOG_ENTRY_FIELDS, f"{label}.log_entry")
    event = exact_object(observation["event"], PRODUCT_EVENT_FIELDS, f"{label}.event")
    projected_entries = [
        {field: entry[field] for field in LOG_ENTRY_FIELDS}
        for entry in entries
        if LOG_ENTRY_FIELDS <= set(entry)
    ]
    if sum(entry == log_entry for entry in projected_entries) != 1:
        raise PerformanceLedgerError(f"{label} query does not retain its exact log entry")
    if (
        log_entry["subsystem"] != PRODUCT_LOG_SUBSYSTEM
        or log_entry["category"] != PRODUCT_LOG_CATEGORY
        or type(log_entry["processID"]) is not int
        or log_entry["processID"] < 1
        or type(log_entry["machTimestamp"]) is not int
        or log_entry["machTimestamp"] < 1
    ):
        raise PerformanceLedgerError(f"{label} OSLog source identity is invalid")
    try:
        encoded_event = canonical_json(event).decode("utf-8")
    except (RawArtifactError, UnicodeDecodeError) as error:
        raise PerformanceLedgerError(f"{label} event is not canonical JSON") from error
    if log_entry["eventMessage"] != PRODUCT_OBSERVATION_PREFIX + encoded_event:
        raise PerformanceLedgerError(f"{label} event differs from its OSLog message")
    matching_product_entries = [
        entry
        for entry in projected_entries
        if entry["processImagePath"] == COMPONENT_IDENTITIES["host"]["executable"]
        and entry["subsystem"] == PRODUCT_LOG_SUBSYSTEM
        and entry["category"] == PRODUCT_LOG_CATEGORY
        and isinstance(entry["machTimestamp"], int)
        and entry["eventMessage"].startswith(PRODUCT_OBSERVATION_PREFIX)
    ]
    if not matching_product_entries or log_entry["machTimestamp"] != max(
        entry["machTimestamp"] for entry in matching_product_entries
    ):
        raise PerformanceLedgerError(f"{label} is not the latest event in its query")
    if (
        type(event["schema_version"]) is not int
        or event["schema_version"] != 1
        or event["document"] != PRODUCT_OBSERVATION_DOCUMENT
        or event["component"] != "host"
        or event["event"] != "engine_snapshot"
        or type(event["sequence"]) is not int
        or event["sequence"] < 1
        or type(event["recorded_unix_ms"]) is not int
        or event["recorded_unix_ms"] < 1
    ):
        raise PerformanceLedgerError(f"{label} event identity/sequence is invalid")
    if log_entry["processImagePath"] != COMPONENT_IDENTITIES["host"]["executable"]:
        raise PerformanceLedgerError(f"{label} did not come from the installed Host")
    process = exact_object(event["process"], PRODUCT_PROCESS_FIELDS, f"{label}.event.process")
    if (
        process["pid"] != log_entry["processID"]
        or type(process["start_unix_ms"]) is not int
        or not 1 <= process["start_unix_ms"] <= event["recorded_unix_ms"]
    ):
        raise PerformanceLedgerError(f"{label} Host process identity is invalid")
    event_candidate = exact_object(
        event["candidate"], PRODUCT_CANDIDATE_FIELDS, f"{label}.event.candidate"
    )
    if event_candidate != {
        "version": candidate["version"],
        "build_number": candidate["build_number"],
    }:
        raise PerformanceLedgerError(f"{label} event binds a different candidate")
    payload = exact_object(event["payload"], {"state"}, f"{label}.event.payload")
    state = _state(payload["state"], f"{label}.event.payload.state")
    recorded_at = _timestamp(
        _format_milliseconds(event["recorded_unix_ms"]), f"{label}.event.recorded_at"
    )
    if abs(
        (
            _oslog_timestamp(log_entry["timestamp"], f"{label}.log_entry.timestamp")
            - recorded_at
        ).total_seconds()
    ) > 1:
        raise PerformanceLedgerError(f"{label} event/log wall timestamps disagree")
    query_start = _log_query_timestamp(
        command["argv"][8], f"{label}.query_command.argv.start"
    )
    query_end = _log_query_timestamp(
        command["argv"][10], f"{label}.query_command.argv.end"
    )
    if not query_start <= recorded_at < query_end:
        raise PerformanceLedgerError(f"{label} query window does not cover its event")
    event_sha256 = hashlib.sha256(canonical_json(event)).hexdigest()
    return {
        "event_sha256": event_sha256,
        "event_sequence": event["sequence"],
        "recorded_at": recorded_at,
        "mach_timestamp": log_entry["machTimestamp"],
        "process": process,
        "state": state,
        "query": command,
    }


def _signing_observation(value: Any, label: str) -> dict[str, Any]:
    observation = exact_object(value, SIGNING_OBSERVATION_FIELDS, label)
    component = observation["component"]
    expected = COMPONENT_IDENTITIES.get(component)
    if expected is None:
        raise PerformanceLedgerError(f"{label}.component is unsupported")
    identity = exact_object(observation["identity"], SIGNING_IDENTITY_FIELDS, f"{label}.identity")
    if (
        identity["executable"] != expected["executable"]
        or identity["team_id"] != TEAM_ID
        or identity["signing_identifier"] != expected["signing_identifier"]
        or not isinstance(identity["cdhash"], str)
        or _CDHASH_RE.fullmatch(identity["cdhash"]) is None
    ):
        raise PerformanceLedgerError(f"{label} signing identity is not the release component")
    _sha256(
        identity["designated_requirement_sha256"],
        f"{label}.identity.designated_requirement_sha256",
    )
    command = _command(
        observation["command"], f"{label}.command", role="performance-codesign"
    )
    if command["argv"] != (
        "/usr/bin/codesign",
        "-d",
        "-r-",
        "--verbose=4",
        expected["codesign_target"],
    ):
        raise PerformanceLedgerError(f"{label}.command is not the fixed codesign query")
    lines = (command["stdout"] + command["stderr"]).splitlines()
    for required in (
        f"Executable={identity['executable']}",
        f"Identifier={identity['signing_identifier']}",
        f"TeamIdentifier={TEAM_ID}",
        f"CDHash={identity['cdhash']}",
    ):
        if lines.count(required) != 1:
            raise PerformanceLedgerError(f"{label}.command output omits {required!r}")
    requirements = [line.removeprefix("designated => ") for line in lines if line.startswith("designated => ")]
    if len(requirements) != 1 or hashlib.sha256(
        requirements[0].encode("utf-8")
    ).hexdigest() != identity["designated_requirement_sha256"]:
        raise PerformanceLedgerError(f"{label} designated requirement hash differs")
    normalized = {
        "component": component,
        "identity": identity,
        "command": command,
        "command_sha256": command["argv_sha256"],
        "observer_executable_sha256": command["observer_executable_sha256"],
    }
    normalized["observation_sha256"] = hashlib.sha256(canonical_json(observation)).hexdigest()
    return normalized


def _canonical_artifact_json(
    artifacts: ArtifactReader,
    descriptor: Any,
    *,
    expected_kind: str,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    parsed, data = artifacts.read(
        descriptor,
        expected_kinds={expected_kind},
        label=label,
    )
    value = load_json_bytes(data, label)
    if not isinstance(value, dict) or canonical_json(value) + b"\n" != data:
        raise PerformanceLedgerError(f"{label} is not a canonical JSON object")
    return parsed.as_dict(), value


def _same_context(
    candidate_value: Any,
    run_value: Any,
    *,
    candidate: dict[str, Any],
    run: dict[str, Any],
    label: str,
) -> None:
    if _candidate(candidate_value) != candidate:
        raise PerformanceLedgerError(f"{label} candidate differs from the ledger")
    if _run(run_value) != run:
        raise PerformanceLedgerError(f"{label} run differs from the ledger")


def _profile_documents(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        raise PerformanceLedgerError("shaping intent profiles must be a list")
    expected = tuple(
        {"id": profile_id, **WEAK_NETWORK_PROFILES[profile_id]}
        for profile_id in sorted(WEAK_NETWORK_PROFILES)
    )
    if canonical_json(value) != canonical_json(list(expected)):
        raise PerformanceLedgerError("shaping intent profiles differ from source")
    return expected


def _sudo_command(
    value: Any,
    *,
    role: str,
    argv: tuple[str, ...],
    label: str,
) -> dict[str, Any]:
    command = _command(value, label, role=role)
    if command["argv"] != argv:
        raise PerformanceLedgerError(f"{label}.argv differs from the fixed command")
    return command


def _pipe_query_argv(pipe_id: str) -> tuple[str, ...]:
    return (
        "/usr/bin/sudo",
        "-n",
        "/usr/sbin/dnctl",
        "pipe",
        "show",
        pipe_id,
    )


def _pf_query_argv() -> tuple[str, ...]:
    return (
        "/usr/bin/sudo",
        "-n",
        "/sbin/pfctl",
        "-a",
        PF_ANCHOR,
        "-sr",
    )


def _pf_status_argv() -> tuple[str, ...]:
    return (
        "/usr/bin/sudo",
        "-n",
        "/sbin/pfctl",
        "-s",
        "info",
    )


def _dnctl_apply_argv(profile_id: str) -> tuple[str, ...]:
    profile = WEAK_NETWORK_PROFILES[profile_id]
    result = [
        "/usr/bin/sudo",
        "-n",
        "/usr/sbin/dnctl",
        "pipe",
        profile["pipe_id"],
        "config",
    ]
    if profile["kind"] == "outage":
        result.extend(("plr", "1"))
    else:
        result.extend(
            (
                "delay",
                str(profile["latency_ms"]),
                "plr",
                format(profile["loss_percent"] / 100.0, ".12g"),
                "bw",
                f"{format(profile['bandwidth_mbps'], '.12g')}Mbit/s",
            )
        )
    return tuple(result)


def _pf_apply_argv(profile_id: str) -> tuple[str, ...]:
    return (
        "/usr/bin/sudo",
        "-n",
        "/sbin/pfctl",
        "-a",
        PF_ANCHOR,
        "-f",
        PROFILE_FILES[profile_id],
    )


def _restore_argvs(pipe_id: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        (
            "/usr/bin/sudo",
            "-n",
            "/sbin/pfctl",
            "-a",
            PF_ANCHOR,
            "-F",
            "rules",
        ),
        (
            "/usr/bin/sudo",
            "-n",
            "/usr/sbin/dnctl",
            "pipe",
            "delete",
            pipe_id,
        ),
    )


def _require_effective_profile(output: str, profile_id: str, label: str) -> None:
    profile = WEAK_NETWORK_PROFILES[profile_id]
    pipe_id = profile["pipe_id"]
    if re.search(rf"\b{re.escape(pipe_id)}\b", output) is None:
        raise PerformanceLedgerError(f"{label} does not show its dummynet pipe")
    if profile["kind"] == "outage":
        patterns = (r"\bplr\s+1(?:[.]0+)?\b",)
    else:
        loss_fraction = profile["loss_percent"] / 100.0
        patterns = (
            rf"\b{profile['latency_ms']}(?:[.]0+)?\s*ms\b",
            rf"\b{format(loss_fraction, '.12g').replace('.', '[.]')}(?:0*)\b",
            rf"\b{format(profile['bandwidth_mbps'], '.12g').replace('.', '[.]')}(?:[.]0+)?\s*Mbit/s\b",
        )
    if any(re.search(pattern, output, re.IGNORECASE) is None for pattern in patterns):
        raise PerformanceLedgerError(f"{label} does not show the effective profile")


def _require_effective_pf_rules(output: str, profile_id: str, label: str) -> None:
    pipe_id = WEAK_NETWORK_PROFILES[profile_id]["pipe_id"]
    expected_rules = [
        f"dummynet in quick all pipe {pipe_id}",
        f"dummynet out quick all pipe {pipe_id}",
    ]
    if [line.strip() for line in output.splitlines() if line.strip()] != expected_rules:
        raise PerformanceLedgerError(f"{label} differs from the exact reviewed PF rules")


def _ordered_commands(
    commands: list[dict[str, Any]], label: str
) -> tuple[datetime, datetime]:
    if not commands:
        raise PerformanceLedgerError(f"{label} contains no commands")
    previous = commands[0]["started_at"]
    for command in commands:
        if command["started_at"] < previous:
            raise PerformanceLedgerError(f"{label} command wall times regress")
        previous = command["completed_at"]
    return commands[0]["started_at"], commands[-1]["completed_at"]


def _empty_shaping_state(
    value: Any, label: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    state = exact_object(value, {"pf_status_query", "pf_query", "pipe_queries"}, label)
    pf_status = _sudo_command(
        state["pf_status_query"],
        role="performance-pf-status",
        argv=_pf_status_argv(),
        label=f"{label}.pf_status_query",
    )
    if re.search(r"(?m)^Status:\s+Enabled(?:\s|$)", pf_status["stdout"]) is None:
        raise PerformanceLedgerError(
            f"{label} packet filter is not already enabled by the host"
        )
    pf = _sudo_command(
        state["pf_query"],
        role="performance-pf-query",
        argv=_pf_query_argv(),
        label=f"{label}.pf_query",
    )
    if pf["stdout"].strip():
        raise PerformanceLedgerError(f"{label} fixed PF anchor is not empty")
    pipe_values = state["pipe_queries"]
    if not isinstance(pipe_values, list) or len(pipe_values) != len(
        WEAK_NETWORK_PROFILES
    ):
        raise PerformanceLedgerError(f"{label}.pipe_queries is incomplete")
    pipes: dict[str, dict[str, Any]] = {}
    for index, profile_id in enumerate(sorted(WEAK_NETWORK_PROFILES)):
        pipe_id = WEAK_NETWORK_PROFILES[profile_id]["pipe_id"]
        query = _sudo_command(
            pipe_values[index],
            role="performance-dnctl-query",
            argv=_pipe_query_argv(pipe_id),
            label=f"{label}.pipe_queries[{index}]",
        )
        if re.search(rf"\b{re.escape(pipe_id)}\b", query["stdout"]):
            raise PerformanceLedgerError(f"{label} fixed dummynet pipe already exists")
        pipes[pipe_id] = query
    _ordered_commands([pf_status, pf, *pipes.values()], label)
    return pf_status, pf, pipes


def _intent(
    value: Any,
    *,
    candidate: dict[str, Any],
    run: dict[str, Any],
) -> dict[str, Any]:
    intent = exact_object(value, INTENT_FIELDS, "performance shaping intent")
    if (
        type(intent["schema_version"]) is not int
        or intent["schema_version"] != 1
        or intent["document"] != SHAPING_INTENT_DOCUMENT
    ):
        raise PerformanceLedgerError("performance shaping intent header is invalid")
    _same_context(
        intent["candidate"],
        intent["run"],
        candidate=candidate,
        run=run,
        label="performance shaping intent",
    )
    created_at = _timestamp(intent["created_at"], "performance shaping intent.created_at")
    preflight = _sudo_command(
        intent["privilege_preflight"],
        role="performance-sudo-preflight",
        argv=("/usr/bin/sudo", "-n", "-v"),
        label="performance shaping intent.privilege_preflight",
    )
    if preflight["completed_at"] > created_at:
        raise PerformanceLedgerError("shaping WAL predates neither preflight nor mutation")
    if intent["anchor"] != PF_ANCHOR:
        raise PerformanceLedgerError("performance shaping anchor differs from source")
    _profile_documents(intent["profiles"])
    pf_status, pf, pipes = _empty_shaping_state(
        intent["original_state"], "performance shaping intent.original_state"
    )
    if max(
        [
            pf_status["completed_at"],
            pf["completed_at"],
            *(query["completed_at"] for query in pipes.values()),
        ]
    ) > created_at:
        raise PerformanceLedgerError("shaping intent was not written after original-state queries")
    transactions = intent["transactions"]
    expected_transactions = [
        {"index": index, "profile_id": profile_id}
        for index, profile_id in enumerate(
            profile_id
            for profile_id in sorted(WEAK_NETWORK_PROFILES)
            for _ in range(SERIES_SAMPLE_COUNT)
        )
    ]
    if canonical_json(transactions) != canonical_json(expected_transactions):
        raise PerformanceLedgerError("shaping WAL transaction plan differs from source")
    return {
        "captured_at": min(
            preflight["started_at"],
            pf_status["started_at"],
            pf["started_at"],
            *(query["started_at"] for query in pipes.values()),
        ),
        "created_at": created_at,
        "original_pf": pf,
        "original_pipes": pipes,
        "transactions": expected_transactions,
    }


def _transaction_commands(
    value: Any,
    *,
    expected_index: int,
    expected_profile_id: str,
    original_pf: dict[str, Any],
    original_pipes: dict[str, dict[str, Any]],
    created_at: datetime,
) -> dict[str, Any]:
    label = f"performance shaping restoration.transactions[{expected_index}]"
    transaction = exact_object(value, SHAPING_TRANSACTION_FIELDS, label)
    if (
        type(transaction["index"]) is not int
        or transaction["index"] != expected_index
        or transaction["profile_id"] != expected_profile_id
    ):
        raise PerformanceLedgerError(f"{label} index/profile differs from WAL")
    applied_ns = _positive_int(
        transaction["applied_monotonic_ns"], f"{label}.applied_monotonic_ns"
    )
    restored_ns = _positive_int(
        transaction["restored_monotonic_ns"], f"{label}.restored_monotonic_ns"
    )
    if restored_ns <= applied_ns:
        raise PerformanceLedgerError(f"{label} monotonic restore does not follow apply")
    pipe_id = WEAK_NETWORK_PROFILES[expected_profile_id]["pipe_id"]
    groups = {
        "apply_commands": (
            ("performance-dnctl-apply", _dnctl_apply_argv(expected_profile_id)),
            ("performance-pf-apply", _pf_apply_argv(expected_profile_id)),
        ),
        "effective_queries": (
            ("performance-dnctl-query", _pipe_query_argv(pipe_id)),
            ("performance-pf-query", _pf_query_argv()),
        ),
        "restore_commands": tuple(
            (role, argv)
            for role, argv in zip(
                ("performance-pf-restore", "performance-dnctl-restore"),
                _restore_argvs(pipe_id),
                strict=True,
            )
        ),
        "restoration_queries": (
            ("performance-dnctl-query", _pipe_query_argv(pipe_id)),
            ("performance-pf-query", _pf_query_argv()),
        ),
    }
    parsed_groups: dict[str, list[dict[str, Any]]] = {}
    all_commands: list[dict[str, Any]] = []
    for group, specifications in groups.items():
        raw_commands = transaction[group]
        if not isinstance(raw_commands, list) or len(raw_commands) != len(specifications):
            raise PerformanceLedgerError(f"{label}.{group} is incomplete")
        parsed = [
            _sudo_command(
                raw_commands[index],
                role=role,
                argv=argv,
                label=f"{label}.{group}[{index}]",
            )
            for index, (role, argv) in enumerate(specifications)
        ]
        parsed_groups[group] = parsed
        all_commands.extend(parsed)
    started_at, completed_at = _ordered_commands(all_commands, label)
    if started_at <= created_at:
        raise PerformanceLedgerError(f"{label} mutation did not follow the durable intent")
    effective_dnctl, effective_pf = parsed_groups["effective_queries"]
    _require_effective_profile(
        effective_dnctl["stdout"], expected_profile_id, f"{label}.effective_queries[0]"
    )
    _require_effective_pf_rules(
        effective_pf["stdout"], expected_profile_id, f"{label}.effective_queries[1]"
    )
    restored_dnctl, restored_pf = parsed_groups["restoration_queries"]
    original_dnctl = original_pipes[pipe_id]
    if (restored_dnctl["stdout"], restored_dnctl["stderr"]) != (
        original_dnctl["stdout"],
        original_dnctl["stderr"],
    ) or (restored_pf["stdout"], restored_pf["stderr"]) != (
        original_pf["stdout"],
        original_pf["stderr"],
    ):
        raise PerformanceLedgerError(f"{label} restoration query differs from original state")
    if (
        WEAK_NETWORK_PROFILES[expected_profile_id]["kind"] == "outage"
        and restored_ns - applied_ns < 30_000_000_000
    ):
        raise PerformanceLedgerError(f"{label} outage did not last 30 monotonic seconds")
    if abs(
        (completed_at - started_at).total_seconds()
        - (restored_ns - applied_ns) / 1_000_000_000
    ) > 1:
        raise PerformanceLedgerError(f"{label} shaping wall/monotonic durations disagree")
    return {
        "profile_id": expected_profile_id,
        "applied_monotonic_ns": applied_ns,
        "restored_monotonic_ns": restored_ns,
        "started_at": started_at,
        "completed_at": completed_at,
    }


def _restoration(
    value: Any,
    *,
    intent_descriptor: dict[str, Any],
    intent: dict[str, Any],
    candidate: dict[str, Any],
    run: dict[str, Any],
) -> dict[str, Any]:
    restoration = exact_object(
        value, RESTORATION_FIELDS, "performance shaping restoration"
    )
    if (
        type(restoration["schema_version"]) is not int
        or restoration["schema_version"] != 1
        or restoration["document"] != SHAPING_RESTORATION_DOCUMENT
    ):
        raise PerformanceLedgerError("performance shaping restoration header is invalid")
    if _candidate(restoration["candidate"]) != candidate or _run(
        restoration["run"]
    ) != run:
        raise PerformanceLedgerError("performance shaping restoration context differs")
    if restoration["intent_artifact"] != intent_descriptor:
        raise PerformanceLedgerError("shaping restoration binds a different intent artifact")
    transactions = restoration["transactions"]
    if not isinstance(transactions, list) or len(transactions) != len(
        intent["transactions"]
    ):
        raise PerformanceLedgerError("shaping restoration transaction list is incomplete")
    parsed = [
        _transaction_commands(
            transaction,
            expected_index=index,
            expected_profile_id=planned["profile_id"],
            original_pf=intent["original_pf"],
            original_pipes=intent["original_pipes"],
            created_at=intent["created_at"],
        )
        for index, (planned, transaction) in enumerate(
            zip(intent["transactions"], transactions, strict=True)
        )
    ]
    for previous, current in zip(parsed, parsed[1:]):
        if (
            current["applied_monotonic_ns"] <= previous["restored_monotonic_ns"]
            or current["started_at"] < previous["completed_at"]
        ):
            raise PerformanceLedgerError("shaping transactions overlap or regress")
    completed_at = _timestamp(
        restoration["completed_at"], "performance shaping restoration.completed_at"
    )
    if not parsed or completed_at < parsed[-1]["completed_at"]:
        raise PerformanceLedgerError("shaping restoration completion predates its final query")
    return {"completed_at": completed_at, "transactions": parsed}


def _shaping(
    value: Any,
    *,
    artifacts: ArtifactReader,
    candidate: dict[str, Any],
    run: dict[str, Any],
) -> dict[str, Any]:
    shaping = exact_object(
        value,
        {"intent_artifact", "restoration_artifact"},
        "performance ledger.shaping",
    )
    intent_descriptor, intent_value = _canonical_artifact_json(
        artifacts,
        shaping["intent_artifact"],
        expected_kind=SHAPING_KIND,
        label="performance shaping intent artifact",
    )
    restoration_descriptor, restoration_value = _canonical_artifact_json(
        artifacts,
        shaping["restoration_artifact"],
        expected_kind=SHAPING_KIND,
        label="performance shaping restoration artifact",
    )
    intent = _intent(intent_value, candidate=candidate, run=run)
    restoration = _restoration(
        restoration_value,
        intent_descriptor=intent_descriptor,
        intent=intent,
        candidate=candidate,
        run=run,
    )
    return {
        "intent_descriptor": intent_descriptor,
        "restoration_descriptor": restoration_descriptor,
        "intent_document": intent_value,
        "restoration_document": restoration_value,
        "intent": intent,
        "restoration": restoration,
    }


def operation_id(observation: dict[str, Any]) -> str:
    """Derive the operation identity only from the signed Host event."""

    material = {
        "host_process": observation["process"],
        "generation": observation["state"]["generation"],
        "desired_mode": observation["state"]["desired_mode"],
        "phase": observation["state"]["phase"],
        "config_digest": observation["state"]["config_digest"],
    }
    return hashlib.sha256(
        b"cfw-performance-operation-v1\0" + canonical_json(material)
    ).hexdigest()


def _ps_roster_rows(output: str, label: str) -> dict[int, tuple[int, str, str]]:
    rows: dict[int, tuple[int, str, str]] = {}
    for index, line in enumerate(output.splitlines()):
        if not line.strip():
            continue
        fields = line.split(maxsplit=7)
        if len(fields) != 8:
            raise PerformanceLedgerError(f"{label}[{index}] is not a fixed ps row")
        try:
            pid = int(fields[0])
            uid = int(fields[1])
        except ValueError as error:
            raise PerformanceLedgerError(f"{label}[{index}] PID/UID is invalid") from error
        start_time = " ".join(fields[2:7])
        executable = fields[7]
        if (
            not 1 <= pid <= 2**31 - 1
            or not 0 <= uid <= 2**31 - 1
            or pid in rows
            or not start_time
            or not executable.startswith("/")
        ):
            raise PerformanceLedgerError(f"{label}[{index}] process identity is invalid")
        rows[pid] = (uid, start_time, executable)
    if not rows:
        raise PerformanceLedgerError(f"{label} contains no processes")
    return rows


def _runtime_executable_is_exact(component: str, executable: str) -> bool:
    if component != "packet_tunnel":
        return executable == COMPONENT_IDENTITIES[component]["executable"]
    embedded = COMPONENT_IDENTITIES[component]["executable"]
    runtime_pattern = (
        r"/Library/SystemExtensions/"
        r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
        r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/"
        r"com[.]bill[.]clashformac[.]packet-tunnel[.]systemextension/"
        r"Contents/MacOS/CFWPacketTunnel"
    )
    return executable == embedded or re.fullmatch(runtime_pattern, executable) is not None


def _roster(
    value: Any,
    discovery_value: Any,
    command_value: Any,
    *,
    mode: str,
    observation: dict[str, Any],
    signing: dict[str, dict[str, Any]],
    label: str,
) -> tuple[
    tuple[dict[str, Any], ...],
    list[dict[str, Any]],
    dict[str, Any],
    list[dict[str, Any]],
]:
    expected_components = _EXPECTED_ROSTER[mode]
    if not isinstance(value, list) or len(value) != len(expected_components):
        raise PerformanceLedgerError(f"{label} does not contain the exact mode roster")
    processes = tuple(
        exact_object(process, ROSTER_PROCESS_FIELDS, f"{label}[{index}]")
        for index, process in enumerate(value)
    )
    if tuple(process["component"] for process in processes) != expected_components:
        raise PerformanceLedgerError(f"{label} component order differs from source")
    pids = tuple(process["pid"] for process in processes)
    if any(type(pid) is not int or not 1 <= pid <= 2**31 - 1 for pid in pids) or len(
        set(pids)
    ) != len(pids):
        raise PerformanceLedgerError(f"{label} PID set is invalid")
    expected_owner_components = expected_components
    if not isinstance(discovery_value, list) or len(discovery_value) != len(
        expected_owner_components
    ):
        raise PerformanceLedgerError(f"{label} owner discovery command set is incomplete")
    discovery_commands: list[dict[str, Any]] = []
    for index, component in enumerate(expected_owner_components):
        command = _command(
            discovery_value[index],
            f"{label}_discovery_commands[{index}]",
            role="performance-owner-discovery",
        )
        executable = COMPONENT_IDENTITIES[component]["executable"]
        if command["argv"] != (
            "/usr/bin/pgrep",
            "-x",
            PROCESS_NAMES[component],
        ):
            raise PerformanceLedgerError(
                f"{label}_discovery_commands[{index}] argv differs from source"
            )
        discovered = [line for line in command["stdout"].splitlines() if line]
        expected_pid = str(processes[index]["pid"])
        if discovered != [expected_pid]:
            raise PerformanceLedgerError(
                f"{label}_discovery_commands[{index}] did not find one exact owner"
            )
        discovery_commands.append(command)
    command = _command(command_value, f"{label}_command", role="performance-process-roster")
    expected_argv = (
        "/bin/ps",
        "-p",
        ",".join(str(pid) for pid in sorted(pids)),
        "-o",
        "pid=,uid=,lstart=,comm=",
    )
    if command["argv"] != expected_argv:
        raise PerformanceLedgerError(f"{label}_command argv differs from the fixed roster query")
    rows = _ps_roster_rows(command["stdout"], f"{label}_command.stdout")
    if set(rows) != set(pids):
        raise PerformanceLedgerError(f"{label}_command returned a different PID set")
    runtime_signing_commands: list[dict[str, Any]] = []
    for index, process in enumerate(processes):
        component = process["component"]
        identity = signing[component]
        expected_identity = identity["identity"]
        pid = process["pid"]
        uid, start_time, executable = rows[pid]
        if (
            type(process["uid"]) is not int
            or process["uid"] != uid
            or process["start_time"] != start_time
            or process["executable"] != executable
            or not _runtime_executable_is_exact(component, executable)
            or process["team_id"] != expected_identity["team_id"]
            or process["signing_identifier"] != expected_identity["signing_identifier"]
            or process["cdhash"] != expected_identity["cdhash"]
            or process["designated_requirement_sha256"]
            != expected_identity["designated_requirement_sha256"]
            or process["signing_observation_sha256"]
            != identity["observation_sha256"]
        ):
            raise PerformanceLedgerError(f"{label} process identity differs from signed ps bytes")
        product_hash = process["product_event_sha256"]
        if component == "host":
            if pid != observation["process"]["pid"] or product_hash != observation[
                "event_sha256"
            ]:
                raise PerformanceLedgerError(f"{label} Host differs from its product event")
        elif product_hash is not None:
            raise PerformanceLedgerError(f"{label} owner event hash must be null without an owner event")
        runtime_command = _command(
            process["runtime_signing_command"],
            f"{label}[{index}].runtime_signing_command",
            role="performance-runtime-codesign",
        )
        if runtime_command["argv"] != (
            "/usr/bin/codesign",
            "-d",
            "-r-",
            "--verbose=4",
            executable,
        ):
            raise PerformanceLedgerError(f"{label}[{index}] runtime codesign argv differs")
        output_lines = (runtime_command["stdout"] + runtime_command["stderr"]).splitlines()
        required_lines = (
            f"Executable={executable}",
            f"Identifier={process['signing_identifier']}",
            f"TeamIdentifier={process['team_id']}",
            f"CDHash={process['cdhash']}",
        )
        if any(output_lines.count(line) != 1 for line in required_lines):
            raise PerformanceLedgerError(f"{label}[{index}] runtime code identity differs")
        requirements = [
            line.removeprefix("designated => ")
            for line in output_lines
            if line.startswith("designated => ")
        ]
        if len(requirements) != 1 or hashlib.sha256(
            requirements[0].encode("utf-8")
        ).hexdigest() != process["designated_requirement_sha256"]:
            raise PerformanceLedgerError(f"{label}[{index}] runtime requirement differs")
        runtime_signing_commands.append(runtime_command)
    _ordered_commands(runtime_signing_commands, f"{label} runtime signing")
    if runtime_signing_commands[0]["started_at"] < command["completed_at"]:
        raise PerformanceLedgerError(f"{label} runtime signing did not follow ps")
    return processes, discovery_commands, command, runtime_signing_commands


def _network_quality(value: Any, label: str) -> tuple[dict[str, Any], float, float]:
    command = _command(value, label, role="performance-network-quality")
    if command["argv"] != (
        "/usr/bin/networkQuality",
        "-c",
        "-M",
        str(NETWORK_QUALITY_MAX_SECONDS),
    ):
        raise PerformanceLedgerError(f"{label}.argv differs from the fixed traffic probe")
    output = _strict_json(command["stdout"], f"{label}.stdout")
    if not isinstance(output, dict):
        raise PerformanceLedgerError(f"{label}.stdout is not a JSON object")
    for field in ("start_date", "end_date", "interface_name"):
        if not isinstance(output.get(field), str) or not output[field].strip():
            raise PerformanceLedgerError(f"{label}.stdout.{field} is missing")
    for key, item in output.items():
        if key.lower().startswith("error") and item not in (None, "", [], {}):
            raise PerformanceLedgerError(f"{label}.stdout contains a traffic error")
    base_rtt = _number(output.get("base_rtt"), f"{label}.stdout.base_rtt", positive=True)
    throughput_bits = _number(
        output.get("dl_throughput"), f"{label}.stdout.dl_throughput", positive=True
    )
    return command, base_rtt, throughput_bits / 1_000_000.0


def _resource_command(
    value: Any, roster: tuple[dict[str, Any], ...], label: str
) -> tuple[dict[str, Any], float, float]:
    command = _command(value, label, role="performance-resource")
    pids = sorted(process["pid"] for process in roster)
    if command["argv"] != (
        "/bin/ps",
        "-p",
        ",".join(str(pid) for pid in pids),
        "-o",
        "pid=,pcpu=,rss=",
    ):
        raise PerformanceLedgerError(f"{label}.argv differs from the fixed resource query")
    observed: dict[int, tuple[float, int]] = {}
    for index, line in enumerate(command["stdout"].splitlines()):
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 3:
            raise PerformanceLedgerError(f"{label}.stdout[{index}] is malformed")
        try:
            pid = int(fields[0])
            cpu = float(fields[1])
            rss_kib = int(fields[2])
        except ValueError as error:
            raise PerformanceLedgerError(f"{label}.stdout[{index}] is not numeric") from error
        if (
            pid in observed
            or pid not in pids
            or not math.isfinite(cpu)
            or cpu < 0
            or rss_kib < 0
        ):
            raise PerformanceLedgerError(f"{label}.stdout[{index}] value is invalid")
        observed[pid] = (cpu, rss_kib)
    if set(observed) != set(pids):
        raise PerformanceLedgerError(f"{label} did not observe the exact process roster")
    return (
        command,
        sum(item[0] for item in observed.values()),
        sum(item[1] for item in observed.values()) / 1024.0,
    )


def _fd_command(
    value: Any, roster: tuple[dict[str, Any], ...], label: str
) -> tuple[dict[str, Any], int]:
    command = _command(value, label, role="performance-file-descriptors")
    pids = sorted(process["pid"] for process in roster)
    if command["argv"] != (
        "/usr/sbin/lsof",
        "-nP",
        "-a",
        "-p",
        ",".join(str(pid) for pid in pids),
    ):
        raise PerformanceLedgerError(f"{label}.argv differs from the fixed lsof query")
    lines = [line for line in command["stdout"].splitlines() if line.strip()]
    if not lines or lines[0].split()[:2] != ["COMMAND", "PID"]:
        raise PerformanceLedgerError(f"{label}.stdout lacks the lsof header")
    for index, line in enumerate(lines[1:], start=1):
        fields = line.split()
        if len(fields) < 2:
            raise PerformanceLedgerError(f"{label}.stdout[{index}] is malformed")
        try:
            pid = int(fields[1])
        except ValueError as error:
            raise PerformanceLedgerError(f"{label}.stdout[{index}] PID is invalid") from error
        if pid not in pids:
            raise PerformanceLedgerError(f"{label}.stdout contains an unexpected PID")
    return command, len(lines) - 1


def _diagnostic_command(value: Any, label: str) -> tuple[dict[str, Any], list[str]]:
    command = _command(value, label, role="performance-diagnostic-inventory")
    argv = command["argv"]
    if (
        len(argv) != 16
        or argv[0:3]
        != ("/usr/bin/find", "-s", "/Library/Logs/DiagnosticReports")
        or re.fullmatch(r"/Users/[^/]+/Library/Logs/DiagnosticReports", argv[3]) is None
        or argv[4:]
        != (
            "-maxdepth",
            "1",
            "-type",
            "f",
            "(",
            "-iname",
            "*clash*",
            "-o",
            "-iname",
            "*cfw*",
            ")",
            "-print",
        )
    ):
        raise PerformanceLedgerError(f"{label}.argv differs from the fixed crash inventory")
    paths = [line for line in command["stdout"].splitlines() if line]
    if paths != sorted(set(paths)) or len(paths) > MAX_CRASH_PATHS:
        raise PerformanceLedgerError(f"{label}.stdout crash paths are not unique/sorted")
    roots = tuple(argv[2:4])
    for path in paths:
        candidate = PurePosixPath(path)
        if not candidate.is_absolute() or not any(
            candidate.parent == PurePosixPath(root) for root in roots
        ):
            raise PerformanceLedgerError(f"{label}.stdout contains an out-of-root path")
    return command, paths


def _crash_log_command(value: Any, label: str) -> tuple[dict[str, Any], list[Any]]:
    command = _command(value, label, role="performance-crash-log")
    argv = command["argv"]
    if (
        len(argv) != 13
        or argv[:7]
        != (
            "/usr/bin/log",
            "show",
            "--style",
            "ndjson",
            "--info",
            "--timezone",
            "UTC",
        )
        or argv[7] != "--start"
        or argv[9] != "--end"
        or argv[11:] != ("--predicate", CRASH_LOG_PREDICATE)
    ):
        raise PerformanceLedgerError(f"{label}.argv differs from the fixed crash-log query")
    start = _log_query_timestamp(argv[8], f"{label}.argv.start")
    end = _log_query_timestamp(argv[10], f"{label}.argv.end")
    if not start <= end <= command["completed_at"]:
        raise PerformanceLedgerError(f"{label} window is not causal")
    entries = [
        _strict_json(line, f"{label}.stdout[{index}]")
        for index, line in enumerate(command["stdout"].splitlines())
        if line.strip()
    ]
    if any(not isinstance(entry, dict) for entry in entries):
        raise PerformanceLedgerError(f"{label}.stdout contains a non-object entry")
    return command, entries


def _measurement(
    value: Any,
    *,
    kind: str,
    roster: tuple[dict[str, Any], ...],
    sample_monotonic_ns: int,
    shaping: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    if kind in {"connect-start", "connect-end", "disconnect-start", "disconnect-end"}:
        measurement = exact_object(value, {"pair_index"}, label)
        index = measurement["pair_index"]
        if type(index) is not int or not 0 <= index < SERIES_SAMPLE_COUNT:
            raise PerformanceLedgerError(f"{label}.pair_index is invalid")
        return {"index": index, "commands": []}
    if kind in {"network-baseline", "network-measured", "soak-traffic"}:
        index_field = "index" if kind == "soak-traffic" else "pair_index"
        fields = {index_field, "command", "base_rtt_ms", "download_mbps"}
        measurement = exact_object(value, fields, label)
        maximum = SOAK_TRAFFIC_COUNT if kind == "soak-traffic" else SERIES_SAMPLE_COUNT
        index = measurement[index_field]
        if type(index) is not int or not 0 <= index < maximum:
            raise PerformanceLedgerError(f"{label}.{index_field} is invalid")
        command, rtt, throughput = _network_quality(measurement["command"], f"{label}.command")
        if not math.isclose(
            _number(measurement["base_rtt_ms"], f"{label}.base_rtt_ms"),
            rtt,
            rel_tol=0.0,
            abs_tol=1e-12,
        ) or not math.isclose(
            _number(measurement["download_mbps"], f"{label}.download_mbps"),
            throughput,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise PerformanceLedgerError(f"{label} differs from networkQuality JSON")
        return {
            "index": index,
            "base_rtt_ms": rtt,
            "download_mbps": throughput,
            "commands": [command],
        }
    if kind == "resource":
        measurement = exact_object(
            value, {"index", "command", "cpu_percent", "rss_mib"}, label
        )
        index = measurement["index"]
        if type(index) is not int or not 0 <= index < SERIES_SAMPLE_COUNT:
            raise PerformanceLedgerError(f"{label}.index is invalid")
        command, cpu, rss = _resource_command(
            measurement["command"], roster, f"{label}.command"
        )
        if not math.isclose(
            _number(measurement["cpu_percent"], f"{label}.cpu_percent"),
            cpu,
            rel_tol=0.0,
            abs_tol=1e-12,
        ) or not math.isclose(
            _number(measurement["rss_mib"], f"{label}.rss_mib"),
            rss,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise PerformanceLedgerError(f"{label} differs from fixed ps output")
        return {"index": index, "cpu_percent": cpu, "rss_mib": rss, "commands": [command]}
    if kind == "weak-recovery":
        measurement = exact_object(
            value,
            {
                "transaction_index",
                "profile_id",
                "command",
                "base_rtt_ms",
                "download_mbps",
            },
            label,
        )
        index = measurement["transaction_index"]
        transactions = shaping["restoration"]["transactions"]
        if type(index) is not int or not 0 <= index < len(transactions):
            raise PerformanceLedgerError(f"{label}.transaction_index is invalid")
        transaction = transactions[index]
        if measurement["profile_id"] != transaction["profile_id"]:
            raise PerformanceLedgerError(f"{label} profile differs from its shaping transaction")
        if sample_monotonic_ns <= transaction["restored_monotonic_ns"]:
            raise PerformanceLedgerError(f"{label} recovery probe predates restoration")
        command, rtt, throughput = _network_quality(measurement["command"], f"{label}.command")
        if command["started_at"] < transaction["completed_at"]:
            raise PerformanceLedgerError(f"{label} traffic probe predates restoration query")
        if not math.isclose(
            _number(measurement["base_rtt_ms"], f"{label}.base_rtt_ms"),
            rtt,
            rel_tol=0.0,
            abs_tol=1e-12,
        ) or not math.isclose(
            _number(measurement["download_mbps"], f"{label}.download_mbps"),
            throughput,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise PerformanceLedgerError(f"{label} differs from networkQuality JSON")
        recovery_ms = (sample_monotonic_ns - transaction["restored_monotonic_ns"]) / 1_000_000
        return {
            "index": index,
            "profile_id": transaction["profile_id"],
            "recovery_ms": recovery_ms,
            "commands": [command],
        }
    if kind == "switch":
        measurement = exact_object(
            value,
            {
                "index",
                "resource_command",
                "fd_command",
                "cpu_percent",
                "rss_mib",
                "fd_count",
            },
            label,
        )
        index = measurement["index"]
        if type(index) is not int or not 0 <= index < SWITCH_SAMPLE_COUNT:
            raise PerformanceLedgerError(f"{label}.index is invalid")
        resource_command, cpu, rss = _resource_command(
            measurement["resource_command"], roster, f"{label}.resource_command"
        )
        fd_command, fd_count = _fd_command(
            measurement["fd_command"], roster, f"{label}.fd_command"
        )
        _ordered_commands([resource_command, fd_command], label)
        if (
            not math.isclose(
                _number(measurement["cpu_percent"], f"{label}.cpu_percent"),
                cpu,
                rel_tol=0.0,
                abs_tol=1e-12,
            )
            or not math.isclose(
                _number(measurement["rss_mib"], f"{label}.rss_mib"),
                rss,
                rel_tol=0.0,
                abs_tol=1e-12,
            )
            or type(measurement["fd_count"]) is not int
            or measurement["fd_count"] != fd_count
        ):
            raise PerformanceLedgerError(f"{label} differs from fixed ps/lsof output")
        return {
            "index": index,
            "cpu_percent": cpu,
            "rss_mib": rss,
            "fd_count": fd_count,
            "commands": [resource_command, fd_command],
        }
    if kind == "soak-heartbeat":
        measurement = exact_object(value, {"index"}, label)
        index = measurement["index"]
        if type(index) is not int or not 0 <= index < SOAK_HEARTBEAT_COUNT:
            raise PerformanceLedgerError(f"{label}.index is invalid")
        return {"index": index, "commands": []}
    if kind in {"crash-baseline", "crash-final"}:
        measurement = exact_object(
            value,
            {
                "stage",
                "diagnostic_command",
                "crash_log_command",
                "diagnostic_paths",
                "crash_log_entries",
            },
            label,
        )
        expected_stage = kind.removeprefix("crash-")
        if measurement["stage"] != expected_stage:
            raise PerformanceLedgerError(f"{label}.stage differs from sample kind")
        diagnostic_command, paths = _diagnostic_command(
            measurement["diagnostic_command"], f"{label}.diagnostic_command"
        )
        crash_command, entries = _crash_log_command(
            measurement["crash_log_command"], f"{label}.crash_log_command"
        )
        _ordered_commands([diagnostic_command, crash_command], label)
        if measurement["diagnostic_paths"] != paths or measurement[
            "crash_log_entries"
        ] != entries:
            raise PerformanceLedgerError(f"{label} crash declarations differ from command bytes")
        return {
            "stage": expected_stage,
            "paths": paths,
            "entries": entries,
            "crash_window": (
                _log_query_timestamp(
                    crash_command["argv"][8], f"{label}.crash_window.start"
                ),
                _log_query_timestamp(
                    crash_command["argv"][10], f"{label}.crash_window.end"
                ),
            ),
            "commands": [diagnostic_command, crash_command],
        }
    raise PerformanceLedgerError(f"{label} has unsupported sample kind {kind!r}")


def _sample(
    value: Any,
    *,
    expected_sequence: int,
    candidate: dict[str, Any],
    signing: dict[str, dict[str, Any]],
    shaping: dict[str, Any],
) -> dict[str, Any]:
    label = f"performance ledger.samples[{expected_sequence}]"
    sample = exact_object(value, SAMPLE_FIELDS, label)
    if sample["sequence"] != expected_sequence:
        raise PerformanceLedgerError("performance sample sequence is not contiguous")
    kind = sample["kind"]
    if kind not in _SAMPLE_COUNTS:
        raise PerformanceLedgerError(f"{label}.kind is unsupported")
    wall_time = _timestamp(sample["wall_time"], f"{label}.wall_time")
    monotonic_ns = _positive_int(sample["monotonic_ns"], f"{label}.monotonic_ns")
    observation = _product_observation(
        sample["state_observation"], candidate=candidate, label=f"{label}.state_observation"
    )
    state = observation["state"]
    mode = state["desired_mode"]
    if (
        sample["generation"] != state["generation"]
        or sample["mode"] != mode
        or sample["terminal_state"] != state["phase"]
        or sample["operation_id"] != operation_id(observation)
    ):
        raise PerformanceLedgerError(f"{label} operation/generation/mode/terminal state drifted")
    roster, discovery_commands, roster_command, runtime_signing_commands = _roster(
        sample["roster"],
        sample["roster_discovery_commands"],
        sample["roster_command"],
        mode=mode,
        observation=observation,
        signing=signing,
        label=f"{label}.roster",
    )
    if observation["query"]["completed_at"] > roster_command["started_at"]:
        raise PerformanceLedgerError(f"{label} roster was not observed after product state")
    if wall_time != runtime_signing_commands[-1]["completed_at"]:
        raise PerformanceLedgerError(f"{label}.wall_time differs from signed roster completion")
    measurement = _measurement(
        sample["measurement"],
        kind=kind,
        roster=roster,
        sample_monotonic_ns=monotonic_ns,
        shaping=shaping,
        label=f"{label}.measurement",
    )
    for command in measurement["commands"]:
        if command["completed_at"] > observation["query"]["started_at"]:
            raise PerformanceLedgerError(f"{label} measurement was not followed by state/roster")
    discovery_end = (
        _ordered_commands(discovery_commands, f"{label}.roster discovery")[1]
        if discovery_commands
        else None
    )
    next_start = (
        measurement["commands"][0]["started_at"]
        if measurement["commands"]
        else observation["query"]["started_at"]
    )
    discovery_after_state = bool(discovery_commands) and (
        discovery_commands[0]["started_at"] >= observation["query"]["completed_at"]
        and discovery_end is not None
        and discovery_end <= roster_command["started_at"]
    )
    if (
        discovery_end is not None
        and discovery_end > next_start
        and not discovery_after_state
    ):
        raise PerformanceLedgerError(
            f"{label} owner discovery was neither before measurement nor after state"
        )
    return {
        "sequence": expected_sequence,
        "kind": kind,
        "wall_time": wall_time,
        "monotonic_ns": monotonic_ns,
        "operation_id": sample["operation_id"],
        "generation": sample["generation"],
        "mode": mode,
        "terminal_state": sample["terminal_state"],
        "event_sequence": observation["event_sequence"],
        "event_sha256": observation["event_sha256"],
        "event_mach_timestamp": observation["mach_timestamp"],
        "host_process": observation["process"],
        "roster": roster,
        "measurement": measurement,
    }


def _indexed_samples(
    grouped: dict[str, list[dict[str, Any]]], kind: str, count: int
) -> list[dict[str, Any]]:
    samples = sorted(grouped[kind], key=lambda sample: sample["measurement"]["index"])
    if [sample["measurement"]["index"] for sample in samples] != list(range(count)):
        raise PerformanceLedgerError(f"performance {kind} indices are not exact/contiguous")
    return samples


def _same_roster(
    left: tuple[dict[str, Any], ...], right: tuple[dict[str, Any], ...]
) -> bool:
    def stable(process: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in process.items()
            if key not in {"product_event_sha256", "runtime_signing_command"}
        }

    return tuple(stable(process) for process in left) == tuple(
        stable(process) for process in right
    )


def _validate_sample_timeline(samples: list[dict[str, Any]]) -> None:
    if not samples:
        raise PerformanceLedgerError("performance sample ledger is empty")
    first_host = samples[0]["host_process"]
    previous = samples[0]
    pid_identities: dict[int, tuple[Any, ...]] = {}
    for sample in samples:
        if sample["host_process"] != first_host:
            raise PerformanceLedgerError("Host restarted during one performance ledger")
        if sample["event_sequence"] < previous["event_sequence"]:
            raise PerformanceLedgerError("signed product event sequence regressed")
        if sample["event_mach_timestamp"] < previous["event_mach_timestamp"]:
            raise PerformanceLedgerError("signed product mach timestamp regressed")
        if sample["generation"] < previous["generation"]:
            raise PerformanceLedgerError("performance generation regressed")
        if sample is not samples[0]:
            wall_delta = (sample["wall_time"] - previous["wall_time"]).total_seconds()
            monotonic_delta = (
                sample["monotonic_ns"] - previous["monotonic_ns"]
            ) / 1_000_000_000
            if (
                wall_delta < 0
                or monotonic_delta <= 0
                or abs(wall_delta - monotonic_delta) > INTERVAL_TOLERANCE_SECONDS
            ):
                raise PerformanceLedgerError(
                    "performance wall and monotonic sample timelines disagree"
                )
        for process in sample["roster"]:
            identity = (
                process["component"],
                process["start_time"],
                process["executable"],
                process["team_id"],
                process["signing_identifier"],
                process["cdhash"],
                process["designated_requirement_sha256"],
            )
            existing = pid_identities.setdefault(process["pid"], identity)
            if existing != identity:
                raise PerformanceLedgerError("performance roster contains PID reuse")
        previous = sample


def _transition_series(grouped: dict[str, list[dict[str, Any]]]) -> dict[str, list[float]]:
    connect_start = _indexed_samples(grouped, "connect-start", SERIES_SAMPLE_COUNT)
    connect_end = _indexed_samples(grouped, "connect-end", SERIES_SAMPLE_COUNT)
    disconnect_start = _indexed_samples(grouped, "disconnect-start", SERIES_SAMPLE_COUNT)
    disconnect_end = _indexed_samples(grouped, "disconnect-end", SERIES_SAMPLE_COUNT)
    connect_ms: list[float] = []
    disconnect_ms: list[float] = []
    for index in range(SERIES_SAMPLE_COUNT):
        start = connect_start[index]
        connected = connect_end[index]
        stopping = disconnect_start[index]
        ended = disconnect_end[index]
        if (
            start["mode"] != "off"
            or connected["mode"] != "tunnel"
            or stopping["mode"] != "tunnel"
            or ended["mode"] != "off"
            or not start["monotonic_ns"] < connected["monotonic_ns"]
            <= stopping["monotonic_ns"] < ended["monotonic_ns"]
            or connected["generation"] <= start["generation"]
            or stopping["generation"] != connected["generation"]
            or stopping["operation_id"] != connected["operation_id"]
            or ended["generation"] <= stopping["generation"]
        ):
            raise PerformanceLedgerError(
                f"performance transition pair {index} is not an exact Off/Tunnel cycle"
            )
        if index and start["operation_id"] != disconnect_end[index - 1]["operation_id"]:
            raise PerformanceLedgerError(
                f"performance transition pair {index} does not continue restored Off"
            )
        connect_ms.append(
            (connected["monotonic_ns"] - start["monotonic_ns"]) / 1_000_000
        )
        disconnect_ms.append(
            (ended["monotonic_ns"] - stopping["monotonic_ns"]) / 1_000_000
        )
    return {"connect_ms": connect_ms, "disconnect_ms": disconnect_ms}


def _network_series(grouped: dict[str, list[dict[str, Any]]]) -> dict[str, list[float]]:
    baseline = _indexed_samples(grouped, "network-baseline", SERIES_SAMPLE_COUNT)
    measured = _indexed_samples(grouped, "network-measured", SERIES_SAMPLE_COUNT)
    baseline_mbps: list[float] = []
    measured_mbps: list[float] = []
    added_latency: list[float] = []
    for index, (proxy, tunnel) in enumerate(zip(baseline, measured, strict=True)):
        if (
            proxy["mode"] != "system_proxy"
            or tunnel["mode"] != "tunnel"
            or tunnel["monotonic_ns"] <= proxy["monotonic_ns"]
            or tunnel["generation"] <= proxy["generation"]
        ):
            raise PerformanceLedgerError(f"performance network pair {index} state is invalid")
        base_rtt = proxy["measurement"]["base_rtt_ms"]
        measured_rtt = tunnel["measurement"]["base_rtt_ms"]
        baseline_mbps.append(proxy["measurement"]["download_mbps"])
        measured_mbps.append(tunnel["measurement"]["download_mbps"])
        added_latency.append(max(0.0, 100.0 * (measured_rtt - base_rtt) / base_rtt))
    return {
        "baseline_mbps": baseline_mbps,
        "measured_mbps": measured_mbps,
        "added_latency_percent": added_latency,
    }


def _resource_series(grouped: dict[str, list[dict[str, Any]]]) -> dict[str, list[float]]:
    samples = _indexed_samples(grouped, "resource", SERIES_SAMPLE_COUNT)
    if any(sample["mode"] != "tunnel" for sample in samples):
        raise PerformanceLedgerError("performance resource samples are not active Tunnel")
    return {
        "active_idle_cpu_percent": [
            sample["measurement"]["cpu_percent"] for sample in samples
        ],
        "active_rss_mib": [sample["measurement"]["rss_mib"] for sample in samples],
    }


def _weak_series(grouped: dict[str, list[dict[str, Any]]]) -> dict[str, list[float]]:
    samples = _indexed_samples(
        grouped, "weak-recovery", SERIES_SAMPLE_COUNT * len(WEAK_NETWORK_PROFILES)
    )
    result = {profile_id: [] for profile_id in WEAK_NETWORK_PROFILES}
    expected_profiles = [
        profile_id
        for profile_id in sorted(WEAK_NETWORK_PROFILES)
        for _ in range(SERIES_SAMPLE_COUNT)
    ]
    for index, sample in enumerate(samples):
        profile_id = expected_profiles[index]
        if sample["mode"] != "tunnel" or sample["measurement"]["profile_id"] != profile_id:
            raise PerformanceLedgerError(f"performance weak recovery {index} state/profile is invalid")
        result[profile_id].append(sample["measurement"]["recovery_ms"])
    return result


def _switch_series(grouped: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    samples = _indexed_samples(grouped, "switch", SWITCH_SAMPLE_COUNT)
    previous: dict[str, Any] | None = None
    for index, sample in enumerate(samples):
        expected_mode = "system_proxy" if index % 2 == 0 else "tunnel"
        if sample["mode"] != expected_mode or (
            previous is not None and sample["generation"] <= previous["generation"]
        ):
            raise PerformanceLedgerError(
                f"performance switch[{index}] did not reach its exact next terminal mode"
            )
        previous = sample
    rss = [sample["measurement"]["rss_mib"] for sample in samples]
    fds = [sample["measurement"]["fd_count"] for sample in samples]
    return {
        "switch_count": len(samples) - 1,
        "rss_growth_mib": max(rss) - rss[0],
        "fd_growth": max(fds) - fds[0],
        "records": [
            {"index": index, "rss_mib": rss[index], "fd_count": fds[index]}
            for index in range(len(samples))
        ],
    }


def _fixed_intervals(
    samples: list[dict[str, Any]],
    *,
    interval_seconds: int,
    tolerance_seconds: int,
    label: str,
) -> None:
    for previous, current in zip(samples, samples[1:]):
        delta = (current["monotonic_ns"] - previous["monotonic_ns"]) / 1_000_000_000
        if abs(delta - interval_seconds) > tolerance_seconds:
            raise PerformanceLedgerError(f"{label} fixed interval is missing or delayed")


def _soak(
    grouped: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    heartbeats = _indexed_samples(grouped, "soak-heartbeat", SOAK_HEARTBEAT_COUNT)
    traffic = _indexed_samples(grouped, "soak-traffic", SOAK_TRAFFIC_COUNT)
    baseline = grouped["crash-baseline"][0]
    final = grouped["crash-final"][0]
    _fixed_intervals(
        heartbeats,
        interval_seconds=SOAK_HEARTBEAT_INTERVAL_SECONDS,
        tolerance_seconds=INTERVAL_TOLERANCE_SECONDS,
        label="soak heartbeat",
    )
    _fixed_intervals(
        traffic,
        interval_seconds=SOAK_TRAFFIC_INTERVAL_SECONDS,
        tolerance_seconds=TRAFFIC_INTERVAL_TOLERANCE_SECONDS,
        label="soak traffic",
    )
    reference = heartbeats[0]
    soak_identity = (
        reference["operation_id"],
        reference["generation"],
        reference["mode"],
        reference["terminal_state"],
    )
    for sample in [*heartbeats, *traffic, baseline, final]:
        identity = (
            sample["operation_id"],
            sample["generation"],
            sample["mode"],
            sample["terminal_state"],
        )
        if (
            identity != soak_identity
            or sample["mode"] != "tunnel"
            or not _same_roster(sample["roster"], reference["roster"])
        ):
            raise PerformanceLedgerError("soak samples do not retain one live signed operation")
    duration_ns = heartbeats[-1]["monotonic_ns"] - heartbeats[0]["monotonic_ns"]
    if duration_ns < SOAK_DURATION_SECONDS * 1_000_000_000:
        raise PerformanceLedgerError("soak heartbeat continuity is shorter than three hours")
    if (
        traffic[0]["monotonic_ns"] < heartbeats[0]["monotonic_ns"]
        or traffic[-1]["monotonic_ns"] > heartbeats[-1]["monotonic_ns"]
        or baseline["monotonic_ns"] > heartbeats[0]["monotonic_ns"]
        or final["monotonic_ns"] < heartbeats[-1]["monotonic_ns"]
    ):
        raise PerformanceLedgerError("soak traffic/crash boundaries do not cover the heartbeat span")
    baseline_crash = baseline["measurement"]
    final_crash = final["measurement"]
    if (
        baseline_crash["paths"] != final_crash["paths"]
        or baseline_crash["entries"]
        or final_crash["entries"]
        or baseline_crash["crash_window"][1] > heartbeats[0]["wall_time"]
        or final_crash["crash_window"][0] > heartbeats[0]["wall_time"]
        or final_crash["crash_window"][1] < heartbeats[-1]["wall_time"]
    ):
        raise PerformanceLedgerError("DiagnosticReports/crash-log soak delta is not empty and covering")
    return {
        "started_at": heartbeats[0]["wall_time"],
        "ended_at": heartbeats[-1]["wall_time"],
        "duration_hours": duration_ns / 3_600_000_000_000,
        "heartbeat_count": len(heartbeats),
        "traffic_count": len(traffic),
        "crash_count": 0,
    }


def _command_observer_hashes(*documents: Any) -> dict[str, str]:
    hashes: dict[str, str] = {}

    def visit(value: Any, label: str) -> None:
        if isinstance(value, dict):
            if set(value) == COMMAND_FIELDS:
                command = _command(value, label)
                executable = command["argv"][0]
                existing = hashes.setdefault(
                    executable, command["observer_executable_sha256"]
                )
                if existing != command["observer_executable_sha256"]:
                    raise PerformanceLedgerError(
                        f"observer executable identity changed for {executable}"
                    )
                return
            for key, item in value.items():
                visit(item, f"{label}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{label}[{index}]")

    for index, document in enumerate(documents):
        visit(document, f"performance document[{index}]")
    return hashes


def validate_performance_ledger(
    value: Any,
    *,
    artifacts: ArtifactReader,
) -> dict[str, Any]:
    """Validate and derive a performance result from three proof-free artifacts."""

    try:
        ledger = exact_object(value, LEDGER_FIELDS, "performance sample ledger")
        if (
            type(ledger["schema_version"]) is not int
            or ledger["schema_version"] != LEDGER_SCHEMA_VERSION
            or ledger["document"] != LEDGER_DOCUMENT
            or type(ledger["heartbeat_interval_seconds"]) is not int
            or ledger["heartbeat_interval_seconds"]
            != SOAK_HEARTBEAT_INTERVAL_SECONDS
            or type(ledger["traffic_interval_seconds"]) is not int
            or ledger["traffic_interval_seconds"] != SOAK_TRAFFIC_INTERVAL_SECONDS
        ):
            raise PerformanceLedgerError("performance sample ledger source contract drifted")
        candidate = _candidate(ledger["candidate"])
        run = _run(ledger["run"])
        parameters = _parameters(ledger["parameters"], run)
        signing_values = ledger["signing_observations"]
        expected_components = tuple(sorted(COMPONENT_IDENTITIES))
        if not isinstance(signing_values, list) or len(signing_values) != len(
            expected_components
        ):
            raise PerformanceLedgerError("performance signing observations are incomplete")
        signing_items = tuple(
            _signing_observation(value, f"performance signing_observations[{index}]")
            for index, value in enumerate(signing_values)
        )
        if tuple(item["component"] for item in signing_items) != expected_components:
            raise PerformanceLedgerError("performance signing observation order differs")
        signing = {item["component"]: item for item in signing_items}
        shaping = _shaping(
            ledger["shaping"], artifacts=artifacts, candidate=candidate, run=run
        )
        raw_samples = ledger["samples"]
        expected_count = sum(_SAMPLE_COUNTS.values())
        if not isinstance(raw_samples, list) or len(raw_samples) != expected_count:
            raise PerformanceLedgerError(
                f"performance sample ledger requires exactly {expected_count} samples"
            )
        samples = [
            _sample(
                sample,
                expected_sequence=index,
                candidate=candidate,
                signing=signing,
                shaping=shaping,
            )
            for index, sample in enumerate(raw_samples)
        ]
        grouped = {kind: [] for kind in _SAMPLE_COUNTS}
        for sample in samples:
            grouped[sample["kind"]].append(sample)
        for kind, count in _SAMPLE_COUNTS.items():
            if len(grouped[kind]) != count:
                raise PerformanceLedgerError(
                    f"performance sample ledger requires exactly {count} {kind} samples"
                )
        _validate_sample_timeline(samples)
        latency = _transition_series(grouped)
        network = _network_series(grouped)
        resources = _resource_series(grouped)
        weak_network = _weak_series(grouped)
        switch = _switch_series(grouped)
        soak = _soak(grouped)
        captured_at = _timestamp(ledger["captured_at"], "performance ledger.captured_at")
        completed_at = _timestamp(ledger["completed_at"], "performance ledger.completed_at")
        expected_completed = max(
            samples[-1]["wall_time"], shaping["restoration"]["completed_at"]
        )
        expected_captured = min(
            shaping["intent"]["captured_at"],
            *(item["command"]["started_at"] for item in signing_items),
        )
        if captured_at != expected_captured or completed_at != expected_completed:
            raise PerformanceLedgerError("performance ledger capture bounds are not source-derived")
        if not captured_at < samples[0]["wall_time"] <= completed_at:
            raise PerformanceLedgerError("performance sample bounds are not causal")
        _command_observer_hashes(
            ledger,
            shaping["intent_document"],
            shaping["restoration_document"],
        )
        return {
            "candidate": candidate,
            "run": run,
            "parameters": parameters,
            "captured_at": captured_at,
            "completed_at": completed_at,
            "weak_network": weak_network,
            "latency": {
                **latency,
                "added_latency_percent": network["added_latency_percent"],
            },
            "throughput": {
                "baseline_mbps": network["baseline_mbps"],
                "measured_mbps": network["measured_mbps"],
            },
            "resources": resources,
            "switch_cycle": switch,
            "soak": soak,
            "artifacts": [
                {
                    "subject": SHAPING_INTENT_SUBJECT,
                    "descriptor": shaping["intent_descriptor"],
                },
                {
                    "subject": SHAPING_RESTORATION_SUBJECT,
                    "descriptor": shaping["restoration_descriptor"],
                },
            ],
        }
    except RawArtifactError as error:
        raise PerformanceLedgerError(str(error)) from error
