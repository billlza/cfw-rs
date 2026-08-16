#!/usr/bin/env python3
"""Proof-to-byte signed-installed lifecycle matrix validator.

Each required probe references one raw command/event artifact. The validator
reopens those bytes and recomputes the accepted exit/event sequence; a report
cannot turn a missing, skipped, or failed command into a passing declaration.
Collector authenticity remains an aggregate-level external trust gate.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import ipaddress
import os
from pathlib import Path
import re
from typing import Any, Callable

if __package__:
    from .physical_machine_identity import (
        BOOT_DOCUMENT as BOOT_ENVIRONMENT_SCHEME,
        DOCUMENT as MACHINE_IDENTITY_SCHEME,
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from .packet_capture import (
        ALLOWED_LINK_TYPES,
        PacketCaptureError,
        timestamp_fraction,
        validate_capture_tokens,
    )
    from .raw_artifacts import (
        ArtifactReader,
        RawArtifactError,
        canonical_json,
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
        BOOT_DOCUMENT as BOOT_ENVIRONMENT_SCHEME,
        DOCUMENT as MACHINE_IDENTITY_SCHEME,
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from packet_capture import (  # type: ignore
        ALLOWED_LINK_TYPES,
        PacketCaptureError,
        timestamp_fraction,
        validate_capture_tokens,
    )
    from raw_artifacts import (  # type: ignore
        ArtifactReader,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_file,
        parse_proof_binding,
        require_identifier,
        require_sha256,
    )


SCHEMA_VERSION = 4
HARNESS_VERSION = "lifecycle-matrix-v4"
EVENT_SCHEMA_VERSION = 3
EVENT_DOCUMENT = "cfw-lifecycle-proof-event-v3"
OBSERVATION_SCHEMA_VERSION = 1
OBSERVATION_DOCUMENT = "cfw-lifecycle-observation-v1"
PRODUCT_VERSION = "0.4.0"
REQUIRED_ARCHITECTURE = "arm64"
MAX_REPORT_BYTES = 1 * 1024 * 1024
MACOS_BUILD_RE = re.compile(r"^[0-9]{2}[A-Z][0-9]{1,5}[a-z]?$")
CDHASH_RE = re.compile(r"^[0-9a-f]{40}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,31}$")

TEAM_ID = "YKUPL7Z869"
HOST_SIGNING_IDENTIFIER = "com.bill.clashformac"
PACKET_TUNNEL_IDENTIFIER = "com.bill.clashformac.packet-tunnel"
SYSTEM_EXTENSION_WRAPPER_NAME = f"{PACKET_TUNNEL_IDENTIFIER}.systemextension"
RENDERER_READY_DOCUMENT = "migration-handoff-renderer-ready-v2"
WKWEBVIEW_WIDTH = 850
WKWEBVIEW_HEIGHT = 603


class LifecycleMatrixError(ValueError):
    """The lifecycle evidence is incomplete, drifted, or behaviorally invalid."""


def _positive_int(minimum: int) -> Callable[[Any, str], int]:
    def _check(value: Any, label: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise LifecycleMatrixError(f"{label} must be an integer >= {minimum}")
        return value

    return _check


# (category, expected command exit, terminal observation, attribute checks)
PROBE_SPECS: dict[str, tuple[str, int, str, dict[str, Callable[[Any, str], int]]]] = {
    "inside-out-signatures": ("identity", 0, "identity-verified", {}),
    "team-id": ("identity", 0, "identity-verified", {}),
    "bundle-identifiers": ("identity", 0, "identity-verified", {}),
    "entitlements": ("identity", 0, "identity-verified", {}),
    "provisioning": ("identity", 0, "identity-verified", {}),
    "daemon-registration-approval": ("daemon", 0, "approval-observed", {}),
    "daemon-registration-denial": ("daemon", 77, "denial-observed", {}),
    "system-extension-approval": ("system-extension", 0, "approval-observed", {}),
    "system-extension-pending": ("system-extension", 0, "pending-observed", {}),
    "system-extension-restart": ("system-extension", 0, "restart-observed", {}),
    "network-extension-approval": ("network-extension", 0, "approval-observed", {}),
    "network-extension-denial": ("network-extension", 77, "denial-observed", {}),
    "network-extension-pending": ("network-extension", 0, "pending-observed", {}),
    "renderer-ready-v2": ("migration", 0, "ordered-ready-observed", {}),
    "upgrade": ("packaging", 0, "transition-observed", {}),
    "replacement": ("packaging", 0, "transition-observed", {}),
    "downgrade-refusal": ("packaging", 77, "denial-observed", {}),
    "install-cleanup": ("packaging", 0, "cleanup-observed", {}),
    "uninstall-cleanup": ("packaging", 0, "cleanup-observed", {}),
    "login": ("session", 0, "transition-observed", {}),
    "logout": ("session", 0, "transition-observed", {}),
    "lock": ("session", 0, "transition-observed", {}),
    "fast-user-switching": (
        "session",
        0,
        "transition-observed",
        {"user_count": _positive_int(2)},
    ),
    "concurrent-starts": (
        "concurrency",
        0,
        "serialization-observed",
        {"concurrent_start_count": _positive_int(2)},
    ),
    "cancellation": ("concurrency", 0, "cancellation-observed", {}),
    "sleep-wake": ("power", 0, "recovery-observed", {}),
    "wkwebview-850x603": ("visual", 0, "pixel-buffer-observed", {}),
    "reboot-recovery": ("power", 0, "recovery-observed", {}),
    "host-crash": ("crash", 0, "recovery-observed", {}),
    "global-authority-crash": ("crash", 0, "recovery-observed", {}),
    "proxy-agent-crash": ("crash", 0, "recovery-observed", {}),
    "provider-crash": ("crash", 0, "recovery-observed", {}),
}

IDENTITY_PROBE_IDS = (
    "inside-out-signatures",
    "team-id",
    "bundle-identifiers",
    "entitlements",
    "provisioning",
)
if {
    probe_id for probe_id, spec in PROBE_SPECS.items() if spec[0] == "identity"
} != set(IDENTITY_PROBE_IDS):
    raise RuntimeError("lifecycle identity probe contract drifted")

IDENTITY_FINAL_BUILD = "40005"
IDENTITY_OBSERVATION_DOCUMENT = "cfw-physical-identity-observation-v2"
IDENTITY_OBSERVATION_SCHEMA_VERSION = 2
IDENTITY_OBSERVATION_MAXIMUM_BYTES = 1024 * 1024
IDENTITY_VERIFIER_OUTPUT_LIMIT = 384 * 1024
IDENTITY_VERIFIER_ROLE = "release-identity-verifier"
IDENTITY_FIXED_COMMAND = (
    "scripts/verify_release_app.sh",
    "target/candidates/0.4.0/signed/Clash for Mac.app",
    "target/candidates/0.4.0/release-build/40005/native-products",
)
IDENTITY_FIXED_COMMAND_SHA256 = hashlib.sha256(
    canonical_json(list(IDENTITY_FIXED_COMMAND))
).hexdigest()
IDENTITY_OBSERVATION_SUBJECTS = frozenset(
    f"{probe_id}:observation" for probe_id in IDENTITY_PROBE_IDS
)

REQUIRED_PROBES = frozenset(PROBE_SPECS)
OPERATION_FIELDS = {"operation_id", "installation_id", "epoch", "generation"}
ENVIRONMENT_FIELDS = {
    "machine_sha256",
    "machine_identity_scheme",
    "hardware_model",
    "virtualization_present",
    "boot_environment_sha256",
    "boot_environment_scheme",
    "macos_build",
    "architecture",
    "operation_context",
}
PROBE_FIELDS = {"id", "attributes", "artifact"}
OBSERVATION_DOCUMENT_FIELDS = {
    "schema_version",
    "document",
    "candidate",
    "run_id",
    "environment",
    "probe_id",
    "category",
    "command",
    "started_at",
    "finished_at",
    "exit_code",
    "events",
    "attributes",
    "evidence",
}
EVENT_DOCUMENT_FIELDS = {
    "schema_version",
    "document",
    "proof",
    "probe_id",
    "observation_artifact",
}
EVENT_FIELDS = {"sequence", "type", "probe_id", "observation"}
IDENTITY_OBSERVATION_FIELDS = {
    "schema_version",
    "document",
    "batch_sha256",
    "probe_id",
    "candidate",
    "run_id",
    "environment",
    "command",
    "started_at",
    "finished_at",
}
IDENTITY_OBSERVATION_CANDIDATE_FIELDS = {
    "version",
    "build_number",
    "app_manifest_sha256",
    "signed_app_tree_sha256",
    "artifact_hash_manifest_sha256",
    "built_at",
}
IDENTITY_OBSERVATION_COMMAND_FIELDS = {
    "role",
    "command",
    "command_sha256",
    "exit_code",
    "duration_ms",
    "stdout_sha256",
    "stderr_sha256",
    "stdout",
    "stderr",
}

LIFECYCLE_EVENT_SUBJECTS = REQUIRED_PROBES
LIFECYCLE_OBSERVATION_SUBJECTS = frozenset(
    f"{probe_id}:observation" for probe_id in REQUIRED_PROBES
)
LIFECYCLE_SPECIAL_SUBJECTS = frozenset(
    {
        "renderer-ready-v2:trace",
        "network-extension-approval:trace",
        "network-extension-denial:trace",
        "network-extension-pending:trace",
        "sleep-wake:trace",
        "sleep-wake:packet",
        "wkwebview-850x603:metadata",
        "wkwebview-850x603:pixels",
    }
)
EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS = frozenset(
    LIFECYCLE_OBSERVATION_SUBJECTS | LIFECYCLE_SPECIAL_SUBJECTS
)
EXPECTED_LIFECYCLE_RAW_SUBJECTS = frozenset(
    LIFECYCLE_EVENT_SUBJECTS | EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS
)


def expected_lifecycle_raw_kinds(subject: str) -> frozenset[str]:
    """Return the exact artifact kind set for one source-pinned raw subject."""

    if subject not in EXPECTED_LIFECYCLE_RAW_SUBJECTS:
        raise LifecycleMatrixError("lifecycle raw subject is not source-pinned")
    if subject in LIFECYCLE_OBSERVATION_SUBJECTS:
        return frozenset({"lifecycle-observation"})
    if subject == "renderer-ready-v2:trace":
        return frozenset({"renderer-ready-trace"})
    if subject in {
        "network-extension-approval:trace",
        "network-extension-denial:trace",
        "network-extension-pending:trace",
    }:
        return frozenset({"network-extension-trace"})
    if subject == "sleep-wake:trace":
        return frozenset({"sleep-wake-trace"})
    if subject == "sleep-wake:packet":
        return frozenset({"packet-pcap", "packet-pcapng"})
    if subject == "wkwebview-850x603:metadata":
        return frozenset({"wkwebview-metadata"})
    if subject == "wkwebview-850x603:pixels":
        return frozenset({"wkwebview-rgba"})
    if subject in LIFECYCLE_EVENT_SUBJECTS:
        return frozenset({"lifecycle-event"})
    raise LifecycleMatrixError("lifecycle raw subject kind contract drifted")

SPECIAL_EVIDENCE_PROBES = frozenset(
    {
        "renderer-ready-v2",
        "network-extension-approval",
        "network-extension-denial",
        "network-extension-pending",
        "sleep-wake",
        "wkwebview-850x603",
    }
)


def required_probe_ids() -> frozenset[str]:
    return REQUIRED_PROBES


def probe_matrix() -> dict[str, str]:
    return {probe: spec[0] for probe, spec in PROBE_SPECS.items()}


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LifecycleMatrixError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise LifecycleMatrixError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise LifecycleMatrixError(f"{label} must use UTC")
    return parsed


def _operation_context(value: Any, label: str) -> dict[str, Any]:
    context = exact_object(value, OPERATION_FIELDS, label)
    operation_id = require_identifier(context["operation_id"], f"{label}.operation_id")
    installation_id = require_identifier(
        context["installation_id"], f"{label}.installation_id"
    )
    epoch = context["epoch"]
    generation = context["generation"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise LifecycleMatrixError(f"{label}.epoch must be a non-negative integer")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise LifecycleMatrixError(f"{label}.generation must be a positive integer")
    return {
        "operation_id": operation_id,
        "installation_id": installation_id,
        "epoch": epoch,
        "generation": generation,
    }


def _environment(value: Any, label: str = "environment") -> dict[str, Any]:
    environment = exact_object(value, ENVIRONMENT_FIELDS, label)
    machine = require_sha256(environment["machine_sha256"], f"{label}.machine_sha256")
    if environment["machine_identity_scheme"] != MACHINE_IDENTITY_SCHEME:
        raise LifecycleMatrixError(f"{label}.machine_identity_scheme is unsupported")
    try:
        hardware_model = validate_physical_hardware_model(
            environment["hardware_model"]
        )
    except PhysicalMachineIdentityError as error:
        raise LifecycleMatrixError(f"{label}.hardware_model is invalid") from error
    if environment["virtualization_present"] is not False:
        raise LifecycleMatrixError(f"{label} must not be virtualized")
    boot_environment = require_sha256(
        environment["boot_environment_sha256"],
        f"{label}.boot_environment_sha256",
    )
    if environment["boot_environment_scheme"] != BOOT_ENVIRONMENT_SCHEME:
        raise LifecycleMatrixError(f"{label}.boot_environment_scheme is unsupported")
    macos_build = environment["macos_build"]
    if not isinstance(macos_build, str) or not MACOS_BUILD_RE.fullmatch(macos_build):
        raise LifecycleMatrixError(f"{label}.macos_build is not a macOS build identifier")
    if environment["architecture"] != REQUIRED_ARCHITECTURE:
        raise LifecycleMatrixError(f"{label}.architecture must be arm64")
    return {
        "machine_sha256": machine,
        "machine_identity_scheme": MACHINE_IDENTITY_SCHEME,
        "hardware_model": hardware_model,
        "virtualization_present": False,
        "boot_environment_sha256": boot_environment,
        "boot_environment_scheme": BOOT_ENVIRONMENT_SCHEME,
        "macos_build": macos_build,
        "architecture": REQUIRED_ARCHITECTURE,
        "operation_context": _operation_context(
            environment["operation_context"], f"{label}.operation_context"
        ),
    }


_IDENTITY_DIAGNOSTIC_RE = re.compile(
    r"(?i)(?:^|[^a-z])(warnings?|errors?)(?:[^a-z]|$)"
)
_IDENTITY_CODESIGN_PREFIXES = ("--prepared:", "--validated:")
_IDENTITY_CODESIGN_SUFFIXES = (
    ": valid on disk",
    ": satisfies its Designated Requirement",
)


def parse_lifecycle_environment(
    value: Any, label: str = "environment"
) -> dict[str, Any]:
    """Public strict parser shared by pre-nonce lifecycle adapters."""

    return _environment(value, label)


def _identity_verifier_text(value: Any, label: str) -> tuple[str, bytes]:
    if not isinstance(value, str):
        raise LifecycleMatrixError(f"{label} must be UTF-8 text")
    try:
        data = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise LifecycleMatrixError(f"{label} contains invalid Unicode") from error
    if len(data) > IDENTITY_VERIFIER_OUTPUT_LIMIT:
        raise LifecycleMatrixError(f"{label} exceeds its byte bound")
    if "\x00" in value:
        raise LifecycleMatrixError(f"{label} contains a NUL byte")
    if _IDENTITY_DIAGNOSTIC_RE.search(value) is not None:
        raise LifecycleMatrixError(f"{label} contains a warning or error diagnostic")
    return value, data


def _identity_candidate_app(stdout: str) -> str:
    lines = stdout.splitlines()
    prefix = "release app verified: "
    app_lines = [line for line in lines if line.startswith(prefix)]
    if len(app_lines) != 1:
        raise LifecycleMatrixError(
            "identity verifier stdout must contain one release-app success line"
        )
    app = app_lines[0][len(prefix) :]
    expected_suffix = "/" + IDENTITY_FIXED_COMMAND[1]
    if (
        not os.path.isabs(app)
        or os.path.normpath(app) != app
        or not app.endswith(expected_suffix)
        or len(app) == len(expected_suffix)
    ):
        raise LifecycleMatrixError(
            "identity verifier stdout names a non-final candidate path"
        )
    required = {
        (
            "identity: YKUPL7Z869 / com.bill.clashformac / "
            "com.bill.clashformac.packet-tunnel / "
            "com.bill.clashformac.proxy-agent"
        ),
        "platform: arm64 / macOS 15.0+",
        f"build number: {IDENTITY_FINAL_BUILD}",
    }
    for line in required:
        if lines.count(line) != 1:
            raise LifecycleMatrixError(
                "identity verifier stdout is missing a fixed success assertion"
            )
    if any(line.startswith("notarization: pre-submission") for line in lines):
        raise LifecycleMatrixError(
            "identity verifier observation used the pre-notary command mode"
        )
    return app


def _identity_codesign_subject(line: str) -> str | None:
    for prefix in _IDENTITY_CODESIGN_PREFIXES:
        if line.startswith(prefix):
            return line[len(prefix) :]
    for suffix in _IDENTITY_CODESIGN_SUFFIXES:
        if line.endswith(suffix):
            return line[: -len(suffix)]
    return None


def _validate_identity_codesign_stderr(stderr: str, app: str) -> None:
    lines = [line for line in stderr.splitlines() if line]
    for line in lines:
        subject = _identity_codesign_subject(line)
        if (
            subject is None
            or not os.path.isabs(subject)
            or os.path.normpath(subject) != subject
            or (subject != app and not subject.startswith(app + os.sep))
        ):
            raise LifecycleMatrixError(
                "identity verifier stderr contains a non-candidate codesign line"
            )
    for required in (
        f"{app}: valid on disk",
        f"{app}: satisfies its Designated Requirement",
    ):
        if lines.count(required) != 1:
            raise LifecycleMatrixError(
                "identity verifier stderr lacks the final app codesign result"
            )


def _identity_observation_command(value: Any) -> dict[str, Any]:
    command = exact_object(
        value,
        IDENTITY_OBSERVATION_COMMAND_FIELDS,
        "identity observation.command",
    )
    stdout, stdout_bytes = _identity_verifier_text(
        command["stdout"], "identity observation.command.stdout"
    )
    stderr, stderr_bytes = _identity_verifier_text(
        command["stderr"], "identity observation.command.stderr"
    )
    app = _identity_candidate_app(stdout)
    _validate_identity_codesign_stderr(stderr, app)
    stdout_sha256 = require_sha256(
        command["stdout_sha256"], "identity observation.command.stdout_sha256"
    )
    stderr_sha256 = require_sha256(
        command["stderr_sha256"], "identity observation.command.stderr_sha256"
    )
    duration_ms = command["duration_ms"]
    if (
        command["role"] != IDENTITY_VERIFIER_ROLE
        or command["command"] != list(IDENTITY_FIXED_COMMAND)
        or command["command_sha256"] != IDENTITY_FIXED_COMMAND_SHA256
        or type(command["exit_code"]) is not int
        or command["exit_code"] != 0
        or type(duration_ms) is not int
        or duration_ms < 1
        or duration_ms > 600_000
        or hashlib.sha256(stdout_bytes).hexdigest() != stdout_sha256
        or hashlib.sha256(stderr_bytes).hexdigest() != stderr_sha256
    ):
        raise LifecycleMatrixError(
            "identity observation command/output binding differs from the fixed verifier"
        )
    return {
        "role": IDENTITY_VERIFIER_ROLE,
        "command": list(IDENTITY_FIXED_COMMAND),
        "command_sha256": IDENTITY_FIXED_COMMAND_SHA256,
        "exit_code": 0,
        "duration_ms": duration_ms,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "stdout": stdout,
        "stderr": stderr,
    }


def validate_identity_observation(
    value: Any,
    *,
    probe_id: str,
    candidate: dict[str, Any],
    run_id: str,
    environment: dict[str, Any],
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    """Validate one retained pre-nonce identity-verifier observation."""

    if probe_id not in IDENTITY_PROBE_IDS:
        raise LifecycleMatrixError("identity observation probe is not source-pinned")
    raw = exact_object(
        value, IDENTITY_OBSERVATION_FIELDS, f"{probe_id}.identity_observation"
    )
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != IDENTITY_OBSERVATION_SCHEMA_VERSION
        or raw["document"] != IDENTITY_OBSERVATION_DOCUMENT
        or raw["probe_id"] != probe_id
    ):
        raise LifecycleMatrixError("identity observation schema/probe binding differs")
    if raw["run_id"] != require_identifier(
        run_id, f"{probe_id}.identity_observation.expected_run_id"
    ):
        raise LifecycleMatrixError("identity observation run binding differs")
    observed_candidate = exact_object(
        raw["candidate"],
        IDENTITY_OBSERVATION_CANDIDATE_FIELDS,
        f"{probe_id}.identity_observation.candidate",
    )
    proof_candidate = {
        key: observed_candidate[key]
        for key in IDENTITY_OBSERVATION_CANDIDATE_FIELDS
        if key != "built_at"
    }
    if (
        proof_candidate != candidate
        or observed_candidate["version"] != PRODUCT_VERSION
        or observed_candidate["build_number"] != IDENTITY_FINAL_BUILD
    ):
        raise LifecycleMatrixError("identity observation candidate binding differs")
    observed_environment = _environment(
        raw["environment"], f"{probe_id}.identity_observation.environment"
    )
    if observed_environment != environment:
        raise LifecycleMatrixError("identity observation environment binding differs")
    if raw["started_at"] != started_at or raw["finished_at"] != finished_at:
        raise LifecycleMatrixError("identity observation timestamps differ from its event")
    started = _timestamp(started_at, f"{probe_id}.identity_observation.started_at")
    finished = _timestamp(finished_at, f"{probe_id}.identity_observation.finished_at")
    built_at = _timestamp(
        observed_candidate["built_at"],
        f"{probe_id}.identity_observation.candidate.built_at",
    )
    if built_at > started:
        raise LifecycleMatrixError(
            "identity observation predates its complete candidate binding"
        )
    if not 0 < (finished - started).total_seconds() <= 600:
        raise LifecycleMatrixError("identity observation duration is outside 0..10min")
    command = _identity_observation_command(raw["command"])
    wall_duration_ms = _duration_milliseconds(
        started,
        finished,
        f"{probe_id}.identity_observation timestamps",
    )
    if abs(command["duration_ms"] - wall_duration_ms) > 1:
        raise LifecycleMatrixError(
            "identity observation command duration differs from its timestamps"
        )
    batch_material = {
        "schema_version": IDENTITY_OBSERVATION_SCHEMA_VERSION,
        "document": IDENTITY_OBSERVATION_DOCUMENT,
        "candidate": observed_candidate,
        "run_id": run_id,
        "environment": observed_environment,
        "command": command,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    batch_sha256 = hashlib.sha256(canonical_json(batch_material)).hexdigest()
    if raw["batch_sha256"] != batch_sha256:
        raise LifecycleMatrixError("identity observation batch digest differs")
    return {
        **batch_material,
        "batch_sha256": batch_sha256,
        "probe_id": probe_id,
    }


def _attributes(value: Any, probe_id: str, label: str) -> dict[str, Any]:
    checks = PROBE_SPECS[probe_id][3]
    attributes = exact_object(value, set(checks), label)
    for key, check in checks.items():
        check(attributes[key], f"{label}.{key}")
    return attributes


def _command(value: Any, collector_version: str, probe_id: str, label: str) -> None:
    expected = [collector_version, "lifecycle", probe_id]
    if value != expected:
        raise LifecycleMatrixError(f"{label} does not match the collector probe command")


def _event_sequence(value: Any, probe_id: str, observation: str, label: str) -> None:
    if not isinstance(value, list) or len(value) != 3:
        raise LifecycleMatrixError(f"{label} must contain start/observation/finish")
    expected = (
        (0, "probe-started", ""),
        (1, "probe-observation", observation),
        (2, "probe-finished", ""),
    )
    for index, (sequence, event_type, expected_observation) in enumerate(expected):
        event = exact_object(value[index], EVENT_FIELDS, f"{label}[{index}]")
        if event != {
            "sequence": sequence,
            "type": event_type,
            "probe_id": probe_id,
            "observation": expected_observation,
        }:
            raise LifecycleMatrixError(f"{label}[{index}] differs from the required sequence")


def _duration_milliseconds(started: datetime, finished: datetime, label: str) -> int:
    duration = finished - started
    microseconds = (
        duration.days * 86_400_000_000
        + duration.seconds * 1_000_000
        + duration.microseconds
    )
    if microseconds <= 0 or microseconds % 1_000:
        raise LifecycleMatrixError(f"{label} must be a positive whole-millisecond duration")
    return microseconds // 1_000


def _unix_microseconds(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=value.tzinfo)
    delta = value - epoch
    return (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )


def _bounded_positive_int(
    value: Any, label: str, *, maximum: int = 2**63 - 1
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > maximum
    ):
        raise LifecycleMatrixError(f"{label} must be a bounded positive integer")
    return value


def _renderer_process(value: Any, role: str, label: str) -> dict[str, Any]:
    process = exact_object(
        value,
        {
            "role",
            "pid",
            "start_unix_us",
            "team_id",
            "signing_identifier",
            "executable_sha256",
            "cdhash",
            "designated_requirement_sha256",
        },
        label,
    )
    if process["role"] != role:
        raise LifecycleMatrixError(f"{label}.role must be {role!r}")
    if process["team_id"] != TEAM_ID:
        raise LifecycleMatrixError(f"{label}.team_id differs from the release identity")
    if process["signing_identifier"] != HOST_SIGNING_IDENTIFIER:
        raise LifecycleMatrixError(
            f"{label}.signing_identifier differs from the Host identity"
        )
    cdhash = process["cdhash"]
    if not isinstance(cdhash, str) or not CDHASH_RE.fullmatch(cdhash):
        raise LifecycleMatrixError(f"{label}.cdhash is not a lowercase Code Directory hash")
    return {
        "role": role,
        "pid": _bounded_positive_int(
            process["pid"], f"{label}.pid", maximum=2**31 - 1
        ),
        "start_unix_us": _bounded_positive_int(
            process["start_unix_us"], f"{label}.start_unix_us"
        ),
        "team_id": TEAM_ID,
        "signing_identifier": HOST_SIGNING_IDENTIFIER,
        "executable_sha256": require_sha256(
            process["executable_sha256"], f"{label}.executable_sha256"
        ),
        "cdhash": cdhash,
        "designated_requirement_sha256": require_sha256(
            process["designated_requirement_sha256"],
            f"{label}.designated_requirement_sha256",
        ),
    }


def _validate_renderer_ready_evidence(
    value: Any,
    *,
    artifacts: ArtifactReader,
    candidate: dict[str, Any],
    started_at: str,
    finished_at: str,
) -> list[dict[str, Any]]:
    evidence = exact_object(value, {"trace_artifact"}, "renderer-ready-v2.evidence")
    descriptor, trace_value = artifacts.read_json(
        evidence["trace_artifact"],
        expected_kind="renderer-ready-trace",
        label="renderer-ready-v2.trace_artifact",
    )
    trace = exact_object(
        trace_value,
        {
            "schema_version",
            "protocol",
            "candidate_app_tree_sha256",
            "window_label",
            "started_at",
            "completed_at",
            "processes",
            "events",
        },
        "renderer-ready-v2.trace",
    )
    if type(trace["schema_version"]) is not int or trace["schema_version"] != 1:
        raise LifecycleMatrixError("renderer-ready-v2 trace schema_version must be 1")
    if trace["protocol"] != RENDERER_READY_DOCUMENT or trace["window_label"] != "main":
        raise LifecycleMatrixError("renderer-ready-v2 trace protocol/window binding differs")
    if trace["candidate_app_tree_sha256"] != candidate["signed_app_tree_sha256"]:
        raise LifecycleMatrixError("renderer-ready-v2 trace candidate app-tree binding differs")
    if trace["started_at"] != started_at or trace["completed_at"] != finished_at:
        raise LifecycleMatrixError("renderer-ready-v2 trace timestamps differ from its probe")
    trace_started_dt = _timestamp(started_at, "renderer trace started_at")
    trace_finished_dt = _timestamp(finished_at, "renderer trace completed_at")
    trace_started_us = _unix_microseconds(trace_started_dt)
    trace_finished_us = _unix_microseconds(trace_finished_dt)

    processes = trace["processes"]
    if not isinstance(processes, list) or len(processes) != 2:
        raise LifecycleMatrixError("renderer-ready-v2 trace must bind exactly two processes")
    parent = _renderer_process(processes[0], "handoff-parent", "renderer.processes[0]")
    child = _renderer_process(processes[1], "candidate-child", "renderer.processes[1]")
    if parent["pid"] == child["pid"]:
        raise LifecycleMatrixError("renderer-ready-v2 parent and child PIDs are not distinct")
    if not (
        parent["start_unix_us"]
        <= trace_started_us
        < child["start_unix_us"]
        < trace_finished_us
    ):
        raise LifecycleMatrixError(
            "renderer-ready-v2 process starts do not match the parent/child trace window"
        )
    for field in (
        "team_id",
        "signing_identifier",
        "executable_sha256",
        "cdhash",
        "designated_requirement_sha256",
    ):
        if parent[field] != child[field]:
            raise LifecycleMatrixError(
                f"renderer-ready-v2 signed process identities disagree on {field}"
            )

    expected = (
        ("handoff-parent", "parent-identity-verified"),
        ("handoff-parent", "child-spawned"),
        ("candidate-child", "child-identity-verified"),
        ("candidate-child", "native-ready"),
        ("candidate-child", "renderer-challenge-issued"),
        ("candidate-child", "renderer-ready-v2-published"),
        ("handoff-parent", "renderer-ready-v2-consumed"),
        ("handoff-parent", "parent-exit-committed"),
        ("candidate-child", "parent-absence-proven"),
    )
    events = trace["events"]
    if not isinstance(events, list) or len(events) != len(expected):
        raise LifecycleMatrixError("renderer-ready-v2 trace has an incomplete event sequence")
    duration_ms = _duration_milliseconds(
        trace_started_dt,
        trace_finished_dt,
        "renderer-ready-v2 trace",
    )
    previous_offset = -1
    generation: int | None = None
    challenge_sha256: str | None = None
    challenge_indices = {4, 5, 6}
    for index, (expected_role, expected_event) in enumerate(expected):
        event = exact_object(
            events[index],
            {
                "sequence",
                "offset_ms",
                "process_role",
                "event",
                "generation",
                "challenge_sha256",
            },
            f"renderer.events[{index}]",
        )
        offset = event["offset_ms"]
        if (
            event["sequence"] != index
            or event["process_role"] != expected_role
            or event["event"] != expected_event
            or not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset <= previous_offset
            or offset > duration_ms
        ):
            raise LifecycleMatrixError(
                f"renderer.events[{index}] differs from the required ordered sequence"
            )
        previous_offset = offset
        if index in challenge_indices:
            current_generation = _bounded_positive_int(
                event["generation"], f"renderer.events[{index}].generation", maximum=16
            )
            current_challenge = require_sha256(
                event["challenge_sha256"],
                f"renderer.events[{index}].challenge_sha256",
            )
            if generation is None:
                generation = current_generation
                challenge_sha256 = current_challenge
            elif (current_generation, current_challenge) != (
                generation,
                challenge_sha256,
            ):
                raise LifecycleMatrixError(
                    "renderer-ready-v2 challenge changes during publication/consumption"
                )
        elif event["generation"] is not None or event["challenge_sha256"] is not None:
            raise LifecycleMatrixError(
                f"renderer.events[{index}] carries challenge data outside the handshake"
            )
    if events[0]["offset_ms"] != 0 or events[-1]["offset_ms"] != duration_ms:
        raise LifecycleMatrixError("renderer-ready-v2 events do not cover the probe duration")
    return [{"subject": "renderer-ready-v2:trace", "descriptor": descriptor.as_dict()}]


def _network_extension_identity(value: Any, label: str) -> None:
    identity = exact_object(
        value,
        {
            "team_id",
            "host_bundle_id",
            "provider_bundle_id",
            "system_extension_wrapper_name",
            "executable_sha256",
            "cdhash",
            "designated_requirement_sha256",
        },
        label,
    )
    expected = {
        "team_id": TEAM_ID,
        "host_bundle_id": HOST_SIGNING_IDENTIFIER,
        "provider_bundle_id": PACKET_TUNNEL_IDENTIFIER,
        "system_extension_wrapper_name": SYSTEM_EXTENSION_WRAPPER_NAME,
    }
    for field, expected_value in expected.items():
        if identity[field] != expected_value:
            raise LifecycleMatrixError(f"{label}.{field} differs from the release identity")
    require_sha256(identity["executable_sha256"], f"{label}.executable_sha256")
    if not isinstance(identity["cdhash"], str) or not CDHASH_RE.fullmatch(identity["cdhash"]):
        raise LifecycleMatrixError(f"{label}.cdhash is not a lowercase Code Directory hash")
    require_sha256(
        identity["designated_requirement_sha256"],
        f"{label}.designated_requirement_sha256",
    )


def _validate_network_extension_evidence(
    value: Any,
    *,
    probe_id: str,
    artifacts: ArtifactReader,
    candidate: dict[str, Any],
    started_at: str,
    finished_at: str,
) -> list[dict[str, Any]]:
    evidence = exact_object(value, {"trace_artifact"}, f"{probe_id}.evidence")
    descriptor, trace_value = artifacts.read_json(
        evidence["trace_artifact"],
        expected_kind="network-extension-trace",
        label=f"{probe_id}.trace_artifact",
    )
    trace = exact_object(
        trace_value,
        {
            "schema_version",
            "candidate_app_tree_sha256",
            "probe_id",
            "request_id",
            "started_at",
            "completed_at",
            "extension_identity",
            "events",
        },
        f"{probe_id}.trace",
    )
    if type(trace["schema_version"]) is not int or trace["schema_version"] != 1:
        raise LifecycleMatrixError(f"{probe_id} trace schema_version must be 1")
    if trace["candidate_app_tree_sha256"] != candidate["signed_app_tree_sha256"]:
        raise LifecycleMatrixError(f"{probe_id} candidate app-tree binding differs")
    if trace["probe_id"] != probe_id:
        raise LifecycleMatrixError(f"{probe_id} trace probe binding differs")
    require_identifier(trace["request_id"], f"{probe_id}.trace.request_id")
    if trace["started_at"] != started_at or trace["completed_at"] != finished_at:
        raise LifecycleMatrixError(f"{probe_id} trace timestamps differ from its probe")
    _network_extension_identity(
        trace["extension_identity"], f"{probe_id}.trace.extension_identity"
    )

    states = {
        "network-extension-approval": (
            ("OSSystemExtensionRequest", "request-submitted"),
            ("OSSystemExtensionRequest", "awaiting-user-approval"),
            ("OSSystemExtensionRequest", "extension-activated"),
            ("NEVPNManager", "configuration-enabled"),
        ),
        "network-extension-denial": (
            ("OSSystemExtensionRequest", "request-submitted"),
            ("OSSystemExtensionRequest", "awaiting-user-approval"),
            ("OSSystemExtensionRequest", "user-denied"),
        ),
        "network-extension-pending": (
            ("OSSystemExtensionRequest", "request-submitted"),
            ("OSSystemExtensionRequest", "awaiting-user-approval"),
        ),
    }[probe_id]
    events = trace["events"]
    if not isinstance(events, list) or len(events) != len(states):
        raise LifecycleMatrixError(f"{probe_id} trace has an incomplete typed state sequence")
    duration_ms = _duration_milliseconds(
        _timestamp(started_at, f"{probe_id}.started_at"),
        _timestamp(finished_at, f"{probe_id}.completed_at"),
        f"{probe_id} trace",
    )
    previous_offset = -1
    for index, (source, state) in enumerate(states):
        event = exact_object(
            events[index],
            {"sequence", "offset_ms", "source", "state"},
            f"{probe_id}.events[{index}]",
        )
        offset = event["offset_ms"]
        if (
            event != {
                "sequence": index,
                "offset_ms": offset,
                "source": source,
                "state": state,
            }
            or not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset <= previous_offset
            or offset > duration_ms
        ):
            raise LifecycleMatrixError(
                f"{probe_id}.events[{index}] differs from the required typed state sequence"
            )
        previous_offset = offset
    if events[0]["offset_ms"] != 0:
        raise LifecycleMatrixError(f"{probe_id} state sequence does not start with its probe")
    if probe_id == "network-extension-pending":
        if duration_ms < 30_000 or events[-1]["offset_ms"] >= duration_ms:
            raise LifecycleMatrixError(
                "network-extension-pending requires a bounded 30s non-terminal observation"
            )
    elif events[-1]["offset_ms"] != duration_ms:
        raise LifecycleMatrixError(f"{probe_id} terminal state does not end its probe")
    return [{"subject": f"{probe_id}:trace", "descriptor": descriptor.as_dict()}]


def _sleep_endpoint(value: Any, role: str, label: str) -> dict[str, Any]:
    endpoint = exact_object(value, {"role", "address", "port", "transport"}, label)
    try:
        address = str(ipaddress.ip_address(endpoint["address"]))
    except (TypeError, ValueError) as error:
        raise LifecycleMatrixError(f"{label}.address is invalid") from error
    port = endpoint["port"]
    if (
        endpoint["role"] != role
        or ipaddress.ip_address(address).version != 4
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        or endpoint["transport"] != "tcp"
    ):
        raise LifecycleMatrixError(f"{label} is not a canonical TCP/IPv4 endpoint")
    return {"role": role, "address": address, "port": port, "transport": "tcp"}


def _evidence_token(value: Any, label: str, seen: set[str]) -> bytes:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise LifecycleMatrixError(f"{label} is not a bounded packet token")
    if any(value in existing or existing in value for existing in seen):
        raise LifecycleMatrixError(f"{label} overlaps another sleep/wake token")
    seen.add(value)
    return value.encode("ascii")


def _validate_sleep_wake_evidence(
    value: Any,
    *,
    artifacts: ArtifactReader,
    candidate: dict[str, Any],
    started_at: str,
    finished_at: str,
) -> list[dict[str, Any]]:
    evidence = exact_object(
        value,
        {"trace_artifact", "capture_artifact"},
        "sleep-wake.evidence",
    )
    trace_descriptor, trace_value = artifacts.read_json(
        evidence["trace_artifact"],
        expected_kind="sleep-wake-trace",
        label="sleep-wake.trace_artifact",
    )
    trace = exact_object(
        trace_value,
        {
            "schema_version",
            "probe_id",
            "candidate_app_tree_sha256",
            "interface",
            "endpoints",
            "capture_command_sha256",
            "pre_sleep_send_command_sha256",
            "post_wake_send_command_sha256",
            "capture_sha256",
            "pre_sleep_token",
            "wake_marker_token",
            "post_wake_token",
            "window_end_token",
            "sleep_started_at",
            "wake_observed_at",
            "started_at",
            "completed_at",
            "observation_ms",
            "post_wake_observation_ms",
        },
        "sleep-wake.trace",
    )
    if (
        type(trace["schema_version"]) is not int
        or trace["schema_version"] != 1
        or trace["probe_id"] != "sleep-wake"
    ):
        raise LifecycleMatrixError("sleep-wake trace schema/probe binding differs")
    if trace["candidate_app_tree_sha256"] != candidate["signed_app_tree_sha256"]:
        raise LifecycleMatrixError("sleep-wake candidate app-tree binding differs")
    if trace["started_at"] != started_at or trace["completed_at"] != finished_at:
        raise LifecycleMatrixError("sleep-wake trace timestamps differ from its probe")
    interface = exact_object(
        trace["interface"], {"name", "index", "link_type"}, "sleep-wake.interface"
    )
    if (
        not isinstance(interface["name"], str)
        or not INTERFACE_RE.fullmatch(interface["name"])
        or not interface["name"].startswith("utun")
        or not isinstance(interface["index"], int)
        or isinstance(interface["index"], bool)
        or not 1 <= interface["index"] <= 2**31 - 1
        or not isinstance(interface["link_type"], int)
        or isinstance(interface["link_type"], bool)
        or interface["link_type"] not in ALLOWED_LINK_TYPES
    ):
        raise LifecycleMatrixError("sleep-wake capture interface is invalid")
    endpoints = trace["endpoints"]
    if not isinstance(endpoints, list) or len(endpoints) != 2:
        raise LifecycleMatrixError("sleep-wake endpoints must contain local and remote")
    local = _sleep_endpoint(endpoints[0], "local", "sleep-wake.endpoints[0]")
    remote = _sleep_endpoint(endpoints[1], "remote", "sleep-wake.endpoints[1]")
    if (local["address"], local["port"]) == (remote["address"], remote["port"]):
        raise LifecycleMatrixError("sleep-wake local and remote endpoints must differ")
    command_digests = [
        require_sha256(trace[field], f"sleep-wake.{field}")
        for field in (
            "capture_command_sha256",
            "pre_sleep_send_command_sha256",
            "post_wake_send_command_sha256",
        )
    ]
    if len(set(command_digests)) != len(command_digests):
        raise LifecycleMatrixError("sleep-wake capture/send commands are not independent")
    seen_tokens: set[str] = set()
    pre_sleep = _evidence_token(trace["pre_sleep_token"], "pre_sleep_token", seen_tokens)
    wake_marker = _evidence_token(
        trace["wake_marker_token"], "wake_marker_token", seen_tokens
    )
    post_wake = _evidence_token(trace["post_wake_token"], "post_wake_token", seen_tokens)
    window_end = _evidence_token(
        trace["window_end_token"], "window_end_token", seen_tokens
    )
    capture_descriptor, capture = artifacts.read(
        evidence["capture_artifact"],
        expected_kinds={"packet-pcap", "packet-pcapng"},
        label="sleep-wake.capture_artifact",
    )
    if trace["capture_sha256"] != capture_descriptor.sha256:
        raise LifecycleMatrixError("sleep-wake trace does not bind the capture bytes")
    try:
        full_window = validate_capture_tokens(
            capture,
            capture_descriptor.kind,
            protocol="tcp",
            family="ipv4",
            local_address=local["address"],
            local_port=local["port"],
            remote_address=remote["address"],
            remote_port=remote["port"],
            expected_link_type=interface["link_type"],
            expected_interface_name=interface["name"],
            expected_quic_version=None,
            token=wake_marker,
            start_marker=pre_sleep,
            end_marker=window_end,
            expect_token=True,
            declared_observation_ms=trace["observation_ms"],
        )
        post_wake_window = validate_capture_tokens(
            capture,
            capture_descriptor.kind,
            protocol="tcp",
            family="ipv4",
            local_address=local["address"],
            local_port=local["port"],
            remote_address=remote["address"],
            remote_port=remote["port"],
            expected_link_type=interface["link_type"],
            expected_interface_name=interface["name"],
            expected_quic_version=None,
            token=post_wake,
            start_marker=wake_marker,
            end_marker=window_end,
            expect_token=True,
            declared_observation_ms=trace["post_wake_observation_ms"],
        )
    except PacketCaptureError as error:
        raise LifecycleMatrixError(f"sleep-wake packet proof failed: {error}") from error
    try:
        trace_started = timestamp_fraction(trace["started_at"])
        sleep_started = timestamp_fraction(trace["sleep_started_at"])
        wake_observed = timestamp_fraction(trace["wake_observed_at"])
        trace_completed = timestamp_fraction(trace["completed_at"])
    except PacketCaptureError as error:
        raise LifecycleMatrixError(f"sleep-wake trace timestamp failed: {error}") from error
    if not (
        full_window.started_at
        == trace_started
        < sleep_started
        < wake_observed
        == post_wake_window.started_at
        < trace_completed
        == full_window.ended_at
        == post_wake_window.ended_at
    ):
        raise LifecycleMatrixError(
            "sleep-wake packet timestamps do not prove post-wake traffic"
        )
    return [
        {"subject": "sleep-wake:trace", "descriptor": trace_descriptor.as_dict()},
        {"subject": "sleep-wake:packet", "descriptor": capture_descriptor.as_dict()},
    ]


def _validate_wkwebview_evidence(
    value: Any,
    *,
    artifacts: ArtifactReader,
    candidate: dict[str, Any],
    started_at: str,
    finished_at: str,
) -> list[dict[str, Any]]:
    evidence = exact_object(
        value,
        {"metadata_artifact", "pixels_artifact"},
        "wkwebview-850x603.evidence",
    )
    metadata_descriptor, metadata_value = artifacts.read_json(
        evidence["metadata_artifact"],
        expected_kind="wkwebview-metadata",
        label="wkwebview-850x603.metadata_artifact",
    )
    metadata = exact_object(
        metadata_value,
        {
            "schema_version",
            "probe_id",
            "candidate_app_tree_sha256",
            "window_label",
            "view_class",
            "viewport_width_css_pixels",
            "viewport_height_css_pixels",
            "backing_scale",
            "pixel_width",
            "pixel_height",
            "bytes_per_row",
            "pixel_format",
            "color_space",
            "alpha_mode",
            "screenshot_command_sha256",
            "pixels_sha256",
            "captured_at",
            "completed_at",
        },
        "wkwebview-850x603.metadata",
    )
    if (
        type(metadata["schema_version"]) is not int
        or metadata["schema_version"] != 1
        or metadata["probe_id"] != "wkwebview-850x603"
    ):
        raise LifecycleMatrixError("WKWebView metadata schema/probe binding differs")
    if metadata["candidate_app_tree_sha256"] != candidate["signed_app_tree_sha256"]:
        raise LifecycleMatrixError("WKWebView metadata candidate app-tree binding differs")
    if (
        metadata["window_label"] != "main"
        or metadata["view_class"] != "WKWebView"
        or metadata["viewport_width_css_pixels"] != WKWEBVIEW_WIDTH
        or metadata["viewport_height_css_pixels"] != WKWEBVIEW_HEIGHT
    ):
        raise LifecycleMatrixError("WKWebView metadata does not bind the 850x603 main viewport")
    scale = metadata["backing_scale"]
    if not isinstance(scale, int) or isinstance(scale, bool) or scale not in {1, 2}:
        raise LifecycleMatrixError("WKWebView backing_scale must be 1 or 2")
    pixel_width = WKWEBVIEW_WIDTH * scale
    pixel_height = WKWEBVIEW_HEIGHT * scale
    bytes_per_row = pixel_width * 4
    if (
        metadata["pixel_width"] != pixel_width
        or metadata["pixel_height"] != pixel_height
        or metadata["bytes_per_row"] != bytes_per_row
        or metadata["pixel_format"] != "rgba8"
        or metadata["color_space"] != "srgb"
        or metadata["alpha_mode"] != "opaque"
    ):
        raise LifecycleMatrixError("WKWebView pixel layout differs from its typed viewport")
    require_sha256(
        metadata["screenshot_command_sha256"], "wkwebview.screenshot_command_sha256"
    )
    if metadata["captured_at"] != started_at or metadata["completed_at"] != finished_at:
        raise LifecycleMatrixError("WKWebView metadata timestamps differ from its probe")
    pixels_descriptor, pixels = artifacts.read(
        evidence["pixels_artifact"],
        expected_kinds={"wkwebview-rgba"},
        label="wkwebview-850x603.pixels_artifact",
    )
    if metadata["pixels_sha256"] != pixels_descriptor.sha256:
        raise LifecycleMatrixError("WKWebView metadata does not bind the RGBA bytes")
    if len(pixels) != bytes_per_row * pixel_height:
        raise LifecycleMatrixError("WKWebView RGBA byte count differs from its pixel layout")
    if any(alpha != 0xFF for alpha in pixels[3::4]):
        raise LifecycleMatrixError("WKWebView RGBA capture is not fully opaque")
    colors: set[bytes] = set()
    for offset in range(0, len(pixels), 4):
        colors.add(pixels[offset : offset + 3])
        if len(colors) >= 16:
            break
    if len(colors) < 16:
        raise LifecycleMatrixError("WKWebView RGBA capture is blank or insufficiently rendered")
    return [
        {
            "subject": "wkwebview-850x603:metadata",
            "descriptor": metadata_descriptor.as_dict(),
        },
        {
            "subject": "wkwebview-850x603:pixels",
            "descriptor": pixels_descriptor.as_dict(),
        },
    ]


def _validate_probe_evidence(
    value: Any,
    *,
    probe_id: str,
    artifacts: ArtifactReader,
    candidate: dict[str, Any],
    started_at: str,
    finished_at: str,
) -> list[dict[str, Any]]:
    if probe_id not in SPECIAL_EVIDENCE_PROBES:
        if value is not None:
            raise LifecycleMatrixError(f"{probe_id}.evidence must be null")
        return []
    if probe_id == "renderer-ready-v2":
        return _validate_renderer_ready_evidence(
            value,
            artifacts=artifacts,
            candidate=candidate,
            started_at=started_at,
            finished_at=finished_at,
        )
    if probe_id.startswith("network-extension-"):
        return _validate_network_extension_evidence(
            value,
            probe_id=probe_id,
            artifacts=artifacts,
            candidate=candidate,
            started_at=started_at,
            finished_at=finished_at,
        )
    if probe_id == "sleep-wake":
        return _validate_sleep_wake_evidence(
            value,
            artifacts=artifacts,
            candidate=candidate,
            started_at=started_at,
            finished_at=finished_at,
        )
    if probe_id == "wkwebview-850x603":
        return _validate_wkwebview_evidence(
            value,
            artifacts=artifacts,
            candidate=candidate,
            started_at=started_at,
            finished_at=finished_at,
        )
    raise LifecycleMatrixError(f"unsupported special evidence probe: {probe_id}")


LIFECYCLE_PROBE_EXECUTABLE = (
    "/Library/Application Support/Clash for Mac/ReleaseVerification/"
    "Lifecycle/CFWLifecycleProbe"
)


def lifecycle_probe_command(probe_id: str) -> list[str]:
    if probe_id not in PROBE_SPECS or probe_id in IDENTITY_PROBE_IDS:
        raise LifecycleMatrixError("lifecycle probe command is not source-pinned")
    return [LIFECYCLE_PROBE_EXECUTABLE, "observe", probe_id]


def _observation_candidate(value: Any, label: str) -> dict[str, Any]:
    candidate = exact_object(value, IDENTITY_OBSERVATION_CANDIDATE_FIELDS, label)
    if (
        candidate["version"] != PRODUCT_VERSION
        or candidate["build_number"] != IDENTITY_FINAL_BUILD
    ):
        raise LifecycleMatrixError(f"{label} is not the final lifecycle candidate")
    for field in (
        "app_manifest_sha256",
        "signed_app_tree_sha256",
        "artifact_hash_manifest_sha256",
    ):
        require_sha256(candidate[field], f"{label}.{field}")
    _timestamp(candidate["built_at"], f"{label}.built_at")
    return dict(candidate)


def _validate_standard_observation(
    value: Any,
    *,
    artifacts: ArtifactReader,
    probe_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw = exact_object(
        value,
        OBSERVATION_DOCUMENT_FIELDS,
        f"{probe_id}.observation",
    )
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != OBSERVATION_SCHEMA_VERSION
        or raw["document"] != OBSERVATION_DOCUMENT
    ):
        raise LifecycleMatrixError(
            f"{probe_id}.observation schema/document is unsupported"
        )
    candidate = _observation_candidate(
        raw["candidate"], f"{probe_id}.observation.candidate"
    )
    run_id = require_identifier(raw["run_id"], f"{probe_id}.observation.run_id")
    environment = _environment(
        raw["environment"], f"{probe_id}.observation.environment"
    )
    category, expected_exit, terminal_observation, _checks = PROBE_SPECS[probe_id]
    if raw["probe_id"] != probe_id or raw["category"] != category:
        raise LifecycleMatrixError(
            f"{probe_id}.observation case/category binding differs"
        )
    if raw["command"] != lifecycle_probe_command(probe_id):
        raise LifecycleMatrixError(
            f"{probe_id}.observation command is not the source-pinned helper"
        )
    started = _timestamp(raw["started_at"], f"{probe_id}.observation.started_at")
    finished = _timestamp(raw["finished_at"], f"{probe_id}.observation.finished_at")
    duration = (finished - started).total_seconds()
    if duration <= 0 or duration > 600:
        raise LifecycleMatrixError(
            f"{probe_id}.observation duration is outside 0..10min"
        )
    if raw["exit_code"] != expected_exit:
        raise LifecycleMatrixError(
            f"{probe_id}.observation exit_code differs from the required matrix outcome"
        )
    _event_sequence(
        raw["events"],
        probe_id,
        terminal_observation,
        f"{probe_id}.observation.events",
    )
    attributes = _attributes(
        raw["attributes"], probe_id, f"{probe_id}.observation.attributes"
    )
    evidence_bindings = _validate_probe_evidence(
        raw["evidence"],
        probe_id=probe_id,
        artifacts=artifacts,
        candidate=candidate,
        started_at=raw["started_at"],
        finished_at=raw["finished_at"],
    )
    return (
        {
            "candidate": candidate,
            "run_id": run_id,
            "environment": environment,
            "started_at": raw["started_at"],
            "finished_at": raw["finished_at"],
            "started_at_dt": started,
            "finished_at_dt": finished,
            "attributes": attributes,
            "identity_batch_sha256": None,
            "identity_candidate": None,
        },
        evidence_bindings,
    )


def validate_lifecycle_observation(
    value: Any,
    *,
    artifacts: ArtifactReader,
    probe_id: str,
) -> dict[str, Any]:
    """Strictly validate one proof-free lifecycle observation and its raw evidence."""

    if probe_id not in PROBE_SPECS:
        raise LifecycleMatrixError("lifecycle observation probe is not source-pinned")
    if probe_id in IDENTITY_PROBE_IDS:
        if not isinstance(value, dict):
            raise LifecycleMatrixError(f"{probe_id}.observation is not an object")
        candidate = _observation_candidate(
            value.get("candidate"), f"{probe_id}.observation.candidate"
        )
        run_id = require_identifier(
            value.get("run_id"), f"{probe_id}.observation.run_id"
        )
        environment = _environment(
            value.get("environment"), f"{probe_id}.observation.environment"
        )
        proof_candidate = {
            key: candidate[key]
            for key in IDENTITY_OBSERVATION_CANDIDATE_FIELDS
            if key != "built_at"
        }
        parsed_identity = validate_identity_observation(
            value,
            probe_id=probe_id,
            candidate=proof_candidate,
            run_id=run_id,
            environment=environment,
            started_at=value.get("started_at"),
            finished_at=value.get("finished_at"),
        )
        parsed = {
            "candidate": parsed_identity["candidate"],
            "run_id": parsed_identity["run_id"],
            "environment": parsed_identity["environment"],
            "started_at": parsed_identity["started_at"],
            "finished_at": parsed_identity["finished_at"],
            "started_at_dt": _timestamp(
                parsed_identity["started_at"], f"{probe_id}.started_at"
            ),
            "finished_at_dt": _timestamp(
                parsed_identity["finished_at"], f"{probe_id}.finished_at"
            ),
            "attributes": {},
            "identity_batch_sha256": parsed_identity["batch_sha256"],
            "identity_candidate": parsed_identity["candidate"],
        }
        evidence_bindings: list[dict[str, Any]] = []
    else:
        parsed, evidence_bindings = _validate_standard_observation(
            value,
            artifacts=artifacts,
            probe_id=probe_id,
        )
    return {**parsed, "artifacts": evidence_bindings}


def _validate_lifecycle_observation(
    value: Any,
    *,
    artifacts: ArtifactReader,
    probe_id: str,
    proof: dict[str, Any],
    environment: dict[str, Any],
    report_attributes: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    validated = validate_lifecycle_observation(
        value,
        artifacts=artifacts,
        probe_id=probe_id,
    )
    evidence_bindings = validated["artifacts"]
    parsed = {key: value for key, value in validated.items() if key != "artifacts"}
    proof_candidate = {
        key: parsed["candidate"][key]
        for key in IDENTITY_OBSERVATION_CANDIDATE_FIELDS
        if key != "built_at"
    }
    if proof_candidate != proof["candidate"] or parsed["run_id"] != proof["run_id"]:
        raise LifecycleMatrixError(
            f"{probe_id}.observation candidate/run binding differs from its proof event"
        )
    if parsed["environment"] != environment:
        raise LifecycleMatrixError(
            f"{probe_id}.observation environment differs from its report"
        )
    if parsed["attributes"] != report_attributes:
        raise LifecycleMatrixError(
            f"{probe_id}.observation attributes differ from its report"
        )
    return parsed, evidence_bindings


def _validate_raw_event(
    value: Any,
    *,
    artifacts: ArtifactReader,
    probe_id: str,
    proof: dict[str, Any],
    environment: dict[str, Any],
    report_attributes: dict[str, Any],
) -> tuple[
    datetime,
    datetime,
    list[dict[str, Any]],
    str | None,
    dict[str, Any] | None,
]:
    raw = exact_object(value, EVENT_DOCUMENT_FIELDS, f"{probe_id}.raw_event")
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != EVENT_SCHEMA_VERSION
        or raw["document"] != EVENT_DOCUMENT
    ):
        raise LifecycleMatrixError(
            f"{probe_id}.raw_event schema/document must be lifecycle event v3"
        )
    if parse_proof_binding(raw["proof"], f"{probe_id}.raw_event.proof") != proof:
        raise LifecycleMatrixError(f"{probe_id}.raw_event proof binding differs from its report")
    if raw["probe_id"] != probe_id:
        raise LifecycleMatrixError(f"{probe_id}.raw_event probe binding differs")
    descriptor, observation = artifacts.read_json(
        raw["observation_artifact"],
        expected_kind="lifecycle-observation",
        label=f"{probe_id}.raw_event.observation_artifact",
    )
    parsed, evidence_bindings = _validate_lifecycle_observation(
        observation,
        artifacts=artifacts,
        probe_id=probe_id,
        proof=proof,
        environment=environment,
        report_attributes=report_attributes,
    )
    bindings = [
        {
            "subject": f"{probe_id}:observation",
            "descriptor": descriptor.as_dict(),
        },
        *evidence_bindings,
    ]
    return (
        parsed["started_at_dt"],
        parsed["finished_at_dt"],
        bindings,
        parsed["identity_batch_sha256"],
        parsed["identity_candidate"],
    )


def validate_lifecycle_event(
    value: Any,
    *,
    artifacts: ArtifactReader,
    probe_id: str,
    proof: dict[str, Any],
    environment: dict[str, Any],
    report_attributes: dict[str, Any],
) -> tuple[
    datetime,
    datetime,
    list[dict[str, Any]],
    str | None,
    dict[str, Any] | None,
]:
    """Validate one lifecycle event through the report validator's same path."""

    return _validate_raw_event(
        value,
        artifacts=artifacts,
        probe_id=probe_id,
        proof=proof,
        environment=environment,
        report_attributes=report_attributes,
    )


def _validate(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    document = exact_object(
        value,
        {
            "schema_version",
            "harness_version",
            "proof",
            "environment",
            "captured_at",
            "completed_at",
            "signed_at",
            "probes",
        },
        "lifecycle matrix",
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise LifecycleMatrixError(f"lifecycle matrix schema_version must be {SCHEMA_VERSION}")
    if document["harness_version"] != HARNESS_VERSION:
        raise LifecycleMatrixError(
            f"lifecycle matrix harness_version must be {HARNESS_VERSION!r}"
        )
    proof = parse_proof_binding(document["proof"])
    if proof["candidate"]["version"] != PRODUCT_VERSION:
        raise LifecycleMatrixError("lifecycle matrix is not for version 0.4.0")
    environment = _environment(document["environment"])
    probes = document["probes"]
    if not isinstance(probes, list) or len(probes) != len(REQUIRED_PROBES):
        raise LifecycleMatrixError(
            "lifecycle matrix must contain every required probe exactly once"
        )
    seen: set[str] = set()
    bindings: list[dict[str, Any]] = []
    starts: list[datetime] = []
    finishes: list[datetime] = []
    identity_batches: set[str] = set()
    identity_candidates: list[dict[str, Any]] = []
    for index, raw_probe in enumerate(probes):
        probe = exact_object(raw_probe, PROBE_FIELDS, f"probes[{index}]")
        probe_id = probe["id"]
        if not isinstance(probe_id, str) or probe_id not in PROBE_SPECS:
            raise LifecycleMatrixError(f"probes[{index}] has an unknown probe id: {probe_id!r}")
        if probe_id in seen:
            raise LifecycleMatrixError(f"lifecycle matrix repeats probe: {probe_id!r}")
        seen.add(probe_id)
        report_attributes = _attributes(probe["attributes"], probe_id, f"{probe_id}.attributes")
        descriptor, raw_event = artifacts.read_json(
            probe["artifact"],
            expected_kind="lifecycle-event",
            label=f"{probe_id}.artifact",
        )
        (
            started,
            finished,
            evidence_bindings,
            identity_batch_sha256,
            identity_candidate,
        ) = _validate_raw_event(
            raw_event,
            artifacts=artifacts,
            probe_id=probe_id,
            proof=proof,
            environment=environment,
            report_attributes=report_attributes,
        )
        starts.append(started)
        finishes.append(finished)
        bindings.append({"subject": probe_id, "descriptor": descriptor.as_dict()})
        bindings.extend(evidence_bindings)
        if identity_batch_sha256 is not None:
            identity_batches.add(identity_batch_sha256)
        if identity_candidate is not None:
            identity_candidates.append(identity_candidate)
    if seen != set(REQUIRED_PROBES):
        raise LifecycleMatrixError("lifecycle matrix is missing a required probe")
    if len(identity_batches) != 1:
        raise LifecycleMatrixError(
            "identity observations do not belong to one verifier batch"
        )
    if (
        len(identity_candidates) != len(IDENTITY_PROBE_IDS)
        or any(candidate != identity_candidates[0] for candidate in identity_candidates)
    ):
        raise LifecycleMatrixError(
            "identity observations do not bind one complete candidate"
        )
    subjects = {binding["subject"] for binding in bindings}
    if len(subjects) != len(bindings) or subjects != EXPECTED_LIFECYCLE_RAW_SUBJECTS:
        raise LifecycleMatrixError(
            "lifecycle raw artifact subjects differ from the exact source contract"
        )
    if not starts or _timestamp(document["captured_at"], "captured_at") != min(starts):
        raise LifecycleMatrixError("captured_at differs from the earliest raw probe event")
    completed_at = _timestamp(document["completed_at"], "completed_at")
    signed_at = _timestamp(document["signed_at"], "signed_at")
    if completed_at != max(finishes) or signed_at < completed_at:
        raise LifecycleMatrixError(
            "completed_at/signed_at do not cover every raw probe event"
        )
    return {
        "document": document,
        "proof": proof,
        "environment": environment,
        "probes": sorted(seen),
        "started_at": min(starts),
        "completed_at": completed_at,
        "identity_batch_sha256": next(iter(identity_batches)),
        "identity_candidate": identity_candidates[0],
        "artifacts": bindings,
    }


def validate_lifecycle_matrix(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    try:
        return _validate(value, artifacts)
    except RawArtifactError as error:
        raise LifecycleMatrixError(str(error)) from error


def load_lifecycle_matrix(path: Path, *, evidence_root: Path) -> dict[str, Any]:
    try:
        value = load_json_file(path, maximum=MAX_REPORT_BYTES, label="lifecycle report")
        with ArtifactReader(evidence_root) as artifacts:
            return validate_lifecycle_matrix(value, artifacts)
    except RawArtifactError as error:
        raise LifecycleMatrixError(str(error)) from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        summary = load_lifecycle_matrix(
            arguments.report, evidence_root=arguments.evidence_root
        )
    except (LifecycleMatrixError, OSError) as error:
        raise SystemExit(f"error: lifecycle matrix validation failed: {error}") from error
    print(
        "lifecycle raw evidence structurally verified (collector signature not checked): "
        f"{len(summary['probes'])}/{len(REQUIRED_PROBES)} probes"
    )


if __name__ == "__main__":
    main()
