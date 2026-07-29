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
from pathlib import Path
import re
from typing import Any, Callable

if __package__:
    from .raw_artifacts import (
        ArtifactReader,
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
    from raw_artifacts import (  # type: ignore
        ArtifactReader,
        RawArtifactError,
        exact_object,
        load_json_file,
        parse_proof_binding,
        require_identifier,
        require_sha256,
    )


SCHEMA_VERSION = 2
HARNESS_VERSION = "lifecycle-matrix-v2"
PRODUCT_VERSION = "0.4.0"
REQUIRED_ARCHITECTURE = "arm64"
MAX_REPORT_BYTES = 1 * 1024 * 1024
MACOS_BUILD_RE = re.compile(r"^[0-9]{2}[A-Z][0-9]{1,5}[a-z]?$")


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
    "reboot-recovery": ("power", 0, "recovery-observed", {}),
    "host-crash": ("crash", 0, "recovery-observed", {}),
    "global-authority-crash": ("crash", 0, "recovery-observed", {}),
    "proxy-agent-crash": ("crash", 0, "recovery-observed", {}),
    "provider-crash": ("crash", 0, "recovery-observed", {}),
}

REQUIRED_PROBES = frozenset(PROBE_SPECS)
OPERATION_FIELDS = {"operation_id", "installation_id", "epoch", "generation"}
ENVIRONMENT_FIELDS = {
    "machine_sha256",
    "macos_build",
    "architecture",
    "operation_context",
}
PROBE_FIELDS = {"id", "attributes", "artifact"}
EVENT_DOCUMENT_FIELDS = {
    "schema_version",
    "proof",
    "environment",
    "probe_id",
    "category",
    "command",
    "started_at",
    "finished_at",
    "exit_code",
    "events",
    "attributes",
}
EVENT_FIELDS = {"sequence", "type", "probe_id", "observation"}


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
    macos_build = environment["macos_build"]
    if not isinstance(macos_build, str) or not MACOS_BUILD_RE.fullmatch(macos_build):
        raise LifecycleMatrixError(f"{label}.macos_build is not a macOS build identifier")
    if environment["architecture"] != REQUIRED_ARCHITECTURE:
        raise LifecycleMatrixError(f"{label}.architecture must be arm64")
    return {
        "machine_sha256": machine,
        "macos_build": macos_build,
        "architecture": REQUIRED_ARCHITECTURE,
        "operation_context": _operation_context(
            environment["operation_context"], f"{label}.operation_context"
        ),
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


def _validate_raw_event(
    value: Any,
    *,
    probe_id: str,
    proof: dict[str, Any],
    environment: dict[str, Any],
    report_attributes: dict[str, Any],
) -> datetime:
    raw = exact_object(value, EVENT_DOCUMENT_FIELDS, f"{probe_id}.raw_event")
    if raw["schema_version"] != 1:
        raise LifecycleMatrixError(f"{probe_id}.raw_event schema_version must be 1")
    if parse_proof_binding(raw["proof"], f"{probe_id}.raw_event.proof") != proof:
        raise LifecycleMatrixError(f"{probe_id}.raw_event proof binding differs from its report")
    if _environment(raw["environment"], f"{probe_id}.raw_event.environment") != environment:
        raise LifecycleMatrixError(f"{probe_id}.raw_event environment differs from its report")
    category, expected_exit, observation, _checks = PROBE_SPECS[probe_id]
    if raw["probe_id"] != probe_id or raw["category"] != category:
        raise LifecycleMatrixError(f"{probe_id}.raw_event case/category binding differs")
    _command(
        raw["command"], proof["collector"]["version"], probe_id, f"{probe_id}.raw_event.command"
    )
    started = _timestamp(raw["started_at"], f"{probe_id}.raw_event.started_at")
    finished = _timestamp(raw["finished_at"], f"{probe_id}.raw_event.finished_at")
    duration = (finished - started).total_seconds()
    if duration <= 0 or duration > 600:
        raise LifecycleMatrixError(f"{probe_id}.raw_event duration is outside 0..10min")
    if raw["exit_code"] != expected_exit:
        raise LifecycleMatrixError(
            f"{probe_id}.raw_event exit_code differs from the required matrix outcome"
        )
    _event_sequence(raw["events"], probe_id, observation, f"{probe_id}.raw_event.events")
    if _attributes(raw["attributes"], probe_id, f"{probe_id}.raw_event.attributes") != (
        report_attributes
    ):
        raise LifecycleMatrixError(f"{probe_id}.raw_event attributes differ from its report")
    return started


def _validate(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    document = exact_object(
        value,
        {
            "schema_version",
            "harness_version",
            "proof",
            "environment",
            "captured_at",
            "probes",
        },
        "lifecycle matrix",
    )
    if document["schema_version"] != SCHEMA_VERSION:
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
        starts.append(
            _validate_raw_event(
                raw_event,
                probe_id=probe_id,
                proof=proof,
                environment=environment,
                report_attributes=report_attributes,
            )
        )
        bindings.append({"subject": probe_id, "descriptor": descriptor.as_dict()})
    if seen != set(REQUIRED_PROBES):
        raise LifecycleMatrixError("lifecycle matrix is missing a required probe")
    if not starts or _timestamp(document["captured_at"], "captured_at") != min(starts):
        raise LifecycleMatrixError("captured_at differs from the earliest raw probe event")
    return {
        "document": document,
        "proof": proof,
        "environment": environment,
        "probes": sorted(seen),
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
