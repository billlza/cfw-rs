#!/usr/bin/env python3
"""Create fail-closed physical collector requests from local observations."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable, Sequence

if __package__:
    from .adversarial_clients import (
        ADVERSARIAL_RAW_KINDS,
        HARNESS_VERSION as ADVERSARIAL_VERSION,
        REQUIRED_RAW_SUBJECTS as REQUIRED_ADVERSARIAL_RAW_SUBJECTS,
        expected_raw_kind as expected_adversarial_raw_kind,
    )
    from .lifecycle_matrix import (
        EXPECTED_LIFECYCLE_RAW_SUBJECTS,
        HARNESS_VERSION as LIFECYCLE_VERSION,
        LifecycleMatrixError,
        expected_lifecycle_raw_kinds,
    )
    from .packet_evidence import (
        EXPECTED_PACKET_RAW_SUBJECTS,
        HARNESS_VERSION as PACKET_VERSION,
        OPTIONAL_PACKET_RAW_SUBJECTS,
    )
    from .performance_gates import HARNESS_VERSION as PERFORMANCE_VERSION
    from .performance_ledger import (
        LEDGER_KIND as PERFORMANCE_LEDGER_KIND,
        REQUIRED_PERFORMANCE_SUBJECTS,
        SHAPING_KIND as PERFORMANCE_SHAPING_KIND,
    )
    from .physical_machine_identity import (
        PhysicalMachineIdentityError,
        collect_boot_environment_sha256,
        collect_machine_identity,
    )
    from .raw_artifacts import (
        EVIDENCE_PROFILE,
        MAX_RECEIPT_ARTIFACT_COUNT,
        MAX_TOTAL_ARTIFACT_BYTES,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_file,
        parse_descriptor,
        require_identifier,
        require_sha256,
        utf8_size,
    )
    from ..release_build_identity import BuildIdentityError, canonical_build_version
else:  # pragma: no cover - direct script entrypoint
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from adversarial_clients import (  # type: ignore
        ADVERSARIAL_RAW_KINDS,
        HARNESS_VERSION as ADVERSARIAL_VERSION,
        REQUIRED_RAW_SUBJECTS as REQUIRED_ADVERSARIAL_RAW_SUBJECTS,
        expected_raw_kind as expected_adversarial_raw_kind,
    )
    from lifecycle_matrix import (  # type: ignore
        EXPECTED_LIFECYCLE_RAW_SUBJECTS,
        HARNESS_VERSION as LIFECYCLE_VERSION,
        LifecycleMatrixError,
        expected_lifecycle_raw_kinds,
    )
    from packet_evidence import (  # type: ignore
        EXPECTED_PACKET_RAW_SUBJECTS,
        HARNESS_VERSION as PACKET_VERSION,
        OPTIONAL_PACKET_RAW_SUBJECTS,
    )
    from performance_gates import HARNESS_VERSION as PERFORMANCE_VERSION  # type: ignore
    from performance_ledger import (  # type: ignore
        LEDGER_KIND as PERFORMANCE_LEDGER_KIND,
        REQUIRED_PERFORMANCE_SUBJECTS,
        SHAPING_KIND as PERFORMANCE_SHAPING_KIND,
    )
    from physical_machine_identity import (  # type: ignore
        PhysicalMachineIdentityError,
        collect_boot_environment_sha256,
        collect_machine_identity,
    )
    from raw_artifacts import (  # type: ignore
        EVIDENCE_PROFILE,
        MAX_RECEIPT_ARTIFACT_COUNT,
        MAX_TOTAL_ARTIFACT_BYTES,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_file,
        parse_descriptor,
        require_identifier,
        require_sha256,
        utf8_size,
    )
    from release_build_identity import (  # type: ignore
        BuildIdentityError,
        canonical_build_version,
    )


CONTEXT_DOCUMENT = "cfw-physical-run-context-v1"
CONTEXT_SCHEMA_VERSION = 1
COLLECTOR_REQUEST_SCHEMA_VERSION = 1
PRODUCT_VERSION = "0.4.0"
FINAL_RELEASE_BUILD = "40027"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_COLLECTOR_REQUEST_BYTES = 1 << 20
PRODUCTION_NONCE_TTL = timedelta(hours=6)
MAX_COMMAND_OUTPUT = 4096
COMMAND_TIMEOUT_SECONDS = 10
SYSTEM_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
}
FIXED_PYTHON_PROBE = Path("/opt/homebrew/bin/python3")
PINNED_RUNS = {
    (entry["macos_version"], entry["macos_build"]): entry["os"]
    for entry in EVIDENCE_PROFILE["required_runs"]
}
CANDIDATE_FIELDS = {
    "version",
    "build_number",
    "app_manifest_sha256",
    "signed_app_tree_sha256",
    "artifact_hash_manifest_sha256",
    "built_at",
}
CONTEXT_FIELDS = {
    "schema_version",
    "document",
    "evidence_profile_sha256",
    "candidate",
    "run",
    "initialized_at",
}
CONTEXT_RUN_FIELDS = {
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
NONCE_RESPONSE_FIELDS = {"schema_version", "run_nonce", "expires_at"}
BINDINGS_FIELDS = {
    "schema_version",
    "captured_at",
    "completed_at",
    "reports",
    "raw_artifacts",
}
REPORT_BINDING_FIELDS = {
    "harness",
    "tool_version",
    "captured_at",
    "completed_at",
    "signed_at",
    "descriptor",
}
RAW_ARTIFACT_BINDING_FIELDS = {"harness", "subject", "descriptor"}
EXPECTED_REPORTS = {
    "adversarial": (ADVERSARIAL_VERSION, "adversarial-report"),
    "lifecycle": (LIFECYCLE_VERSION, "lifecycle-report"),
    "packet": (PACKET_VERSION, "packet-report"),
    "performance": (PERFORMANCE_VERSION, "performance-report"),
}
RAW_KINDS_BY_HARNESS = {
    "adversarial": ADVERSARIAL_RAW_KINDS,
    "lifecycle": frozenset(
        {
            "lifecycle-observation",
            "lifecycle-event",
            "network-extension-trace",
            "packet-pcap",
            "renderer-ready-trace",
            "sleep-wake-trace",
            "wkwebview-metadata",
            "wkwebview-rgba",
        }
    ),
    "packet": frozenset(
        {
            "packet-capture-provenance",
            "packet-pcap",
            "packet-pcapng",
            "packet-product-state-observation",
            "packet-send-attempt",
        }
    ),
    "performance": frozenset(
        {PERFORMANCE_LEDGER_KIND, PERFORMANCE_SHAPING_KIND}
    ),
}
REQUIRED_LIFECYCLE_SUBJECTS = EXPECTED_LIFECYCLE_RAW_SUBJECTS
MACOS_BUILD_RE = re.compile(r"^[0-9]{2}[A-Z][0-9]{1,5}$")
UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)


class PhysicalCollectorRequestError(ValueError):
    """A local observation or request input cannot satisfy the release contract."""


Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not UTC_TIMESTAMP_RE.fullmatch(value):
        raise PhysicalCollectorRequestError(
            f"{label} must be a canonical ISO-8601 UTC timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PhysicalCollectorRequestError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PhysicalCollectorRequestError(f"{label} must use UTC")
    return parsed


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _observation_time(value: datetime | None) -> datetime:
    if value is None:
        return _now()
    if value.tzinfo is None or value.utcoffset() is None:
        raise PhysicalCollectorRequestError(
            "collector observation time must be timezone-aware"
        )
    return value.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _verify_cli_runtime() -> None:
    try:
        expected = FIXED_PYTHON_PROBE.resolve(strict=True)
        current = Path(sys.executable).resolve(strict=True)
        metadata = current.stat()
    except (OSError, RuntimeError) as error:
        raise PhysicalCollectorRequestError(
            "fixed physical-collector Python runtime is unavailable"
        ) from error
    if (
        current != expected
        or not current.is_file()
        or current.is_symlink()
        or metadata.st_nlink != 1
        or not os.access(current, os.X_OK)
        or not ((3, 11) <= sys.version_info[:2] < (4, 0))
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.dont_write_bytecode != 1
        or "site" in sys.modules
    ):
        raise PhysicalCollectorRequestError(
            "physical collector request requires the fixed Python 3.11+ "
            "runtime with -I -S -B"
        )


def _run_text(
    command: Sequence[str], *, runner: Runner | None = None
) -> str:
    executor = subprocess.run if runner is None else runner
    try:
        result = executor(
            list(command),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SYSTEM_ENVIRONMENT,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise PhysicalCollectorRequestError(
            f"environment command timed out: {command[0]}"
        ) from error
    if result.returncode != 0 or result.stderr:
        raise PhysicalCollectorRequestError(
            f"environment command failed closed: {command[0]}"
        )
    if not result.stdout or len(result.stdout) > MAX_COMMAND_OUTPUT:
        raise PhysicalCollectorRequestError(
            f"environment command output is outside bounds: {command[0]}"
        )
    try:
        value = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise PhysicalCollectorRequestError(
            f"environment command output is not UTF-8: {command[0]}"
        ) from error
    if (
        not value
        or len(value.encode("utf-8")) > 128
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PhysicalCollectorRequestError(
            f"environment command output is not bounded printable text: {command[0]}"
        )
    return value


def _candidate(value: Any) -> dict[str, Any]:
    candidate = exact_object(value, CANDIDATE_FIELDS, "candidate")
    if candidate["version"] != PRODUCT_VERSION:
        raise PhysicalCollectorRequestError(
            f"candidate.version must be {PRODUCT_VERSION}"
        )
    try:
        build_number = canonical_build_version(
            candidate["build_number"], "candidate.build_number"
        )
    except BuildIdentityError as error:
        raise PhysicalCollectorRequestError(str(error)) from error
    if build_number != FINAL_RELEASE_BUILD:
        raise PhysicalCollectorRequestError(
            f"candidate.build_number must be final release build {FINAL_RELEASE_BUILD}"
        )
    built_at = _timestamp(candidate["built_at"], "candidate.built_at")
    if built_at > _now():
        raise PhysicalCollectorRequestError("candidate.built_at is in the future")
    return {
        "version": PRODUCT_VERSION,
        "build_number": build_number,
        "app_manifest_sha256": require_sha256(
            candidate["app_manifest_sha256"], "candidate.app_manifest_sha256"
        ),
        "signed_app_tree_sha256": require_sha256(
            candidate["signed_app_tree_sha256"],
            "candidate.signed_app_tree_sha256",
        ),
        "artifact_hash_manifest_sha256": require_sha256(
            candidate["artifact_hash_manifest_sha256"],
            "candidate.artifact_hash_manifest_sha256",
        ),
        "built_at": candidate["built_at"],
    }


def _observe_environment(*, runner: Runner | None = None) -> dict[str, Any]:
    machine = collect_machine_identity(runner=runner)
    boot_environment = collect_boot_environment_sha256(runner=runner)
    macos_version = _run_text(("/usr/bin/sw_vers", "-productVersion"), runner=runner)
    macos_build = _run_text(("/usr/bin/sw_vers", "-buildVersion"), runner=runner)
    if not MACOS_BUILD_RE.fullmatch(macos_build):
        raise PhysicalCollectorRequestError("observed macOS build is not canonical")
    os_label = PINNED_RUNS.get((macos_version, macos_build))
    if os_label is None:
        raise PhysicalCollectorRequestError(
            "local macOS version/build is not one of the source-pinned release lanes"
        )
    return {
        "os": os_label,
        "macos_version": macos_version,
        "macos_build": macos_build,
        "machine_sha256": machine.machine_sha256,
        "machine_identity_scheme": EVIDENCE_PROFILE["machine_identity_scheme"],
        "hardware_model": machine.hardware_model,
        "virtualization_present": False,
        "boot_environment_sha256": boot_environment,
        "boot_environment_scheme": EVIDENCE_PROFILE["boot_environment_scheme"],
        "clean_install": True,
    }


def initialize_context(
    candidate: Any,
    *,
    run_id: str,
    clean_install_confirmed: bool,
    runner: Runner | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    if clean_install_confirmed is not True:
        raise PhysicalCollectorRequestError(
            "a clean-install observation must be explicitly confirmed"
        )
    parsed_candidate = _candidate(candidate)
    parsed_run_id = require_identifier(run_id, "run_id")
    observation = _observe_environment(runner=runner)
    observation["run_id"] = parsed_run_id
    profile_sha256 = hashlib.sha256(canonical_json(EVIDENCE_PROFILE)).hexdigest()
    return {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "document": CONTEXT_DOCUMENT,
        "evidence_profile_sha256": profile_sha256,
        "candidate": parsed_candidate,
        "run": observation,
        "initialized_at": _format_timestamp(_now() if observed_at is None else observed_at),
    }


def validate_context(
    value: Any, *, runner: Runner | None = None
) -> dict[str, Any]:
    context = exact_object(value, CONTEXT_FIELDS, "physical run context")
    if (
        type(context["schema_version"]) is not int
        or context["schema_version"] != CONTEXT_SCHEMA_VERSION
        or context["document"] != CONTEXT_DOCUMENT
    ):
        raise PhysicalCollectorRequestError("physical run context schema is unsupported")
    expected_profile = hashlib.sha256(canonical_json(EVIDENCE_PROFILE)).hexdigest()
    if context["evidence_profile_sha256"] != expected_profile:
        raise PhysicalCollectorRequestError(
            "physical run context evidence profile differs from release source"
        )
    candidate = _candidate(context["candidate"])
    run = exact_object(context["run"], CONTEXT_RUN_FIELDS, "physical run context.run")
    require_identifier(run["run_id"], "physical run context.run.run_id")
    if run["clean_install"] is not True or run["virtualization_present"] is not False:
        raise PhysicalCollectorRequestError(
            "physical run context is not a clean non-virtualized observation"
        )
    observed = _observe_environment(runner=runner)
    for field, current in observed.items():
        if run[field] != current:
            raise PhysicalCollectorRequestError(
                f"physical run context drifted at {field}"
            )
    initialized_at = _timestamp(context["initialized_at"], "context.initialized_at")
    if initialized_at > _now():
        raise PhysicalCollectorRequestError("physical run context is future-dated")
    return {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "document": CONTEXT_DOCUMENT,
        "evidence_profile_sha256": expected_profile,
        "candidate": candidate,
        "run": {**observed, "run_id": run["run_id"]},
        "initialized_at": context["initialized_at"],
    }


def build_nonce_request(
    context: Any, *, runner: Runner | None = None
) -> dict[str, Any]:
    validated = validate_context(context, runner=runner)
    run = validated["run"]
    request = {
        "schema_version": COLLECTOR_REQUEST_SCHEMA_VERSION,
        "candidate": validated["candidate"],
        "run": {
            "os": run["os"],
            "macos_version": run["macos_version"],
            "macos_build": run["macos_build"],
            "machine_sha256": run["machine_sha256"],
            "clean_install": True,
            "run_id": run["run_id"],
        },
    }
    return _bounded_request(request)


def _bounded_request(value: dict[str, Any]) -> dict[str, Any]:
    if len(canonical_json(value)) + 1 > MAX_COLLECTOR_REQUEST_BYTES:
        raise PhysicalCollectorRequestError(
            f"collector request exceeds {MAX_COLLECTOR_REQUEST_BYTES} bytes"
        )
    return value


def _bounded_printable(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise PhysicalCollectorRequestError(
            f"{label} must be bounded printable text"
        )
    try:
        encoded_size = utf8_size(value, label)
    except RawArtifactError as error:
        raise PhysicalCollectorRequestError(str(error)) from error
    if (
        not value.strip()
        or encoded_size > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PhysicalCollectorRequestError(
            f"{label} must be bounded printable text"
        )
    return value


def _validated_receipt_bindings(
    material: dict[str, Any],
    *,
    candidate_built_at: datetime,
    context_initialized_at: datetime,
    nonce_issued_at: datetime,
    now: datetime,
) -> tuple[str, str, list[dict[str, Any]], list[dict[str, Any]]]:
    captured_at = _timestamp(material["captured_at"], "bindings.captured_at")
    completed_at = _timestamp(material["completed_at"], "bindings.completed_at")
    if (
        captured_at < candidate_built_at
        or captured_at < context_initialized_at
        or completed_at < captured_at
        or nonce_issued_at < completed_at
        or completed_at > now
    ):
        raise PhysicalCollectorRequestError(
            "physical receipt binding timestamps predate the candidate/context, "
            "are reversed, use a nonce issued before raw completion, or are "
            "future-dated"
        )

    raw_reports = material["reports"]
    raw_artifacts = material["raw_artifacts"]
    if not isinstance(raw_reports, list) or len(raw_reports) != len(EXPECTED_REPORTS):
        raise PhysicalCollectorRequestError(
            "physical receipt reports must contain the four source-pinned harnesses"
        )
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise PhysicalCollectorRequestError("physical raw-artifact bindings are absent")
    if len(raw_reports) + len(raw_artifacts) > MAX_RECEIPT_ARTIFACT_COUNT:
        raise PhysicalCollectorRequestError(
            "physical receipt exceeds "
            f"{MAX_RECEIPT_ARTIFACT_COUNT} artifact descriptors"
        )

    seen_harnesses: set[str] = set()
    seen_paths: set[str] = set()
    seen_digests: set[str] = set()
    total_bytes = 0

    def record_descriptor(descriptor: dict[str, Any], label: str) -> None:
        nonlocal total_bytes
        if descriptor["path"] in seen_paths:
            raise PhysicalCollectorRequestError(
                f"{label} reuses artifact path {descriptor['path']!r}"
            )
        if descriptor["sha256"] in seen_digests:
            raise PhysicalCollectorRequestError(
                f"{label} reuses artifact digest {descriptor['sha256']!r}"
            )
        if descriptor["size"] > MAX_TOTAL_ARTIFACT_BYTES - total_bytes:
            raise PhysicalCollectorRequestError(
                f"physical receipt artifact bytes exceed {MAX_TOTAL_ARTIFACT_BYTES}"
            )
        seen_paths.add(descriptor["path"])
        seen_digests.add(descriptor["sha256"])
        total_bytes += descriptor["size"]

    reports: list[dict[str, Any]] = []
    for index, value in enumerate(raw_reports):
        label = f"bindings.reports[{index}]"
        report = exact_object(value, REPORT_BINDING_FIELDS, label)
        harness = report["harness"]
        if not isinstance(harness, str) or harness not in EXPECTED_REPORTS:
            raise PhysicalCollectorRequestError(f"{label}.harness is unknown")
        if harness in seen_harnesses:
            raise PhysicalCollectorRequestError(
                f"physical receipt repeats report harness {harness!r}"
            )
        seen_harnesses.add(harness)
        expected_version, expected_kind = EXPECTED_REPORTS[harness]
        if report["tool_version"] != expected_version:
            raise PhysicalCollectorRequestError(
                f"{label}.tool_version differs from the source-pinned harness"
            )
        report_captured = _timestamp(report["captured_at"], f"{label}.captured_at")
        report_completed = _timestamp(report["completed_at"], f"{label}.completed_at")
        report_signed = _timestamp(report["signed_at"], f"{label}.signed_at")
        if not (
            candidate_built_at
            <= captured_at
            <= report_captured
            <= report_completed
            <= completed_at
            <= nonce_issued_at
            <= report_signed
            <= now
        ):
            raise PhysicalCollectorRequestError(
                f"{label} timestamps are stale, reversed, or outside its run"
            )
        descriptor = parse_descriptor(
            report["descriptor"],
            expected_kinds={expected_kind},
            label=f"{label}.descriptor",
        ).as_dict()
        record_descriptor(descriptor, label)
        reports.append(
            {
                "harness": harness,
                "tool_version": expected_version,
                "captured_at": report["captured_at"],
                "completed_at": report["completed_at"],
                "signed_at": report["signed_at"],
                "descriptor": descriptor,
            }
        )
    if seen_harnesses != set(EXPECTED_REPORTS):
        raise PhysicalCollectorRequestError(
            "physical receipt omits a source-pinned report harness"
        )

    raw_bindings: list[dict[str, Any]] = []
    seen_raw_subjects: set[tuple[str, str]] = set()
    raw_harness_counts = {harness: 0 for harness in EXPECTED_REPORTS}
    lifecycle_subjects: set[str] = set()
    packet_subjects: set[str] = set()
    performance_subjects: set[str] = set()
    adversarial_subjects: set[str] = set()
    for index, value in enumerate(raw_artifacts):
        label = f"bindings.raw_artifacts[{index}]"
        binding = exact_object(value, RAW_ARTIFACT_BINDING_FIELDS, label)
        harness = binding["harness"]
        if not isinstance(harness, str) or harness not in RAW_KINDS_BY_HARNESS:
            raise PhysicalCollectorRequestError(f"{label}.harness is unknown")
        subject = _bounded_printable(binding["subject"], f"{label}.subject", 256)
        identity = (harness, subject)
        if identity in seen_raw_subjects:
            raise PhysicalCollectorRequestError(
                f"physical receipt repeats raw subject {subject!r} for {harness!r}"
            )
        seen_raw_subjects.add(identity)
        descriptor = parse_descriptor(
            binding["descriptor"],
            expected_kinds=RAW_KINDS_BY_HARNESS[harness],
            label=f"{label}.descriptor",
        ).as_dict()
        if (
            harness == "adversarial"
            and descriptor["kind"] != expected_adversarial_raw_kind(subject)
        ):
            raise PhysicalCollectorRequestError(
                f"{label}.descriptor kind differs from its adversarial subject"
            )
        if harness == "performance":
            expected_performance_kind = (
                PERFORMANCE_LEDGER_KIND
                if subject == "sample-ledger"
                else PERFORMANCE_SHAPING_KIND
            )
            if descriptor["kind"] != expected_performance_kind:
                raise PhysicalCollectorRequestError(
                    f"{label}.descriptor kind differs from its performance subject"
                )
        if harness == "lifecycle":
            try:
                expected_lifecycle_kinds = expected_lifecycle_raw_kinds(subject)
            except LifecycleMatrixError as error:
                raise PhysicalCollectorRequestError(
                    f"{label}.subject is not part of the exact lifecycle matrix"
                ) from error
            if descriptor["kind"] not in expected_lifecycle_kinds:
                raise PhysicalCollectorRequestError(
                    f"{label}.descriptor kind differs from its lifecycle subject"
                )
        record_descriptor(descriptor, label)
        raw_harness_counts[harness] += 1
        if harness == "lifecycle":
            lifecycle_subjects.add(subject)
        elif harness == "packet":
            packet_subjects.add(subject)
        elif harness == "performance":
            performance_subjects.add(subject)
        elif harness == "adversarial":
            adversarial_subjects.add(subject)
        raw_bindings.append(
            {"harness": harness, "subject": subject, "descriptor": descriptor}
        )
    missing_raw_harnesses = {
        harness for harness, count in raw_harness_counts.items() if count == 0
    }
    if missing_raw_harnesses:
        raise PhysicalCollectorRequestError(
            "physical raw artifacts omit harnesses: "
            f"{sorted(missing_raw_harnesses)}"
        )
    if lifecycle_subjects != REQUIRED_LIFECYCLE_SUBJECTS:
        raise PhysicalCollectorRequestError(
            "physical raw artifacts have an incomplete or unknown lifecycle subject set"
        )
    if not EXPECTED_PACKET_RAW_SUBJECTS <= packet_subjects or not packet_subjects <= (
        EXPECTED_PACKET_RAW_SUBJECTS | OPTIONAL_PACKET_RAW_SUBJECTS
    ):
        raise PhysicalCollectorRequestError(
            "physical raw artifacts have an incomplete or unknown packet subject set"
        )
    if adversarial_subjects != REQUIRED_ADVERSARIAL_RAW_SUBJECTS:
        raise PhysicalCollectorRequestError(
            "physical raw artifacts have an incomplete or unknown adversarial subject set"
        )
    if performance_subjects != REQUIRED_PERFORMANCE_SUBJECTS:
        raise PhysicalCollectorRequestError(
            "physical raw artifacts have an incomplete or unknown performance subject set"
        )
    return (
        material["captured_at"],
        material["completed_at"],
        sorted(reports, key=lambda entry: entry["harness"]),
        sorted(raw_bindings, key=lambda entry: (entry["harness"], entry["subject"])),
    )


def validate_nonce_response(
    nonce_response: Any,
    *,
    observed_at: datetime | None = None,
) -> tuple[dict[str, Any], datetime]:
    """Validate one live nonce response and derive its server issue time.

    The issue time is derived from the source-pinned TTL because receipt schema
    v1 intentionally carries only ``expires_at``.  Callers use it to prove that
    immutable local observations completed before the nonce was issued.
    """

    try:
        nonce = exact_object(
            nonce_response, NONCE_RESPONSE_FIELDS, "collector nonce response"
        )
        run_nonce = require_sha256(
            nonce["run_nonce"], "collector nonce response.run_nonce"
        )
    except RawArtifactError as error:
        raise PhysicalCollectorRequestError(str(error)) from error
    if (
        type(nonce["schema_version"]) is not int
        or nonce["schema_version"] != COLLECTOR_REQUEST_SCHEMA_VERSION
    ):
        raise PhysicalCollectorRequestError(
            "collector nonce response schema is unsupported"
        )
    expires_at = _timestamp(
        nonce["expires_at"], "collector nonce response.expires_at"
    )
    now = _observation_time(observed_at)
    if expires_at <= now:
        raise PhysicalCollectorRequestError("collector nonce response is expired")
    nonce_issued_at = expires_at - PRODUCTION_NONCE_TTL
    if nonce_issued_at > now:
        raise PhysicalCollectorRequestError(
            "collector nonce response has a future issue time"
        )
    return {
        "schema_version": COLLECTOR_REQUEST_SCHEMA_VERSION,
        "run_nonce": run_nonce,
        "expires_at": nonce["expires_at"],
    }, nonce_issued_at


def build_receipt_request(
    context: Any,
    nonce_response: Any,
    bindings: Any,
    *,
    runner: Runner | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    validated = validate_context(context, runner=runner)
    nonce, nonce_issued_at = validate_nonce_response(
        nonce_response, observed_at=observed_at
    )
    now = _observation_time(observed_at)
    material = exact_object(bindings, BINDINGS_FIELDS, "physical receipt bindings")
    if type(material["schema_version"]) is not int or material["schema_version"] != 1:
        raise PhysicalCollectorRequestError("physical receipt bindings schema is unsupported")
    captured_at, completed_at, reports, raw_artifacts = _validated_receipt_bindings(
        material,
        candidate_built_at=_timestamp(
            validated["candidate"]["built_at"], "candidate.built_at"
        ),
        context_initialized_at=_timestamp(
            validated["initialized_at"], "context.initialized_at"
        ),
        nonce_issued_at=nonce_issued_at,
        now=now,
    )
    run = validated["run"]
    request = {
        "schema_version": COLLECTOR_REQUEST_SCHEMA_VERSION,
        "candidate": validated["candidate"],
        "run": {
            "os": run["os"],
            "macos_version": run["macos_version"],
            "macos_build": run["macos_build"],
            "machine_sha256": run["machine_sha256"],
            "clean_install": True,
            "captured_at": captured_at,
            "completed_at": completed_at,
            "run_id": run["run_id"],
            "run_nonce": nonce["run_nonce"],
        },
        "reports": reports,
        "raw_artifacts": raw_artifacts,
    }
    return _bounded_request(request)


def _load(path: Path, label: str) -> Any:
    try:
        return load_json_file(path.absolute(), maximum=MAX_INPUT_BYTES, label=label)
    except RawArtifactError as error:
        raise PhysicalCollectorRequestError(str(error)) from error


def _write_new(path: Path, value: Any) -> None:
    absolute = path.absolute()
    parent = absolute.parent
    if not parent.is_dir() or parent.is_symlink():
        raise PhysicalCollectorRequestError(
            "request output parent must be a real directory"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags, 0o600)
    except OSError as error:
        raise PhysicalCollectorRequestError(
            "request output must be a new regular file"
        ) from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(canonical_json(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        absolute.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def self_check() -> None:
    expected_runs = {
        (entry["macos_version"], entry["macos_build"]): entry["os"]
        for entry in EVIDENCE_PROFILE["required_runs"]
    }
    if (
        CONTEXT_SCHEMA_VERSION != 1
        or COLLECTOR_REQUEST_SCHEMA_VERSION != 1
        or EVIDENCE_PROFILE["aggregate_schema_version"] != 5
        or EVIDENCE_PROFILE["aggregator_version"]
        != "physical-evidence-aggregator-v5-single-machine"
        or EVIDENCE_PROFILE["soak_hours_per_run"] != 3
        or FINAL_RELEASE_BUILD != "40027"
        or PINNED_RUNS != expected_runs
        or set(EXPECTED_REPORTS) != set(RAW_KINDS_BY_HARNESS)
        or MAX_COLLECTOR_REQUEST_BYTES != 1 << 20
        or PRODUCTION_NONCE_TTL != timedelta(hours=6)
    ):
        raise PhysicalCollectorRequestError(
            "physical collector request contract wiring is inconsistent"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("self-check")
    initialize = commands.add_parser("initialize")
    initialize.add_argument("--candidate", required=True, type=Path)
    initialize.add_argument("--run-id", required=True)
    initialize.add_argument("--confirm-clean-install", action="store_true")
    initialize.add_argument("--output", required=True, type=Path)
    nonce = commands.add_parser("nonce-request")
    nonce.add_argument("--context", required=True, type=Path)
    nonce.add_argument("--output", required=True, type=Path)
    receipt = commands.add_parser("receipt-request")
    receipt.add_argument("--context", required=True, type=Path)
    receipt.add_argument("--nonce-response", required=True, type=Path)
    receipt.add_argument("--bindings", required=True, type=Path)
    receipt.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        _verify_cli_runtime()
        if arguments.command == "self-check":
            self_check()
            print("physical collector request self-check ok")
            return 0
        if arguments.command == "initialize":
            value = initialize_context(
                _load(arguments.candidate, "physical candidate"),
                run_id=arguments.run_id,
                clean_install_confirmed=arguments.confirm_clean_install,
            )
        elif arguments.command == "nonce-request":
            value = build_nonce_request(
                _load(arguments.context, "physical run context")
            )
        elif arguments.command == "receipt-request":
            value = build_receipt_request(
                _load(arguments.context, "physical run context"),
                _load(arguments.nonce_response, "collector nonce response"),
                _load(arguments.bindings, "physical receipt bindings"),
            )
        else:  # pragma: no cover - argparse enforces the command set
            raise AssertionError("physical collector command dispatch drifted")
        _write_new(arguments.output, value)
        return 0
    except (
        OSError,
        PhysicalCollectorRequestError,
        PhysicalMachineIdentityError,
        RawArtifactError,
        subprocess.SubprocessError,
    ) as error:
        print(f"error: physical collector request failed closed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
