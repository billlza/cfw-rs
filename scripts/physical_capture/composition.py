"""Compose production physical evidence from already verified capture outputs.

This module owns only composition.  Harness modules remain responsible for
proving report and raw-artifact semantics, the request module remains
responsible for the receipt request contract, and the physical evidence
aggregator remains the sole production grant boundary.

There are deliberately no policy, output-path, OS, machine, or success
overrides.  The source-pinned trust policy and the two fixed repository-relative
publication paths are the only production inputs accepted here.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Iterator, Sequence

from scripts.harness.physical_collector_request import (
    COLLECTOR_REQUEST_SCHEMA_VERSION,
    CONTEXT_DOCUMENT,
    CONTEXT_SCHEMA_VERSION,
    EXPECTED_REPORTS,
    RAW_KINDS_BY_HARNESS,
    REQUIRED_LIFECYCLE_SUBJECTS,
    PhysicalCollectorRequestError,
    _bounded_printable,
    _candidate,
    _format_timestamp,
    _timestamp,
    validate_context,
)
from scripts.harness.physical_evidence_aggregator import (
    AGGREGATOR_VERSION,
    GRANTED_LEVEL,
    RECEIPT_SCHEMA_VERSION,
    REPORT_FIELDS,
    REQUIRED_OS,
    RUN_FIELDS,
    SCHEMA_VERSION,
    PhysicalEvidenceError,
    _receipt_payload,
    load_physical_evidence_artifact,
)
from scripts.harness.lifecycle_matrix import (
    LifecycleMatrixError,
    expected_lifecycle_raw_kinds,
)
from scripts.harness.physical_machine_identity import PhysicalMachineIdentityError
from scripts.harness.raw_artifacts import (
    EVIDENCE_PROFILE,
    MAX_RECEIPT_ARTIFACT_COUNT,
    MAX_TOTAL_ARTIFACT_BYTES,
    CollectorTrustPolicy,
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
    parse_descriptor,
    require_identifier,
    require_sha256,
    verify_ps256,
)

from .policy import PhysicalCapturePolicyError, load_source_pinned_policy


RUN_RECORD_DOCUMENT = "cfw-physical-run-record-v1"
RUN_RECORD_SCHEMA_VERSION = 1
RUN_RECORD_FIELDS = {
    "schema_version",
    "document",
    "trust_policy_sha256",
    "candidate",
    "run",
}
RECEIPT_REQUEST_FIELDS = {
    "schema_version",
    "candidate",
    "run",
    "reports",
    "raw_artifacts",
}
RECEIPT_RUN_FIELDS = {
    "os",
    "macos_version",
    "macos_build",
    "machine_sha256",
    "clean_install",
    "captured_at",
    "completed_at",
    "run_id",
    "run_nonce",
}
RECEIPT_REPORT_FIELDS = {
    "harness",
    "tool_version",
    "captured_at",
    "completed_at",
    "signed_at",
    "descriptor",
}
RAW_BINDING_FIELDS = {"harness", "subject", "descriptor"}
RECEIPT_RESPONSE_FIELDS = {
    "schema_version",
    "signed_at",
    "receipt_sha256",
    "signature",
}

AGGREGATE_RELATIVE_PATH = PurePosixPath(
    "target/candidates/0.4.0/release/private-physical-evidence/aggregate.json"
)
DESCRIPTOR_RELATIVE_PATH = PurePosixPath(
    "target/candidates/0.4.0/release/final-candidate/physical-evidence.json"
)
_PRIVATE_DIRECTORY_COMPONENTS = AGGREGATE_RELATIVE_PATH.parts[:-1]
_DESCRIPTOR_DIRECTORY_COMPONENTS = DESCRIPTOR_RELATIVE_PATH.parts[:-1]
_AGGREGATE_FILENAME = AGGREGATE_RELATIVE_PATH.name
_DESCRIPTOR_FILENAME = DESCRIPTOR_RELATIVE_PATH.name
_MAX_AGGREGATE_BYTES = 8 * 1024 * 1024
_MAX_DESCRIPTOR_BYTES = 4 * 1024
_RUN_ORDER = {
    entry["os"]: index for index, entry in enumerate(EVIDENCE_PROFILE["required_runs"])
}


class PhysicalCaptureCompositionError(ValueError):
    """Verified capture inputs cannot form production physical evidence."""


def _parse_timestamp(value: Any, label: str) -> datetime:
    try:
        return _timestamp(value, label)
    except PhysicalCollectorRequestError as error:
        raise PhysicalCaptureCompositionError(str(error)) from error


def _parse_descriptor(
    value: Any, *, expected_kinds: set[str] | frozenset[str], label: str
) -> dict[str, Any]:
    try:
        return parse_descriptor(
            value,
            expected_kinds=expected_kinds,
            label=label,
        ).as_dict()
    except RawArtifactError as error:
        raise PhysicalCaptureCompositionError(str(error)) from error


def _require_identifier(value: Any, label: str) -> str:
    try:
        return require_identifier(value, label)
    except RawArtifactError as error:
        raise PhysicalCaptureCompositionError(str(error)) from error


def _require_sha256(value: Any, label: str) -> str:
    try:
        return require_sha256(value, label)
    except RawArtifactError as error:
        raise PhysicalCaptureCompositionError(str(error)) from error


def _record_descriptor(
    descriptor: dict[str, Any],
    *,
    label: str,
    paths: set[str],
    digests: set[str],
    total_bytes: int,
) -> int:
    path = descriptor["path"]
    digest = descriptor["sha256"]
    if path in paths:
        raise PhysicalCaptureCompositionError(
            f"{label} reuses artifact path {path!r}"
        )
    if digest in digests:
        raise PhysicalCaptureCompositionError(
            f"{label} reuses artifact digest {digest!r}"
        )
    if descriptor["size"] > MAX_TOTAL_ARTIFACT_BYTES - total_bytes:
        raise PhysicalCaptureCompositionError(
            f"physical receipt artifact bytes exceed {MAX_TOTAL_ARTIFACT_BYTES}"
        )
    paths.add(path)
    digests.add(digest)
    return total_bytes + descriptor["size"]


def compose_receipt_bindings(
    reports: Any,
    raw_artifacts: Any,
) -> dict[str, Any]:
    """Build the sole receipt-binding document from four verified reports.

    ``reports`` is the aggregate run's exact harness-to-report mapping.  Raw
    artifacts are already-derived harness bindings, not a directory to scan or
    an operator-authored success declaration.
    """

    if not isinstance(reports, dict) or set(reports) != set(EXPECTED_REPORTS):
        raise PhysicalCaptureCompositionError(
            "verified reports must contain exactly the four source-pinned harnesses"
        )
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise PhysicalCaptureCompositionError(
            "verified raw-artifact bindings must be a non-empty list"
        )
    if len(reports) + len(raw_artifacts) > MAX_RECEIPT_ARTIFACT_COUNT:
        raise PhysicalCaptureCompositionError(
            "physical receipt exceeds "
            f"{MAX_RECEIPT_ARTIFACT_COUNT} artifact descriptors"
        )

    paths: set[str] = set()
    digests: set[str] = set()
    total_bytes = 0
    captured: list[tuple[datetime, str]] = []
    completed: list[tuple[datetime, str]] = []
    normalized_reports: list[dict[str, Any]] = []

    for harness in sorted(EXPECTED_REPORTS):
        label = f"reports.{harness}"
        try:
            report = exact_object(reports[harness], REPORT_FIELDS, label)
        except RawArtifactError as error:
            raise PhysicalCaptureCompositionError(str(error)) from error
        expected_version, expected_kind = EXPECTED_REPORTS[harness]
        if report["tool_version"] != expected_version:
            raise PhysicalCaptureCompositionError(
                f"{label}.tool_version differs from the source-pinned harness"
            )
        captured_at = _parse_timestamp(report["captured_at"], f"{label}.captured_at")
        completed_at = _parse_timestamp(
            report["completed_at"], f"{label}.completed_at"
        )
        signed_at = _parse_timestamp(report["signed_at"], f"{label}.signed_at")
        if not captured_at <= completed_at <= signed_at:
            raise PhysicalCaptureCompositionError(
                f"{label} timestamps are reversed"
            )
        descriptor = _parse_descriptor(
            report["artifact"],
            expected_kinds={expected_kind},
            label=f"{label}.artifact",
        )
        total_bytes = _record_descriptor(
            descriptor,
            label=label,
            paths=paths,
            digests=digests,
            total_bytes=total_bytes,
        )
        captured.append((captured_at, report["captured_at"]))
        completed.append((completed_at, report["completed_at"]))
        normalized_reports.append(
            {
                "harness": harness,
                "tool_version": expected_version,
                "captured_at": report["captured_at"],
                "completed_at": report["completed_at"],
                "signed_at": report["signed_at"],
                "descriptor": descriptor,
            }
        )

    raw_harness_counts = {harness: 0 for harness in EXPECTED_REPORTS}
    seen_subjects: set[tuple[str, str]] = set()
    lifecycle_subjects: set[str] = set()
    normalized_raw: list[dict[str, Any]] = []
    for index, value in enumerate(raw_artifacts):
        label = f"raw_artifacts[{index}]"
        try:
            binding = exact_object(value, RAW_BINDING_FIELDS, label)
        except RawArtifactError as error:
            raise PhysicalCaptureCompositionError(str(error)) from error
        harness = binding["harness"]
        if not isinstance(harness, str) or harness not in RAW_KINDS_BY_HARNESS:
            raise PhysicalCaptureCompositionError(f"{label}.harness is unknown")
        try:
            subject = _bounded_printable(
                binding["subject"], f"{label}.subject", 256
            )
        except PhysicalCollectorRequestError as error:
            raise PhysicalCaptureCompositionError(str(error)) from error
        identity = (harness, subject)
        if identity in seen_subjects:
            raise PhysicalCaptureCompositionError(
                f"{label} repeats subject {subject!r} for {harness!r}"
            )
        seen_subjects.add(identity)
        descriptor = _parse_descriptor(
            binding["descriptor"],
            expected_kinds=RAW_KINDS_BY_HARNESS[harness],
            label=f"{label}.descriptor",
        )
        if harness == "lifecycle":
            try:
                expected_kinds = expected_lifecycle_raw_kinds(subject)
            except LifecycleMatrixError as error:
                raise PhysicalCaptureCompositionError(
                    f"{label}.subject is not part of the exact lifecycle matrix"
                ) from error
            if descriptor["kind"] not in expected_kinds:
                raise PhysicalCaptureCompositionError(
                    f"{label}.descriptor kind differs from its lifecycle subject"
                )
        total_bytes = _record_descriptor(
            descriptor,
            label=label,
            paths=paths,
            digests=digests,
            total_bytes=total_bytes,
        )
        raw_harness_counts[harness] += 1
        if harness == "lifecycle":
            lifecycle_subjects.add(subject)
        normalized_raw.append(
            {"harness": harness, "subject": subject, "descriptor": descriptor}
        )

    missing_harnesses = {
        harness for harness, count in raw_harness_counts.items() if count == 0
    }
    if missing_harnesses:
        raise PhysicalCaptureCompositionError(
            f"verified raw artifacts omit harnesses: {sorted(missing_harnesses)}"
        )
    if lifecycle_subjects != REQUIRED_LIFECYCLE_SUBJECTS:
        raise PhysicalCaptureCompositionError(
            "verified raw artifacts have an incomplete or unknown lifecycle subject set"
        )

    return {
        "schema_version": 1,
        "captured_at": min(captured, key=lambda item: item[0])[1],
        "completed_at": max(completed, key=lambda item: item[0])[1],
        "reports": normalized_reports,
        "raw_artifacts": sorted(
            normalized_raw, key=lambda entry: (entry["harness"], entry["subject"])
        ),
    }


def _source_pinned_policy() -> CollectorTrustPolicy:
    try:
        return load_source_pinned_policy()
    except PhysicalCapturePolicyError as error:
        raise PhysicalCaptureCompositionError(str(error)) from error


def _validated_receipt_request(
    value: Any, *, context: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        request = exact_object(value, RECEIPT_REQUEST_FIELDS, "receipt request")
    except RawArtifactError as error:
        raise PhysicalCaptureCompositionError(str(error)) from error
    if (
        type(request["schema_version"]) is not int
        or request["schema_version"] != COLLECTOR_REQUEST_SCHEMA_VERSION
    ):
        raise PhysicalCaptureCompositionError("receipt request schema is unsupported")
    if request["candidate"] != context["candidate"]:
        raise PhysicalCaptureCompositionError(
            "receipt request candidate differs from the validated run context"
        )
    try:
        run = exact_object(request["run"], RECEIPT_RUN_FIELDS, "receipt request.run")
    except RawArtifactError as error:
        raise PhysicalCaptureCompositionError(str(error)) from error
    context_run = context["run"]
    for field in (
        "os",
        "macos_version",
        "macos_build",
        "machine_sha256",
        "clean_install",
        "run_id",
    ):
        if run[field] != context_run[field]:
            raise PhysicalCaptureCompositionError(
                f"receipt request.run.{field} differs from the validated context"
            )
    if run["clean_install"] is not True:
        raise PhysicalCaptureCompositionError("receipt request run is not a clean install")
    _require_identifier(run["run_id"], "receipt request.run.run_id")
    run_nonce = _require_sha256(run["run_nonce"], "receipt request.run.run_nonce")
    captured_at = _parse_timestamp(
        run["captured_at"], "receipt request.run.captured_at"
    )
    completed_at = _parse_timestamp(
        run["completed_at"], "receipt request.run.completed_at"
    )
    if completed_at < captured_at:
        raise PhysicalCaptureCompositionError(
            "receipt request run timestamps are reversed"
        )

    raw_reports = request["reports"]
    if not isinstance(raw_reports, list) or len(raw_reports) != len(EXPECTED_REPORTS):
        raise PhysicalCaptureCompositionError(
            "receipt request reports must contain exactly four harnesses"
        )
    report_map: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(raw_reports):
        label = f"receipt request.reports[{index}]"
        try:
            report = exact_object(value, RECEIPT_REPORT_FIELDS, label)
        except RawArtifactError as error:
            raise PhysicalCaptureCompositionError(str(error)) from error
        harness = report["harness"]
        if not isinstance(harness, str) or harness not in EXPECTED_REPORTS:
            raise PhysicalCaptureCompositionError(f"{label}.harness is unknown")
        if harness in report_map:
            raise PhysicalCaptureCompositionError(
                f"receipt request repeats report harness {harness!r}"
            )
        report_map[harness] = {
            "tool_version": report["tool_version"],
            "captured_at": report["captured_at"],
            "completed_at": report["completed_at"],
            "signed_at": report["signed_at"],
            "artifact": report["descriptor"],
        }
    bindings = compose_receipt_bindings(report_map, request["raw_artifacts"])
    if bindings["captured_at"] != run["captured_at"] or bindings[
        "completed_at"
    ] != run["completed_at"]:
        raise PhysicalCaptureCompositionError(
            "receipt request run bounds differ from its verified reports"
        )
    if request["reports"] != bindings["reports"]:
        raise PhysicalCaptureCompositionError(
            "receipt request reports are not the canonical composed bindings"
        )
    if request["raw_artifacts"] != bindings["raw_artifacts"]:
        raise PhysicalCaptureCompositionError(
            "receipt request raw artifacts are not the canonical composed bindings"
        )
    normalized_run = {
        **{field: run[field] for field in RECEIPT_RUN_FIELDS},
        "run_nonce": run_nonce,
    }
    return {
        "schema_version": COLLECTOR_REQUEST_SCHEMA_VERSION,
        "candidate": copy.deepcopy(context["candidate"]),
        "run": normalized_run,
        "reports": copy.deepcopy(bindings["reports"]),
        "raw_artifacts": copy.deepcopy(bindings["raw_artifacts"]),
    }, bindings


def compose_run_record(
    context: Any,
    receipt_request: Any,
    receipt_response: Any,
) -> dict[str, Any]:
    """Rebuild and verify one signed aggregate run from production documents."""

    try:
        validated_context = validate_context(context)
    except (
        OSError,
        PhysicalCollectorRequestError,
        PhysicalMachineIdentityError,
        RawArtifactError,
    ) as error:
        raise PhysicalCaptureCompositionError(
            "physical run context cannot be revalidated on this environment"
        ) from error
    if (
        validated_context["schema_version"] != CONTEXT_SCHEMA_VERSION
        or validated_context["document"] != CONTEXT_DOCUMENT
    ):
        raise PhysicalCaptureCompositionError("physical run context schema drifted")

    policy = _source_pinned_policy()
    if validated_context["evidence_profile_sha256"] != policy.evidence_profile_sha256:
        raise PhysicalCaptureCompositionError(
            "physical run context profile differs from the signed collector policy"
        )
    request, bindings = _validated_receipt_request(
        receipt_request, context=validated_context
    )
    try:
        response = exact_object(
            receipt_response, RECEIPT_RESPONSE_FIELDS, "receipt response"
        )
    except RawArtifactError as error:
        raise PhysicalCaptureCompositionError(str(error)) from error
    if (
        type(response["schema_version"]) is not int
        or response["schema_version"] != COLLECTOR_REQUEST_SCHEMA_VERSION
    ):
        raise PhysicalCaptureCompositionError("receipt response schema is unsupported")
    signed_at = _parse_timestamp(response["signed_at"], "receipt response.signed_at")
    if signed_at.microsecond != 0 or _format_timestamp(signed_at) != response["signed_at"]:
        raise PhysicalCaptureCompositionError(
            "receipt response.signed_at is not the server's canonical second timestamp"
        )
    if signed_at > datetime.now(timezone.utc):
        raise PhysicalCaptureCompositionError("receipt response is future-dated")
    run_completed = _parse_timestamp(
        request["run"]["completed_at"], "receipt request.run.completed_at"
    )
    if signed_at < run_completed:
        raise PhysicalCaptureCompositionError(
            "receipt response predates raw run completion"
        )
    for report in bindings["reports"]:
        if _parse_timestamp(
            report["signed_at"], f"reports.{report['harness']}.signed_at"
        ) > signed_at:
            raise PhysicalCaptureCompositionError(
                f"receipt response predates {report['harness']} report signing"
            )

    receipt_sha256 = _require_sha256(
        response["receipt_sha256"], "receipt response.receipt_sha256"
    )
    signature = response["signature"]
    if not isinstance(signature, str):
        raise PhysicalCaptureCompositionError(
            "receipt response.signature must be a PS256 base64url string"
        )
    collector = {
        "version": policy.collector_version,
        "source_sha256": policy.collector_source_sha256,
        "executable_sha256": policy.collector_executable_sha256,
        "key_version": policy.key_version,
        "algorithm": policy.algorithm,
        "signature": signature,
    }
    context_run = validated_context["run"]
    request_run = request["run"]
    run = {
        "os": request_run["os"],
        "macos_version": request_run["macos_version"],
        "macos_build": request_run["macos_build"],
        "machine_sha256": request_run["machine_sha256"],
        "machine_identity_scheme": context_run["machine_identity_scheme"],
        "hardware_model": context_run["hardware_model"],
        "virtualization_present": False,
        "boot_environment_sha256": context_run["boot_environment_sha256"],
        "boot_environment_scheme": context_run["boot_environment_scheme"],
        "clean_install": True,
        "captured_at": request_run["captured_at"],
        "completed_at": request_run["completed_at"],
        "signed_at": response["signed_at"],
        "run_id": request_run["run_id"],
        "run_nonce": request_run["run_nonce"],
        "collector": collector,
        "reports": {
            report["harness"]: {
                "tool_version": report["tool_version"],
                "captured_at": report["captured_at"],
                "completed_at": report["completed_at"],
                "signed_at": report["signed_at"],
                "artifact": copy.deepcopy(report["descriptor"]),
            }
            for report in bindings["reports"]
        },
    }
    payload = _receipt_payload(
        policy_sha256=policy.policy_sha256,
        candidate=request["candidate"],
        run=run,
        collector=collector,
        report_bindings=bindings["reports"],
        raw_bindings=bindings["raw_artifacts"],
    )
    payload_bytes = canonical_json(payload)
    computed_receipt_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if not hmac.compare_digest(computed_receipt_sha256, receipt_sha256):
        raise PhysicalCaptureCompositionError(
            "receipt response digest differs from the reconstructed signed payload"
        )
    try:
        verify_ps256(
            payload_bytes,
            signature,
            modulus=policy.modulus,
            exponent=policy.exponent,
        )
    except RawArtifactError as error:
        raise PhysicalCaptureCompositionError(
            "receipt response PS256 signature is invalid"
        ) from error

    return {
        "schema_version": RUN_RECORD_SCHEMA_VERSION,
        "document": RUN_RECORD_DOCUMENT,
        "trust_policy_sha256": policy.policy_sha256,
        "candidate": copy.deepcopy(request["candidate"]),
        "run": run,
    }


def compose_physical_aggregate(run_records: Any) -> dict[str, Any]:
    """Compose the fixed two-run aggregate without granting evidence trust."""

    if not isinstance(run_records, Sequence) or isinstance(
        run_records, (str, bytes, bytearray)
    ):
        raise PhysicalCaptureCompositionError("run records must be a sequence")
    if len(run_records) != len(REQUIRED_OS):
        raise PhysicalCaptureCompositionError(
            "physical aggregate requires exactly the two source-pinned run records"
        )
    policy = _source_pinned_policy()
    candidate: dict[str, Any] | None = None
    seen_os: set[str] = set()
    runs: list[dict[str, Any]] = []
    for index, value in enumerate(run_records):
        label = f"run_records[{index}]"
        try:
            record = exact_object(value, RUN_RECORD_FIELDS, label)
        except RawArtifactError as error:
            raise PhysicalCaptureCompositionError(str(error)) from error
        if (
            type(record["schema_version"]) is not int
            or record["schema_version"] != RUN_RECORD_SCHEMA_VERSION
            or record["document"] != RUN_RECORD_DOCUMENT
        ):
            raise PhysicalCaptureCompositionError(f"{label} schema is unsupported")
        if record["trust_policy_sha256"] != policy.policy_sha256:
            raise PhysicalCaptureCompositionError(
                f"{label} trust policy differs from release source"
            )
        try:
            parsed_candidate = _candidate(record["candidate"])
            run = exact_object(record["run"], RUN_FIELDS, f"{label}.run")
        except (PhysicalCollectorRequestError, RawArtifactError) as error:
            raise PhysicalCaptureCompositionError(str(error)) from error
        if candidate is None:
            candidate = parsed_candidate
        elif parsed_candidate != candidate:
            raise PhysicalCaptureCompositionError(
                "physical run records bind different candidates"
            )
        os_label = run["os"]
        if os_label not in REQUIRED_OS or os_label in seen_os:
            raise PhysicalCaptureCompositionError(
                f"{label}.run.os is unknown or duplicated"
            )
        seen_os.add(os_label)
        runs.append(copy.deepcopy(run))
    if seen_os != set(REQUIRED_OS) or candidate is None:
        raise PhysicalCaptureCompositionError(
            "physical run records omit a source-pinned OS lane"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "aggregator_version": AGGREGATOR_VERSION,
        "granted_level": GRANTED_LEVEL,
        "trust_policy_sha256": policy.policy_sha256,
        "candidate": candidate,
        "runs": sorted(runs, key=lambda run: _RUN_ORDER[run["os"]]),
    }


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _file_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise PhysicalCaptureCompositionError(
            "physical evidence publication requires no-follow directory support"
        )
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def _check_directory(fd: int, *, label: str, private: bool = False) -> None:
    metadata = os.fstat(fd)
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or mode & 0o022
        or (private and mode != 0o700)
    ):
        privacy = "private 0700" if private else "owner-controlled"
        raise PhysicalCaptureCompositionError(
            f"{label} is not a {privacy} real directory"
        )


@contextmanager
def _open_repository(repository: Path) -> Iterator[tuple[Path, int]]:
    absolute = Path(repository).absolute()
    flags = _directory_flags()
    try:
        observed = os.lstat(absolute)
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise PhysicalCaptureCompositionError(
            "repository root is not an openable real directory"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or _directory_identity(observed) != _directory_identity(opened)
        ):
            raise PhysicalCaptureCompositionError(
                "repository root changed while opening"
            )
        _check_directory(descriptor, label="repository root")
        yield absolute, descriptor
        rebound = os.lstat(absolute)
        if _directory_identity(rebound) != _directory_identity(opened):
            raise PhysicalCaptureCompositionError(
                "repository root path changed during publication"
            )
    finally:
        os.close(descriptor)


def _open_fixed_directory(
    repository_fd: int,
    components: Sequence[str],
    *,
    create_private_leaf: bool,
) -> int:
    current = os.dup(repository_fd)
    flags = _directory_flags()
    try:
        for index, component in enumerate(components):
            is_leaf = index == len(components) - 1
            try:
                next_fd = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                if not create_private_leaf or not is_leaf:
                    raise PhysicalCaptureCompositionError(
                        "fixed publication directory is absent: "
                        f"{'/'.join(components[: index + 1])}"
                    )
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    os.fsync(current)
                    next_fd = os.open(component, flags, dir_fd=current)
                    os.fchmod(next_fd, 0o700)
                    os.fsync(next_fd)
                except OSError as error:
                    raise PhysicalCaptureCompositionError(
                        "private physical evidence directory cannot be created durably"
                    ) from error
            except OSError as error:
                raise PhysicalCaptureCompositionError(
                    f"fixed publication directory is unsafe: {'/'.join(components[: index + 1])}"
                ) from error
            try:
                _check_directory(
                    next_fd,
                    label="/".join(components[: index + 1]),
                    private=create_private_leaf and is_leaf,
                )
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def _require_absent(directory_fd: int, name: str, label: str) -> None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise PhysicalCaptureCompositionError(f"cannot inspect {label}") from error
    raise PhysicalCaptureCompositionError(f"refusing to replace existing {label}")


def _read_named_file(
    directory_fd: int,
    name: str,
    *,
    maximum: int,
    expected_identity: tuple[int, int] | None = None,
) -> tuple[bytes, tuple[int, int]]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise PhysicalCaptureCompositionError(
            f"published evidence cannot be reopened: {name}"
        ) from error
    try:
        before = os.fstat(descriptor)
        identity = _file_identity(before)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size < 1
            or before.st_size > maximum
            or (expected_identity is not None and identity != expected_identity)
        ):
            raise PhysicalCaptureCompositionError(
                f"published evidence is not a private bounded regular file: {name}"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise PhysicalCaptureCompositionError(
                    f"published evidence was truncated while reading: {name}"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PhysicalCaptureCompositionError(
                f"published evidence grew while reading: {name}"
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    rebound = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (
        _file_identity(before) != _file_identity(after)
        or _file_identity(before) != _file_identity(rebound)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise PhysicalCaptureCompositionError(
            f"published evidence changed while reading: {name}"
        )
    return b"".join(chunks), identity


def _unlink_if_identity(
    directory_fd: int, name: str, identity: tuple[int, int]
) -> None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise PhysicalCaptureCompositionError(
            f"cannot inspect failed publication output during cleanup: {name}"
        ) from error
    if _file_identity(metadata) != identity:
        raise PhysicalCaptureCompositionError(
            f"refusing to remove publication output whose identity changed: {name}"
        )
    try:
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as error:
        raise PhysicalCaptureCompositionError(
            f"failed publication output could not be removed durably: {name}"
        ) from error


def _write_new_file(
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    maximum: int,
) -> tuple[int, str, tuple[int, int]]:
    if not data or len(data) > maximum:
        raise PhysicalCaptureCompositionError(
            f"publication bytes for {name} are outside the fixed bound"
        )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except OSError as error:
        raise PhysicalCaptureCompositionError(
            f"refusing to replace or follow publication output {name}"
        ) from error
    identity: tuple[int, int] | None = None
    try:
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        identity = _file_identity(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise PhysicalCaptureCompositionError(
                f"new publication output is unsafe: {name}"
            )
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise PhysicalCaptureCompositionError(
                    f"publication write was incomplete: {name}"
                )
            offset += written
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if _file_identity(after) != identity or after.st_size != len(data):
            raise PhysicalCaptureCompositionError(
                f"publication output changed while writing: {name}"
            )
    except BaseException as error:
        os.close(descriptor)
        if identity is not None:
            try:
                _unlink_if_identity(directory_fd, name, identity)
            except PhysicalCaptureCompositionError as cleanup_error:
                raise cleanup_error from error
        raise
    else:
        os.close(descriptor)
    try:
        os.fsync(directory_fd)
        reopened, rebound_identity = _read_named_file(
            directory_fd,
            name,
            maximum=maximum,
            expected_identity=identity,
        )
        if not hmac.compare_digest(reopened, data):
            raise PhysicalCaptureCompositionError(
                f"publication output bytes changed after writing: {name}"
            )
    except BaseException as error:
        try:
            _unlink_if_identity(directory_fd, name, identity)
        except PhysicalCaptureCompositionError as cleanup_error:
            raise cleanup_error from error
        raise
    return len(data), hashlib.sha256(data).hexdigest(), rebound_identity


def publish_physical_evidence(
    repository: Path,
    run_records: Any,
) -> dict[str, Any]:
    """Publish and twice revalidate the fixed production aggregate descriptor."""

    aggregate = compose_physical_aggregate(run_records)
    policy = _source_pinned_policy()
    aggregate_bytes = canonical_json(aggregate) + b"\n"
    aggregate_identity: tuple[int, int] | None = None
    descriptor_identity: tuple[int, int] | None = None

    with _open_repository(Path(repository)) as (repository_path, repository_fd):
        descriptor_directory_fd = _open_fixed_directory(
            repository_fd,
            _DESCRIPTOR_DIRECTORY_COMPONENTS,
            create_private_leaf=False,
        )
        try:
            private_directory_fd = _open_fixed_directory(
                repository_fd,
                _PRIVATE_DIRECTORY_COMPONENTS,
                create_private_leaf=True,
            )
            try:
                _require_absent(
                    descriptor_directory_fd,
                    _DESCRIPTOR_FILENAME,
                    "physical evidence descriptor",
                )
                _require_absent(
                    private_directory_fd,
                    _AGGREGATE_FILENAME,
                    "physical evidence aggregate",
                )
                size, digest, aggregate_identity = _write_new_file(
                    private_directory_fd,
                    _AGGREGATE_FILENAME,
                    aggregate_bytes,
                    maximum=_MAX_AGGREGATE_BYTES,
                )
                descriptor = {
                    "kind": "physical-aggregate",
                    "path": AGGREGATE_RELATIVE_PATH.as_posix(),
                    "size": size,
                    "sha256": digest,
                }
                try:
                    load_physical_evidence_artifact(
                        descriptor,
                        evidence_root=repository_path,
                        trust_policy=policy,
                        fixture=False,
                    )
                except (OSError, PhysicalEvidenceError, RawArtifactError) as error:
                    raise PhysicalCaptureCompositionError(
                        "composed aggregate failed production validation"
                    ) from error

                descriptor_bytes = canonical_json(descriptor) + b"\n"
                _, _, descriptor_identity = _write_new_file(
                    descriptor_directory_fd,
                    _DESCRIPTOR_FILENAME,
                    descriptor_bytes,
                    maximum=_MAX_DESCRIPTOR_BYTES,
                )
                reopened_descriptor, _ = _read_named_file(
                    descriptor_directory_fd,
                    _DESCRIPTOR_FILENAME,
                    maximum=_MAX_DESCRIPTOR_BYTES,
                    expected_identity=descriptor_identity,
                )
                try:
                    parsed_descriptor = load_json_bytes(
                        reopened_descriptor, "physical evidence descriptor"
                    )
                except RawArtifactError as error:
                    raise PhysicalCaptureCompositionError(
                        "published physical evidence descriptor is malformed"
                    ) from error
                if parsed_descriptor != descriptor:
                    raise PhysicalCaptureCompositionError(
                        "published physical evidence descriptor bytes drifted"
                    )
                try:
                    load_physical_evidence_artifact(
                        descriptor,
                        evidence_root=repository_path,
                        trust_policy=policy,
                        fixture=False,
                    )
                except (OSError, PhysicalEvidenceError, RawArtifactError) as error:
                    raise PhysicalCaptureCompositionError(
                        "published aggregate failed its final production revalidation"
                    ) from error
                return descriptor
            except BaseException as error:
                if descriptor_identity is not None:
                    try:
                        _unlink_if_identity(
                            descriptor_directory_fd,
                            _DESCRIPTOR_FILENAME,
                            descriptor_identity,
                        )
                    except PhysicalCaptureCompositionError as cleanup_error:
                        raise cleanup_error from error
                if aggregate_identity is not None:
                    try:
                        _unlink_if_identity(
                            private_directory_fd,
                            _AGGREGATE_FILENAME,
                            aggregate_identity,
                        )
                    except PhysicalCaptureCompositionError as cleanup_error:
                        raise cleanup_error from error
                raise
            finally:
                os.close(private_directory_fd)
        finally:
            os.close(descriptor_directory_fd)


__all__ = [
    "AGGREGATE_RELATIVE_PATH",
    "DESCRIPTOR_RELATIVE_PATH",
    "PhysicalCaptureCompositionError",
    "RUN_RECORD_DOCUMENT",
    "RUN_RECORD_SCHEMA_VERSION",
    "compose_physical_aggregate",
    "compose_receipt_bindings",
    "compose_run_record",
    "publish_physical_evidence",
]
