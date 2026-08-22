"""Session-aware proof-free physical performance collection.

There is deliberately no CLI or privileged helper in this module.  An operator
must first install the three reviewed PF profiles at their fixed root-owned
paths, run ``sudo -v`` in a separate terminal, and drive product mode changes
through the normal signed application.  This adapter then uses only fixed
absolute OS-tool argv vectors through :class:`ObservationCapture`.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable, Final, Protocol, Sequence, runtime_checkable

from scripts.harness import performance_ledger as contract
from scripts.harness.performance_ledger import PerformanceLedgerError
from scripts.harness.physical_collector_request import (
    FINAL_RELEASE_BUILD,
    PRODUCT_VERSION,
    PhysicalCollectorRequestError,
    validate_context,
)
from scripts.harness.raw_artifacts import (
    ArtifactReader,
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
)

from .archive import PhysicalCaptureArchiveError, SecureArchive
from .execution import CommandResult, CommandSpec, ProbeExecutionError
from .observation import ObservationArtifact, ObservationCapture, PhysicalObservationError
from .session import PhysicalCaptureSession, PhysicalCaptureSessionError


OBSERVATION_DIRECTORY: Final = "raw/performance/observations"
LEDGER_OBSERVATION_SUBJECT: Final = f"performance:{contract.LEDGER_SUBJECT}"
INTENT_OBSERVATION_SUBJECT: Final = f"performance:{contract.SHAPING_INTENT_SUBJECT}"
RESTORATION_OBSERVATION_SUBJECT: Final = (
    f"performance:{contract.SHAPING_RESTORATION_SUBJECT}"
)
FAILURE_RESTORATION_RELATIVE: Final = (
    f"{OBSERVATION_DIRECTORY}/shaping-restoration-failed.json"
)
RESTORATION_FAILURE_DOCUMENT: Final = (
    "cfw-performance-shaping-restoration-failure-v2"
)
RESTORATION_FAILURE_SCHEMA_VERSION: Final = 2
RESTART_RECOVERY_FILENAME_RE: Final = re.compile(
    r"^shaping-restart-recovery-(?P<attempt>[0-9]{2})[.]json$"
)
RESTART_RECOVERY_DOCUMENT: Final = (
    "cfw-performance-shaping-restart-recovery-v3"
)
RESTART_RECOVERY_SCHEMA_VERSION: Final = 3
MAX_RESTART_RECOVERY_ATTEMPTS: Final = 3
MAX_PERFORMANCE_ARTIFACT_BYTES: Final = 8 * 1024 * 1024
MODE_CHANGE_TIMEOUT_SECONDS: Final = 120.0
SOAK_WAIT_SLICE_SECONDS: Final = 30.0
COMMAND_TIMEOUT_SECONDS: Final = 60.0
NETWORK_TIMEOUT_SECONDS: Final = 15.0
PRIVILEGE_PREFLIGHT_INSTRUCTION: Final = (
    "In a separate terminal run exactly `sudo -v`, then return here. "
    "Do not install a helper or pass a command/path to the collector."
)
RECOVERY_PREFLIGHT_INSTRUCTION: Final = (
    "Run exactly `sudo -v` in a separate terminal for shaping recovery."
)


class PerformanceCaptureError(RuntimeError):
    """A real performance observation failed or could not be restored."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RestartRecoveryStatus(str, Enum):
    INCOMPLETE = "incomplete"
    COMPLETE = "complete"


@runtime_checkable
class PerformanceOperator(Protocol):
    """Explicit out-of-process operator checkpoints; never evidence by itself."""

    def request_terminal_mode(
        self,
        mode: str,
        *,
        reason: str,
        iteration: int,
        deadline: datetime,
    ) -> None: ...

    def confirm_privileged_preflight(self, instruction: str) -> None: ...


Cancelled = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class PerformanceObservationBatch:
    ledger: ObservationArtifact
    shaping_intent: ObservationArtifact
    shaping_restoration: ObservationArtifact

    def descriptor_mapping(self) -> dict[str, dict[str, object]]:
        return {
            self.ledger.subject: self.ledger.descriptor.as_dict(),
            self.shaping_intent.subject: self.shaping_intent.descriptor.as_dict(),
            self.shaping_restoration.subject: self.shaping_restoration.descriptor.as_dict(),
        }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _log_query_boundary(value: datetime, *, upper: bool) -> datetime:
    normalized = value.astimezone(timezone.utc)
    boundary = normalized.replace(microsecond=0)
    return boundary + timedelta(seconds=1) if upper else boundary


def _log_query_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _wait_until_wall(deadline: datetime, cancelled: Cancelled) -> None:
    while True:
        _check_cancelled(cancelled)
        remaining = (deadline - _utc_now()).total_seconds()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 0.25))


def _decode(value: bytes, label: str) -> str:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PerformanceCaptureError(
            "command_output_invalid", f"{label} is not UTF-8"
        ) from error
    if "\x00" in text:
        raise PerformanceCaptureError(
            "command_output_invalid", f"{label} contains a NUL byte"
        )
    return text


def _executable_sha256(path: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or metadata.st_size > 128 * 1024 * 1024
        ):
            raise PerformanceCaptureError(
                "observer_executable_unsafe",
                f"fixed observer executable is unsafe: {path}",
            )
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise PerformanceCaptureError(
            "observer_executable_unreadable",
            f"fixed observer executable cannot be hashed: {path}",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _command_document(
    capture: ObservationCapture,
    repository: Path,
    *,
    role: str,
    argv: tuple[str, ...],
    timeout: float = COMMAND_TIMEOUT_SECONDS,
    stdout_limit: int = contract.MAX_COMMAND_OUTPUT_BYTES,
    stderr_limit: int = contract.MAX_COMMAND_OUTPUT_BYTES,
) -> dict[str, Any]:
    before = _executable_sha256(argv[0])
    try:
        result = capture.run_command(
            CommandSpec(
                role=role,
                argv=argv,
                cwd=repository,
                timeout_seconds=timeout,
                accepted_exit_codes=frozenset({0}),
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
            )
        )
    except (PhysicalCaptureSessionError, PhysicalObservationError, ProbeExecutionError) as error:
        raise PerformanceCaptureError(
            "fixed_command_failed", f"fixed performance command failed: {role}"
        ) from error
    after = _executable_sha256(argv[0])
    if after != before:
        raise PerformanceCaptureError(
            "observer_executable_drifted",
            f"fixed observer executable changed while running: {argv[0]}",
        )
    return _result_document(result, argv=argv, executable_sha256=before)


def _result_document(
    result: CommandResult,
    *,
    argv: tuple[str, ...],
    executable_sha256: str,
) -> dict[str, Any]:
    stdout = _decode(result.stdout, f"{result.role}.stdout")
    stderr = _decode(result.stderr, f"{result.role}.stderr")
    return {
        "role": result.role,
        "argv": list(argv),
        "argv_sha256": result.argv_sha256,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "duration_ms": result.duration_ms,
        "exit_code": result.exit_code,
        "stdout_size": len(result.stdout),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdout": stdout,
        "stderr_size": len(result.stderr),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderr": stderr,
        "observer_executable_sha256": executable_sha256,
    }


def _check_cancelled(cancelled: Cancelled) -> None:
    if cancelled():
        raise PerformanceCaptureError(
            "performance_capture_cancelled", "performance collection was cancelled"
        )


def _wait_until(deadline_ns: int, cancelled: Cancelled) -> None:
    while True:
        _check_cancelled(cancelled)
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            return
        time.sleep(min(remaining, SOAK_WAIT_SLICE_SECONDS))


def _validate_profile_files() -> None:
    directories = {Path(path).parent for path in contract.PROFILE_FILES.values()}
    for directory in directories:
        # The path handed to privileged pfctl must not be redirectable by the
        # collecting user after validation.  Validate every non-root component
        # without following symlinks; root-owned, non-writable ancestors reduce
        # the remaining race to an already-privileged root process.
        current = Path(directory.anchor)
        for component in directory.parts[1:]:
            current /= component
            try:
                metadata = current.lstat()
            except OSError as error:
                raise PerformanceCaptureError(
                    "shaping_profile_directory_unsafe",
                    "fixed shaping profile directory is unavailable",
                ) from error
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
            ):
                raise PerformanceCaptureError(
                    "shaping_profile_directory_unsafe",
                    "fixed shaping profile directory is not root-owned and immutable",
                )
    for profile_id, profile in contract.WEAK_NETWORK_PROFILES.items():
        path = contract.PROFILE_FILES[profile_id]
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = -1
        try:
            descriptor = os.open(path, flags)
            metadata = os.fstat(descriptor)
            data = os.read(descriptor, 4097)
        except OSError as error:
            raise PerformanceCaptureError(
                "shaping_profile_unavailable",
                f"fixed root-owned shaping profile is unavailable: {profile_id}",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or len(data) > 4096
            or hashlib.sha256(data).hexdigest() != profile["profile_sha256"]
        ):
            raise PerformanceCaptureError(
                "shaping_profile_drifted",
                f"fixed shaping profile differs from reviewed source: {profile_id}",
            )


def _capture_context(context: object) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        validated = validate_context(context)
        candidate = copy.deepcopy(validated["candidate"])
        source_run = validated["run"]
        run = {
            key: copy.deepcopy(source_run[key])
            for key in contract.RUN_FIELDS
        }
    except (
        KeyError,
        PhysicalCollectorRequestError,
        RawArtifactError,
    ) as error:
        raise PerformanceCaptureError(
            "performance_context_invalid",
            "performance context failed strict revalidation",
        ) from error
    if (
        candidate["version"] != PRODUCT_VERSION
        or candidate["build_number"] != FINAL_RELEASE_BUILD
    ):
        raise PerformanceCaptureError(
            "not_final_candidate",
            f"performance capture requires final 0.4.0 build {FINAL_RELEASE_BUILD}",
        )
    return candidate, run


def _capture_inputs(
    context: object, parameters: object
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    candidate, run = _capture_context(context)
    try:
        parsed_parameters = copy.deepcopy(contract._parameters(parameters, run))
    except (PerformanceLedgerError, RawArtifactError) as error:
        raise PerformanceCaptureError(
            "performance_context_invalid",
            "performance parameters failed strict revalidation",
        ) from error
    return candidate, run, parsed_parameters


def _require_operator(operator: object) -> PerformanceOperator:
    if not isinstance(operator, PerformanceOperator):
        raise PerformanceCaptureError(
            "invalid_operator",
            "performance capture requires explicit operator checkpoint methods",
        )
    return operator


class _Recorder:
    def __init__(
        self,
        *,
        session: PhysicalCaptureSession,
        capture: ObservationCapture,
        candidate: dict[str, Any],
        run: dict[str, Any],
        context_sha256: str,
        parameters: dict[str, Any],
        operator: PerformanceOperator,
        cancelled: Cancelled,
    ) -> None:
        self.session = session
        self.capture = capture
        self.repository = session.archive.repository
        self.candidate = candidate
        self.run = run
        self.context_sha256 = context_sha256
        self.parameters = parameters
        self.operator = operator
        self.cancelled = cancelled
        self.log_start = _utc_now() - timedelta(seconds=1)
        self.signing_values: list[dict[str, Any]] = []
        self.signing_by_component: dict[str, dict[str, Any]] = {}
        self.samples: list[dict[str, Any]] = []
        self.shaping_transactions: list[dict[str, Any]] = []
        self.intent_artifact: ObservationArtifact | None = None
        self.restoration_artifact: ObservationArtifact | None = None

    def command(
        self,
        role: str,
        argv: tuple[str, ...],
        *,
        timeout: float = COMMAND_TIMEOUT_SECONDS,
        honor_cancellation: bool = True,
    ) -> dict[str, Any]:
        if honor_cancellation:
            _check_cancelled(self.cancelled)
        return _command_document(
            self.capture,
            self.repository,
            role=role,
            argv=argv,
            timeout=timeout,
        )

    def publish(
        self,
        *,
        subject: str,
        kind: str,
        filename: str,
        value: dict[str, Any],
    ) -> ObservationArtifact:
        data = canonical_json(value) + b"\n"
        try:
            return self.capture.write_bytes(
                subject=subject,
                kind=kind,
                relative=f"{OBSERVATION_DIRECTORY}/{filename}",
                data=data,
            )
        except (PhysicalCaptureSessionError, PhysicalObservationError) as error:
            raise PerformanceCaptureError(
                "performance_observation_archive_failed",
                f"cannot exclusively archive performance observation {filename}",
            ) from error

    def capture_signing(self) -> None:
        for component in sorted(contract.COMPONENT_IDENTITIES):
            expected = contract.COMPONENT_IDENTITIES[component]
            command = self.command(
                "performance-codesign",
                (
                    "/usr/bin/codesign",
                    "-d",
                    "-r-",
                    "--verbose=4",
                    expected["codesign_target"],
                ),
            )
            lines = (command["stdout"] + command["stderr"]).splitlines()
            values: dict[str, str] = {}
            for field in ("Executable", "Identifier", "TeamIdentifier", "CDHash"):
                matches = [line.split("=", 1)[1] for line in lines if line.startswith(f"{field}=")]
                if len(matches) != 1:
                    raise PerformanceCaptureError(
                        "signing_identity_ambiguous",
                        f"codesign output has no unique {field} for {component}",
                    )
                values[field] = matches[0]
            requirements = [
                line.removeprefix("designated => ")
                for line in lines
                if line.startswith("designated => ")
            ]
            if len(requirements) != 1:
                raise PerformanceCaptureError(
                    "signing_identity_ambiguous",
                    f"codesign output has no unique requirement for {component}",
                )
            observation = {
                "component": component,
                "identity": {
                    "executable": values["Executable"],
                    "team_id": values["TeamIdentifier"],
                    "signing_identifier": values["Identifier"],
                    "cdhash": values["CDHash"].lower(),
                    "designated_requirement_sha256": hashlib.sha256(
                        requirements[0].encode("utf-8")
                    ).hexdigest(),
                },
                "command": command,
            }
            try:
                parsed = contract._signing_observation(
                    observation, f"performance signing {component}"
                )
            except (PerformanceLedgerError, RawArtifactError) as error:
                raise PerformanceCaptureError(
                    "signing_identity_invalid",
                    f"installed signing identity is invalid for {component}",
                ) from error
            self.signing_values.append(observation)
            self.signing_by_component[component] = parsed

    def request_mode(self, mode: str, *, reason: str, iteration: int) -> None:
        _check_cancelled(self.cancelled)
        started = time.monotonic()
        deadline = _utc_now() + timedelta(seconds=MODE_CHANGE_TIMEOUT_SECONDS)
        try:
            self.operator.request_terminal_mode(
                mode,
                reason=reason,
                iteration=iteration,
                deadline=deadline,
            )
        except Exception as error:
            raise PerformanceCaptureError(
                "operator_mode_change_failed",
                f"operator did not complete {mode} checkpoint",
            ) from error
        if time.monotonic() - started > MODE_CHANGE_TIMEOUT_SECONDS:
            raise PerformanceCaptureError(
                "operator_mode_change_timeout",
                f"operator exceeded the fixed {mode} checkpoint timeout",
            )
        _check_cancelled(self.cancelled)

    def observe_state(self, expected_mode: str) -> tuple[dict[str, Any], dict[str, Any]]:
        query_end = _log_query_boundary(_utc_now(), upper=True)
        _wait_until_wall(query_end, self.cancelled)
        command = self.command(
            "product-observation-log",
            (
                "/usr/bin/log",
                "show",
                "--style",
                "ndjson",
                "--info",
                "--timezone",
                "UTC",
                "--start",
                _log_query_timestamp(
                    _log_query_boundary(self.log_start, upper=False)
                ),
                "--end",
                _log_query_timestamp(query_end),
                "--predicate",
                contract.PRODUCT_LOG_PREDICATE,
            ),
        )
        projected: list[dict[str, Any]] = []
        try:
            for index, line in enumerate(command["stdout"].splitlines()):
                if not line.strip():
                    continue
                entry = contract._strict_json(line, f"product log[{index}]")
                if isinstance(entry, dict) and contract.LOG_ENTRY_FIELDS <= set(entry):
                    projected.append(
                        {field: entry[field] for field in contract.LOG_ENTRY_FIELDS}
                    )
        except PerformanceLedgerError as error:
            raise PerformanceCaptureError(
                "product_observation_invalid", "Unified Log output is not strict NDJSON"
            ) from error
        matching = [
            entry
            for entry in projected
            if entry["processImagePath"]
            == contract.COMPONENT_IDENTITIES["host"]["executable"]
            and entry["subsystem"] == contract.PRODUCT_LOG_SUBSYSTEM
            and entry["category"] == contract.PRODUCT_LOG_CATEGORY
            and isinstance(entry["machTimestamp"], int)
            and isinstance(entry["eventMessage"], str)
            and entry["eventMessage"].startswith(contract.PRODUCT_OBSERVATION_PREFIX)
        ]
        if not matching:
            raise PerformanceCaptureError(
                "product_observation_missing",
                "fixed Unified Log query returned no signed Host state",
            )
        log_entry = max(matching, key=lambda entry: entry["machTimestamp"])
        message = log_entry["eventMessage"].removeprefix(contract.PRODUCT_OBSERVATION_PREFIX)
        try:
            event = contract._strict_json(message, "product event")
            observation = {
                "log_entry": log_entry,
                "event": event,
                "query_command": command,
            }
            parsed = contract._product_observation(
                observation,
                candidate=self.candidate,
                label="performance product observation",
            )
        except (PerformanceLedgerError, RawArtifactError) as error:
            raise PerformanceCaptureError(
                "product_observation_invalid",
                "latest signed Host state failed strict validation",
            ) from error
        if parsed["state"]["desired_mode"] != expected_mode:
            raise PerformanceCaptureError(
                "product_terminal_mode_mismatch",
                f"signed Host state did not reach exact terminal mode {expected_mode}",
            )
        # Retain only the latest event's second as the next query floor.  This
        # still reopens the carried signed event and every later transition,
        # while preventing a three-hour run from duplicating its full log
        # history into every sample and overflowing the bounded ledger.
        self.log_start = parsed["recorded_at"]
        return observation, parsed

    def discover_roster(
        self, mode: str
    ) -> tuple[tuple[str, ...], list[dict[str, Any]], dict[str, int]]:
        components = contract._EXPECTED_ROSTER[mode]
        commands: list[dict[str, Any]] = []
        pids: dict[str, int] = {}
        for component in components:
            executable = contract.COMPONENT_IDENTITIES[component]["executable"]
            command = self.command(
                "performance-owner-discovery",
                (
                    "/usr/bin/pgrep",
                    "-x",
                    contract.PROCESS_NAMES[component],
                ),
            )
            values = [line for line in command["stdout"].splitlines() if line]
            if len(values) != 1 or not values[0].isdigit():
                raise PerformanceCaptureError(
                    "process_roster_ambiguous",
                    f"fixed process discovery did not return one {component}",
                )
            pid = int(values[0])
            if not 1 <= pid <= 2**31 - 1 or pid in pids.values():
                raise PerformanceCaptureError(
                    "process_roster_ambiguous",
                    f"fixed process discovery returned an invalid {component} PID",
                )
            commands.append(command)
            pids[component] = pid
        return components, commands, pids

    def capture_roster(
        self,
        components: tuple[str, ...],
        pids: dict[str, int],
        observation: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
        command = self.command(
            "performance-process-roster",
            (
                "/bin/ps",
                "-p",
                ",".join(str(pid) for pid in sorted(pids.values())),
                "-o",
                "pid=,uid=,lstart=,comm=",
            ),
        )
        try:
            rows = contract._ps_roster_rows(
                command["stdout"], "performance process roster"
            )
        except PerformanceLedgerError as error:
            raise PerformanceCaptureError(
                "process_roster_invalid", "fixed ps output is not an exact roster"
            ) from error
        if set(rows) != set(pids.values()):
            raise PerformanceCaptureError(
                "process_roster_invalid", "fixed ps output differs from discovered PIDs"
            )
        event_sha256 = hashlib.sha256(canonical_json(observation["event"])).hexdigest()
        roster: list[dict[str, Any]] = []
        runtime_commands: list[dict[str, Any]] = []
        for component in components:
            pid = pids[component]
            uid, start_time, executable = rows[pid]
            signing = self.signing_by_component[component]
            identity = signing["identity"]
            process = {
                "component": component,
                "pid": pid,
                "uid": uid,
                "start_time": start_time,
                "executable": executable,
                "team_id": identity["team_id"],
                "signing_identifier": identity["signing_identifier"],
                "cdhash": identity["cdhash"],
                "designated_requirement_sha256": identity[
                    "designated_requirement_sha256"
                ],
                "product_event_sha256": event_sha256 if component == "host" else None,
                "signing_observation_sha256": signing["observation_sha256"],
            }
            runtime_command = self.command(
                "performance-runtime-codesign",
                (
                    "/usr/bin/codesign",
                    "-d",
                    "-r-",
                    "--verbose=4",
                    executable,
                ),
            )
            process["runtime_signing_command"] = runtime_command
            roster.append(process)
            runtime_commands.append(runtime_command)
        return roster, command, runtime_commands

    def sample(
        self,
        *,
        kind: str,
        expected_mode: str,
        measurement_factory: Callable[
            [tuple[str, ...], dict[str, int]], tuple[dict[str, Any], list[dict[str, Any]]]
        ],
    ) -> dict[str, Any]:
        components, discoveries, pids = self.discover_roster(expected_mode)
        measurement, _measurement_commands = measurement_factory(components, pids)
        observation, parsed = self.observe_state(expected_mode)
        if pids["host"] != parsed["process"]["pid"]:
            raise PerformanceCaptureError(
                "host_process_mismatch",
                "fixed Host process discovery differs from signed Host event",
            )
        roster, roster_command, runtime_signing_commands = self.capture_roster(
            components, pids, observation
        )
        raw = {
            "sequence": len(self.samples),
            "kind": kind,
            "wall_time": runtime_signing_commands[-1]["completed_at"],
            "monotonic_ns": time.monotonic_ns(),
            "operation_id": contract.operation_id(parsed),
            "generation": parsed["state"]["generation"],
            "mode": parsed["state"]["desired_mode"],
            "terminal_state": parsed["state"]["phase"],
            "state_observation": observation,
            "roster": roster,
            "roster_discovery_commands": discoveries,
            "roster_command": roster_command,
            "measurement": measurement,
        }
        self.samples.append(raw)
        return raw

    @staticmethod
    def transition_measurement(index: int) -> Callable[
        [tuple[str, ...], dict[str, int]], tuple[dict[str, Any], list[dict[str, Any]]]
    ]:
        return lambda _components, _pids: ({"pair_index": index}, [])

    def network_measurement(
        self, *, index: int, index_field: str = "pair_index"
    ) -> Callable[
        [tuple[str, ...], dict[str, int]], tuple[dict[str, Any], list[dict[str, Any]]]
    ]:
        def produce(
            _components: tuple[str, ...], _pids: dict[str, int]
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            command = self.command(
                "performance-network-quality",
                (
                    "/usr/bin/networkQuality",
                    "-c",
                    "-M",
                    str(contract.NETWORK_QUALITY_MAX_SECONDS),
                ),
                timeout=NETWORK_TIMEOUT_SECONDS,
            )
            try:
                _parsed, rtt, throughput = contract._network_quality(
                    command, "performance networkQuality"
                )
            except PerformanceLedgerError as error:
                raise PerformanceCaptureError(
                    "network_quality_invalid",
                    "networkQuality did not return complete positive JSON metrics",
                ) from error
            return (
                {
                    index_field: index,
                    "command": command,
                    "base_rtt_ms": rtt,
                    "download_mbps": throughput,
                },
                [command],
            )

        return produce

    def resource_measurement(
        self, *, index: int
    ) -> Callable[
        [tuple[str, ...], dict[str, int]], tuple[dict[str, Any], list[dict[str, Any]]]
    ]:
        def produce(
            components: tuple[str, ...], pids: dict[str, int]
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            values = sorted(pids[component] for component in components)
            command = self.command(
                "performance-resource",
                (
                    "/bin/ps",
                    "-p",
                    ",".join(str(pid) for pid in values),
                    "-o",
                    "pid=,pcpu=,rss=",
                ),
            )
            try:
                _parsed, cpu, rss = contract._resource_command(
                    command,
                    tuple({"pid": pid} for pid in values),
                    "performance resource",
                )
            except PerformanceLedgerError as error:
                raise PerformanceCaptureError(
                    "resource_observation_invalid", "fixed ps resource output is invalid"
                ) from error
            return (
                {
                    "index": index,
                    "command": command,
                    "cpu_percent": cpu,
                    "rss_mib": rss,
                },
                [command],
            )

        return produce

    def switch_measurement(
        self, *, index: int
    ) -> Callable[
        [tuple[str, ...], dict[str, int]], tuple[dict[str, Any], list[dict[str, Any]]]
    ]:
        def produce(
            components: tuple[str, ...], pids: dict[str, int]
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            values = sorted(pids[component] for component in components)
            resource = self.command(
                "performance-resource",
                (
                    "/bin/ps",
                    "-p",
                    ",".join(str(pid) for pid in values),
                    "-o",
                    "pid=,pcpu=,rss=",
                ),
            )
            fds = self.command(
                "performance-file-descriptors",
                (
                    "/usr/sbin/lsof",
                    "-nP",
                    "-a",
                    "-p",
                    ",".join(str(pid) for pid in values),
                ),
            )
            roster = tuple({"pid": pid} for pid in values)
            try:
                _resource, cpu, rss = contract._resource_command(
                    resource, roster, "performance switch resource"
                )
                _fd, fd_count = contract._fd_command(
                    fds, roster, "performance switch descriptors"
                )
            except PerformanceLedgerError as error:
                raise PerformanceCaptureError(
                    "switch_resource_invalid", "fixed switch ps/lsof output is invalid"
                ) from error
            return (
                {
                    "index": index,
                    "resource_command": resource,
                    "fd_command": fds,
                    "cpu_percent": cpu,
                    "rss_mib": rss,
                    "fd_count": fd_count,
                },
                [resource, fds],
            )

        return produce

    def shaping_intent(self) -> dict[str, Any]:
        try:
            self.operator.confirm_privileged_preflight(
                PRIVILEGE_PREFLIGHT_INSTRUCTION
            )
        except Exception as error:
            raise PerformanceCaptureError(
                "operator_privilege_preflight_failed",
                "operator did not confirm the explicit sudo ticket step",
            ) from error
        preflight = self.command(
            "performance-sudo-preflight", ("/usr/bin/sudo", "-n", "-v")
        )
        original_pf_status = self.command(
            "performance-pf-status", contract._pf_status_argv()
        )
        original_pf = self.command(
            "performance-pf-query", contract._pf_query_argv()
        )
        original_pipes = [
            self.command(
                "performance-dnctl-query",
                contract._pipe_query_argv(
                    contract.WEAK_NETWORK_PROFILES[profile_id]["pipe_id"]
                ),
            )
            for profile_id in sorted(contract.WEAK_NETWORK_PROFILES)
        ]
        transactions = [
            {"index": index, "profile_id": profile_id}
            for index, profile_id in enumerate(
                profile_id
                for profile_id in sorted(contract.WEAK_NETWORK_PROFILES)
                for _ in range(contract.SERIES_SAMPLE_COUNT)
            )
        ]
        intent = {
            "schema_version": 1,
            "document": contract.SHAPING_INTENT_DOCUMENT,
            "candidate": copy.deepcopy(self.candidate),
            "run": copy.deepcopy(self.run),
            "created_at": _timestamp(_utc_now()),
            "privilege_preflight": preflight,
            "anchor": contract.PF_ANCHOR,
            "profiles": [
                {"id": profile_id, **contract.WEAK_NETWORK_PROFILES[profile_id]}
                for profile_id in sorted(contract.WEAK_NETWORK_PROFILES)
            ],
            "original_state": {
                "pf_status_query": original_pf_status,
                "pf_query": original_pf,
                "pipe_queries": original_pipes,
            },
            "transactions": transactions,
        }
        try:
            contract._intent(intent, candidate=self.candidate, run=self.run)
        except (PerformanceLedgerError, RawArtifactError) as error:
            raise PerformanceCaptureError(
                "shaping_intent_invalid",
                "pre-mutation shaping WAL failed strict validation",
            ) from error
        self.intent_artifact = self.publish(
            subject=INTENT_OBSERVATION_SUBJECT,
            kind=contract.SHAPING_KIND,
            filename="shaping-intent.json",
            value=intent,
        )
        return intent

    def _restore_profile(
        self, profile_id: str
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[tuple[str, PerformanceCaptureError]],
    ]:
        pipe_id = contract.WEAK_NETWORK_PROFILES[profile_id]["pipe_id"]
        restore_argvs = contract._restore_argvs(pipe_id)
        commands: list[dict[str, Any]] = []
        queries: list[dict[str, Any]] = []
        failures: list[tuple[str, PerformanceCaptureError]] = []
        for role, argv in (
            ("performance-pf-restore", restore_argvs[0]),
            ("performance-dnctl-restore", restore_argvs[1]),
        ):
            try:
                commands.append(
                    self.command(role, argv, honor_cancellation=False)
                )
            except PerformanceCaptureError as error:
                failures.append((role, error))
        for role, argv in (
            ("performance-dnctl-query", contract._pipe_query_argv(pipe_id)),
            ("performance-pf-query", contract._pf_query_argv()),
        ):
            try:
                queries.append(self.command(role, argv, honor_cancellation=False))
            except PerformanceCaptureError as error:
                failures.append((role, error))
        return commands, queries, failures

    @staticmethod
    def _cleanup_is_empty(
        profile_id: str, restoration_queries: list[dict[str, Any]]
    ) -> bool:
        if len(restoration_queries) != 2:
            return False
        pipe_id = contract.WEAK_NETWORK_PROFILES[profile_id]["pipe_id"]
        dnctl, pf = restoration_queries
        return (
            isinstance(dnctl.get("stdout"), str)
            and re.search(rf"\b{re.escape(pipe_id)}\b", dnctl["stdout"]) is None
            and isinstance(pf.get("stdout"), str)
            and not pf["stdout"].strip()
        )

    def _record_failed_restoration(
        self,
        *,
        profile_id: str,
        index: int,
        restore_commands: list[dict[str, Any]],
        restoration_queries: list[dict[str, Any]],
        restoration_failures: list[tuple[str, PerformanceCaptureError]],
        cleanup_succeeded: bool,
    ) -> None:
        if self.intent_artifact is None:
            raise PerformanceCaptureError(
                "shaping_failure_unobservable",
                "shaping restoration failure has no durable intent binding",
            )
        value = {
            "schema_version": RESTORATION_FAILURE_SCHEMA_VERSION,
            "document": RESTORATION_FAILURE_DOCUMENT,
            "candidate": copy.deepcopy(self.candidate),
            "run": copy.deepcopy(self.run),
            "transaction_index": index,
            "profile_id": profile_id,
            "cleanup_succeeded": cleanup_succeeded,
            "recorded_at": _timestamp(_utc_now()),
            "state": self.session.state.value,
            "archive_root": self.session.archive.root_relative_to_target,
            "journal_tip_sha256": self.session.snapshot.last_event_sha256,
            "context_sha256": self.context_sha256,
            "shaping_intent_sha256": self.intent_artifact.descriptor.sha256,
            "restore_commands": restore_commands,
            "restoration_queries": restoration_queries,
            "failures": [
                {"role": role, "code": error.code}
                for role, error in restoration_failures
            ],
        }
        try:
            self.capture.write_bytes(
                subject="performance:shaping-restoration-failure",
                kind=contract.SHAPING_KIND,
                relative=FAILURE_RESTORATION_RELATIVE,
                data=canonical_json(value) + b"\n",
            )
        except (PhysicalCaptureSessionError, PhysicalObservationError) as error:
            raise PerformanceCaptureError(
                "shaping_failure_unobservable",
                "shaping failure cleanup could not be durably recorded",
            ) from error

    def shaping_transaction(
        self,
        *,
        profile_id: str,
        index: int,
    ) -> dict[str, Any]:
        profile = contract.WEAK_NETWORK_PROFILES[profile_id]
        pipe_id = profile["pipe_id"]
        applied_ns = time.monotonic_ns()
        apply_commands: list[dict[str, Any]] = []
        effective_queries: list[dict[str, Any]] = []
        restore_commands: list[dict[str, Any]] = []
        restoration_queries: list[dict[str, Any]] = []
        failure: BaseException | None = None
        try:
            apply_commands = [
                self.command(
                    "performance-dnctl-apply",
                    contract._dnctl_apply_argv(profile_id),
                ),
                self.command(
                    "performance-pf-apply", contract._pf_apply_argv(profile_id)
                ),
            ]
            effective_queries = [
                self.command(
                    "performance-dnctl-query", contract._pipe_query_argv(pipe_id)
                ),
                self.command("performance-pf-query", contract._pf_query_argv()),
            ]
            if profile["kind"] == "outage":
                _wait_until(
                    applied_ns + profile["outage_seconds"] * 1_000_000_000,
                    self.cancelled,
                )
        except BaseException as error:
            failure = error
        restore_commands, restoration_queries, restoration_failures = (
            self._restore_profile(profile_id)
        )
        if failure is None and restoration_failures:
            failure = restoration_failures[0][1]
        restored_ns = time.monotonic_ns()
        if failure is not None:
            cleanup_succeeded = self._cleanup_is_empty(
                profile_id, restoration_queries
            )
            self._record_failed_restoration(
                profile_id=profile_id,
                index=index,
                restore_commands=restore_commands,
                restoration_queries=restoration_queries,
                restoration_failures=restoration_failures,
                cleanup_succeeded=cleanup_succeeded,
            )
            raise PerformanceCaptureError(
                "shaping_transaction_failed",
                "weak-network transaction failed; this session must be abandoned",
            ) from failure
        transaction = {
            "index": index,
            "profile_id": profile_id,
            "applied_monotonic_ns": applied_ns,
            "restored_monotonic_ns": restored_ns,
            "apply_commands": apply_commands,
            "effective_queries": effective_queries,
            "restore_commands": restore_commands,
            "restoration_queries": restoration_queries,
        }
        self.shaping_transactions.append(transaction)
        return transaction

    def weak_measurement(
        self, *, transaction: dict[str, Any]
    ) -> Callable[
        [tuple[str, ...], dict[str, int]], tuple[dict[str, Any], list[dict[str, Any]]]
    ]:
        network = self.network_measurement(index=transaction["index"])

        def produce(
            components: tuple[str, ...], pids: dict[str, int]
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            measurement, commands = network(components, pids)
            return (
                {
                    "transaction_index": transaction["index"],
                    "profile_id": transaction["profile_id"],
                    "command": measurement["command"],
                    "base_rtt_ms": measurement["base_rtt_ms"],
                    "download_mbps": measurement["download_mbps"],
                },
                commands,
            )

        return produce

    def complete_shaping(self, intent: dict[str, Any]) -> dict[str, Any]:
        if self.intent_artifact is None:
            raise PerformanceCaptureError(
                "shaping_intent_missing", "cannot restore shaping without its durable WAL"
            )
        restoration = {
            "schema_version": 1,
            "document": contract.SHAPING_RESTORATION_DOCUMENT,
            "candidate": copy.deepcopy(self.candidate),
            "run": copy.deepcopy(self.run),
            "intent_artifact": self.intent_artifact.descriptor.as_dict(),
            "completed_at": _timestamp(_utc_now()),
            "transactions": self.shaping_transactions,
        }
        try:
            parsed_intent = contract._intent(
                intent, candidate=self.candidate, run=self.run
            )
            contract._restoration(
                restoration,
                intent_descriptor=self.intent_artifact.descriptor.as_dict(),
                intent=parsed_intent,
                candidate=self.candidate,
                run=self.run,
            )
        except (PerformanceLedgerError, RawArtifactError) as error:
            raise PerformanceCaptureError(
                "shaping_restoration_invalid",
                "complete shaping restoration failed strict validation",
            ) from error
        self.restoration_artifact = self.publish(
            subject=RESTORATION_OBSERVATION_SUBJECT,
            kind=contract.SHAPING_KIND,
            filename="shaping-restoration.json",
            value=restoration,
        )
        return restoration

    def crash_measurement(
        self,
        *,
        stage: str,
        window_start: datetime,
        window_end: datetime,
    ) -> Callable[
        [tuple[str, ...], dict[str, int]], tuple[dict[str, Any], list[dict[str, Any]]]
    ]:
        home = Path.home()
        expected_home = re.fullmatch(r"/Users/[^/]+", str(home))
        if expected_home is None:
            raise PerformanceCaptureError(
                "diagnostic_home_invalid",
                "collector user home is not one fixed /Users account",
            )
        user_reports = f"{home}/Library/Logs/DiagnosticReports"

        def produce(
            _components: tuple[str, ...], _pids: dict[str, int]
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            query_start = _log_query_boundary(window_start, upper=False)
            query_end = _log_query_boundary(window_end, upper=True)
            _wait_until_wall(query_end, self.cancelled)
            diagnostic = self.command(
                "performance-diagnostic-inventory",
                (
                    "/usr/bin/find",
                    "-s",
                    "/Library/Logs/DiagnosticReports",
                    user_reports,
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
                ),
            )
            paths = [line for line in diagnostic["stdout"].splitlines() if line]
            crash_log = self.command(
                "performance-crash-log",
                (
                    "/usr/bin/log",
                    "show",
                    "--style",
                    "ndjson",
                    "--info",
                    "--timezone",
                    "UTC",
                    "--start",
                    _log_query_timestamp(query_start),
                    "--end",
                    _log_query_timestamp(query_end),
                    "--predicate",
                    contract.CRASH_LOG_PREDICATE,
                ),
            )
            entries: list[Any] = []
            try:
                entries = [
                    contract._strict_json(line, f"performance crash log[{index}]")
                    for index, line in enumerate(crash_log["stdout"].splitlines())
                    if line.strip()
                ]
            except PerformanceLedgerError as error:
                raise PerformanceCaptureError(
                    "crash_log_invalid", "fixed crash-log output is not strict NDJSON"
                ) from error
            return (
                {
                    "stage": stage,
                    "diagnostic_command": diagnostic,
                    "crash_log_command": crash_log,
                    "diagnostic_paths": paths,
                    "crash_log_entries": entries,
                },
                [diagnostic, crash_log],
            )

        return produce

    def capture_soak(self) -> None:
        self.request_mode("tunnel", reason="three-hour-soak", iteration=0)
        baseline_started = _utc_now() - timedelta(seconds=1)
        baseline = self.sample(
            kind="crash-baseline",
            expected_mode="tunnel",
            measurement_factory=self.crash_measurement(
                stage="baseline",
                window_start=baseline_started,
                window_end=_utc_now(),
            ),
        )
        heartbeat_zero = self.sample(
            kind="soak-heartbeat",
            expected_mode="tunnel",
            measurement_factory=lambda _components, _pids: ({"index": 0}, []),
        )
        base_ns = heartbeat_zero["monotonic_ns"]
        schedule: list[tuple[int, str, int]] = []
        schedule.extend(
            (
                base_ns + round(300.5 * index * 1_000_000_000),
                "heartbeat",
                index,
            )
            for index in range(1, contract.SOAK_HEARTBEAT_COUNT)
        )
        schedule.extend(
            (
                base_ns + (10 + 900 * index) * 1_000_000_000,
                "traffic",
                index,
            )
            for index in range(contract.SOAK_TRAFFIC_COUNT)
        )
        for deadline_ns, sample_type, index in sorted(schedule):
            _wait_until(deadline_ns, self.cancelled)
            if sample_type == "heartbeat":
                self.sample(
                    kind="soak-heartbeat",
                    expected_mode="tunnel",
                    measurement_factory=lambda _components, _pids, index=index: (
                        {"index": index},
                        [],
                    ),
                )
            else:
                self.sample(
                    kind="soak-traffic",
                    expected_mode="tunnel",
                    measurement_factory=self.network_measurement(
                        index=index, index_field="index"
                    ),
                )
        heartbeats = [
            sample for sample in self.samples if sample["kind"] == "soak-heartbeat"
        ]
        last_heartbeat = heartbeats[-1]
        final_window_end = datetime.fromisoformat(
            last_heartbeat["wall_time"][:-1] + "+00:00"
        )
        self.sample(
            kind="crash-final",
            expected_mode="tunnel",
            measurement_factory=self.crash_measurement(
                stage="final",
                window_start=datetime.fromisoformat(
                    heartbeat_zero["wall_time"][:-1] + "+00:00"
                )
                - timedelta(milliseconds=1),
                window_end=final_window_end,
            ),
        )
        if baseline["monotonic_ns"] > heartbeat_zero["monotonic_ns"]:
            raise PerformanceCaptureError(
                "soak_boundary_invalid", "crash baseline did not precede heartbeat zero"
            )

    def capture_series(self, intent: dict[str, Any]) -> None:
        # Force one real transition before the first Off sample so Unified Log
        # always contains a fresh, queryable terminal event even when the app
        # was already Off long before collection began.
        self.request_mode(
            "system_proxy", reason="transition-series-precondition", iteration=0
        )
        self.request_mode("off", reason="transition-series-start", iteration=0)
        for index in range(contract.SERIES_SAMPLE_COUNT):
            self.sample(
                kind="connect-start",
                expected_mode="off",
                measurement_factory=self.transition_measurement(index),
            )
            self.request_mode("tunnel", reason="connect-latency", iteration=index)
            self.sample(
                kind="connect-end",
                expected_mode="tunnel",
                measurement_factory=self.transition_measurement(index),
            )
            self.sample(
                kind="disconnect-start",
                expected_mode="tunnel",
                measurement_factory=self.transition_measurement(index),
            )
            self.request_mode("off", reason="disconnect-latency", iteration=index)
            self.sample(
                kind="disconnect-end",
                expected_mode="off",
                measurement_factory=self.transition_measurement(index),
            )
        for index in range(contract.SERIES_SAMPLE_COUNT):
            self.request_mode(
                "system_proxy", reason="throughput-libbox-baseline", iteration=index
            )
            self.sample(
                kind="network-baseline",
                expected_mode="system_proxy",
                measurement_factory=self.network_measurement(index=index),
            )
            self.request_mode("tunnel", reason="throughput-tunnel", iteration=index)
            self.sample(
                kind="network-measured",
                expected_mode="tunnel",
                measurement_factory=self.network_measurement(index=index),
            )
        for planned in intent["transactions"]:
            transaction = self.shaping_transaction(
                profile_id=planned["profile_id"], index=planned["index"]
            )
            self.sample(
                kind="weak-recovery",
                expected_mode="tunnel",
                measurement_factory=self.weak_measurement(transaction=transaction),
            )
        self.complete_shaping(intent)
        for index in range(contract.SERIES_SAMPLE_COUNT):
            self.sample(
                kind="resource",
                expected_mode="tunnel",
                measurement_factory=self.resource_measurement(index=index),
            )
        for index in range(contract.SWITCH_SAMPLE_COUNT):
            mode = "system_proxy" if index % 2 == 0 else "tunnel"
            self.request_mode(mode, reason="mode-switch-cycle", iteration=index)
            self.sample(
                kind="switch",
                expected_mode=mode,
                measurement_factory=self.switch_measurement(index=index),
            )
        self.capture_soak()

    def complete_ledger(self) -> PerformanceObservationBatch:
        if self.intent_artifact is None or self.restoration_artifact is None:
            raise PerformanceCaptureError(
                "performance_shaping_incomplete",
                "ledger cannot close without intent and restoration artifacts",
            )
        ledger = {
            "schema_version": contract.LEDGER_SCHEMA_VERSION,
            "document": contract.LEDGER_DOCUMENT,
            "candidate": copy.deepcopy(self.candidate),
            "run": copy.deepcopy(self.run),
            "parameters": copy.deepcopy(self.parameters),
            "captured_at": self.signing_values[0]["command"]["started_at"],
            "completed_at": self.samples[-1]["wall_time"],
            "heartbeat_interval_seconds": contract.SOAK_HEARTBEAT_INTERVAL_SECONDS,
            "traffic_interval_seconds": contract.SOAK_TRAFFIC_INTERVAL_SECONDS,
            "signing_observations": self.signing_values,
            "shaping": {
                "intent_artifact": self.intent_artifact.descriptor.as_dict(),
                "restoration_artifact": self.restoration_artifact.descriptor.as_dict(),
            },
            "samples": self.samples,
        }
        evidence_root = (
            self.session.archive.repository
            / "target"
            / self.session.archive.root_relative_to_target
        ).absolute()
        try:
            with ArtifactReader(evidence_root) as artifacts:
                contract.validate_performance_ledger(ledger, artifacts=artifacts)
        except (PerformanceLedgerError, RawArtifactError) as error:
            raise PerformanceCaptureError(
                "performance_ledger_invalid",
                "captured performance ledger failed strict source validation",
            ) from error
        ledger_artifact = self.publish(
            subject=LEDGER_OBSERVATION_SUBJECT,
            kind=contract.LEDGER_KIND,
            filename="sample-ledger.json",
            value=ledger,
        )
        return PerformanceObservationBatch(
            ledger=ledger_artifact,
            shaping_intent=self.intent_artifact,
            shaping_restoration=self.restoration_artifact,
        )


def capture_performance_observations(
    *,
    session: PhysicalCaptureSession,
    context: object,
    parameters: object,
    operator: object,
    cancelled: Cancelled | None = None,
) -> PerformanceObservationBatch:
    """Execute the complete pre-nonce physical performance contract once."""

    if not isinstance(session, PhysicalCaptureSession):
        raise PerformanceCaptureError(
            "invalid_session",
            "performance capture requires a locked PhysicalCaptureSession",
        )
    cancellation = (lambda: False) if cancelled is None else cancelled
    if not callable(cancellation):
        raise PerformanceCaptureError(
            "invalid_cancellation", "performance cancellation source is not callable"
        )
    try:
        capture = session.observation_capture()
    except PhysicalCaptureSessionError as error:
        raise PerformanceCaptureError(
            "performance_collection_closed",
            "performance capture may run only before RAW_COMPLETED",
        ) from error
    candidate, run, parsed_parameters = _capture_inputs(context, parameters)
    selected_operator = _require_operator(operator)
    _validate_profile_files()
    recorder = _Recorder(
        session=session,
        capture=capture,
        candidate=candidate,
        run=run,
        context_sha256=hashlib.sha256(canonical_json(context) + b"\n").hexdigest(),
        parameters=parsed_parameters,
        operator=selected_operator,
        cancelled=cancellation,
    )
    recorder.capture_signing()
    intent = recorder.shaping_intent()
    recorder.capture_series(intent)
    try:
        session.require_collection_open()
    except PhysicalCaptureSessionError as error:
        raise PerformanceCaptureError(
            "performance_collection_closed",
            "collection closed before the performance ledger was archived",
        ) from error
    return recorder.complete_ledger()


_RESTORATION_FAILURE_CODES: Final = frozenset(
    {
        "fixed_command_failed",
        "observer_executable_drifted",
        "observer_executable_unreadable",
        "observer_executable_unsafe",
    }
)


def _validate_restoration_outcome(
    *,
    profile_id: str,
    restore_commands: object,
    restoration_queries: object,
    failures: object,
    label: str,
) -> tuple[list[dict[str, Any]], bool, bool]:
    pipe_id = contract.WEAK_NETWORK_PROFILES[profile_id]["pipe_id"]
    restore_argvs = contract._restore_argvs(pipe_id)
    restore_specs = (
        ("performance-pf-restore", restore_argvs[0]),
        ("performance-dnctl-restore", restore_argvs[1]),
    )
    query_specs = (
        ("performance-dnctl-query", contract._pipe_query_argv(pipe_id)),
        ("performance-pf-query", contract._pf_query_argv()),
    )
    if not isinstance(restore_commands, list) or not isinstance(
        restoration_queries, list
    ):
        raise RawArtifactError(f"{label} command groups are not lists")

    parsed_commands: list[dict[str, Any]] = []
    successful_roles: list[str] = []
    for group_name, raw_commands, specifications in (
        ("restore_commands", restore_commands, restore_specs),
        ("restoration_queries", restoration_queries, query_specs),
    ):
        if len(raw_commands) > len(specifications):
            raise RawArtifactError(f"{label} has too many command results")
        specification_by_role = {role: argv for role, argv in specifications}
        group_roles: list[str] = []
        for command_index, raw_command in enumerate(raw_commands):
            if not isinstance(raw_command, dict):
                raise RawArtifactError(f"{label} command is not an object")
            role = raw_command.get("role")
            if (
                not isinstance(role, str)
                or role not in specification_by_role
                or role in group_roles
            ):
                raise RawArtifactError(f"{label} command role is invalid")
            parsed_commands.append(
                contract._sudo_command(
                    raw_command,
                    role=role,
                    argv=specification_by_role[role],
                    label=f"{label}.{group_name}[{command_index}]",
                )
            )
            group_roles.append(role)
        successful_roles.extend(group_roles)

    if not isinstance(failures, list) or len(failures) > 4:
        raise RawArtifactError(f"{label} failures are not bounded")
    failure_roles: list[str] = []
    for failure_index, raw_failure in enumerate(failures):
        failure = exact_object(
            raw_failure,
            {"role", "code"},
            f"{label}.failures[{failure_index}]",
        )
        role = failure["role"]
        code = failure["code"]
        if (
            not isinstance(role, str)
            or not isinstance(code, str)
            or role in failure_roles
            or code not in _RESTORATION_FAILURE_CODES
        ):
            raise RawArtifactError(f"{label} failure is invalid")
        failure_roles.append(role)

    expected_roles = [role for role, _argv in (*restore_specs, *query_specs)]
    failure_role_set = set(failure_roles)
    if (
        successful_roles
        != [role for role in expected_roles if role not in failure_role_set]
        or failure_roles
        != [role for role in expected_roles if role in failure_role_set]
        or set(successful_roles) & failure_role_set
        or (set(successful_roles) | failure_role_set) != set(expected_roles)
    ):
        raise RawArtifactError(f"{label} command outcomes are incomplete")

    parsed_by_role = {command["role"]: command for command in parsed_commands}
    dnctl_query = parsed_by_role.get("performance-dnctl-query")
    pf_query = parsed_by_role.get("performance-pf-query")
    empty_state = (
        dnctl_query is not None
        and pf_query is not None
        and re.search(rf"\b{re.escape(pipe_id)}\b", dnctl_query["stdout"])
        is None
        and not pf_query["stdout"].strip()
    )
    return parsed_commands, empty_state, not failures and empty_state


def validate_shaping_restoration_failure(
    data: bytes,
    *,
    expected_candidate: dict[str, Any],
    expected_run: dict[str, Any],
    expected_state: str,
    expected_archive_root: str,
    expected_journal_tip_sha256: str,
    expected_context_sha256: str,
    expected_shaping_intent_sha256: str,
    parsed_intent: dict[str, Any],
    abandonment_recorded_at: datetime,
) -> datetime:
    """Strictly reopen the source-owned failed shaping restoration record."""

    fields = {
        "schema_version",
        "document",
        "candidate",
        "run",
        "transaction_index",
        "profile_id",
        "cleanup_succeeded",
        "recorded_at",
        "state",
        "archive_root",
        "journal_tip_sha256",
        "context_sha256",
        "shaping_intent_sha256",
        "restore_commands",
        "restoration_queries",
        "failures",
    }
    try:
        value = load_json_bytes(data, "shaping restoration failure")
        failure = exact_object(value, fields, "shaping restoration failure")
        if canonical_json(failure) + b"\n" != data:
            raise RawArtifactError("shaping restoration failure is not canonical JSON")
        candidate = contract._candidate(failure["candidate"])
        run = contract._run(failure["run"])
        recorded_at = contract._timestamp(
            failure["recorded_at"], "shaping restoration failure.recorded_at"
        )
        transaction_index = failure["transaction_index"]
        transactions = parsed_intent["transactions"]
        if (
            type(failure["schema_version"]) is not int
            or failure["schema_version"] != RESTORATION_FAILURE_SCHEMA_VERSION
            or failure["document"] != RESTORATION_FAILURE_DOCUMENT
            or candidate != expected_candidate
            or run != expected_run
            or type(transaction_index) is not int
            or not 0 <= transaction_index < len(transactions)
            or failure["profile_id"]
            != transactions[transaction_index]["profile_id"]
            or expected_state != "collecting"
            or failure["state"] != expected_state
            or failure["archive_root"] != expected_archive_root
            or failure["journal_tip_sha256"] != expected_journal_tip_sha256
            or failure["context_sha256"] != expected_context_sha256
            or failure["shaping_intent_sha256"]
            != expected_shaping_intent_sha256
            or re.fullmatch(r"[0-9a-f]{64}", failure["journal_tip_sha256"])
            is None
            or re.fullmatch(r"[0-9a-f]{64}", failure["context_sha256"])
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}", failure["shaping_intent_sha256"]
            )
            is None
            or recorded_at < parsed_intent["created_at"]
            or recorded_at >= abandonment_recorded_at + timedelta(seconds=1)
        ):
            raise RawArtifactError("shaping restoration failure identity differs")
        parsed_commands, cleanup_succeeded, _restored = (
            _validate_restoration_outcome(
                profile_id=failure["profile_id"],
                restore_commands=failure["restore_commands"],
                restoration_queries=failure["restoration_queries"],
                failures=failure["failures"],
                label="shaping restoration failure",
            )
        )
        if (
            type(failure["cleanup_succeeded"]) is not bool
            or failure["cleanup_succeeded"] is not cleanup_succeeded
        ):
            raise RawArtifactError(
                "shaping restoration cleanup flag differs from command outcomes"
            )
        if parsed_commands:
            started_at, completed_at = contract._ordered_commands(
                parsed_commands, "shaping restoration failure commands"
            )
            if (
                started_at < parsed_intent["created_at"]
                or completed_at > recorded_at
            ):
                raise RawArtifactError(
                    "shaping restoration failure command times escape its window"
                )
    except (
        IndexError,
        KeyError,
        PerformanceLedgerError,
        RawArtifactError,
        TypeError,
        ValueError,
    ) as error:
        raise PerformanceCaptureError(
            "shaping_restoration_failure_invalid",
            "shaping restoration failure failed strict reopening",
        ) from error
    return recorded_at


def _validate_restart_recovery_record(
    data: bytes,
    *,
    expected_candidate: dict[str, Any],
    expected_run: dict[str, Any],
    expected_attempt: int,
    expected_state: str,
    expected_archive_root: str,
    expected_journal_tip_sha256: str,
    expected_context_sha256: str,
    expected_shaping_intent_sha256: str,
    predecessor_recorded_at: datetime,
    abandonment_recorded_at: datetime,
) -> tuple[dict[str, Any], datetime, bool]:

    fields = {
        "schema_version",
        "document",
        "candidate",
        "run",
        "attempt",
        "recorded_at",
        "requires_session_abandonment",
        "state",
        "archive_root",
        "journal_tip_sha256",
        "context_sha256",
        "shaping_intent_sha256",
        "privilege_preflight",
        "records",
    }
    record_fields = {
        "profile_id",
        "restored",
        "restore_commands",
        "restoration_queries",
        "failures",
    }
    try:
        value = load_json_bytes(data, "shaping restart recovery")
        recovery = exact_object(value, fields, "shaping restart recovery")
        if canonical_json(recovery) + b"\n" != data:
            raise RawArtifactError("shaping restart recovery is not canonical JSON")
        candidate = contract._candidate(recovery["candidate"])
        run = contract._run(recovery["run"])
        recorded_at = contract._timestamp(
            recovery["recorded_at"], "shaping restart recovery.recorded_at"
        )
        if (
            type(recovery["schema_version"]) is not int
            or recovery["schema_version"] != RESTART_RECOVERY_SCHEMA_VERSION
            or recovery["document"] != RESTART_RECOVERY_DOCUMENT
            or candidate != expected_candidate
            or run != expected_run
            or type(recovery["attempt"]) is not int
            or recovery["attempt"] != expected_attempt
            or recovery["requires_session_abandonment"] is not True
            or expected_state != "collecting"
            or recovery["state"] != expected_state
            or recovery["archive_root"] != expected_archive_root
            or recovery["journal_tip_sha256"]
            != expected_journal_tip_sha256
            or recovery["context_sha256"] != expected_context_sha256
            or recovery["shaping_intent_sha256"]
            != expected_shaping_intent_sha256
            or re.fullmatch(
                r"[0-9a-f]{64}", recovery["journal_tip_sha256"]
            )
            is None
            or re.fullmatch(r"[0-9a-f]{64}", recovery["context_sha256"])
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}", recovery["shaping_intent_sha256"]
            )
            is None
            or recorded_at < predecessor_recorded_at
            or recorded_at
            >= abandonment_recorded_at + timedelta(seconds=1)
        ):
            raise RawArtifactError("shaping restart recovery identity differs")

        privilege_preflight = contract._sudo_command(
            recovery["privilege_preflight"],
            role="performance-sudo-preflight",
            argv=("/usr/bin/sudo", "-n", "-v"),
            label="shaping restart recovery.privilege_preflight",
        )

        records = recovery["records"]
        expected_profiles = sorted(contract.WEAK_NETWORK_PROFILES)
        if not isinstance(records, list) or len(records) != len(
            expected_profiles
        ):
            raise RawArtifactError("shaping restart recovery profile set is incomplete")
        parsed_commands: list[dict[str, Any]] = [privilege_preflight]
        all_restored = True
        for index, profile_id in enumerate(expected_profiles):
            item = exact_object(
                records[index],
                record_fields,
                f"shaping restart recovery.records[{index}]",
            )
            if item["profile_id"] != profile_id:
                raise RawArtifactError("shaping restart recovery profile order differs")
            parsed_groups, _empty_state, restored = (
                _validate_restoration_outcome(
                    profile_id=profile_id,
                    restore_commands=item["restore_commands"],
                    restoration_queries=item["restoration_queries"],
                    failures=item["failures"],
                    label=f"shaping restart recovery.records[{index}]",
                )
            )
            if type(item["restored"]) is not bool or item["restored"] is not restored:
                raise RawArtifactError(
                    "shaping restart recovery restored flag differs from outcomes"
                )
            all_restored = all_restored and restored
            parsed_commands.extend(parsed_groups)
        if parsed_commands:
            started_at, completed_at = contract._ordered_commands(
                parsed_commands, "shaping restart recovery commands"
            )
            if (
                started_at < predecessor_recorded_at
                or completed_at > recorded_at
            ):
                raise RawArtifactError(
                    "shaping restart recovery command times escape the attempt window"
                )
    except (
        KeyError,
        PerformanceLedgerError,
        RawArtifactError,
        TypeError,
        ValueError,
    ) as error:
        raise PerformanceCaptureError(
            "shaping_recovery_chain_invalid",
            "shaping restart recovery failed strict reopening",
        ) from error
    return recovery, recorded_at, all_restored


def validate_restart_recovery_chain(
    records: Sequence[tuple[int, bytes]],
    *,
    expected_candidate: dict[str, Any],
    expected_run: dict[str, Any],
    expected_state: str,
    expected_archive_root: str,
    expected_journal_tip_sha256: str,
    expected_context_sha256: str,
    expected_shaping_intent_sha256: str,
    intent_created_at: datetime,
    restoration_failure_recorded_at: datetime | None,
    predecessor_recorded_at: datetime,
    abandonment_recorded_at: datetime,
) -> RestartRecoveryStatus:
    """Strictly reopen the complete, ordered shaping recovery lifecycle."""

    attempts = [attempt for attempt, _data in records]
    if (
        not 1 <= len(records) <= MAX_RESTART_RECOVERY_ATTEMPTS
        or attempts != list(range(1, len(records) + 1))
    ):
        raise PerformanceCaptureError(
            "shaping_recovery_chain_invalid",
            "shaping restart recovery attempts are not contiguous and bounded",
        )
    if intent_created_at < predecessor_recorded_at:
        raise PerformanceCaptureError(
            "shaping_recovery_chain_invalid",
            "shaping intent predates its collecting journal predecessor",
        )
    previous_recorded_at = (
        intent_created_at
        if restoration_failure_recorded_at is None
        else restoration_failure_recorded_at
    )
    if previous_recorded_at < intent_created_at:
        raise PerformanceCaptureError(
            "shaping_recovery_chain_invalid",
            "shaping restoration failure predates its durable intent",
        )
    final_status: RestartRecoveryStatus | None = None
    for index, (attempt, data) in enumerate(records):
        _record, recorded_at, complete = _validate_restart_recovery_record(
            data,
            expected_candidate=expected_candidate,
            expected_run=expected_run,
            expected_attempt=attempt,
            expected_state=expected_state,
            expected_archive_root=expected_archive_root,
            expected_journal_tip_sha256=expected_journal_tip_sha256,
            expected_context_sha256=expected_context_sha256,
            expected_shaping_intent_sha256=expected_shaping_intent_sha256,
            predecessor_recorded_at=previous_recorded_at,
            abandonment_recorded_at=abandonment_recorded_at,
        )
        if index < len(records) - 1 and complete:
            raise PerformanceCaptureError(
                "shaping_recovery_chain_invalid",
                "a complete shaping recovery cannot precede another attempt",
            )
        if index > 0 and recorded_at <= previous_recorded_at:
            raise PerformanceCaptureError(
                "shaping_recovery_chain_invalid",
                "shaping restart recovery attempt times are not strictly increasing",
            )
        previous_recorded_at = recorded_at
        final_status = (
            RestartRecoveryStatus.COMPLETE
            if complete
            else RestartRecoveryStatus.INCOMPLETE
        )
    if final_status is None:  # pragma: no cover - records is non-empty above
        raise PerformanceCaptureError(
            "shaping_recovery_chain_invalid",
            "shaping restart recovery chain has no final record",
        )
    return final_status


def _next_restart_recovery_attempt(archive: SecureArchive) -> int:
    try:
        names = archive.list_names(OBSERVATION_DIRECTORY)
    except PhysicalCaptureArchiveError as error:
        raise PerformanceCaptureError(
            "shaping_recovery_state_unreadable",
            "restart recovery cannot inspect the performance observation namespace",
        ) from error
    attempts: list[int] = []
    for name in names:
        match = RESTART_RECOVERY_FILENAME_RE.fullmatch(name)
        if match is not None:
            attempts.append(int(match.group("attempt")))
    if attempts != list(range(1, len(attempts) + 1)):
        raise PerformanceCaptureError(
            "shaping_recovery_state_invalid",
            "restart recovery attempts are not a contiguous source-owned sequence",
        )
    next_attempt = len(attempts) + 1
    if next_attempt > MAX_RESTART_RECOVERY_ATTEMPTS:
        raise PerformanceCaptureError(
            "shaping_recovery_attempts_exhausted",
            "fixed shaping recovery exhausted its bounded attempt count",
        )
    return next_attempt


def recover_interrupted_performance_shaping(
    *,
    session: PhysicalCaptureSession,
    context: object,
    operator: object,
) -> ObservationArtifact:
    """Restore every fixed shaping resource after restart, then force abandonment.

    This produces an observable failure record, never a valid restoration
    artifact.  The caller must abandon the session and collect a fresh complete
    run because an interrupted timing interval cannot be reconstructed.
    """

    if not isinstance(session, PhysicalCaptureSession):
        raise PerformanceCaptureError(
            "invalid_session", "shaping recovery requires a locked capture session"
        )
    try:
        capture = session.observation_capture()
    except PhysicalCaptureSessionError as error:
        raise PerformanceCaptureError(
            "performance_collection_closed",
            "shaping recovery is available only while collection remains open",
        ) from error
    candidate, run = _capture_context(context)
    selected_operator = _require_operator(operator)
    attempt = _next_restart_recovery_attempt(session.archive)
    try:
        selected_operator.confirm_privileged_preflight(
            RECOVERY_PREFLIGHT_INSTRUCTION
        )
    except Exception as error:
        raise PerformanceCaptureError(
            "operator_privilege_preflight_failed",
            "operator did not confirm sudo ticket for recovery",
        ) from error
    repository = session.archive.repository
    privilege_preflight = _command_document(
        capture,
        repository,
        role="performance-sudo-preflight",
        argv=("/usr/bin/sudo", "-n", "-v"),
    )
    records: list[dict[str, Any]] = []
    all_restored = True
    for profile_id in sorted(contract.WEAK_NETWORK_PROFILES):
        pipe_id = contract.WEAK_NETWORK_PROFILES[profile_id]["pipe_id"]
        restore_argvs = contract._restore_argvs(pipe_id)
        restore_commands: list[dict[str, Any]] = []
        restoration_queries: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        for role, argv in (
            ("performance-pf-restore", restore_argvs[0]),
            ("performance-dnctl-restore", restore_argvs[1]),
        ):
            try:
                restore_commands.append(
                    _command_document(
                        capture, repository, role=role, argv=argv
                    )
                )
            except PerformanceCaptureError as error:
                failures.append({"role": role, "code": error.code})
        for role, argv in (
            (
                "performance-dnctl-query",
                contract._pipe_query_argv(pipe_id),
            ),
            ("performance-pf-query", contract._pf_query_argv()),
        ):
            try:
                restoration_queries.append(
                    _command_document(
                        capture, repository, role=role, argv=argv
                    )
                )
            except PerformanceCaptureError as error:
                failures.append({"role": role, "code": error.code})
        restored = (
            not failures
            and len(restoration_queries) == 2
            and
            re.search(rf"\b{re.escape(pipe_id)}\b", restoration_queries[0]["stdout"])
            is None
            and not restoration_queries[1]["stdout"].strip()
        )
        all_restored = all_restored and restored
        records.append(
            {
                "profile_id": profile_id,
                "restored": restored,
                "restore_commands": restore_commands,
                "restoration_queries": restoration_queries,
                "failures": failures,
            }
        )
    try:
        value = {
            "schema_version": RESTART_RECOVERY_SCHEMA_VERSION,
            "document": RESTART_RECOVERY_DOCUMENT,
            "candidate": candidate,
            "run": run,
            "attempt": attempt,
            "recorded_at": _timestamp(_utc_now()),
            "requires_session_abandonment": True,
            "state": session.state.value,
            "archive_root": session.archive.root_relative_to_target,
            "journal_tip_sha256": session.snapshot.last_event_sha256,
            "context_sha256": hashlib.sha256(
                canonical_json(context) + b"\n"
            ).hexdigest(),
            "shaping_intent_sha256": session.archive.describe_file(
                f"{OBSERVATION_DIRECTORY}/shaping-intent.json",
                maximum=MAX_PERFORMANCE_ARTIFACT_BYTES,
            ).sha256,
            "privilege_preflight": privilege_preflight,
            "records": records,
        }
        artifact = capture.write_bytes(
            subject=f"performance:shaping-restart-recovery:{attempt:02d}",
            kind=contract.SHAPING_KIND,
            relative=(
                f"{OBSERVATION_DIRECTORY}/"
                f"shaping-restart-recovery-{attempt:02d}.json"
            ),
            data=canonical_json(value) + b"\n",
        )
    except (
        PhysicalCaptureArchiveError,
        PhysicalCaptureSessionError,
        PhysicalObservationError,
        RawArtifactError,
    ) as error:
        raise PerformanceCaptureError(
            "shaping_recovery_unobservable",
            "restart recovery could not be durably recorded",
        ) from error
    if not all_restored:
        raise PerformanceCaptureError(
            "shaping_recovery_incomplete",
            "restart recovery remains observable but fixed shaping state is not empty",
        )
    return artifact


__all__ = [
    "FAILURE_RESTORATION_RELATIVE",
    "MAX_RESTART_RECOVERY_ATTEMPTS",
    "MODE_CHANGE_TIMEOUT_SECONDS",
    "OBSERVATION_DIRECTORY",
    "PRIVILEGE_PREFLIGHT_INSTRUCTION",
    "RECOVERY_PREFLIGHT_INSTRUCTION",
    "RESTART_RECOVERY_DOCUMENT",
    "RESTART_RECOVERY_FILENAME_RE",
    "RESTART_RECOVERY_SCHEMA_VERSION",
    "RESTORATION_FAILURE_DOCUMENT",
    "RESTORATION_FAILURE_SCHEMA_VERSION",
    "PerformanceCaptureError",
    "PerformanceObservationBatch",
    "PerformanceOperator",
    "RestartRecoveryStatus",
    "capture_performance_observations",
    "recover_interrupted_performance_shaping",
    "validate_restart_recovery_chain",
    "validate_shaping_restoration_failure",
]
