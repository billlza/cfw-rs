from __future__ import annotations

from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
import hashlib
import io
import os
from pathlib import Path
import tempfile
from types import MappingProxyType
import unittest
from unittest.mock import patch

from scripts.harness import performance_ledger as performance_contract
from scripts.harness.raw_artifacts import (
    EVIDENCE_PROFILE,
    RawArtifactError,
    canonical_json,
    load_json_bytes,
)
from scripts.physical_capture import collector as collector_driver
from scripts.physical_capture.archive import PRIVATE_FILE_MODE, SecureArchive
from scripts.physical_capture.collector import (
    PRODUCER_ORDER,
    PRODUCER_REGISTRY,
    PhysicalCollectorDriverError,
    _collect_harness_session,
    _load_committed_candidate,
    _load_producer_checkpoint,
    _parser,
    _require_previous_attempt_abandoned,
    _write_producer_checkpoint,
    collect_performance_session,
    recover_performance_session,
)
from scripts.physical_capture.observation import ObservationArtifact
from scripts.physical_capture.observation import publish_observation_manifest
from scripts.physical_capture.performance import (
    FAILURE_RESTORATION_RELATIVE,
    OBSERVATION_DIRECTORY,
    PRIVILEGE_PREFLIGHT_INSTRUCTION,
    RESTART_RECOVERY_DOCUMENT,
    RESTART_RECOVERY_SCHEMA_VERSION,
    RESTORATION_FAILURE_DOCUMENT,
    RESTORATION_FAILURE_SCHEMA_VERSION,
    PerformanceCaptureError,
)
from scripts.physical_capture.performance_operator import (
    PerformanceOperatorAdapterError,
    SignalCancellation,
    TerminalPerformanceOperator,
)
from scripts.physical_capture.session import (
    CaptureEvent,
    CaptureState,
    PhysicalCaptureSession,
    PhysicalCaptureSessionError,
)
from scripts.publication.common import tree_digest
from scripts.tests.performance_evidence_fixture import (
    _command as performance_command,
)


class _Prompt:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls: list[tuple[str, datetime]] = []

    def request(self, message: str, *, deadline: datetime) -> str:
        self.calls.append((message, deadline))
        return self.answer


class PhysicalCaptureCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name)
        (self.repository / "target").mkdir()

    def session(
        self,
        name: str = "collector",
        *,
        context: dict[str, object] | None = None,
    ) -> PhysicalCaptureSession:
        root = (
            name
            if name.startswith("physical-capture/")
            else "physical-capture/v040/macos15/attempt-01"
        )
        attempt = root.rsplit("attempt-", maxsplit=1)[-1]
        context_data = canonical_json(
            {"run": {"os": "macos15"}} if context is None else context
        ) + b"\n"
        parameter_data = canonical_json({}) + b"\n"
        intent_sha256 = collector_driver._collector_intent_sha256(
            "macos15", attempt, context_data, parameter_data
        )
        session = PhysicalCaptureSession.create(
            self.repository,
            root,
            intent_sha256=intent_sha256,
        )
        session.archive.write_bytes(
            collector_driver.CONTEXT_RELATIVE, context_data
        )
        session.archive.write_bytes(
            collector_driver.PARAMETERS_RELATIVE, parameter_data
        )
        session.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=intent_sha256,
        )
        self.addCleanup(session.close)
        return session

    def test_collector_requires_the_manifest_bound_candidate_commit_marker(self) -> None:
        entries = [
            {
                "path": "artifacts/signed-app",
                "sha256": hashlib.sha256(b"signed-app").hexdigest(),
            }
        ]
        manifest_sha256 = tree_digest(entries)
        manifest = {"entries": entries, "sha256": manifest_sha256}
        candidate = {"artifact_hash_manifest_sha256": manifest_sha256}
        candidate_path = self.repository / "physical-collector-candidate.json"
        manifest_path = self.repository / "physical-candidate-manifest.json"
        manifest_path.write_bytes(canonical_json(manifest))

        with patch.object(
            collector_driver,
            "FINAL_CANDIDATE",
            candidate_path,
        ), patch.object(
            collector_driver,
            "FINAL_CANDIDATE_MANIFEST",
            manifest_path,
        ):
            with self.assertRaisesRegex(RawArtifactError, "openable"):
                _load_committed_candidate()

            candidate_path.write_bytes(canonical_json(candidate))
            self.assertEqual(_load_committed_candidate(), candidate)

            manifest_path.unlink()
            with self.assertRaisesRegex(RawArtifactError, "openable"):
                _load_committed_candidate()
            manifest_path.write_bytes(canonical_json(manifest))

            candidate_path.write_bytes(
                canonical_json({"artifact_hash_manifest_sha256": "0" * 64})
            )
            with self.assertRaisesRegex(RawArtifactError, "does not bind"):
                _load_committed_candidate()

    @staticmethod
    def abandon_with_source_failure(
        session: PhysicalCaptureSession, harness: str = "lifecycle"
    ) -> None:
        collector_driver._record_producer_failure(
            session,
            harness,
            PhysicalCollectorDriverError(
                "fixture_failure", "source-owned fixture failure"
            ),
        )

    @staticmethod
    def release_context(run_id: str = "run-40037-macos15") -> dict[str, object]:
        def digest(value: str) -> str:
            return hashlib.sha256(value.encode("utf-8")).hexdigest()

        return {
            "schema_version": 1,
            "document": "cfw-physical-run-context-v1",
            "evidence_profile_sha256": hashlib.sha256(
                canonical_json(EVIDENCE_PROFILE)
            ).hexdigest(),
            "candidate": {
                "version": "0.4.0",
                "build_number": "40037",
                "app_manifest_sha256": digest("app-manifest"),
                "signed_app_tree_sha256": digest("signed-app-tree"),
                "artifact_hash_manifest_sha256": digest("artifact-manifest"),
                "built_at": "2026-08-01T23:00:00Z",
            },
            "run": {
                "os": "macos15",
                "macos_version": "15.7.8",
                "macos_build": "24G824",
                "machine_sha256": digest("machine"),
                "machine_identity_scheme": EVIDENCE_PROFILE[
                    "machine_identity_scheme"
                ],
                "hardware_model": "Mac16,1",
                "virtualization_present": False,
                "boot_environment_sha256": digest("boot"),
                "boot_environment_scheme": EVIDENCE_PROFILE[
                    "boot_environment_scheme"
                ],
                "clean_install": True,
                "run_id": run_id,
            },
            "initialized_at": "2026-08-01T23:30:00Z",
        }

    def write_shaping_intent(
        self,
        session: PhysicalCaptureSession,
        context: dict[str, object],
        *,
        command_cursor: datetime | None = None,
        created_at_override: datetime | None = None,
    ) -> tuple[ObservationArtifact, datetime]:
        candidate = context["candidate"]
        run = context["run"]
        assert isinstance(candidate, dict)
        assert isinstance(run, dict)
        cursor = (
            session.snapshot.last_recorded_at + timedelta(milliseconds=1)
            if command_cursor is None
            else command_cursor
        )

        def command(
            role: str, argv: tuple[str, ...], *, stdout: str = ""
        ) -> dict[str, object]:
            nonlocal cursor
            started = cursor
            completed = started + timedelta(milliseconds=1)
            cursor = completed + timedelta(milliseconds=1)
            return performance_command(
                role, argv, started, completed, stdout=stdout
            )

        preflight = command(
            "performance-sudo-preflight",
            ("/usr/bin/sudo", "-n", "-v"),
        )
        pf_status = command(
            "performance-pf-status",
            performance_contract._pf_status_argv(),
            stdout="Status: Enabled\n",
        )
        pf_query = command(
            "performance-pf-query",
            performance_contract._pf_query_argv(),
        )
        pipe_queries = [
            command(
                "performance-dnctl-query",
                performance_contract._pipe_query_argv(
                    performance_contract.WEAK_NETWORK_PROFILES[profile_id][
                        "pipe_id"
                    ]
                ),
            )
            for profile_id in sorted(
                performance_contract.WEAK_NETWORK_PROFILES
            )
        ]
        created_at_value = (
            cursor if created_at_override is None else created_at_override
        )
        created_at = created_at_value.astimezone(timezone.utc).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        intent = {
            "schema_version": 1,
            "document": performance_contract.SHAPING_INTENT_DOCUMENT,
            "candidate": candidate,
            "run": run,
            "created_at": created_at,
            "privilege_preflight": preflight,
            "anchor": performance_contract.PF_ANCHOR,
            "profiles": [
                {
                    "id": profile_id,
                    **performance_contract.WEAK_NETWORK_PROFILES[profile_id],
                }
                for profile_id in sorted(
                    performance_contract.WEAK_NETWORK_PROFILES
                )
            ],
            "original_state": {
                "pf_status_query": pf_status,
                "pf_query": pf_query,
                "pipe_queries": pipe_queries,
            },
            "transactions": [
                {"index": index, "profile_id": profile_id}
                for index, profile_id in enumerate(
                    profile_id
                    for profile_id in sorted(
                        performance_contract.WEAK_NETWORK_PROFILES
                    )
                    for _ in range(performance_contract.SERIES_SAMPLE_COUNT)
                )
            ],
        }
        artifact = session.observation_capture().write_bytes(
            subject="performance:shaping-intent",
            kind="performance-shaping-transaction",
            relative=f"{OBSERVATION_DIRECTORY}/shaping-intent.json",
            data=canonical_json(intent) + b"\n",
        )
        return artifact, max(cursor, created_at_value)

    def restart_recovery_value(
        self,
        session: PhysicalCaptureSession,
        context: dict[str, object],
        *,
        intent: ObservationArtifact,
        cursor: datetime,
        attempt: int = 1,
        complete_commands: bool = True,
        failed_roles: frozenset[str] = frozenset(),
    ) -> dict[str, object]:
        candidate = context["candidate"]
        run = context["run"]
        assert isinstance(candidate, dict)
        assert isinstance(run, dict)
        records: list[dict[str, object]] = []

        def command(
            role: str, argv: tuple[str, ...]
        ) -> dict[str, object]:
            nonlocal cursor
            started = cursor
            completed = started + timedelta(milliseconds=1)
            cursor = completed + timedelta(milliseconds=1)
            return performance_command(role, argv, started, completed)

        privilege_preflight = command(
            "performance-sudo-preflight", ("/usr/bin/sudo", "-n", "-v")
        )

        for profile_id in sorted(performance_contract.WEAK_NETWORK_PROFILES):
            pipe_id = performance_contract.WEAK_NETWORK_PROFILES[profile_id][
                "pipe_id"
            ]
            restore_argvs = performance_contract._restore_argvs(pipe_id)
            failures: list[dict[str, str]] = []

            def maybe_command(
                role: str, argv: tuple[str, ...]
            ) -> dict[str, object] | None:
                if role in failed_roles:
                    failures.append(
                        {"role": role, "code": "fixed_command_failed"}
                    )
                    return None
                return command(role, argv)

            restore_commands = (
                [
                    result
                    for result in (
                        maybe_command(
                            "performance-pf-restore", restore_argvs[0]
                        ),
                        maybe_command(
                            "performance-dnctl-restore", restore_argvs[1]
                        ),
                    )
                    if result is not None
                ]
                if complete_commands
                else []
            )
            restoration_queries = (
                [
                    result
                    for result in (
                        maybe_command(
                            "performance-dnctl-query",
                            performance_contract._pipe_query_argv(pipe_id),
                        ),
                        maybe_command(
                            "performance-pf-query",
                            performance_contract._pf_query_argv(),
                        ),
                    )
                    if result is not None
                ]
                if complete_commands
                else []
            )
            records.append(
                {
                    "profile_id": profile_id,
                    "restored": complete_commands and not failures,
                    "restore_commands": restore_commands,
                    "restoration_queries": restoration_queries,
                    "failures": failures,
                }
            )
        return {
            "schema_version": RESTART_RECOVERY_SCHEMA_VERSION,
            "document": RESTART_RECOVERY_DOCUMENT,
            "candidate": candidate,
            "run": run,
            "attempt": attempt,
            "recorded_at": cursor.astimezone(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "requires_session_abandonment": True,
            "state": session.state.value,
            "archive_root": session.archive.root_relative_to_target,
            "journal_tip_sha256": session.snapshot.last_event_sha256,
            "context_sha256": session.archive.describe_file(
                collector_driver.CONTEXT_RELATIVE,
                maximum=collector_driver.MAX_INPUT_BYTES,
            ).sha256,
            "shaping_intent_sha256": intent.descriptor.sha256,
            "privilege_preflight": privilege_preflight,
            "records": records,
        }

    @staticmethod
    def write_restart_recovery(
        session: PhysicalCaptureSession,
        value: dict[str, object],
        *,
        attempt: int,
    ) -> ObservationArtifact:
        return session.observation_capture().write_bytes(
            subject=f"performance:shaping-restart-recovery:{attempt:02d}",
            kind="performance-shaping-transaction",
            relative=(
                f"{OBSERVATION_DIRECTORY}/"
                f"shaping-restart-recovery-{attempt:02d}.json"
            ),
            data=canonical_json(value) + b"\n",
        )

    @staticmethod
    def cursor_after_recovery(value: dict[str, object]) -> datetime:
        recorded_at = value["recorded_at"]
        assert isinstance(recorded_at, str)
        assert recorded_at.endswith("Z")
        return (
            datetime.fromisoformat(recorded_at[:-1] + "+00:00")
            + timedelta(milliseconds=1)
        )

    def restoration_failure_value(
        self,
        session: PhysicalCaptureSession,
        context: dict[str, object],
        *,
        intent: ObservationArtifact,
        cursor: datetime,
        failed_roles: frozenset[str] = frozenset(),
    ) -> dict[str, object]:
        candidate = context["candidate"]
        run = context["run"]
        assert isinstance(candidate, dict)
        assert isinstance(run, dict)
        profile_id = sorted(performance_contract.WEAK_NETWORK_PROFILES)[0]
        pipe_id = performance_contract.WEAK_NETWORK_PROFILES[profile_id][
            "pipe_id"
        ]
        restore_argvs = performance_contract._restore_argvs(pipe_id)
        failures: list[dict[str, str]] = []

        def outcome(
            role: str, argv: tuple[str, ...]
        ) -> dict[str, object] | None:
            nonlocal cursor
            if role in failed_roles:
                failures.append(
                    {"role": role, "code": "fixed_command_failed"}
                )
                return None
            started = cursor
            completed = started + timedelta(milliseconds=1)
            cursor = completed + timedelta(milliseconds=1)
            return performance_command(role, argv, started, completed)

        restore_commands = [
            result
            for result in (
                outcome("performance-pf-restore", restore_argvs[0]),
                outcome("performance-dnctl-restore", restore_argvs[1]),
            )
            if result is not None
        ]
        restoration_queries = [
            result
            for result in (
                outcome(
                    "performance-dnctl-query",
                    performance_contract._pipe_query_argv(pipe_id),
                ),
                outcome(
                    "performance-pf-query",
                    performance_contract._pf_query_argv(),
                ),
            )
            if result is not None
        ]
        cleanup_succeeded = all(
            role not in failed_roles
            for role in (
                "performance-dnctl-query",
                "performance-pf-query",
            )
        )
        return {
            "schema_version": RESTORATION_FAILURE_SCHEMA_VERSION,
            "document": RESTORATION_FAILURE_DOCUMENT,
            "candidate": candidate,
            "run": run,
            "transaction_index": 0,
            "profile_id": profile_id,
            "cleanup_succeeded": cleanup_succeeded,
            "recorded_at": cursor.astimezone(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "state": session.state.value,
            "archive_root": session.archive.root_relative_to_target,
            "journal_tip_sha256": session.snapshot.last_event_sha256,
            "context_sha256": session.archive.describe_file(
                collector_driver.CONTEXT_RELATIVE,
                maximum=collector_driver.MAX_INPUT_BYTES,
            ).sha256,
            "shaping_intent_sha256": intent.descriptor.sha256,
            "restore_commands": restore_commands,
            "restoration_queries": restoration_queries,
            "failures": failures,
        }

    def fixture_observations(
        self, session: PhysicalCaptureSession, harness: str
    ) -> dict[str, dict[str, object]]:
        required, _allowed = collector_driver._expected_subject_sets(harness)
        capture = session.observation_capture()
        return {
            subject: capture.write_bytes(
                subject=subject,
                kind=collector_driver._expected_subject_kind(harness, subject),
                relative=(
                    f"raw/{harness}/observations/observation-{index:03d}"
                    f"{collector_driver.ARTIFACT_KINDS[collector_driver._expected_subject_kind(harness, subject)].suffix}"
                ),
                data=canonical_json({"subject": subject}) + b"\n",
            ).descriptor.as_dict()
            for index, subject in enumerate(sorted(required))
        }

    def seed_completed(
        self,
        session: PhysicalCaptureSession,
        harnesses: tuple[str, ...],
    ) -> dict[str, dict[str, dict[str, object]]]:
        completed: dict[str, dict[str, dict[str, object]]] = {}
        predecessor = collector_driver.ROOT_PRODUCER_CHECKPOINT_SHA256
        for harness in harnesses:
            collector_driver._write_producer_attempt(
                session,
                harness,
                predecessor_checkpoint_sha256=predecessor,
            )
            observations = self.fixture_observations(session, harness)
            completed[harness] = _write_producer_checkpoint(
                session, harness, observations
            )
            predecessor = collector_driver._producer_progress(
                session
            ).checkpoint_sha256[harness]
        return completed

    def test_operator_accepts_only_exact_source_owned_mode_checkpoint(self) -> None:
        now = datetime(2026, 8, 2, tzinfo=timezone.utc)
        token = "confirm mode tunnel connect-latency 3"
        prompt = _Prompt(token)
        operator = TerminalPerformanceOperator(prompt, now=lambda: now)
        operator.request_terminal_mode(
            "tunnel",
            reason="connect-latency",
            iteration=3,
            deadline=now + timedelta(seconds=120),
        )
        self.assertEqual(len(prompt.calls), 1)
        self.assertIn(token, prompt.calls[0][0])

    def test_operator_rejects_unknown_checkpoint_before_prompt(self) -> None:
        now = datetime(2026, 8, 2, tzinfo=timezone.utc)
        prompt = _Prompt("confirm mode tunnel caller-selected 0")
        operator = TerminalPerformanceOperator(prompt, now=lambda: now)
        with self.assertRaisesRegex(
            PerformanceOperatorAdapterError, "unknown terminal-mode"
        ):
            operator.request_terminal_mode(
                "tunnel",
                reason="caller-selected",
                iteration=0,
                deadline=now + timedelta(seconds=120),
            )
        self.assertEqual(prompt.calls, [])

    def test_operator_privilege_confirmation_is_exact(self) -> None:
        now = datetime(2026, 8, 2, tzinfo=timezone.utc)
        prompt = _Prompt("not-confirmed")
        operator = TerminalPerformanceOperator(prompt, now=lambda: now)
        with self.assertRaisesRegex(
            PerformanceOperatorAdapterError, "exact sudo checkpoint"
        ):
            operator.confirm_privileged_preflight(
                PRIVILEGE_PREFLIGHT_INSTRUCTION
            )

    def test_cli_exposes_only_fixed_commands_and_lane_enum(self) -> None:
        parser = _parser()
        parsed = parser.parse_args(
            [
                "collect",
                "--harness",
                "lifecycle",
                "--lane",
                "macos15",
                "--attempt",
                "01",
            ]
        )
        self.assertEqual(parsed.harness, "lifecycle")
        recovered = parser.parse_args(
            [
                "recover-journal",
                "--lane",
                "macos15",
                "--attempt",
                "01",
            ]
        )
        self.assertEqual(recovered.command, "recover-journal")
        published = parser.parse_args(
            [
                "publish",
                "--macos15-attempt",
                "01",
                "--current-macos-attempt",
                "02",
            ]
        )
        self.assertEqual(published.current_macos_attempt, "02")
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "collect",
                        "--harness",
                        "performance",
                        "--lane",
                        "macos15",
                        "--attempt",
                        "01",
                        "--session-root",
                        "/tmp/injected",
                    ]
                )
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "collect",
                        "--harness",
                        "performance",
                        "--lane",
                        "other-os",
                        "--attempt",
                        "01",
                    ]
                )
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "publish",
                        "--macos15-attempt",
                        "01",
                        "--current-macos-attempt",
                        "01",
                        "--output",
                        "/tmp/injected",
                    ]
                )
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "collect",
                        "--harness",
                        "performance",
                        "--lane",
                        "macos15",
                        "--attempt",
                        "99",
                    ]
                )
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "collect",
                        "--harness",
                        "caller-selected",
                        "--lane",
                        "macos15",
                        "--attempt",
                        "01",
                    ]
                )

    def test_regular_capture_failure_is_recorded_and_abandoned(self) -> None:
        session = self.session("regular-failure")
        with patch(
            "scripts.physical_capture.collector.capture_performance_observations",
            side_effect=PerformanceCaptureError("fixed_failure", "injected"),
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                collect_performance_session(
                    session=session,
                    context={},
                    parameters={},
                    operator=object(),
                    cancelled=lambda: False,
                )
        self.assertEqual(raised.exception.code, "performance_session_abandoned")
        self.assertEqual(session.state, CaptureState.ABANDONED)
        failure = session.archive.read_bytes("failures/performance-collector.json")
        self.assertIn(b'"code":"fixed_failure"', failure)

    def test_producer_registry_is_exact_immutable_and_ordered(self) -> None:
        self.assertEqual(set(PRODUCER_REGISTRY), set(PRODUCER_ORDER))
        with self.assertRaises(TypeError):
            PRODUCER_REGISTRY["unknown"] = object()

    def test_out_of_order_producer_is_rejected_without_running_it(self) -> None:
        session = self.session("out-of-order")
        with self.assertRaises(PhysicalCollectorDriverError) as raised:
            _collect_harness_session(
                session=session,
                harness="adversarial",
                context={},
                parameters={},
                operator=object(),
                cancelled=lambda: False,
            )
        self.assertEqual(raised.exception.code, "producer_order_invalid")
        self.assertEqual(session.state, CaptureState.COLLECTING)

    def test_producer_checkpoint_reopens_only_exact_retained_bytes(self) -> None:
        session = self.session("checkpoint")
        harness = "lifecycle"
        observations = self.fixture_observations(session, harness)
        collector_driver._write_producer_attempt(
            session,
            harness,
            predecessor_checkpoint_sha256=(
                collector_driver.ROOT_PRODUCER_CHECKPOINT_SHA256
            ),
        )
        recorded = _write_producer_checkpoint(
            session, harness, observations
        )
        self.assertEqual(
            _load_producer_checkpoint(session, harness), recorded
        )

        raw = (
            self.repository
            / "target"
            / session.archive.root_relative_to_target
            / f"raw/{harness}/observations/observation-000.json"
        )
        raw.write_bytes(b'{"subject":"tampered"}\n')
        with self.assertRaises(PhysicalCollectorDriverError) as raised:
            _load_producer_checkpoint(session, harness)
        self.assertEqual(raised.exception.code, "producer_observation_drifted")

    def test_pending_only_attempt_marker_is_discarded_before_handler(self) -> None:
        session = self.session("pending-marker")
        session.archive.ensure_directory(
            collector_driver.PRODUCER_ATTEMPT_DIRECTORY
        )
        root = (
            self.repository
            / "target"
            / session.archive.root_relative_to_target
            / collector_driver.PRODUCER_ATTEMPT_DIRECTORY
        )
        pending = root / (".lifecycle.json.pending-" + "a" * 32)
        expected_attempt = collector_driver._producer_attempt_bytes(
            session,
            "lifecycle",
            predecessor_checkpoint_sha256=(
                collector_driver.ROOT_PRODUCER_CHECKPOINT_SHA256
            ),
        )
        pending.write_bytes(expected_attempt[:29])
        pending.chmod(0o600)
        calls: list[str] = []

        def handler(
            active: PhysicalCaptureSession,
            _context: object,
            _parameters: object,
            _operator: object,
            _cancelled: object,
        ) -> dict[str, dict[str, object]]:
            calls.append("lifecycle")
            return self.fixture_observations(active, "lifecycle")

        registry = MappingProxyType(
            {**PRODUCER_REGISTRY, "lifecycle": handler}
        )
        with patch.object(collector_driver, "PRODUCER_REGISTRY", registry):
            _observations, raw_complete = _collect_harness_session(
                session=session,
                harness="lifecycle",
                context={},
                parameters={},
                operator=object(),
                cancelled=lambda: False,
            )
        self.assertEqual(calls, ["lifecycle"])
        self.assertFalse(raw_complete)
        self.assertFalse(pending.exists())
        self.assertEqual(session.state, CaptureState.COLLECTING)

    def test_nonprefix_pending_attempt_never_invokes_handler(self) -> None:
        session = self.session("pending-marker-junk")
        session.archive.ensure_directory(
            collector_driver.PRODUCER_ATTEMPT_DIRECTORY
        )
        root = (
            self.repository
            / "target"
            / session.archive.root_relative_to_target
            / collector_driver.PRODUCER_ATTEMPT_DIRECTORY
        )
        pending = root / (".lifecycle.json.pending-" + "b" * 32)
        pending.write_bytes(b"not-an-attempt-prefix\n")
        pending.chmod(PRIVATE_FILE_MODE)
        calls: list[str] = []

        def handler(*_arguments: object) -> dict[str, dict[str, object]]:
            calls.append("called")
            return {}

        registry = MappingProxyType(
            {**PRODUCER_REGISTRY, "lifecycle": handler}
        )
        with patch.object(collector_driver, "PRODUCER_REGISTRY", registry):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _collect_harness_session(
                    session=session,
                    harness="lifecycle",
                    context={},
                    parameters={},
                    operator=object(),
                    cancelled=lambda: False,
                )
        self.assertEqual(raised.exception.code, "producer_transaction_ambiguous")
        self.assertEqual(calls, [])
        self.assertEqual(session.state, CaptureState.ABANDONED)
        self.assertTrue(pending.is_file())

    def test_committed_attempt_without_checkpoint_never_reruns_handler(self) -> None:
        session = self.session("committed-attempt")
        collector_driver._write_producer_attempt(
            session,
            "lifecycle",
            predecessor_checkpoint_sha256=(
                collector_driver.ROOT_PRODUCER_CHECKPOINT_SHA256
            ),
        )
        calls: list[str] = []

        def handler(*_arguments: object) -> dict[str, dict[str, object]]:
            calls.append("called")
            return {}

        registry = MappingProxyType(
            {**PRODUCER_REGISTRY, "lifecycle": handler}
        )
        with patch.object(collector_driver, "PRODUCER_REGISTRY", registry):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _collect_harness_session(
                    session=session,
                    harness="lifecycle",
                    context={},
                    parameters={},
                    operator=object(),
                    cancelled=lambda: False,
                )
        self.assertEqual(raised.exception.code, "producer_attempt_interrupted")
        self.assertEqual(calls, [])
        self.assertEqual(session.state, CaptureState.ABANDONED)

    def test_final_failure_record_resumes_abandonment_without_rederiving_code(self) -> None:
        session = self.session("failure-final-crash")
        archived = collector_driver._failure_record(
            session,
            relative="failures/lifecycle-collector.json",
            expected={
                "schema_version": 1,
                "document": "cfw-physical-producer-failure-v2",
                "harness": "lifecycle",
                "code": "original_handler_failure",
                "state_recorded_at": session.snapshot.last_recorded_at
                .astimezone(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "state": CaptureState.COLLECTING.value,
                "archive_root": session.archive.root_relative_to_target,
                "journal_tip_sha256": session.snapshot.last_event_sha256,
            },
        )
        calls: list[str] = []

        def handler(*_arguments: object) -> dict[str, dict[str, object]]:
            calls.append("called")
            return {}

        registry = MappingProxyType(
            {**PRODUCER_REGISTRY, "lifecycle": handler}
        )
        with patch.object(collector_driver, "PRODUCER_REGISTRY", registry):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _collect_harness_session(
                    session=session,
                    harness="lifecycle",
                    context={},
                    parameters={},
                    operator=object(),
                    cancelled=lambda: False,
                )
        self.assertEqual(raised.exception.code, "collector_failure_resumed")
        self.assertEqual(calls, [])
        self.assertEqual(session.state, CaptureState.ABANDONED)
        self.assertEqual(session.snapshot.last_binding_sha256, archived.sha256)

    def test_initialization_failure_final_resumes_before_input_revalidation(self) -> None:
        root = "physical-capture/v040/macos15/attempt-01"
        intent = hashlib.sha256(b"initialization-intent").hexdigest()
        session = PhysicalCaptureSession.create(
            self.repository, root, intent_sha256=intent
        )
        archived = collector_driver._failure_record(
            session,
            relative=collector_driver.FAILURE_RELATIVE,
            expected={
                "schema_version": 1,
                "document": collector_driver.FAILURE_DOCUMENT,
                "code": "original_initialization_failure",
                "state_recorded_at": session.snapshot.last_recorded_at
                .astimezone(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "state": CaptureState.INITIALIZED.value,
                "archive_root": session.archive.root_relative_to_target,
                "journal_tip_sha256": session.snapshot.last_event_sha256,
            },
        )
        session.close()

        with patch.object(collector_driver, "REPOSITORY", self.repository):
            state = collector_driver._recover_journal("macos15", "01")
        self.assertEqual(state, CaptureState.ABANDONED)
        with PhysicalCaptureSession.open(self.repository, root) as reopened:
            self.assertEqual(reopened.snapshot.last_binding_sha256, archived.sha256)

    def test_complete_checkpoint_prefix_is_frozen_after_restart(self) -> None:
        session = self.session("checkpoint-before-freeze")
        completed = self.seed_completed(session, PRODUCER_ORDER)
        self.assertEqual(session.state, CaptureState.COLLECTING)

        observed, raw_complete = _collect_harness_session(
            session=session,
            harness="lifecycle",
            context={},
            parameters={},
            operator=object(),
            cancelled=lambda: False,
        )
        self.assertEqual(observed, completed["lifecycle"])
        self.assertTrue(raw_complete)
        self.assertEqual(session.state, CaptureState.RAW_COMPLETE)

    def test_published_manifest_without_raw_event_is_exactly_reopened(self) -> None:
        session = self.session("manifest-before-event")
        completed = self.seed_completed(session, PRODUCER_ORDER)
        union = {
            subject: descriptor
            for harness in PRODUCER_ORDER
            for subject, descriptor in completed[harness].items()
        }
        published = publish_observation_manifest(session.archive, union)
        self.assertEqual(session.state, CaptureState.COLLECTING)

        _observed, raw_complete = _collect_harness_session(
            session=session,
            harness="performance",
            context={},
            parameters={},
            operator=object(),
            cancelled=lambda: False,
        )
        self.assertTrue(raw_complete)
        self.assertEqual(
            session.snapshot.observation_manifest_sha256,
            published.root_sha256,
        )

    def test_symlinked_attempt_namespace_blocks_before_handler(self) -> None:
        session = self.session("attempt-symlink")
        root = (
            self.repository
            / "target"
            / session.archive.root_relative_to_target
            / "checkpoints"
        )
        root.mkdir(mode=0o700)
        outside = self.repository / "outside"
        outside.mkdir(mode=0o700)
        (root / "producer-attempts").symlink_to(outside, target_is_directory=True)
        calls: list[str] = []

        def handler(*_arguments: object) -> dict[str, dict[str, object]]:
            calls.append("called")
            return {}

        registry = MappingProxyType(
            {**PRODUCER_REGISTRY, "lifecycle": handler}
        )
        with patch.object(collector_driver, "PRODUCER_REGISTRY", registry):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _collect_harness_session(
                    session=session,
                    harness="lifecycle",
                    context={},
                    parameters={},
                    operator=object(),
                    cancelled=lambda: False,
                )
        self.assertEqual(raised.exception.code, "producer_namespace_unreadable")
        self.assertEqual(calls, [])
        self.assertEqual(session.state, CaptureState.ABANDONED)

    def test_prior_harness_cannot_mask_interrupted_performance_shaping(self) -> None:
        session = self.session("masked-performance")
        self.seed_completed(session, PRODUCER_ORDER[:-1])
        predecessor = collector_driver._producer_progress(
            session
        ).checkpoint_sha256["packet"]
        collector_driver._write_producer_attempt(
            session,
            "performance",
            predecessor_checkpoint_sha256=predecessor,
        )
        session.observation_capture().write_bytes(
            subject="performance:shaping-intent",
            kind="performance-shaping-transaction",
            relative=f"{OBSERVATION_DIRECTORY}/shaping-intent.json",
            data=b"{}\n",
        )

        with self.assertRaises(PhysicalCollectorDriverError) as raised:
            _collect_harness_session(
                session=session,
                harness="lifecycle",
                context={},
                parameters={},
                operator=object(),
                cancelled=lambda: False,
            )
        self.assertEqual(raised.exception.code, "performance_recovery_required")
        self.assertEqual(session.state, CaptureState.COLLECTING)

    def test_new_attempt_requires_contiguous_abandoned_predecessor(self) -> None:
        root = "physical-capture/v040/macos15/attempt-01"
        session = self.session(root)
        session.close()
        with patch.object(collector_driver, "REPOSITORY", self.repository):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
            self.assertEqual(raised.exception.code, "previous_attempt_not_abandoned")
            with PhysicalCaptureSession.open(self.repository, root) as reopened:
                self.abandon_with_source_failure(reopened)
            _require_previous_attempt_abandoned("macos15", "02")

    def test_new_attempt_rejects_deleted_abandonment_binding(self) -> None:
        root = "physical-capture/v040/macos15/attempt-01"
        session = self.session(root)
        self.abandon_with_source_failure(session)
        session.close()
        (
            self.repository
            / "target"
            / root
            / "failures/lifecycle-collector.json"
        ).unlink()

        with patch.object(collector_driver, "REPOSITORY", self.repository):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_new_attempt_rejects_failure_time_not_bound_to_journal(self) -> None:
        root = "physical-capture/v040/macos15/attempt-01"
        session = self.session(root)
        wrong_time = (
            session.snapshot.last_recorded_at + timedelta(seconds=1)
        ).astimezone(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
        value = {
            "schema_version": 1,
            "document": "cfw-physical-producer-failure-v2",
            "harness": "lifecycle",
            "code": "fixture_failure",
            "state_recorded_at": wrong_time,
            "state": session.state.value,
            "archive_root": session.archive.root_relative_to_target,
            "journal_tip_sha256": session.snapshot.last_event_sha256,
        }
        archived = session.archive.write_bytes(
            "failures/lifecycle-collector.json",
            canonical_json(value) + b"\n",
        )
        session.abandon(binding_sha256=archived.sha256)
        session.close()

        with patch.object(collector_driver, "REPOSITORY", self.repository):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_new_attempt_accepts_bound_journal_recovery_abandonment(self) -> None:
        root = "physical-capture/v040/macos15/attempt-01"
        session = self.session(root)
        sequence = session.snapshot.sequence + 1
        pending_path = (
            self.repository
            / "target"
            / root
            / "journal"
            / (f".{sequence:08d}.json.pending-" + "d" * 32)
        )
        pending_path.touch(mode=PRIVATE_FILE_MODE)
        pending_path.chmod(PRIVATE_FILE_MODE)
        pending = session.archive.pending_files("journal")[0]
        session._write_or_reopen_resolution_intent(
            pending,
            session.snapshot,
            observed=b"",
            event=CaptureEvent.SESSION_ABANDONED,
            action="partial-event-abandoned",
        )
        session.archive.discard_pending(pending)
        session.close()
        with PhysicalCaptureSession.recover(
            self.repository, root, discard_incomplete=True
        ) as recovered:
            self.assertEqual(recovered.state, CaptureState.ABANDONED)

        with patch.object(collector_driver, "REPOSITORY", self.repository):
            _require_previous_attempt_abandoned("macos15", "02")

    def test_new_attempt_accepts_bound_failure_recovery(self) -> None:
        root = "physical-capture/v040/macos15/attempt-01"
        session = self.session(root)
        session.archive.ensure_directory("failures")
        pending_path = (
            self.repository
            / "target"
            / root
            / "failures"
            / (".lifecycle-collector.json.pending-" + "e" * 32)
        )
        observed = b'{"schema_version":1'
        pending_path.write_bytes(observed)
        pending_path.chmod(PRIVATE_FILE_MODE)
        pending = session.archive.pending_files("failures")[0]
        recovery = collector_driver._write_or_reopen_failure_recovery(
            session, pending, observed
        )
        session.archive.discard_pending(pending)
        session.abandon(binding_sha256=recovery.sha256)
        session.close()

        with patch.object(collector_driver, "REPOSITORY", self.repository):
            _require_previous_attempt_abandoned("macos15", "02")

    def test_new_attempt_rejects_traversal_in_failure_recovery(self) -> None:
        root = "physical-capture/v040/macos15/attempt-01"
        session = self.session(root)
        value = {
            "schema_version": 1,
            "document": collector_driver.FAILURE_RECOVERY_DOCUMENT,
            "state": session.state.value,
            "archive_root": session.archive.root_relative_to_target,
            "journal_tip_sha256": session.snapshot.last_event_sha256,
            "pending_relative_path": (
                "failures/../failures/.lifecycle-collector.json.pending-"
                + "f" * 32
            ),
            "pending_final_relative_path": (
                "failures/lifecycle-collector.json"
            ),
            "pending_size": 0,
            "pending_sha256": hashlib.sha256(b"").hexdigest(),
            "action": "abandon-after-interrupted-failure-record",
        }
        archived = session.archive.write_bytes(
            collector_driver.FAILURE_RECOVERY_RELATIVE,
            canonical_json(value) + b"\n",
        )
        session.abandon(binding_sha256=archived.sha256)
        session.close()

        with patch.object(collector_driver, "REPOSITORY", self.repository):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_attempt_sequence_revalidates_every_predecessor_closure(self) -> None:
        first = self.session("physical-capture/v040/macos15/attempt-01")
        self.abandon_with_source_failure(first)
        first.close()

        with patch.object(collector_driver, "REPOSITORY", self.repository):
            _require_previous_attempt_abandoned("macos15", "02")
            second = self.session(
                "physical-capture/v040/macos15/attempt-02"
            )
            second.close()
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "03")
            self.assertEqual(
                raised.exception.code, "previous_attempt_not_abandoned"
            )
            with PhysicalCaptureSession.open(
                self.repository,
                "physical-capture/v040/macos15/attempt-02",
            ) as reopened:
                self.abandon_with_source_failure(reopened)
            _require_previous_attempt_abandoned("macos15", "03")

    def test_quarantined_uninitialized_attempt_allows_only_next_attempt(self) -> None:
        root = "physical-capture/v040/macos15/attempt-01"
        with SecureArchive.create(self.repository, root) as archive:
            lock_fd = archive.create_lock_file("session.lock")
            os.close(lock_fd)
            archive.ensure_directory("journal")
        pending = (
            self.repository
            / "target"
            / root
            / "journal"
            / (".00000001.json.pending-" + "2" * 32)
        )
        pending.touch(mode=PRIVATE_FILE_MODE)
        pending.chmod(PRIVATE_FILE_MODE)
        with self.assertRaises(PhysicalCaptureSessionError):
            PhysicalCaptureSession.recover(
                self.repository, root, discard_incomplete=True
            )

        with patch.object(collector_driver, "REPOSITORY", self.repository):
            _require_previous_attempt_abandoned("macos15", "02")
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "03")
        self.assertEqual(raised.exception.code, "previous_attempt_unavailable")

    def test_interrupted_shaping_requires_recovery_without_abandonment(self) -> None:
        session = self.session("recovery-required")
        session.observation_capture().write_bytes(
            subject="performance:shaping-intent",
            kind="performance-shaping-transaction",
            relative=f"{OBSERVATION_DIRECTORY}/shaping-intent.json",
            data=b"{}\n",
        )
        with self.assertRaises(PhysicalCollectorDriverError) as raised:
            collect_performance_session(
                session=session,
                context={},
                parameters={},
                operator=object(),
                cancelled=lambda: False,
            )
        self.assertEqual(raised.exception.code, "performance_recovery_required")
        self.assertEqual(session.state, CaptureState.COLLECTING)

    def test_successful_restart_recovery_forces_session_abandonment(self) -> None:
        context = self.release_context()
        session = self.session("recovery-success", context=context)
        intent, cursor = self.write_shaping_intent(session, context)

        def recover(**_arguments: object) -> ObservationArtifact:
            value = self.restart_recovery_value(
                session, context, intent=intent, cursor=cursor
            )
            return self.write_restart_recovery(session, value, attempt=1)

        with patch(
            "scripts.physical_capture.collector.recover_interrupted_performance_shaping",
            side_effect=recover,
        ) as recovery, patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            observed = recover_performance_session(
                session=session, context=context, operator=object()
            )
        recovery.assert_called_once()
        descriptor = session.archive.describe_file(
            f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-01.json",
            maximum=collector_driver.MAX_INPUT_BYTES,
        ).descriptor("performance-shaping-transaction")
        self.assertEqual(observed, descriptor)
        self.assertEqual(session.state, CaptureState.ABANDONED)

    def test_complete_recovery_before_abandonment_is_idempotently_committed(
        self,
    ) -> None:
        context = self.release_context()
        session = self.session("recovery-crash-before-abandon", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        value = self.restart_recovery_value(
            session, context, intent=intent, cursor=cursor
        )
        artifact = self.write_restart_recovery(session, value, attempt=1)

        with patch(
            "scripts.physical_capture.collector.recover_interrupted_performance_shaping",
            side_effect=AssertionError("complete recovery must not rerun"),
        ) as recovery, patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            observed = recover_performance_session(
                session=session, context=context, operator=object()
            )
        recovery.assert_not_called()
        self.assertEqual(observed, artifact.descriptor.as_dict())
        self.assertEqual(session.state, CaptureState.ABANDONED)
        self.assertEqual(
            session.snapshot.last_binding_sha256, artifact.descriptor.sha256
        )

    def test_malformed_recovery_prefix_blocks_before_sudo_retry(self) -> None:
        context = self.release_context()
        session = self.session("recovery-malformed-prefix", context=context)
        self.write_shaping_intent(session, context)
        session.observation_capture().write_bytes(
            subject="performance:shaping-restart-recovery:01",
            kind="performance-shaping-transaction",
            relative=(
                f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-01.json"
            ),
            data=b"{}\n",
        )

        with patch(
            "scripts.physical_capture.collector.recover_interrupted_performance_shaping"
        ) as recovery, patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                recover_performance_session(
                    session=session, context=context, operator=object()
                )
        recovery.assert_not_called()
        self.assertEqual(
            raised.exception.code, "performance_recovery_state_invalid"
        )
        self.assertEqual(session.state, CaptureState.COLLECTING)

    def test_incomplete_recovery_prefix_allows_one_strict_next_attempt(self) -> None:
        context = self.release_context()
        session = self.session("recovery-incomplete-prefix", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        first = self.restart_recovery_value(
            session,
            context,
            intent=intent,
            cursor=cursor,
            attempt=1,
            failed_roles=frozenset({"performance-pf-restore"}),
        )
        self.write_restart_recovery(session, first, attempt=1)

        def recover(**_arguments: object) -> ObservationArtifact:
            second = self.restart_recovery_value(
                session,
                context,
                intent=intent,
                cursor=self.cursor_after_recovery(first),
                attempt=2,
            )
            return self.write_restart_recovery(session, second, attempt=2)

        with patch(
            "scripts.physical_capture.collector.recover_interrupted_performance_shaping",
            side_effect=recover,
        ) as recovery, patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            observed = recover_performance_session(
                session=session, context=context, operator=object()
            )
        recovery.assert_called_once()
        second = session.archive.describe_file(
            f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-02.json",
            maximum=collector_driver.MAX_INPUT_BYTES,
        )
        self.assertEqual(observed["sha256"], second.sha256)
        self.assertEqual(session.state, CaptureState.ABANDONED)

    def test_committed_recovery_abandonment_is_idempotently_reopened(self) -> None:
        context = self.release_context()
        session = self.session("recovery-idempotent", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        value = self.restart_recovery_value(
            session, context, intent=intent, cursor=cursor
        )
        artifact = session.observation_capture().write_bytes(
            subject="performance:shaping-restart-recovery:01",
            kind="performance-shaping-transaction",
            relative=(
                f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-01.json"
            ),
            data=canonical_json(value) + b"\n",
        )
        session.abandon(binding_sha256=artifact.descriptor.sha256)

        with patch(
            "scripts.physical_capture.collector.recover_interrupted_performance_shaping",
            side_effect=AssertionError("committed recovery must not rerun"),
        ) as recovery, patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            observed = recover_performance_session(
                session=session, context=context, operator=object()
            )
        recovery.assert_not_called()
        self.assertEqual(observed, artifact.descriptor.as_dict())
        self.assertEqual(session.state, CaptureState.ABANDONED)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            _require_previous_attempt_abandoned("macos15", "02")

    def test_empty_shaping_recovery_commands_cannot_open_next_attempt(self) -> None:
        context = self.release_context()
        session = self.session("recovery-empty-commands", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        value = self.restart_recovery_value(
            session,
            context,
            intent=intent,
            cursor=cursor,
            complete_commands=False,
        )
        artifact = session.observation_capture().write_bytes(
            subject="performance:shaping-restart-recovery:01",
            kind="performance-shaping-transaction",
            relative=(
                f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-01.json"
            ),
            data=canonical_json(value) + b"\n",
        )
        session.abandon(binding_sha256=artifact.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_missing_recovery_preflight_cannot_open_next_attempt(self) -> None:
        context = self.release_context()
        session = self.session("recovery-missing-preflight", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        value = self.restart_recovery_value(
            session, context, intent=intent, cursor=cursor
        )
        del value["privilege_preflight"]
        artifact = self.write_restart_recovery(session, value, attempt=1)
        session.abandon(binding_sha256=artifact.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_failed_recovery_history_then_complete_recovery_opens_next_attempt(
        self,
    ) -> None:
        context = self.release_context()
        session = self.session("recovery-retry-success", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        first = self.restart_recovery_value(
            session,
            context,
            intent=intent,
            cursor=cursor,
            attempt=1,
            failed_roles=frozenset({"performance-pf-restore"}),
        )
        self.write_restart_recovery(session, first, attempt=1)
        second = self.restart_recovery_value(
            session,
            context,
            intent=intent,
            cursor=self.cursor_after_recovery(first),
            attempt=2,
        )
        final = self.write_restart_recovery(session, second, attempt=2)
        session.abandon(binding_sha256=final.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            _require_previous_attempt_abandoned("macos15", "02")

    def test_malformed_recovery_history_cannot_open_next_attempt(self) -> None:
        context = self.release_context()
        session = self.session("recovery-malformed-history", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        session.observation_capture().write_bytes(
            subject="performance:shaping-restart-recovery:01",
            kind="performance-shaping-transaction",
            relative=(
                f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-01.json"
            ),
            data=b"{}\n",
        )
        second = self.restart_recovery_value(
            session,
            context,
            intent=intent,
            cursor=cursor + timedelta(seconds=1),
            attempt=2,
        )
        final = self.write_restart_recovery(session, second, attempt=2)
        session.abandon(binding_sha256=final.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_completed_recovery_history_cannot_precede_another_attempt(self) -> None:
        context = self.release_context()
        session = self.session("recovery-complete-history", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        first = self.restart_recovery_value(
            session, context, intent=intent, cursor=cursor, attempt=1
        )
        self.write_restart_recovery(session, first, attempt=1)
        second = self.restart_recovery_value(
            session,
            context,
            intent=intent,
            cursor=self.cursor_after_recovery(first),
            attempt=2,
        )
        final = self.write_restart_recovery(session, second, attempt=2)
        session.abandon(binding_sha256=final.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_recovery_attempt_times_must_strictly_increase(self) -> None:
        context = self.release_context()
        session = self.session("recovery-time-regression", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        first = self.restart_recovery_value(
            session,
            context,
            intent=intent,
            cursor=cursor,
            attempt=1,
            failed_roles=frozenset({"performance-pf-restore"}),
        )
        self.write_restart_recovery(session, first, attempt=1)
        second = self.restart_recovery_value(
            session,
            context,
            intent=intent,
            cursor=cursor,
            attempt=2,
        )
        final = self.write_restart_recovery(session, second, attempt=2)
        session.abandon(binding_sha256=final.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_valid_restoration_failure_then_recovery_opens_next_attempt(
        self,
    ) -> None:
        context = self.release_context()
        session = self.session("recovery-with-failure-record", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        failure = self.restoration_failure_value(
            session,
            context,
            intent=intent,
            cursor=cursor,
            failed_roles=frozenset({"performance-pf-restore"}),
        )
        session.observation_capture().write_bytes(
            subject="performance:shaping-restoration-failure",
            kind="performance-shaping-transaction",
            relative=FAILURE_RESTORATION_RELATIVE,
            data=canonical_json(failure) + b"\n",
        )
        recovery = self.restart_recovery_value(
            session,
            context,
            intent=intent,
            cursor=self.cursor_after_recovery(failure),
        )
        final = self.write_restart_recovery(session, recovery, attempt=1)
        session.abandon(binding_sha256=final.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            _require_previous_attempt_abandoned("macos15", "02")

    def test_malformed_restoration_failure_cannot_open_next_attempt(self) -> None:
        context = self.release_context()
        session = self.session("recovery-bad-failure-record", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        session.observation_capture().write_bytes(
            subject="performance:shaping-restoration-failure",
            kind="performance-shaping-transaction",
            relative=FAILURE_RESTORATION_RELATIVE,
            data=b"{}\n",
        )
        recovery = self.restart_recovery_value(
            session, context, intent=intent, cursor=cursor
        )
        final = self.write_restart_recovery(session, recovery, attempt=1)
        session.abandon(binding_sha256=final.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_shaping_intent_commands_cannot_predate_collection(self) -> None:
        context = self.release_context()
        session = self.session("recovery-predating-intent", context=context)
        predecessor = session.snapshot.last_recorded_at
        intent, cursor = self.write_shaping_intent(
            session,
            context,
            command_cursor=predecessor - timedelta(seconds=1),
            created_at_override=predecessor + timedelta(milliseconds=1),
        )
        recovery = self.restart_recovery_value(
            session, context, intent=intent, cursor=cursor
        )
        final = self.write_restart_recovery(session, recovery, attempt=1)
        session.abandon(binding_sha256=final.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_cross_session_shaping_recovery_copy_is_rejected(self) -> None:
        context = self.release_context()
        source = self.session(
            "physical-capture/v040/macos15/attempt-02",
            context=context,
        )
        source_intent, cursor = self.write_shaping_intent(source, context)
        source_value = self.restart_recovery_value(
            source,
            context,
            intent=source_intent,
            cursor=cursor,
        )
        source_recovery = source.observation_capture().write_bytes(
            subject="performance:shaping-restart-recovery:01",
            kind="performance-shaping-transaction",
            relative=(
                f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-01.json"
            ),
            data=canonical_json(source_value) + b"\n",
        )

        target = self.session(
            "physical-capture/v040/macos15/attempt-01",
            context=context,
        )
        source_intent_data = source.archive.read_bytes(
            source_intent.descriptor.path,
            maximum=collector_driver.MAX_INPUT_BYTES,
        )
        target.observation_capture().write_bytes(
            subject="performance:shaping-intent",
            kind="performance-shaping-transaction",
            relative=f"{OBSERVATION_DIRECTORY}/shaping-intent.json",
            data=source_intent_data,
        )
        source_recovery_data = source.archive.read_bytes(
            source_recovery.descriptor.path,
            maximum=collector_driver.MAX_INPUT_BYTES,
        )
        copied = target.observation_capture().write_bytes(
            subject="performance:shaping-restart-recovery:01",
            kind="performance-shaping-transaction",
            relative=(
                f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-01.json"
            ),
            data=source_recovery_data,
        )
        target.abandon(binding_sha256=copied.descriptor.sha256)
        target.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_noncontiguous_shaping_recovery_attempts_are_rejected(self) -> None:
        context = self.release_context()
        session = self.session("recovery-gap", context=context)
        intent, cursor = self.write_shaping_intent(session, context)
        first = self.restart_recovery_value(
            session, context, intent=intent, cursor=cursor, attempt=1
        )
        session.observation_capture().write_bytes(
            subject="performance:shaping-restart-recovery:01",
            kind="performance-shaping-transaction",
            relative=(
                f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-01.json"
            ),
            data=canonical_json(first) + b"\n",
        )
        third = self.restart_recovery_value(
            session, context, intent=intent, cursor=cursor, attempt=3
        )
        artifact = session.observation_capture().write_bytes(
            subject="performance:shaping-restart-recovery:03",
            kind="performance-shaping-transaction",
            relative=(
                f"{OBSERVATION_DIRECTORY}/shaping-restart-recovery-03.json"
            ),
            data=canonical_json(third) + b"\n",
        )
        session.abandon(binding_sha256=artifact.descriptor.sha256)
        session.close()

        with patch.object(
            collector_driver, "REPOSITORY", self.repository
        ), patch.object(
            collector_driver, "validate_context", return_value=context
        ):
            with self.assertRaises(PhysicalCollectorDriverError) as raised:
                _require_previous_attempt_abandoned("macos15", "02")
        self.assertEqual(
            raised.exception.code, "previous_attempt_abandonment_invalid"
        )

    def test_signal_latch_changes_state_without_raising_in_handler(self) -> None:
        cancellation = SignalCancellation()
        self.assertFalse(cancellation.cancelled())
        cancellation._handle(15, None)
        self.assertTrue(cancellation.cancelled())


if __name__ == "__main__":
    unittest.main()
