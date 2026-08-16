from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.harness import performance_ledger as contract
from scripts.physical_capture.performance import (
    PerformanceCaptureError,
    RESTART_RECOVERY_DOCUMENT,
    RESTART_RECOVERY_SCHEMA_VERSION,
    _Recorder,
    _log_query_boundary,
    _require_operator,
    _validate_profile_files,
    capture_performance_observations,
    recover_interrupted_performance_shaping,
)
from scripts.physical_capture.session import CaptureEvent, PhysicalCaptureSession


REPOSITORY = Path(__file__).resolve().parents[2]


class _Operator:
    def request_terminal_mode(self, mode, *, reason, iteration, deadline) -> None:
        raise AssertionError("closed-session test must not reach an operator checkpoint")

    def confirm_privileged_preflight(self, instruction: str) -> None:
        raise AssertionError("closed-session test must not reach privileged preflight")


class _RecoveryOperator:
    def request_terminal_mode(self, mode, *, reason, iteration, deadline) -> None:
        raise AssertionError("recovery must not request a product mode")

    def confirm_privileged_preflight(self, instruction: str) -> None:
        return None


class _CleanupRecorder(_Recorder):
    def __init__(self, *, fail_roles: frozenset[str] = frozenset()) -> None:
        self.cancelled = lambda: True
        self.calls: list[tuple[str, bool]] = []
        self.failure_recorded: bool | None = None
        self.fail_roles = fail_roles
        self.shaping_transactions = []

    def command(self, role, argv, *, timeout=60.0, honor_cancellation=True):
        self.calls.append((role, honor_cancellation))
        if honor_cancellation:
            raise PerformanceCaptureError("performance_capture_cancelled", "cancelled")
        if role in self.fail_roles:
            raise PerformanceCaptureError("fixed_command_failed", "injected failure")
        return {"role": role, "argv": list(argv), "stdout": ""}

    def _record_failed_restoration(
        self,
        *,
        profile_id,
        index,
        restore_commands,
        restoration_queries,
        restoration_failures,
        cleanup_succeeded,
    ) -> None:
        self.failure_recorded = cleanup_succeeded


class PerformanceCaptureTests(unittest.TestCase):
    def test_operator_protocol_is_checked_without_type_suppression(self) -> None:
        operator = _Operator()
        self.assertIs(_require_operator(operator), operator)
        with self.assertRaisesRegex(
            PerformanceCaptureError, "explicit operator checkpoint methods"
        ):
            _require_operator(SimpleNamespace(request_terminal_mode=lambda: None))

    def test_log_query_upper_bound_is_always_exclusive_next_second(self) -> None:
        exact = datetime(2026, 8, 1, 20, 4, 51, tzinfo=timezone.utc)
        fractional = exact.replace(microsecond=924344)
        expected = datetime(2026, 8, 1, 20, 4, 52, tzinfo=timezone.utc)
        self.assertEqual(_log_query_boundary(exact, upper=True), expected)
        self.assertEqual(_log_query_boundary(fractional, upper=True), expected)
        self.assertEqual(_log_query_boundary(fractional, upper=False), exact)

    def test_reviewed_pf_profiles_match_source_pinned_hashes(self) -> None:
        directory = REPOSITORY / "scripts/physical_capture/performance_profiles"
        for profile_id, profile in contract.WEAK_NETWORK_PROFILES.items():
            data = (directory / f"{profile_id}.pf").read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), profile["profile_sha256"])
            self.assertEqual(
                data.decode("ascii").splitlines(),
                [
                    f"dummynet in quick all pipe {profile['pipe_id']}",
                    f"dummynet out quick all pipe {profile['pipe_id']}",
                ],
            )

    def test_installed_pf_profiles_require_exact_read_only_mode(self) -> None:
        directory_metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        profile_metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        with (
            patch.object(Path, "lstat", return_value=directory_metadata),
            patch("scripts.physical_capture.performance.os.open", return_value=41),
            patch("scripts.physical_capture.performance.os.fstat", return_value=profile_metadata),
            patch("scripts.physical_capture.performance.os.read", return_value=b"profile"),
            patch("scripts.physical_capture.performance.os.close"),
        ):
            with self.assertRaisesRegex(PerformanceCaptureError, "reviewed source"):
                _validate_profile_files()

    def test_installed_pf_profile_directory_must_be_root_owned(self) -> None:
        unsafe_directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=501)
        with patch.object(Path, "lstat", return_value=unsafe_directory):
            with self.assertRaisesRegex(PerformanceCaptureError, "root-owned"):
                _validate_profile_files()

    def test_capture_requires_locked_collecting_session(self) -> None:
        with self.assertRaisesRegex(PerformanceCaptureError, "locked PhysicalCaptureSession"):
            capture_performance_observations(
                session=object(),
                context={},
                parameters={},
                operator=_Operator(),
            )
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "target").mkdir()
            session = PhysicalCaptureSession.create(
                repository,
                "performance-session",
                intent_sha256="a" * 64,
            )
            self.addCleanup(session.close)
            with self.assertRaisesRegex(PerformanceCaptureError, "before RAW_COMPLETED"):
                capture_performance_observations(
                    session=session,
                    context={},
                    parameters={},
                    operator=_Operator(),
                )

    def test_cancellation_still_runs_fixed_restore_and_records_failure(self) -> None:
        recorder = _CleanupRecorder()
        with self.assertRaisesRegex(PerformanceCaptureError, "must be abandoned"):
            recorder.shaping_transaction(
                profile_id="latency-100ms-loss-1pct-10mbps",
                index=0,
            )
        self.assertTrue(recorder.failure_recorded)
        self.assertEqual(
            recorder.calls,
            [
                ("performance-dnctl-apply", True),
                ("performance-pf-restore", False),
                ("performance-dnctl-restore", False),
                ("performance-dnctl-query", False),
                ("performance-pf-query", False),
            ],
        )

    def test_cleanup_attempts_every_fixed_step_after_one_restore_failure(self) -> None:
        recorder = _CleanupRecorder(
            fail_roles=frozenset({"performance-pf-restore"})
        )
        with self.assertRaisesRegex(PerformanceCaptureError, "must be abandoned"):
            recorder.shaping_transaction(
                profile_id="latency-100ms-loss-1pct-10mbps",
                index=0,
            )
        self.assertTrue(recorder.failure_recorded)
        self.assertEqual(
            [role for role, _honor_cancellation in recorder.calls],
            [
                "performance-dnctl-apply",
                "performance-pf-restore",
                "performance-dnctl-restore",
                "performance-dnctl-query",
                "performance-pf-query",
            ],
        )

    def test_shaping_argv_contract_has_no_caller_text_or_shell(self) -> None:
        for profile_id, profile in contract.WEAK_NETWORK_PROFILES.items():
            apply = contract._dnctl_apply_argv(profile_id)
            pf = contract._pf_apply_argv(profile_id)
            restore = contract._restore_argvs(profile["pipe_id"])
            self.assertEqual(apply[:3], ("/usr/bin/sudo", "-n", "/usr/sbin/dnctl"))
            self.assertEqual(pf[:3], ("/usr/bin/sudo", "-n", "/sbin/pfctl"))
            self.assertTrue(all(command[0] == "/usr/bin/sudo" for command in restore))
            self.assertNotIn("/bin/sh", {*apply, *pf, *restore[0], *restore[1]})

    def test_restart_recovery_attempts_every_fixed_step_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "target").mkdir()
            session = PhysicalCaptureSession.create(
                repository, "restart-recovery", intent_sha256="a" * 64
            )
            self.addCleanup(session.close)
            session.append(CaptureEvent.COLLECTION_STARTED, binding_sha256="b" * 64)
            intent = session.observation_capture().write_bytes(
                subject="performance:shaping-intent",
                kind="performance-shaping-transaction",
                relative="raw/performance/observations/shaping-intent.json",
                data=b"{}\n",
            )
            roles: list[str] = []
            failed = False

            def command(_capture, _repository, *, role, argv, **_kwargs):
                nonlocal failed
                del argv
                roles.append(role)
                if role == "performance-pf-restore" and not failed:
                    failed = True
                    raise PerformanceCaptureError("fixed_command_failed", "injected")
                return {"role": role, "stdout": ""}

            with (
                patch(
                    "scripts.physical_capture.performance._capture_context",
                    return_value=({"version": "0.4.0"}, {}),
                ),
                patch(
                    "scripts.physical_capture.performance._command_document",
                    side_effect=command,
                ),
            ):
                with self.assertRaisesRegex(
                    PerformanceCaptureError, "fixed shaping state is not empty"
                ):
                    recover_interrupted_performance_shaping(
                        session=session,
                        context={},
                        operator=_RecoveryOperator(),
                    )

            self.assertEqual(roles.count("performance-pf-restore"), 3)
            self.assertEqual(roles.count("performance-dnctl-restore"), 3)
            self.assertEqual(roles.count("performance-dnctl-query"), 3)
            self.assertEqual(roles.count("performance-pf-query"), 3)
            record = json.loads(
                session.archive.read_bytes(
                    "raw/performance/observations/"
                    "shaping-restart-recovery-01.json"
                )
            )
            self.assertEqual(
                record["schema_version"], RESTART_RECOVERY_SCHEMA_VERSION
            )
            self.assertEqual(record["document"], RESTART_RECOVERY_DOCUMENT)
            self.assertEqual(
                record["privilege_preflight"]["role"],
                "performance-sudo-preflight",
            )
            self.assertEqual(
                roles.count("performance-sudo-preflight"), 1
            )
            self.assertEqual(record["state"], "collecting")
            self.assertEqual(record["archive_root"], "restart-recovery")
            self.assertEqual(
                record["journal_tip_sha256"],
                session.snapshot.last_event_sha256,
            )
            self.assertEqual(
                record["context_sha256"],
                hashlib.sha256(b"{}\n").hexdigest(),
            )
            self.assertEqual(
                record["shaping_intent_sha256"], intent.descriptor.sha256
            )
            failures = [failure for item in record["records"] for failure in item["failures"]]
            self.assertEqual(
                failures,
                [{"code": "fixed_command_failed", "role": "performance-pf-restore"}],
            )


if __name__ == "__main__":
    unittest.main()
