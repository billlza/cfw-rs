from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.harness.lifecycle_matrix import PROBE_SPECS
from scripts.harness.raw_artifacts import canonical_json
from scripts.physical_capture import lifecycle
from scripts.physical_capture.execution import CommandResult, command_sha256
from scripts.physical_capture.lifecycle import LifecycleCaptureError
from scripts.physical_capture.session import (
    CaptureEvent,
    PhysicalCaptureSession,
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class LifecycleCaptureBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name)
        (self.repository / "target").mkdir()
        self.session = PhysicalCaptureSession.create(
            self.repository,
            "physical-capture/lifecycle-errors",
            intent_sha256=_sha256("intent"),
        )
        self.addCleanup(self.session.close)
        self.session.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=_sha256("collection"),
        )
        self.state = lifecycle._CaptureBatchState(
            self.session,
            {},
            self.session.observation_capture(),
            {},
        )

    def result(
        self,
        *,
        stdout: bytes,
        stderr: bytes = b"",
        exit_code: int = 0,
    ) -> CommandResult:
        argv = tuple(lifecycle.lifecycle_probe_command("login"))
        return CommandResult(
            role="lifecycle-observation-probe",
            argv_sha256=command_sha256(argv),
            started_at="2026-08-02T01:00:00.000Z",
            completed_at="2026-08-02T01:00:01.000Z",
            duration_ms=1000,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )

    def valid_login_observation(self) -> dict[str, object]:
        environment = {
            "machine_sha256": _sha256("machine"),
            "machine_identity_scheme": "cfw-physical-machine-identity-v1",
            "hardware_model": "Mac16,1",
            "virtualization_present": False,
            "boot_environment_sha256": _sha256("boot"),
            "boot_environment_scheme": "cfw-boot-environment-v1",
            "macos_build": "24G824",
            "architecture": "arm64",
            "operation_context": {
                "operation_id": "operation-macos15",
                "installation_id": "installation-macos15",
                "epoch": 1,
                "generation": 1,
            },
        }
        candidate = {
            "version": "0.4.0",
            "build_number": "40038",
            "app_manifest_sha256": _sha256("app"),
            "signed_app_tree_sha256": _sha256("tree"),
            "artifact_hash_manifest_sha256": _sha256("artifacts"),
            "built_at": "2026-08-01T00:00:00Z",
        }
        self.state.context = {
            "candidate": candidate,
            "run": {
                "run_id": "run-40038-macos15",
                **{
                    field: environment[field]
                    for field in lifecycle._CONTEXT_ENVIRONMENT_FIELDS
                },
            },
        }
        return {
            "schema_version": 1,
            "document": "cfw-lifecycle-observation-v1",
            "candidate": candidate,
            "run_id": "run-40038-macos15",
            "environment": environment,
            "probe_id": "login",
            "category": "session",
            "command": lifecycle.lifecycle_probe_command("login"),
            "started_at": "2026-08-02T01:00:00.000Z",
            "finished_at": "2026-08-02T01:00:01.000Z",
            "exit_code": 0,
            "events": [
                {
                    "sequence": 0,
                    "type": "probe-started",
                    "probe_id": "login",
                    "observation": "",
                },
                {
                    "sequence": 1,
                    "type": "probe-observation",
                    "probe_id": "login",
                    "observation": "transition-observed",
                },
                {
                    "sequence": 2,
                    "type": "probe-finished",
                    "probe_id": "login",
                    "observation": "",
                },
            ],
            "attributes": {},
            "evidence": None,
        }

    def assert_capture_error(
        self, result: CommandResult, expected_code: str
    ) -> None:
        with patch.object(self.state.capture, "run_command", return_value=result):
            with self.assertRaises(LifecycleCaptureError) as raised:
                lifecycle._capture_standard_probe(self.state, "login")
        self.assertEqual(raised.exception.code, expected_code)

    def test_stderr_fails_with_typed_error(self) -> None:
        self.assert_capture_error(
            self.result(stdout=b"{}\n", stderr=b"unexpected diagnostic\n"),
            "lifecycle_probe_stderr",
        )

    def test_noncanonical_output_fails_with_typed_error(self) -> None:
        self.assert_capture_error(
            self.result(stdout=b'{"probe_id":"login"}\n\n'),
            "lifecycle_observation_invalid",
        )

    def test_command_result_binding_mismatch_fails_with_typed_error(self) -> None:
        value = {
            "probe_id": "login",
            "command": lifecycle.lifecycle_probe_command("login"),
            "started_at": "2026-08-02T01:00:00.000Z",
            "finished_at": "2026-08-02T01:00:02.000Z",
            "exit_code": 0,
        }
        self.assert_capture_error(
            self.result(stdout=canonical_json(value) + b"\n"),
            "lifecycle_command_binding_mismatch",
        )

    def test_pre_nonce_proof_and_nonce_are_rejected_before_archive(self) -> None:
        for field in ("proof", "run_nonce"):
            with self.subTest(field=field):
                value = {
                    "probe_id": "login",
                    "command": lifecycle.lifecycle_probe_command("login"),
                    "started_at": "2026-08-02T01:00:00.000Z",
                    "finished_at": "2026-08-02T01:00:01.000Z",
                    "exit_code": 0,
                    field: "0" * 64,
                }
                self.assert_capture_error(
                    self.result(stdout=canonical_json(value) + b"\n"),
                    "pre_nonce_proof_material",
                )

    def test_registry_standard_adapter_reaches_validated_observation_archive(self) -> None:
        value = self.valid_login_observation()
        result = self.result(stdout=canonical_json(value) + b"\n")
        capture, _materialize = lifecycle.LIFECYCLE_PRODUCER_REGISTRY["login"]
        with patch.object(self.state.capture, "run_command", return_value=result):
            artifacts = capture(self.state, "login")
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].subject, "login:observation")
        self.assertEqual(artifacts[0].descriptor.kind, "lifecycle-observation")
        self.assertEqual(self.state.environment, value["environment"])

    def test_registry_is_the_exact_immutable_probe_closure(self) -> None:
        self.assertEqual(set(lifecycle.LIFECYCLE_PRODUCER_REGISTRY), set(PROBE_SPECS))
        self.assertEqual(len(lifecycle.LIFECYCLE_PRODUCER_REGISTRY), 32)
        with self.assertRaises(TypeError):
            lifecycle.LIFECYCLE_PRODUCER_REGISTRY["unknown"] = (
                lifecycle._capture_standard_probe,
                lifecycle._materialize_probe,
            )


if __name__ == "__main__":
    unittest.main()
