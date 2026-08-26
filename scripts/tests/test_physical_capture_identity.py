from __future__ import annotations

import copy
import hashlib
import inspect
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.harness.lifecycle_matrix import (
    IDENTITY_OBSERVATION_SUBJECTS,
    IDENTITY_PROBE_IDS,
)
from scripts.harness.physical_collector_request import PhysicalCollectorRequestError
from scripts.harness.raw_artifacts import (
    EVIDENCE_PROFILE,
    load_json_bytes,
)
from scripts.hash_artifact import build_manifest
from scripts.physical_capture import identity
from scripts.physical_capture import observation
from scripts.physical_capture.archive import PhysicalCaptureArchiveError
from scripts.physical_capture.execution import (
    CommandResult,
    ProbeExecutionError,
    command_sha256,
)
from scripts.physical_capture.identity import IdentityProbeError
from scripts.physical_capture.session import (
    CaptureEvent,
    CaptureState,
    PhysicalCaptureSession,
)


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class IdentityProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        (self.repository / "target").mkdir(mode=0o755)
        verifier = self.repository / identity.VERIFIER_RELATIVE
        verifier.parent.mkdir()
        verifier.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        verifier.chmod(0o755)
        self.app = self.repository / identity.FINAL_APP_RELATIVE
        self.app.mkdir(parents=True)
        (self.app / "Contents").mkdir()
        (self.repository / identity.FINAL_NATIVE_PRODUCTS_RELATIVE).mkdir(
            parents=True
        )
        self.tree_sha256 = build_manifest(
            self.app, algorithm="sha256-tree-v2"
        )["sha256"]
        candidate = {
            "version": identity.GA_VERSION,
            "build_number": identity.GA_BUILD,
            "app_manifest_sha256": _sha256("app-manifest"),
            "signed_app_tree_sha256": self.tree_sha256,
            "artifact_hash_manifest_sha256": _sha256("artifact-manifest"),
            "built_at": "2026-07-27T00:00:00Z",
        }
        run = {
            "os": "macos15",
            "macos_version": "15.7.8",
            "macos_build": "24G824",
            "machine_sha256": _sha256("machine"),
            "machine_identity_scheme": EVIDENCE_PROFILE["machine_identity_scheme"],
            "hardware_model": "Mac16,1",
            "virtualization_present": False,
            "boot_environment_sha256": _sha256("boot"),
            "boot_environment_scheme": EVIDENCE_PROFILE["boot_environment_scheme"],
            "clean_install": True,
            "run_id": "run-macos15",
        }
        self.context = {
            "schema_version": 1,
            "document": "cfw-physical-run-context-v1",
            "evidence_profile_sha256": _sha256("profile"),
            "candidate": candidate,
            "run": run,
            "initialized_at": "2026-08-01T23:59:00Z",
        }
        self.environment = {
            "machine_sha256": run["machine_sha256"],
            "machine_identity_scheme": run["machine_identity_scheme"],
            "hardware_model": run["hardware_model"],
            "virtualization_present": False,
            "boot_environment_sha256": run["boot_environment_sha256"],
            "boot_environment_scheme": run["boot_environment_scheme"],
            "macos_build": run["macos_build"],
            "architecture": "arm64",
            "operation_context": {
                "operation_id": "operation-macos15",
                "installation_id": "installation-macos15",
                "epoch": 1,
                "generation": 1,
            },
        }
        self.session = PhysicalCaptureSession.create(
            self.repository,
            "physical-capture/run-macos15",
            intent_sha256=_sha256("intent"),
        )
        self.session.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=_sha256("collection"),
        )
        self.archive = self.session.archive
        self.captured: identity.IdentityObservationBatch | None = None

    def tearDown(self) -> None:
        self.session.close()
        self.temporary.cleanup()

    def command_result(
        self,
        spec: object,
        *,
        exit_code: int = 0,
        stdout: bytes | None = None,
        stderr: bytes | None = None,
        started_at: str = "2026-08-02T00:00:00.000Z",
        completed_at: str = "2026-08-02T00:00:01.000Z",
    ) -> CommandResult:
        if stdout is None:
            stdout = (
                f"release app verified: {self.app}\n"
                "identity: YKUPL7Z869 / com.bill.clashformac / "
                "com.bill.clashformac.packet-tunnel / "
                "com.bill.clashformac.proxy-agent\n"
                "platform: arm64 / macOS 15.0+\n"
                f"build number: {identity.GA_BUILD}\n"
            ).encode("utf-8")
        if stderr is None:
            stderr = (
                f"--prepared:{self.app}/Contents\n"
                f"--validated:{self.app}/Contents\n"
                f"{self.app}: valid on disk\n"
                f"{self.app}: satisfies its Designated Requirement\n"
            ).encode("utf-8")
        return CommandResult(
            role=spec.role,
            argv_sha256=command_sha256(spec.argv),
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=1000,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )

    def capture_observations(self) -> identity.IdentityObservationBatch:
        with patch.object(identity, "validate_context") as context_validator, patch.object(
            observation, "run_fixed_command"
        ) as runner:
            context_validator.return_value = copy.deepcopy(self.context)
            runner.side_effect = lambda spec: self.command_result(spec)
            captured = identity.capture_identity_observation(
                session=self.session,
                context=self.context,
                environment=self.environment,
            )
        context_validator.assert_called_once_with(self.context)
        self.assertEqual(runner.call_count, 1)
        spec = runner.call_args.args[0]
        self.assertEqual(
            spec.argv,
            (
                str(self.repository / identity.VERIFIER_RELATIVE),
                str(self.app),
                str(self.repository / identity.FINAL_NATIVE_PRODUCTS_RELATIVE),
                "--context",
                "canonical-native-content",
            ),
        )
        self.captured = captured
        return captured

    def complete_nonce(self) -> None:
        if self.session.state is CaptureState.COLLECTING:
            if self.captured is None:
                raise AssertionError("identity observations were not captured")
            self.session.complete_observations(self.captured.descriptor_mapping())
            for event in (
                CaptureEvent.NONCE_REQUEST_PREPARED,
                CaptureEvent.NONCE_ATTEMPT_STARTED,
                CaptureEvent.NONCE_RESPONSE_RECORDED,
            ):
                self.session.append(event, binding_sha256=_sha256(event.value))
        self.assertIs(self.session.state, CaptureState.NONCE_RECEIVED)

    def test_capture_retains_five_distinct_proof_free_observations(self) -> None:
        captured = self.capture_observations()
        manifest_descriptors = captured.descriptor_mapping()
        self.assertEqual(set(manifest_descriptors), set(IDENTITY_OBSERVATION_SUBJECTS))
        observation_descriptors = {
            probe_id: manifest_descriptors[f"{probe_id}:observation"]
            for probe_id in IDENTITY_PROBE_IDS
        }
        self.assertEqual(
            len({item["path"] for item in observation_descriptors.values()}), 5
        )
        self.assertEqual(
            len({item["sha256"] for item in observation_descriptors.values()}), 5
        )
        for probe_id, descriptor in observation_descriptors.items():
            self.assertEqual(descriptor["kind"], "lifecycle-observation")
            self.assertEqual(
                descriptor["path"],
                f"raw/lifecycle/observations/{probe_id}.json",
            )
            observation_bytes = self.archive.read_bytes(descriptor["path"])
            observation = load_json_bytes(observation_bytes, probe_id)
            self.assertNotIn(b"run_nonce", observation_bytes)
            self.assertNotIn("proof", observation)
            self.assertEqual(observation["probe_id"], probe_id)
            self.assertEqual(observation["candidate"], self.context["candidate"])
            self.assertEqual(observation["run_id"], self.context["run"]["run_id"])
            self.assertEqual(observation["environment"], self.environment)
            self.assertEqual(observation["batch_sha256"], captured.batch_sha256)

    def test_verifier_failure_and_timeout_publish_no_observations(self) -> None:
        for failure in (
            ProbeExecutionError("fixed probe returned an unexpected exit code"),
            ProbeExecutionError("fixed probe exceeded its timeout"),
        ):
            with self.subTest(failure=str(failure)), patch.object(
                identity, "validate_context", return_value=copy.deepcopy(self.context)
            ), patch.object(observation, "run_fixed_command", side_effect=failure):
                with self.assertRaises(IdentityProbeError) as raised:
                    identity.capture_identity_observation(
                        session=self.session,
                        context=self.context,
                        environment=self.environment,
                    )
                self.assertEqual(raised.exception.code, "identity_verifier_failed")
                observation_root = (
                    self.repository
                    / "target/physical-capture/run-macos15/raw/lifecycle/observations"
                )
                self.assertFalse(observation_root.exists())

    def test_warning_and_nonzero_result_are_rejected_before_archive(self) -> None:
        for result_kind in ("warning", "nonzero"):
            with self.subTest(result_kind=result_kind), patch.object(
                identity, "validate_context", return_value=copy.deepcopy(self.context)
            ), patch.object(observation, "run_fixed_command") as runner:
                if result_kind == "warning":
                    runner.side_effect = lambda spec: self.command_result(
                        spec,
                        stdout=(
                            f"release app verified: {self.app}\n"
                            "warning: degraded signature verification\n"
                        ).encode("utf-8"),
                    )
                    expected_code = "identity_observation_invalid"
                else:
                    runner.side_effect = lambda spec: self.command_result(
                        spec, exit_code=1
                    )
                    expected_code = "identity_verifier_result_drift"
                with self.assertRaises(IdentityProbeError) as raised:
                    identity.capture_identity_observation(
                        session=self.session,
                        context=self.context,
                        environment=self.environment,
                    )
                self.assertEqual(raised.exception.code, expected_code)

    def test_candidate_tree_drift_blocks_observations(self) -> None:
        def mutate_candidate(spec: object) -> CommandResult:
            (self.app / "Contents/drift").write_bytes(b"changed")
            return self.command_result(spec)

        with patch.object(
            identity, "validate_context", return_value=copy.deepcopy(self.context)
        ), patch.object(observation, "run_fixed_command", side_effect=mutate_candidate):
            with self.assertRaises(IdentityProbeError) as raised:
                identity.capture_identity_observation(
                    session=self.session,
                    context=self.context,
                    environment=self.environment,
                )
        self.assertEqual(raised.exception.code, "candidate_tree_drift")

    def test_context_and_environment_are_validated_before_verifier(self) -> None:
        with patch.object(
            identity,
            "validate_context",
            side_effect=PhysicalCollectorRequestError("context drift"),
        ), patch.object(observation, "run_fixed_command") as runner:
            with self.assertRaises(IdentityProbeError) as raised:
                identity.capture_identity_observation(
                    session=self.session,
                    context=self.context,
                    environment=self.environment,
                )
            self.assertEqual(raised.exception.code, "identity_context_invalid")
            runner.assert_not_called()

        drifted_environment = copy.deepcopy(self.environment)
        drifted_environment["machine_sha256"] = _sha256("foreign-machine")
        with patch.object(
            identity, "validate_context", return_value=copy.deepcopy(self.context)
        ), patch.object(observation, "run_fixed_command") as runner:
            with self.assertRaises(IdentityProbeError) as raised:
                identity.capture_identity_observation(
                    session=self.session,
                    context=self.context,
                    environment=drifted_environment,
                )
            self.assertEqual(raised.exception.code, "identity_environment_drift")
            runner.assert_not_called()

    def test_observation_archive_failure_is_fail_closed(self) -> None:
        with patch.object(
            identity, "validate_context", return_value=copy.deepcopy(self.context)
        ), patch.object(observation, "run_fixed_command") as runner, patch.object(
            self.archive,
            "write_bytes",
            side_effect=PhysicalCaptureArchiveError("disk_full", "simulated failure"),
        ):
            runner.side_effect = lambda spec: self.command_result(spec)
            with self.assertRaises(IdentityProbeError) as raised:
                identity.capture_identity_observation(
                    session=self.session,
                    context=self.context,
                    environment=self.environment,
                )
        self.assertEqual(raised.exception.code, "identity_observation_archive_failed")

    def test_post_nonce_capture_rejects_before_verifier_execution(self) -> None:
        self.capture_observations()
        self.complete_nonce()
        with patch.object(observation, "run_fixed_command") as runner, patch.object(
            identity, "build_manifest"
        ) as tree_hasher, patch.object(identity, "validate_context") as context_validator:
            with self.assertRaises(IdentityProbeError) as raised:
                identity.capture_identity_observation(
                    session=self.session,
                    context=self.context,
                    environment=self.environment,
                )
        self.assertEqual(raised.exception.code, "identity_collection_closed")
        runner.assert_not_called()
        tree_hasher.assert_not_called()
        context_validator.assert_not_called()

    def test_required_subjects_and_public_apis_are_fixed(self) -> None:
        self.assertEqual(
            IDENTITY_OBSERVATION_SUBJECTS,
            frozenset(f"{probe}:observation" for probe in IDENTITY_PROBE_IDS),
        )
        capture_parameters = inspect.signature(
            identity.capture_identity_observation
        ).parameters
        self.assertEqual(
            set(capture_parameters), {"session", "context", "environment"}
        )
        forbidden = {"passed", "exit", "exit_code", "observation", "argv"}
        self.assertTrue(forbidden.isdisjoint(capture_parameters))
        self.assertFalse(hasattr(identity, "materialize_identity_events"))


if __name__ == "__main__":
    unittest.main()
