from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts.harness.raw_artifacts import canonical_json, load_json_bytes
from scripts.physical_capture import observation as observation_module
from scripts.physical_capture.archive import (
    PRIVATE_FILE_MODE,
    PhysicalCaptureArchiveError,
)
from scripts.physical_capture.execution import CommandSpec, ReadinessSpec
from scripts.physical_capture.observation import (
    OBSERVATION_MANIFEST_RELATIVE,
    PhysicalObservationError,
    publish_observation_manifest,
)
from scripts.physical_capture.session import (
    CaptureEvent,
    CaptureState,
    PhysicalCaptureSession,
    PhysicalCaptureSessionError,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _wait_for_path(path: Path, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.01)
    return path.exists()


_PHASE_CLOSURE_PROBE = (
    'if [ "$1" = ready ]; then printf "READY\\n"; '
    'elif [ "$1" != silent ]; then exit 64; fi; '
    '( /usr/bin/touch "$2"; while [ ! -e "$3" ]; do /bin/sleep 0.01; done; '
    '/usr/bin/touch "$4" ) & /bin/sleep 30'
)


class PhysicalCaptureObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        (self.repository / "target").mkdir(mode=0o755)
        self.relative = "physical-capture/run-40005-macos15"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @property
    def root(self) -> Path:
        return self.repository / "target" / self.relative

    def collecting_session(self) -> PhysicalCaptureSession:
        session = PhysicalCaptureSession.create(
            self.repository,
            self.relative,
            intent_sha256=_digest("intent"),
        )
        session.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=_digest("collection"),
        )
        return session

    @staticmethod
    def observations(session: PhysicalCaptureSession) -> dict[str, dict[str, object]]:
        capture = session.observation_capture()
        second = capture.write_bytes(
            subject="zeta:observation",
            kind="lifecycle-event",
            relative="raw/lifecycle/observations/zeta.json",
            data=b'{"probe":"zeta"}\n',
        )
        first = capture.write_bytes(
            subject="alpha:observation",
            kind="packet-capture-provenance",
            relative="raw/packet/observations/alpha.json",
            data=b'{"probe":"alpha"}\n',
        )
        # Deliberately return insertion order opposite to canonical subject order.
        return {
            second.subject: second.descriptor.as_dict(),
            first.subject: first.descriptor.as_dict(),
        }

    def completed_session(self) -> PhysicalCaptureSession:
        session = self.collecting_session()
        session.complete_observations(self.observations(session))
        return session

    def test_manifest_is_canonical_reopened_and_bound_to_raw_completed(self) -> None:
        session = self.collecting_session()
        supplied = self.observations(session)
        manifest = session.complete_observations(supplied)
        self.assertEqual(session.state, CaptureState.RAW_COMPLETE)
        self.assertEqual(
            session.snapshot.observation_manifest_sha256,
            manifest.root_sha256,
        )
        self.assertEqual(session.snapshot.last_binding_sha256, manifest.root_sha256)
        data = session.archive.read_bytes(OBSERVATION_MANIFEST_RELATIVE)
        self.assertEqual(hashlib.sha256(data).hexdigest(), manifest.root_sha256)
        value = load_json_bytes(data, "manifest")
        self.assertEqual(
            [entry["subject"] for entry in value["observations"]],
            ["alpha:observation", "zeta:observation"],
        )
        self.assertEqual(value["observation_count"], 2)
        self.assertEqual(manifest.descriptor_mapping(), {
            subject: supplied[subject] for subject in sorted(supplied)
        })

        session.append(
            CaptureEvent.NONCE_REQUEST_PREPARED,
            binding_sha256=_digest("nonce-request"),
        )
        self.assertEqual(
            session.snapshot.observation_manifest_sha256,
            manifest.root_sha256,
        )
        session.close()

        with PhysicalCaptureSession.open(self.repository, self.relative) as reopened:
            self.assertEqual(
                reopened.load_observation_manifest().root_sha256,
                manifest.root_sha256,
            )
            with self.assertRaisesRegex(
                PhysicalCaptureArchiveError,
                "immutable",
            ):
                reopened.archive.write_bytes(
                    "raw/lifecycle/observations/late.json",
                    b"late\n",
                )

    def test_observation_namespace_is_sealed_but_post_nonce_outputs_remain_writable(
        self,
    ) -> None:
        with self.completed_session() as session:
            with self.assertRaises(PhysicalCaptureArchiveError) as raised:
                session.archive.write_bytes(
                    "raw/lifecycle/observations/late.json",
                    b"late\n",
                )
            self.assertEqual(raised.exception.code, "archive_namespace_sealed")
            with self.assertRaises(PhysicalCaptureArchiveError) as lock_raised:
                session.archive.open_lock_file(
                    "raw/lifecycle/observations/zeta.json"
                )
            self.assertEqual(
                lock_raised.exception.code,
                "archive_namespace_sealed",
            )
            final = session.archive.write_bytes(
                "raw/lifecycle/final-event.json",
                b'{"proof":"post-nonce-materialization"}\n',
            )
            self.assertEqual(final.relative_path, "raw/lifecycle/final-event.json")

    def test_direct_raw_completed_with_arbitrary_digest_is_rejected(self) -> None:
        with self.collecting_session() as session:
            sequence = session.snapshot.sequence
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                session.append(
                    CaptureEvent.RAW_COMPLETED,
                    binding_sha256=_digest("invented-raw-root"),
                )
            self.assertEqual(
                raised.exception.code,
                "raw_completion_requires_manifest",
            )
            self.assertEqual(session.snapshot.sequence, sequence)
            self.assertEqual(session.state, CaptureState.COLLECTING)

    def test_existing_identical_manifest_is_restart_safe_before_raw_event(self) -> None:
        with self.collecting_session() as session:
            supplied = self.observations(session)
            first = publish_observation_manifest(session.archive, supplied)
            second = session.complete_observations(supplied)
            self.assertEqual(first, second)
            self.assertEqual(session.state, CaptureState.RAW_COMPLETE)

    def test_manifest_prefix_pending_is_recovered_before_raw_completion(self) -> None:
        with self.collecting_session() as session:
            supplied = self.observations(session)
            normalized = observation_module._mapping_observations(supplied)
            expected = observation_module._canonical_manifest_bytes(normalized)
            pending = self.root / "raw" / (
                ".observation-manifest.json.pending-" + "a" * 32
            )
            pending.write_bytes(expected[:31])
            pending.chmod(PRIVATE_FILE_MODE)
            session.complete_observations(supplied)
            self.assertEqual(session.state, CaptureState.RAW_COMPLETE)
            self.assertFalse(pending.exists())

    def test_manifest_mismatched_pending_fails_closed(self) -> None:
        with self.collecting_session() as session:
            supplied = self.observations(session)
            pending = self.root / "raw" / (
                ".observation-manifest.json.pending-" + "b" * 32
            )
            pending.write_bytes(b"not-an-expected-prefix")
            pending.chmod(PRIVATE_FILE_MODE)
            with self.assertRaises(PhysicalCaptureSessionError):
                session.complete_observations(supplied)
            self.assertEqual(session.state, CaptureState.COLLECTING)
            self.assertTrue(pending.exists())

    def test_final_manifest_cleans_matching_leftover_pending(self) -> None:
        with self.collecting_session() as session:
            supplied = self.observations(session)
            manifest = publish_observation_manifest(session.archive, supplied)
            data = session.archive.read_bytes(OBSERVATION_MANIFEST_RELATIVE)
            pending = self.root / "raw" / (
                ".observation-manifest.json.pending-" + "c" * 32
            )
            pending.write_bytes(data[:19])
            pending.chmod(PRIVATE_FILE_MODE)
            completed = session.complete_observations(supplied)
            self.assertEqual(completed, manifest)
            self.assertFalse(pending.exists())

    def test_duplicate_path_or_digest_cannot_enter_manifest(self) -> None:
        with self.collecting_session() as session:
            capture = session.observation_capture()
            observation = capture.write_bytes(
                subject="first:observation",
                kind="lifecycle-event",
                relative="raw/lifecycle/observations/first.json",
                data=b'{"probe":"first"}\n',
            )
            descriptor = observation.descriptor.as_dict()
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                session.complete_observations(
                    {
                        observation.subject: descriptor,
                        "second:observation": dict(descriptor),
                    }
                )
            self.assertEqual(raised.exception.code, "observation_manifest_invalid")
            self.assertEqual(session.state, CaptureState.COLLECTING)

    def test_unlisted_pre_nonce_file_prevents_manifest_completion(self) -> None:
        with self.collecting_session() as session:
            supplied = self.observations(session)
            session.archive.write_bytes(
                "raw/lifecycle/observations/unlisted.json",
                b'{"probe":"unlisted"}\n',
            )
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                session.complete_observations(supplied)
            self.assertEqual(raised.exception.code, "observation_manifest_invalid")
            self.assertEqual(session.state, CaptureState.COLLECTING)
            self.assertFalse((self.root / OBSERVATION_MANIFEST_RELATIVE).exists())

    def test_unsafe_empty_observation_namespace_is_not_treated_as_absent(self) -> None:
        with self.collecting_session() as session:
            supplied = self.observations(session)
            outside = self.repository / "outside"
            outside.mkdir(mode=0o700)
            harness = self.root / "raw/adversarial"
            harness.mkdir(mode=0o700)
            (harness / "observations").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                session.complete_observations(supplied)
            self.assertEqual(raised.exception.code, "observation_manifest_invalid")
            self.assertEqual(session.state, CaptureState.COLLECTING)
            self.assertFalse((self.root / OBSERVATION_MANIFEST_RELATIVE).exists())

    def test_out_of_namespace_observation_is_rejected_before_write(self) -> None:
        with self.collecting_session() as session:
            capture = session.observation_capture()
            with self.assertRaises(PhysicalObservationError) as raised:
                capture.write_bytes(
                    subject="outside:observation",
                    kind="lifecycle-event",
                    relative="raw/lifecycle/outside.json",
                    data=b"outside\n",
                )
            self.assertEqual(raised.exception.code, "invalid_observation_path")
            self.assertFalse((self.root / "raw/lifecycle/outside.json").exists())

    def test_producer_and_runner_fail_before_work_after_raw_completed(self) -> None:
        session = self.collecting_session()
        capture = session.observation_capture()
        observations = self.observations(session)
        session.complete_observations(observations)

        with patch(
            "scripts.physical_capture.observation.run_fixed_command"
        ) as runner:
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                capture.run_command(
                    CommandSpec(
                        role="must-not-run",
                        argv=("/bin/echo", "forbidden"),
                        cwd=self.repository,
                        timeout_seconds=1,
                    )
                )
            self.assertEqual(raised.exception.code, "observation_phase_closed")
            runner.assert_not_called()

        with patch(
            "scripts.physical_capture.observation.start_fixed_command"
        ) as starter:
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                capture.start_command(
                    CommandSpec(
                        role="must-not-start",
                        argv=("/bin/echo", "forbidden"),
                        cwd=self.repository,
                        timeout_seconds=1,
                    )
                )
            self.assertEqual(raised.exception.code, "observation_phase_closed")
            starter.assert_not_called()

        with self.assertRaises(PhysicalCaptureSessionError):
            capture.write_bytes(
                subject="late:observation",
                kind="lifecycle-event",
                relative="raw/lifecycle/observations/late.json",
                data=b"late\n",
            )
        self.assertFalse((self.root / "raw/lifecycle/observations/late.json").exists())
        session.close()

    def test_started_observation_command_waits_and_finishes_while_collecting(
        self,
    ) -> None:
        with self.collecting_session() as session:
            capture = session.observation_capture()
            spec = CommandSpec(
                role="observation-ready",
                argv=("/bin/sh", "-c", "printf 'READY\\n'; printf 'done\\n' >&2"),
                cwd=self.repository,
                timeout_seconds=2,
                stdout_limit=64,
                stderr_limit=64,
            )
            with capture.start_command(spec) as command:
                command.wait_for_readiness(
                    ReadinessSpec("stdout", b"READY\n", 1.0)
                )
                result = command.finish()
            self.assertEqual(result.stdout, b"READY\n")
            self.assertEqual(result.stderr, b"done\n")

    def test_phase_closure_after_start_cancels_command_before_readiness(self) -> None:
        session = self.collecting_session()
        capture = session.observation_capture()
        retained = capture.write_bytes(
            subject="phase:sentinel",
            kind="lifecycle-event",
            relative="raw/lifecycle/observations/phase-sentinel.json",
            data=b'{"phase":"collecting"}\n',
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "phase-closed-descendant"
            descendant_started = Path(directory) / "phase-closed-descendant-started"
            release_descendant = Path(directory) / "release-phase-closed-descendant"
            command = capture.start_command(
                CommandSpec(
                    role="phase-closed-probe",
                    argv=(
                        "/bin/sh",
                        "-c",
                        _PHASE_CLOSURE_PROBE,
                        "phase-closed-probe",
                        "silent",
                        str(descendant_started),
                        str(release_descendant),
                        str(marker),
                    ),
                    cwd=Path(directory),
                    timeout_seconds=5,
                    stdout_limit=64,
                )
            )
            try:
                self.assertTrue(_wait_for_path(descendant_started, 2.0))
                session.complete_observations(
                    {retained.subject: retained.descriptor.as_dict()}
                )
                with self.assertRaises(PhysicalCaptureSessionError) as raised:
                    command.wait_for_readiness(
                        ReadinessSpec("stdout", b"READY\n", 1.0)
                    )
                self.assertEqual(raised.exception.code, "observation_phase_closed")
                release_descendant.touch()
                self.assertFalse(_wait_for_path(marker, 0.5))
            finally:
                command.cancel()
        session.close()

    def test_phase_closure_between_readiness_and_finish_cancels_command(self) -> None:
        session = self.collecting_session()
        capture = session.observation_capture()
        retained = capture.write_bytes(
            subject="phase:ready-sentinel",
            kind="lifecycle-event",
            relative="raw/lifecycle/observations/phase-ready-sentinel.json",
            data=b'{"phase":"ready"}\n',
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "finish-after-phase-close"
            descendant_started = Path(directory) / "finish-descendant-started"
            release_descendant = Path(directory) / "release-finish-descendant"
            command = capture.start_command(
                CommandSpec(
                    role="phase-ready-probe",
                    argv=(
                        "/bin/sh",
                        "-c",
                        _PHASE_CLOSURE_PROBE,
                        "phase-ready-probe",
                        "ready",
                        str(descendant_started),
                        str(release_descendant),
                        str(marker),
                    ),
                    cwd=Path(directory),
                    timeout_seconds=5,
                    stdout_limit=64,
                )
            )
            try:
                command.wait_for_readiness(ReadinessSpec("stdout", b"READY\n", 5.0))
                self.assertTrue(_wait_for_path(descendant_started, 2.0))
                session.complete_observations(
                    {retained.subject: retained.descriptor.as_dict()}
                )
                with self.assertRaises(PhysicalCaptureSessionError) as raised:
                    command.finish()
                self.assertEqual(raised.exception.code, "observation_phase_closed")
                release_descendant.touch()
                self.assertFalse(_wait_for_path(marker, 0.5))
            finally:
                command.cancel()
        session.close()

    def test_deleted_observation_prevents_restart(self) -> None:
        session = self.completed_session()
        session.close()
        (self.root / "raw/lifecycle/observations/zeta.json").unlink()
        with self.assertRaises(PhysicalCaptureSessionError) as raised:
            PhysicalCaptureSession.open(self.repository, self.relative)
        self.assertEqual(raised.exception.code, "observation_manifest_invalid")

    def test_replaced_observation_prevents_next_transition(self) -> None:
        with self.completed_session() as session:
            path = self.root / "raw/lifecycle/observations/zeta.json"
            path.write_bytes(b'{"probe":"replaced"}\n')
            path.chmod(PRIVATE_FILE_MODE)
            sequence = session.snapshot.sequence
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                session.append(
                    CaptureEvent.NONCE_REQUEST_PREPARED,
                    binding_sha256=_digest("nonce-request"),
                )
            self.assertEqual(raised.exception.code, "observation_manifest_invalid")
            self.assertEqual(session.snapshot.sequence, sequence)

    def test_reordered_manifest_prevents_next_transition(self) -> None:
        with self.completed_session() as session:
            path = self.root / OBSERVATION_MANIFEST_RELATIVE
            value = load_json_bytes(path.read_bytes(), "manifest")
            value["observations"].reverse()
            path.write_bytes(canonical_json(value) + b"\n")
            path.chmod(PRIVATE_FILE_MODE)
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                session.append(
                    CaptureEvent.NONCE_REQUEST_PREPARED,
                    binding_sha256=_digest("nonce-request"),
                )
            self.assertEqual(raised.exception.code, "observation_manifest_invalid")

    def test_externally_added_observation_prevents_next_transition(self) -> None:
        with self.completed_session() as session:
            extra = self.root / "raw/lifecycle/observations/extra.json"
            extra.write_bytes(b'{"probe":"extra"}\n')
            extra.chmod(PRIVATE_FILE_MODE)
            with self.assertRaises(PhysicalCaptureSessionError) as raised:
                session.append(
                    CaptureEvent.NONCE_REQUEST_PREPARED,
                    binding_sha256=_digest("nonce-request"),
                )
            self.assertEqual(raised.exception.code, "observation_manifest_invalid")


if __name__ == "__main__":
    unittest.main()
