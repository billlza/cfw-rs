from __future__ import annotations

import contextlib
import io
from unittest.mock import patch

from scripts import release_driver_context, release_driver_notarization
from scripts.candidate_artifact_binding import TOOLCHAIN_METADATA_ORDER
from scripts.candidate_freeze import CandidateFreezeError
from scripts.release_driver_context import CHECKOUT, DriverError, common_guards
from scripts.release_executor_source import ExecutorSource, ExecutorSourceError, FrozenReleaseSources
from scripts.tests.test_release_driver import COMMIT, DriverFixture


class FrozenExecutorGuardTests(DriverFixture):
    def setUp(self) -> None:
        super().setUp()
        self.enroll()
        self.executor_commit = "b" * 40
        self.sources = FrozenReleaseSources(
            ExecutorSource(self.release.operator, self.executor_commit, "2" * 64),
            ExecutorSource(self.release.artifact, COMMIT, "1" * 64),
        )
        self.prefix = (
            "/usr/bin/env", "GIT_OPTIONAL_LOCKS=0", "/usr/bin/git", "-C", str(self.release.operator)
        )
        self.machine.answer(self.prefix + ("rev-parse", "--verify", "HEAD"), stdout=self.executor_commit)

    def test_verified_executor_keeps_the_enrolled_product_identity(self) -> None:
        with (
            patch.object(release_driver_context, "capture_frozen_release_sources", return_value=self.sources) as read,
            patch.object(release_driver_context, "read_frozen_toolchain_metadata", return_value={}) as frozen,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(common_guards(self.context()), COMMIT)
        read.assert_called_once_with(self.release.operator)
        frozen.assert_called_once_with(self.release.artifact, source_identity=self.sources.artifact.identity)
        self.assertIn(f"frozen product source: {COMMIT}", output.getvalue())
        self.assertIn(f"evidence executor source: {self.executor_commit}", output.getvalue())
        self.assertEqual(self.machine.executed, [])

    def test_missing_or_invalid_freeze_does_not_admit_a_different_operator(self) -> None:
        with (
            patch.object(release_driver_context, "capture_frozen_release_sources", return_value=self.sources),
            patch.object(release_driver_context, "read_frozen_toolchain_metadata",
                         side_effect=CandidateFreezeError("invalid", "not a valid frozen candidate")),
        ):
            with self.assertRaises(DriverError) as rejected:
                common_guards(self.context())
        self.assertEqual(rejected.exception.status, CHECKOUT)
        self.assertEqual(self.machine.executed, [])

    def test_missing_historical_executor_objects_fail_before_any_command(self) -> None:
        with patch.object(release_driver_context, "capture_frozen_release_sources",
                          side_effect=ExecutorSourceError("missing Git objects")):
            with self.assertRaisesRegex(DriverError, "missing Git objects"):
                common_guards(self.context())
        self.assertEqual(self.machine.executed, [])

    def test_dirty_operator_is_not_relabelled_as_an_executor(self) -> None:
        self.machine.answer(self.prefix + ("status", "--porcelain"), stdout=" M script.py\n")
        with patch.object(release_driver_context, "capture_frozen_release_sources") as read:
            with self.assertRaisesRegex(DriverError, "uncommitted"):
                common_guards(self.context())
        read.assert_not_called()
        self.assertEqual(self.machine.executed, [])

    def test_a_different_artifact_commit_or_path_cannot_use_the_enrollment(self) -> None:
        for artifact in (
            ExecutorSource(self.release.artifact, "c" * 40, "1" * 64),
            ExecutorSource(self.home / "different-artifact", COMMIT, "1" * 64),
        ):
            with self.subTest(artifact=artifact), patch.object(
                release_driver_context, "capture_frozen_release_sources",
                return_value=FrozenReleaseSources(self.sources.executor, artifact),
            ), patch.object(release_driver_context, "read_frozen_toolchain_metadata") as read:
                with self.assertRaisesRegex(DriverError, "enrolled artifact"):
                    common_guards(self.context())
                read.assert_not_called()

    def test_an_executor_change_during_admission_is_rejected(self) -> None:
        changed = FrozenReleaseSources(
            ExecutorSource(self.release.operator, "c" * 40, "3" * 64), self.sources.artifact
        )
        with (
            patch.object(release_driver_context, "capture_frozen_release_sources", return_value=changed),
            patch.object(release_driver_context, "read_frozen_toolchain_metadata", return_value={}),
        ):
            with self.assertRaisesRegex(DriverError, "changed during source admission"):
                common_guards(self.context())


class NotaryRecoveryDispatchTests(DriverFixture):
    def test_recovery_passes_the_original_source_and_observation_without_building_or_signing(self) -> None:
        self.enroll()
        sources = FrozenReleaseSources(
            ExecutorSource(self.release.operator, "b" * 40, "2" * 64),
            ExecutorSource(self.release.artifact, COMMIT, "1" * 64),
        )
        metadata = {key: "3" * 64 for key in TOOLCHAIN_METADATA_ORDER}
        observation = (self.home / "retry-observation.json").resolve()
        observation.write_text("{}")
        identifier = "aaaaaaaa-2222-3333-4444-555555555555"
        with patch.object(release_driver_notarization, "verified_frozen_sources", return_value=(sources, metadata)):
            with contextlib.redirect_stdout(io.StringIO()):
                result = release_driver_notarization.recover_notarization(
                    self.context(), ["--recover-notarization-id", identifier,
                                     "--adopt-upload-observation", str(observation)]
                )
        self.assertEqual(result, 0)
        self.assertEqual(len(self.machine.executed), 1)
        argv, cwd = self.machine.executed[0]
        self.assertEqual(argv[0], "./scripts/run_notarization_transaction.sh")
        self.assertEqual(cwd, self.release.operator)
        values = dict(zip(argv[1::2], argv[2::2], strict=True))
        self.assertEqual(values["--recover-submission-id"], identifier)
        self.assertEqual(values["--adopt-upload-observation"], str(observation))
        self.assertEqual(values["--repository-commit"], COMMIT)
        self.assertEqual(values["--release-source-sha256"], "1" * 64)
        self.assertEqual(values["--artifact-repository"], str(self.release.artifact))
        self.assertEqual(values["--toolchain-root"], str(self.release.artifact / "target/toolchains"))
        self.assertEqual(values["--go-module-cache-tree-sha256"], "3" * 64)
        self.assertNotIn("--ga", argv)
        self.assertFalse(any("build_signed_candidate" in value for value in argv))

    def test_noncanonical_observation_is_refused_before_source_reads_or_commands(self) -> None:
        with patch.object(release_driver_notarization, "verified_frozen_sources") as read:
            with self.assertRaisesRegex(DriverError, "absolute canonical"):
                release_driver_notarization.recover_notarization(
                    self.context(), ["--recover-notarization-id", "not-yet-validated",
                                     "--adopt-upload-observation", "relative.json"]
                )
        read.assert_not_called()
        self.assertEqual(self.machine.executed, [])
