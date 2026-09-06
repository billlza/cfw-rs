from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.publication.common import PublicationError
from scripts.publication.bounded_process import BoundedProcessError
from scripts.publication import sealed_manifest
from scripts.repository_source_identity import SourceIdentityError
from scripts import sealed_evidence_manifest


COMMIT = "a" * 40
SOURCE = "b" * 64


class SourceGateCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        scripts = self.repository / "scripts"
        scripts.mkdir()
        self.gate = scripts / "gate.py"
        self.gate.write_text("raise SystemExit(0)\n", encoding="utf-8")
        self.output = self.repository / "source-gates.json"
        self.addCleanup(self.output.unlink, missing_ok=True)
        self.journal = self.repository / "source-gate-journal"
        self.arguments = argparse.Namespace(output=self.output, journal=None)
        self.identity = {
            "repositoryCommit": COMMIT,
            "releaseSourceSha256": SOURCE,
        }

    def collect(
        self,
        identities: list[dict[str, str]],
        *,
        exit_code: int = 0,
        expect_run: bool = True,
        required_gates: dict[str, str] | None = None,
    ) -> None:
        gates = {"test-gate": "scripts/gate.py"} if required_gates is None else required_gates
        completed = subprocess.CompletedProcess(
            args=[
                "/bin/bash",
                "-p",
                "-c",
                'source "$1/scripts/release_python_launcher.sh"; '
                'cfw_run_release_python_script "$1" "$2"',
                "source-gate-python",
                str(self.repository),
                str(self.gate),
            ],
            returncode=exit_code,
            stdout=b"gate passed\n",
            stderr=b"",
        )
        with patch.object(
            sealed_evidence_manifest,
            "_repository",
            return_value=self.repository,
        ), patch.object(
            sealed_evidence_manifest,
            "load_pins",
            return_value={"fixture": "pin"},
        ), patch.object(
            sealed_evidence_manifest,
            "release_tool_environment",
            return_value={
                "CFW_RELEASE_PYTHON_EXECUTABLE": "/fixed/python3",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        ), patch.object(
            sealed_evidence_manifest,
            "REQUIRED_SOURCE_GATES",
            gates,
        ), patch.object(
            sealed_manifest,
            "REQUIRED_SOURCE_GATES",
            gates,
        ), patch.object(
            sealed_evidence_manifest,
            "current_identity",
            side_effect=identities,
        ), patch.object(
            sealed_evidence_manifest,
            "run_bounded_process",
            return_value=completed,
        ) as runner:
            try:
                sealed_evidence_manifest.command_collect_source_gates(self.arguments)
            finally:
                if expect_run:
                    self.assertEqual(runner.call_args.args[0], completed.args)
                    self.assertEqual(runner.call_args.kwargs["cwd"], self.repository)
                else:
                    runner.assert_not_called()

    def test_collection_binds_clean_source_before_and_after_gate_set(self) -> None:
        self.collect([self.identity, self.identity])
        document = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], 3)
        self.assertEqual(document["document"], "p0-source-gates-v3")
        self.assertEqual(document["attempt_number"], 1)
        self.assertEqual(document["attempt_outcome"], "completed")
        self.assertEqual(document["prior_attempt_sha256s"], [])
        self.assertEqual(document["repository_commit"], COMMIT)
        self.assertEqual(document["release_source_sha256"], SOURCE)
        self.assertEqual(document["gates"][0]["commit"], COMMIT)
        self.assertEqual(document["gates"][0]["release_source_sha256"], SOURCE)
        self.assertEqual(
            self.output.read_bytes(),
            (self.journal / "attempt-0001.json").read_bytes(),
        )

    def test_source_change_during_collection_refuses_to_write_a_record(self) -> None:
        changed = dict(self.identity, releaseSourceSha256="c" * 64)
        with self.assertRaisesRegex(PublicationError, "identity changed"):
            self.collect([self.identity, changed])
        self.assertFalse(self.output.exists())
        attempt = json.loads(
            (self.journal / "attempt-0001.json").read_text(encoding="utf-8")
        )
        self.assertEqual(attempt["attempt_outcome"], "outcome-unknown")
        self.assertEqual(
            sorted(entry.name for entry in self.journal.iterdir()),
            ["attempt-0001.json", "intent-0001.json"],
        )

    def test_failed_gate_is_recorded_but_the_command_returns_failure(self) -> None:
        with self.assertRaisesRegex(PublicationError, "did not pass"):
            self.collect([self.identity, self.identity], exit_code=7)
        self.assertFalse(self.output.exists())
        document = json.loads(
            (self.journal / "attempt-0001.json").read_text(encoding="utf-8")
        )
        self.assertEqual(document["gates"][0]["status"], "failed")
        self.assertEqual(document["gates"][0]["exit_code"], 7)

    def test_existing_passing_canonical_is_idempotently_verified_without_rerun(self) -> None:
        self.collect([self.identity, self.identity])
        canonical = self.output.read_bytes()
        self.collect([self.identity], expect_run=False)
        self.assertEqual(self.output.read_bytes(), canonical)
        self.assertEqual(
            sorted(entry.name for entry in self.journal.iterdir()),
            ["attempt-0001.json", "intent-0001.json"],
        )

    def test_crash_after_passing_attempt_recovers_same_bytes_without_rerun(self) -> None:
        with patch.object(
            sealed_evidence_manifest,
            "_publish_source_gate_canonical",
            side_effect=RuntimeError("injected crash after attempt append"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected crash"):
                self.collect([self.identity, self.identity])
        attempt = self.journal / "attempt-0001.json"
        self.assertTrue(attempt.is_file())
        self.assertFalse(self.output.exists())

        self.collect([self.identity, self.identity], expect_run=False)
        self.assertEqual(self.output.read_bytes(), attempt.read_bytes())

    def test_different_existing_canonical_fails_closed_without_rerun(self) -> None:
        self.collect([self.identity, self.identity])
        self.output.write_bytes(b'{"different":true}\n')
        with self.assertRaisesRegex(PublicationError, "differs"):
            self.collect([self.identity], expect_run=False)

    def test_failed_attempt_cannot_be_installed_as_canonical(self) -> None:
        with self.assertRaisesRegex(PublicationError, "did not pass"):
            self.collect([self.identity, self.identity], exit_code=7)
        failed = self.journal / "attempt-0001.json"
        self.output.write_bytes(failed.read_bytes())
        with self.assertRaisesRegex(PublicationError, "latest attempt failed"):
            self.collect([self.identity], expect_run=False)

    def test_failed_attempt_can_be_followed_by_one_real_passing_attempt(self) -> None:
        with self.assertRaisesRegex(PublicationError, "did not pass"):
            self.collect([self.identity, self.identity], exit_code=7)
        self.collect([self.identity, self.identity])
        passing = self.journal / "attempt-0002.json"
        self.assertEqual(self.output.read_bytes(), passing.read_bytes())
        self.assertEqual(
            sorted(entry.name for entry in self.journal.iterdir()),
            [
                "attempt-0001.json",
                "attempt-0002.json",
                "intent-0001.json",
                "intent-0002.json",
            ],
        )
        first_digest = sealed_evidence_manifest.hashlib.sha256(
            (self.journal / "attempt-0001.json").read_bytes()
        ).hexdigest()
        self.assertEqual(
            json.loads(passing.read_text(encoding="utf-8"))["prior_attempt_sha256s"],
            [first_digest],
        )

    def test_numbering_gap_fails_closed_without_rerun(self) -> None:
        self.collect([self.identity, self.identity])
        attempt = self.journal / "attempt-0001.json"
        attempt.rename(self.journal / "attempt-0002.json")
        self.output.unlink()
        with self.assertRaisesRegex(PublicationError, "numbering has a gap"):
            self.collect([self.identity], expect_run=False)

    def test_copied_attempt_with_a_different_path_number_fails_closed(self) -> None:
        self.collect([self.identity, self.identity])
        attempt = self.journal / "attempt-0001.json"
        (self.journal / "attempt-0002.json").write_bytes(attempt.read_bytes())
        self.output.unlink()
        with self.assertRaisesRegex(PublicationError, "inconsistent"):
            self.collect([self.identity], expect_run=False)

    def test_identical_failed_results_are_distinct_numbered_attempts(self) -> None:
        for _number in (1, 2):
            with self.assertRaisesRegex(PublicationError, "did not pass"):
                self.collect([self.identity, self.identity], exit_code=7)
        first = json.loads(
            (self.journal / "attempt-0001.json").read_text(encoding="utf-8")
        )
        second = json.loads(
            (self.journal / "attempt-0002.json").read_text(encoding="utf-8")
        )
        self.assertEqual(first["attempt_number"], 1)
        self.assertEqual(second["attempt_number"], 2)
        self.assertEqual(first["gates"], second["gates"])

    def test_complete_pending_attempt_is_promoted_without_rerunning(self) -> None:
        real_promote = sealed_evidence_manifest.promote_private_pending

        def interrupt_attempt_promotion(pending: Path, destination: Path) -> None:
            if destination.name.startswith("attempt-"):
                raise RuntimeError("injected interruption before attempt promotion")
            real_promote(pending, destination)

        with patch.object(
            sealed_evidence_manifest,
            "promote_private_pending",
            side_effect=interrupt_attempt_promotion,
        ):
            with self.assertRaisesRegex(RuntimeError, "injected interruption"):
                self.collect([self.identity, self.identity])
        pending = self.journal / ".attempt-0001.json.pending"
        self.assertTrue(pending.is_file())
        self.assertFalse((self.journal / "attempt-0001.json").exists())

        self.collect([self.identity, self.identity], expect_run=False)
        self.assertFalse(pending.exists())
        self.assertEqual(
            self.output.read_bytes(),
            (self.journal / "attempt-0001.json").read_bytes(),
        )

    def test_attempt_with_unknown_directory_durability_is_resynced_before_canonical(self) -> None:
        real_promote = sealed_evidence_manifest.promote_private_pending

        def fail_after_attempt_rename(pending: Path, destination: Path) -> None:
            real_promote(pending, destination)
            if destination.name.startswith("attempt-"):
                raise PublicationError("injected attempt durability unknown")

        with patch.object(
            sealed_evidence_manifest,
            "promote_private_pending",
            side_effect=fail_after_attempt_rename,
        ):
            with self.assertRaisesRegex(PublicationError, "durability unknown"):
                self.collect([self.identity, self.identity])
        self.assertTrue((self.journal / "attempt-0001.json").is_file())
        self.assertFalse(self.output.exists())

        events: list[str] = []
        real_sync = sealed_evidence_manifest.fsync_locked_directory
        real_publish = sealed_evidence_manifest._publish_source_gate_canonical

        def observe_sync(descriptor: int, path: Path) -> None:
            events.append("journal-fsync")
            real_sync(descriptor, path)

        def observe_publish(output: Path, attempt: object) -> None:
            events.append("canonical-publish")
            self.assertIn("journal-fsync", events)
            real_publish(output, attempt)

        with patch.object(
            sealed_evidence_manifest,
            "fsync_locked_directory",
            side_effect=observe_sync,
        ), patch.object(
            sealed_evidence_manifest,
            "_publish_source_gate_canonical",
            side_effect=observe_publish,
        ):
            self.collect([self.identity, self.identity], expect_run=False)
        self.assertLess(events.index("journal-fsync"), events.index("canonical-publish"))

    def test_failed_recovery_journal_fsync_blocks_canonical_without_rerun(self) -> None:
        with patch.object(
            sealed_evidence_manifest,
            "_publish_source_gate_canonical",
            side_effect=RuntimeError("injected crash after attempt append"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected crash"):
                self.collect([self.identity, self.identity])
        self.assertFalse(self.output.exists())

        with patch.object(
            sealed_evidence_manifest,
            "fsync_locked_directory",
            side_effect=PublicationError("injected journal fsync failure"),
        ), patch.object(
            sealed_evidence_manifest,
            "_publish_source_gate_canonical",
        ) as publish:
            with self.assertRaisesRegex(PublicationError, "journal fsync failure"):
                self.collect([self.identity], expect_run=False)
        publish.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_truncated_pending_attempt_becomes_unknown_and_requires_explicit_retry(self) -> None:
        self.journal.mkdir(mode=0o700)
        sealed_evidence_manifest._create_source_gate_intent(
            self.journal, [], self.identity
        )
        pending = self.journal / ".attempt-0001.json.pending"
        pending.write_bytes(b'{"document"')
        pending.chmod(0o600)
        with self.assertRaisesRegex(PublicationError, "outcome is unknown"):
            self.collect([self.identity], expect_run=False)
        self.assertFalse(pending.exists())
        unknown = json.loads(
            (self.journal / "attempt-0001.json").read_text(encoding="utf-8")
        )
        self.assertEqual(unknown["attempt_outcome"], "outcome-unknown")
        self.assertEqual(unknown["gates"], [])

        with self.assertRaisesRegex(PublicationError, "latest.*outcome is unknown"):
            self.collect([self.identity], expect_run=False)

        self.arguments.retry_after_outcome_unknown = True
        self.collect([self.identity, self.identity])
        passing = json.loads(
            (self.journal / "attempt-0002.json").read_text(encoding="utf-8")
        )
        self.assertEqual(passing["attempt_outcome"], "completed")
        self.assertEqual(len(passing["prior_attempt_sha256s"]), 1)

    def test_complete_pending_intent_is_safe_to_promote_before_first_gate(self) -> None:
        real_promote = sealed_evidence_manifest.promote_private_pending

        def interrupt_intent_promotion(pending: Path, destination: Path) -> None:
            if destination.name.startswith("intent-"):
                raise RuntimeError("injected interruption before intent promotion")
            real_promote(pending, destination)

        with patch.object(
            sealed_evidence_manifest,
            "promote_private_pending",
            side_effect=interrupt_intent_promotion,
        ):
            with self.assertRaisesRegex(RuntimeError, "intent promotion"):
                self.collect([self.identity], expect_run=False)
        self.assertTrue((self.journal / ".intent-0001.json.pending").is_file())

        self.collect([self.identity, self.identity])
        self.assertTrue(self.output.is_file())

    def test_committed_intent_without_result_becomes_unknown_without_rerun(self) -> None:
        self.journal.mkdir(mode=0o700)
        sealed_evidence_manifest._create_source_gate_intent(
            self.journal, [], self.identity
        )
        with self.assertRaisesRegex(PublicationError, "outcome is unknown"):
            self.collect([self.identity], expect_run=False)
        attempt = json.loads(
            (self.journal / "attempt-0001.json").read_text(encoding="utf-8")
        )
        self.assertEqual(attempt["attempt_outcome"], "outcome-unknown")

    def test_canonical_rename_with_unknown_durability_recovers_existing_output(self) -> None:
        real_promote = sealed_evidence_manifest.promote_private_pending

        def fault_after_canonical_rename(pending: Path, destination: Path) -> None:
            real_promote(pending, destination)
            if destination == self.output:
                raise PublicationError("injected canonical durability unknown")

        with patch.object(
            sealed_evidence_manifest,
            "promote_private_pending",
            side_effect=fault_after_canonical_rename,
        ):
            with self.assertRaisesRegex(PublicationError, "durability unknown"):
                self.collect([self.identity, self.identity])
        self.assertTrue(self.output.is_file())
        self.collect([self.identity], expect_run=False)

    def test_journal_cannot_be_the_canonical_output_parent(self) -> None:
        self.arguments = argparse.Namespace(output=self.output, journal=self.output.parent)
        with self.assertRaisesRegex(PublicationError, "below|namespaces must be disjoint"):
            self.collect([self.identity], expect_run=False)

    def test_exhausted_journal_refuses_before_gate_execution(self) -> None:
        with self.assertRaisesRegex(PublicationError, "did not pass"):
            self.collect([self.identity, self.identity], exit_code=7)
        with patch.object(sealed_evidence_manifest, "SOURCE_GATE_MAX_ATTEMPTS", 1):
            with self.assertRaisesRegex(PublicationError, "exhausted"):
                self.collect([self.identity], expect_run=False)

    def test_missing_gate_is_a_structural_failure_without_an_attempt(self) -> None:
        with self.assertRaisesRegex(PublicationError, "script is missing"):
            self.collect(
                [self.identity],
                expect_run=False,
                required_gates={"missing": "scripts/missing.py"},
            )
        self.assertEqual(list(self.journal.iterdir()), [])

    def test_tampered_attempt_fails_closed_without_rerun(self) -> None:
        self.collect([self.identity, self.identity])
        attempt = self.journal / "attempt-0001.json"
        document = json.loads(attempt.read_text(encoding="utf-8"))
        document["gates"][0]["exit_code"] = 9
        attempt.write_bytes(sealed_evidence_manifest.canonical_json(document))
        self.output.unlink()
        with self.assertRaisesRegex(PublicationError, "masks a nonzero"):
            self.collect([self.identity], expect_run=False)

    def test_stale_source_attempt_fails_closed_without_rerun(self) -> None:
        self.collect([self.identity, self.identity])
        self.output.unlink()
        changed = dict(self.identity, releaseSourceSha256="c" * 64)
        with self.assertRaisesRegex(PublicationError, "different release source"):
            self.collect([changed], expect_run=False)

    def test_symlinked_attempt_fails_closed_without_rerun(self) -> None:
        self.collect([self.identity, self.identity])
        attempt = self.journal / "attempt-0001.json"
        saved = self.repository / "saved-attempt.json"
        attempt.rename(saved)
        attempt.symlink_to(saved)
        self.output.unlink()
        with self.assertRaisesRegex(PublicationError, "single-link regular file"):
            self.collect([self.identity], expect_run=False)

    def test_symlinked_journal_fails_closed_before_gate_execution(self) -> None:
        real_journal = self.repository / "real-source-gate-journal"
        real_journal.mkdir()
        self.journal.symlink_to(real_journal, target_is_directory=True)
        with patch.object(
            sealed_evidence_manifest,
            "_repository",
            return_value=self.repository,
        ), patch.object(
            sealed_evidence_manifest,
            "load_pins",
            return_value={"fixture": "pin"},
        ), patch.object(
            sealed_evidence_manifest,
            "release_tool_environment",
            return_value={"CFW_RELEASE_PYTHON_EXECUTABLE": "/fixed/python3"},
        ), patch.object(
            sealed_evidence_manifest,
            "current_identity",
            return_value=self.identity,
        ) as identity, patch.object(
            sealed_evidence_manifest,
            "run_bounded_process",
        ) as runner:
            with self.assertRaisesRegex(PublicationError, "owner-private real directory"):
                sealed_evidence_manifest.command_collect_source_gates(self.arguments)
        identity.assert_called_once_with(
            self.repository,
            require_clean=True,
            environment={"CFW_RELEASE_PYTHON_EXECUTABLE": "/fixed/python3"},
        )
        runner.assert_not_called()

    def test_symlinked_canonical_fails_closed_without_rerun(self) -> None:
        self.collect([self.identity, self.identity])
        saved = self.repository / "saved-canonical.json"
        self.output.rename(saved)
        self.output.symlink_to(saved)
        with self.assertRaisesRegex(PublicationError, "canonical output is a symlink"):
            self.collect([self.identity], expect_run=False)

    def test_explicit_journal_path_is_used(self) -> None:
        explicit = self.repository / "explicit-journal"
        self.arguments = argparse.Namespace(output=self.output, journal=explicit)
        self.collect([self.identity, self.identity])
        self.assertTrue((explicit / "attempt-0001.json").is_file())
        self.assertFalse(self.journal.exists())

    def test_dirty_initial_source_refuses_to_execute_a_gate(self) -> None:
        with patch.object(
            sealed_evidence_manifest,
            "_repository",
            return_value=self.repository,
        ), patch.object(
            sealed_evidence_manifest,
            "load_pins",
            return_value={"fixture": "pin"},
        ), patch.object(
            sealed_evidence_manifest,
            "release_tool_environment",
            return_value={
                "CFW_RELEASE_PYTHON_EXECUTABLE": "/fixed/python3",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        ), patch.object(
            sealed_evidence_manifest,
            "current_identity",
            side_effect=SourceIdentityError("dirty"),
        ), patch.object(sealed_evidence_manifest, "run_bounded_process") as runner:
            with self.assertRaisesRegex(PublicationError, "clean"):
                sealed_evidence_manifest.command_collect_source_gates(self.arguments)
        runner.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.journal.exists())

    def test_timeout_is_recorded_as_nonpassing(self) -> None:
        error = BoundedProcessError(
            "timeout",
            "fixture timeout",
            stdout=b"partial output\n",
        )
        with patch.object(
            sealed_evidence_manifest,
            "_repository",
            return_value=self.repository,
        ), patch.object(
            sealed_evidence_manifest,
            "load_pins",
            return_value={"fixture": "pin"},
        ), patch.object(
            sealed_evidence_manifest,
            "release_tool_environment",
            return_value={"CFW_RELEASE_PYTHON_EXECUTABLE": "/fixed/python3"},
        ), patch.object(
            sealed_evidence_manifest,
            "REQUIRED_SOURCE_GATES",
            {"test-gate": "scripts/gate.py"},
        ), patch.object(
            sealed_manifest,
            "REQUIRED_SOURCE_GATES",
            {"test-gate": "scripts/gate.py"},
        ), patch.object(
            sealed_evidence_manifest,
            "current_identity",
            side_effect=[self.identity, self.identity],
        ), patch.object(
            sealed_evidence_manifest,
            "run_bounded_process",
            side_effect=error,
        ):
            with self.assertRaisesRegex(PublicationError, "did not pass"):
                sealed_evidence_manifest.command_collect_source_gates(self.arguments)
        self.assertFalse(self.output.exists())
        document = json.loads(
            (self.journal / "attempt-0001.json").read_text(encoding="utf-8")
        )
        self.assertEqual(document["gates"][0]["status"], "timeout")
        self.assertEqual(document["gates"][0]["exit_code"], 124)

    def test_output_limit_records_unknown_outcome_without_masking_failure(self) -> None:
        error = BoundedProcessError("output-limit", "fixture output limit")
        with patch.object(
            sealed_evidence_manifest,
            "_repository",
            return_value=self.repository,
        ), patch.object(
            sealed_evidence_manifest,
            "load_pins",
            return_value={"fixture": "pin"},
        ), patch.object(
            sealed_evidence_manifest,
            "release_tool_environment",
            return_value={"CFW_RELEASE_PYTHON_EXECUTABLE": "/fixed/python3"},
        ), patch.object(
            sealed_evidence_manifest,
            "REQUIRED_SOURCE_GATES",
            {"test-gate": "scripts/gate.py"},
        ), patch.object(
            sealed_evidence_manifest,
            "current_identity",
            return_value=self.identity,
        ), patch.object(
            sealed_evidence_manifest,
            "run_bounded_process",
            side_effect=error,
        ):
            with self.assertRaisesRegex(PublicationError, "process boundary"):
                sealed_evidence_manifest.command_collect_source_gates(self.arguments)
        self.assertFalse(self.output.exists())
        attempt = json.loads(
            (self.journal / "attempt-0001.json").read_text(encoding="utf-8")
        )
        self.assertEqual(attempt["attempt_outcome"], "outcome-unknown")
        self.assertEqual(attempt["gates"], [])


if __name__ == "__main__":
    unittest.main()
