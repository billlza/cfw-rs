from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.publication.common import PublicationError
from scripts.repository_source_identity import SourceIdentityError
from scripts import sealed_evidence_manifest


COMMIT = "a" * 40
SOURCE = "b" * 64


class SourceGateCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name)
        scripts = self.repository / "scripts"
        scripts.mkdir()
        self.gate = scripts / "gate.py"
        self.gate.write_text("raise SystemExit(0)\n", encoding="utf-8")
        self.output = self.repository.parent / f"{self.repository.name}-source-gates.json"
        self.addCleanup(self.output.unlink, missing_ok=True)
        self.arguments = argparse.Namespace(output=self.output)
        self.identity = {
            "repositoryCommit": COMMIT,
            "releaseSourceSha256": SOURCE,
        }

    def collect(
        self,
        identities: list[dict[str, str]],
        *,
        exit_code: int = 0,
    ) -> None:
        completed = subprocess.CompletedProcess(
            args=["python3", "-B", str(self.gate)],
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
            "REQUIRED_SOURCE_GATES",
            {"test-gate": "scripts/gate.py"},
        ), patch.object(
            sealed_evidence_manifest,
            "current_identity",
            side_effect=identities,
        ), patch.object(
            sealed_evidence_manifest.subprocess,
            "run",
            return_value=completed,
        ):
            sealed_evidence_manifest.command_collect_source_gates(self.arguments)

    def test_collection_binds_clean_source_before_and_after_every_gate(self) -> None:
        self.collect([self.identity, self.identity])
        document = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], 2)
        self.assertEqual(document["document"], "p0-source-gates-v2")
        self.assertEqual(document["repository_commit"], COMMIT)
        self.assertEqual(document["release_source_sha256"], SOURCE)
        self.assertEqual(document["gates"][0]["commit"], COMMIT)
        self.assertEqual(document["gates"][0]["release_source_sha256"], SOURCE)

    def test_source_change_during_collection_refuses_to_write_a_record(self) -> None:
        changed = dict(self.identity, releaseSourceSha256="c" * 64)
        with self.assertRaisesRegex(PublicationError, "identity changed"):
            self.collect([self.identity, changed])
        self.assertFalse(self.output.exists())

    def test_failed_gate_is_recorded_but_the_command_returns_failure(self) -> None:
        with self.assertRaisesRegex(PublicationError, "did not pass"):
            self.collect([self.identity, self.identity], exit_code=7)
        document = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(document["gates"][0]["status"], "failed")
        self.assertEqual(document["gates"][0]["exit_code"], 7)

    def test_dirty_initial_source_refuses_to_execute_a_gate(self) -> None:
        with patch.object(
            sealed_evidence_manifest,
            "_repository",
            return_value=self.repository,
        ), patch.object(
            sealed_evidence_manifest,
            "current_identity",
            side_effect=SourceIdentityError("dirty"),
        ), patch.object(sealed_evidence_manifest.subprocess, "run") as runner:
            with self.assertRaisesRegex(PublicationError, "clean"):
                sealed_evidence_manifest.command_collect_source_gates(self.arguments)
        runner.assert_not_called()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
