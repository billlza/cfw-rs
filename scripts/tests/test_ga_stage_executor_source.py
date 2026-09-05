from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from scripts.publication import ga_release_contract as contract
from scripts.publication.common import PublicationError, canonical_json
from scripts.publication.orchestrator import (
    seal_ga_acceptance,
    seal_prepackage,
    seal_publication,
)
from scripts.release_executor_source import ExecutorSourceError, capture_executor_source
from scripts.repository_source_identity import RELEASE_PATHS
from scripts.tests.test_production_release_orchestrator import StageFixture


class GAStageExecutorSourceTests(unittest.TestCase):
    """Exercise sealer and verifier provenance against real immutable Git objects."""

    def setUp(self) -> None:
        self.fixture = StageFixture()
        self.addCleanup(self.fixture.cleanup)
        self.repository = self.fixture.repository
        self.module_path = self.repository / "scripts/publication/ga_release_contract.py"
        self.module_path.parent.mkdir(parents=True)
        self.module_path.write_bytes(Path(contract.__file__).read_bytes())
        (self.repository / "scripts/repository_source_identity.py").write_text(
            f"RELEASE_PATHS = {RELEASE_PATHS!r}\n", encoding="utf-8"
        )
        (self.repository / ".gitignore").write_text("target/\n", encoding="utf-8")
        self.policy = self.repository / "docs/evidence-policy.md"
        self.policy.parent.mkdir()
        self._git("init", "-q")
        self._git("config", "user.name", "Release Test")
        self._git("config", "user.email", "release-test@example.invalid")
        self._commit_policy("candidate source")
        self.artifact = capture_executor_source(self.repository)
        self.fixture.candidate_source = {
            "repository_commit": self.artifact.repository_commit,
            "release_source_sha256": self.artifact.release_source_sha256,
        }
        self._commit_policy("sealing policy")
        self.sealer = capture_executor_source(self.repository)
        self.manifest_path = self.fixture.ga_root / "prepackage/manifest.json"
        for source_patch in (
            patch.object(contract, "__file__", str(self.module_path)),
            patch.object(
                contract,
                "live_verify_hosted_ci_receipt",
                return_value={"document": "live-hosted-ci-fixture"},
            ),
        ):
            source_patch.start()
            self.addCleanup(source_patch.stop)
        composition = patch.object(
            contract, "_prepackage_files", side_effect=self._prepackage_files
        )
        self.compose = composition.start()
        self.addCleanup(composition.stop)

    def _git(self, *arguments: str) -> None:
        subprocess.run(
            [
                "/usr/bin/git", "-C", str(self.repository),
                "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                *arguments,
            ],
            check=True,
            capture_output=True,
        )

    def _commit_policy(self, text: str) -> None:
        self.policy.write_text(text + "\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-q", "-m", text)

    def _prepackage_files(
        self,
        repository: Path,
        executor_source: dict[str, str],
        *,
        expected_live_hosted_ci: dict[str, str] | None = None,
    ) -> dict[str, bytes]:
        self.assertEqual(repository, self.repository)
        return self.fixture.prepackage_files(executor_source=executor_source)

    def test_later_clean_verifier_preserves_original_sealer_and_candidate(self) -> None:
        sealed = seal_prepackage(self.repository, executor=self.sealer)
        self.assertEqual(sealed["executor_source"], self.sealer.identity)
        self.assertEqual(sealed["bindings"]["source"], self.fixture.candidate_source)
        self.assertNotEqual(self.sealer.identity, self.artifact.identity)
        original = self.manifest_path.read_bytes()
        self._commit_policy("later verifier policy")
        verifier = capture_executor_source(self.repository)
        self.assertNotEqual(verifier.identity, self.sealer.identity)
        self.compose.reset_mock()

        self.assertEqual(contract.verify_stage(self.repository, "prepackage"), sealed)
        self.assertEqual(self.manifest_path.read_bytes(), original)
        self.assertEqual(self.compose.call_args.args[1], self.sealer.identity)

    def test_historical_but_not_running_executor_cannot_create_a_seal(self) -> None:
        with self.assertRaisesRegex(PublicationError, "differs from the running source"):
            seal_prepackage(self.repository, executor=self.artifact)
        self.compose.assert_not_called()
        self.assertFalse(self.manifest_path.exists())

    def test_each_stage_keeps_its_own_sealer_across_later_policy_commits(self) -> None:
        prepackage = seal_prepackage(self.repository, executor=self.sealer)
        prepackage_bytes = self.manifest_path.read_bytes()
        with (
            patch.object(
                contract, "_ga_acceptance_files", side_effect=self.fixture.ga_acceptance_files
            ),
            patch.object(
                contract, "_publication_files", side_effect=self.fixture.publication_files
            ),
        ):
            self._commit_policy("acceptance policy")
            acceptance_executor = capture_executor_source(self.repository)
            acceptance = seal_ga_acceptance(self.repository, executor=acceptance_executor)
            acceptance_path = self.fixture.ga_root / "ga-acceptance/manifest.json"
            acceptance_bytes = acceptance_path.read_bytes()
            self._commit_policy("publication policy")
            publication_executor = capture_executor_source(self.repository)
            publication = seal_publication(self.repository, executor=publication_executor)
            self._commit_policy("later read-only verifier policy")
            self.assertEqual(contract.verify_stage(self.repository, "publication"), publication)

        self.assertEqual(prepackage["executor_source"], self.sealer.identity)
        self.assertEqual(acceptance["executor_source"], acceptance_executor.identity)
        self.assertEqual(publication["executor_source"], publication_executor.identity)
        self.assertEqual(self.manifest_path.read_bytes(), prepackage_bytes)
        self.assertEqual(acceptance_path.read_bytes(), acceptance_bytes)

    def test_same_identity_at_a_different_executor_path_is_rejected(self) -> None:
        selected = replace(self.sealer, repository=self.repository / "other")
        with self.assertRaisesRegex(PublicationError, "differs from the running source"):
            seal_prepackage(self.repository, executor=selected)
        self.compose.assert_not_called()
        self.assertFalse(self.manifest_path.exists())

    def test_dirty_executor_stops_before_stage_composition(self) -> None:
        self.policy.write_text("uncommitted policy\n", encoding="utf-8")
        with self.assertRaises(ExecutorSourceError):
            seal_prepackage(self.repository, executor=self.sealer)
        self.compose.assert_not_called()
        self.assertFalse(self.manifest_path.exists())

    def test_historical_sealer_digest_drift_is_rejected_before_recomposition(self) -> None:
        sealed = seal_prepackage(self.repository, executor=self.sealer)
        sealed["executor_source"]["releaseSourceSha256"] = "f" * 64
        self.manifest_path.write_bytes(canonical_json(sealed))
        self.compose.reset_mock()
        with self.assertRaisesRegex(PublicationError, "differs from its historical source"):
            contract.verify_stage(self.repository, "prepackage")
        self.compose.assert_not_called()

    def test_unavailable_historical_sealer_is_rejected_before_recomposition(self) -> None:
        sealed = seal_prepackage(self.repository, executor=self.sealer)
        sealed["executor_source"]["repositoryCommit"] = "f" * 40
        self.manifest_path.write_bytes(canonical_json(sealed))
        self.compose.reset_mock()
        with self.assertRaisesRegex(PublicationError, "Git history is unavailable"):
            contract.verify_stage(self.repository, "prepackage")
        self.compose.assert_not_called()

    def test_dirty_later_verifier_does_not_rewrite_existing_seal(self) -> None:
        seal_prepackage(self.repository, executor=self.sealer)
        original = self.manifest_path.read_bytes()
        self.policy.write_text("uncommitted verifier\n", encoding="utf-8")
        self.compose.reset_mock()
        with self.assertRaises(ExecutorSourceError):
            contract.verify_stage(self.repository, "prepackage")
        self.compose.assert_not_called()
        self.assertEqual(self.manifest_path.read_bytes(), original)

    def test_verifier_drift_during_recomposition_is_rejected(self) -> None:
        seal_prepackage(self.repository, executor=self.sealer)
        original = self.manifest_path.read_bytes()

        def drift(
            repository: Path,
            executor_source: dict[str, str],
            *,
            expected_live_hosted_ci: dict[str, str] | None = None,
        ) -> dict[str, bytes]:
            files = self._prepackage_files(repository, executor_source)
            self.policy.write_text("changed during verification\n", encoding="utf-8")
            return files

        self.compose.side_effect = drift
        with self.assertRaises(ExecutorSourceError):
            contract.verify_stage(self.repository, "prepackage")
        self.assertEqual(self.manifest_path.read_bytes(), original)

    def test_manifest_change_during_recomposition_is_rejected(self) -> None:
        sealed = seal_prepackage(self.repository, executor=self.sealer)

        def drift(
            repository: Path,
            executor_source: dict[str, str],
            *,
            expected_live_hosted_ci: dict[str, str] | None = None,
        ) -> dict[str, bytes]:
            files = self._prepackage_files(repository, executor_source)
            sealed["executor_source"] = self.artifact.identity
            self.manifest_path.write_bytes(canonical_json(sealed))
            return files

        self.compose.side_effect = drift
        with self.assertRaisesRegex(PublicationError, "changed while reopening"):
            contract.verify_stage(self.repository, "prepackage")


if __name__ == "__main__":
    unittest.main()
