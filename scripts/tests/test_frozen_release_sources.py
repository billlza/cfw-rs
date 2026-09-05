from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from scripts.release_build_identity import frozen_ga_repository
from scripts.release_executor_source import (
    ExecutorSourceError,
    FrozenReleaseSources,
    capture_frozen_release_sources,
    require_frozen_sources_unchanged,
)
from scripts.repository_source_identity import SourceIdentityError


EXECUTOR_IDENTITY = {"repositoryCommit": "a" * 40, "releaseSourceSha256": "b" * 64}
ARTIFACT_IDENTITY = {"repositoryCommit": "c" * 40, "releaseSourceSha256": "d" * 64}


class FrozenReleaseSourcesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.executor = Path(self.temporary.name).resolve()
        self.artifact = frozen_ga_repository(self.executor)
        self.artifact.mkdir(parents=True)
        self.identities = {
            self.executor: dict(EXECUTOR_IDENTITY),
            self.artifact: dict(ARTIFACT_IDENTITY),
        }
        self.source_reader = Mock(side_effect=lambda path: self.identities[path])
        self.historical_reader = Mock(return_value=dict(EXECUTOR_IDENTITY))

    def capture(self) -> FrozenReleaseSources:
        return capture_frozen_release_sources(
            self.executor,
            source_reader=self.source_reader,
            historical_reader=self.historical_reader,
        )

    def test_fixed_artifact_repository_has_no_source_checkout_fallback(self) -> None:
        self.assertEqual(
            self.artifact, self.executor / "target/release-worktrees/40042"
        )

    def test_artifact_and_executor_keep_distinct_clean_identities(self) -> None:
        sources = self.capture()
        self.assertEqual(sources.executor.repository, self.executor)
        self.assertEqual(sources.executor.identity, EXECUTOR_IDENTITY)
        self.assertEqual(sources.artifact.repository, self.artifact)
        self.assertEqual(sources.artifact.identity, ARTIFACT_IDENTITY)
        self.historical_reader.assert_called_once_with(self.artifact, "a" * 40)
        self.assertEqual(self.source_reader.call_count, 4)

    def test_missing_frozen_checkout_does_not_use_executor_as_artifact(self) -> None:
        self.artifact.rmdir()
        with self.assertRaises(ExecutorSourceError):
            self.capture()
        self.historical_reader.assert_not_called()

    def test_symlinked_frozen_checkout_is_rejected(self) -> None:
        self.artifact.rmdir()
        self.artifact.symlink_to(self.executor, target_is_directory=True)
        with self.assertRaises(ExecutorSourceError):
            self.capture()
        self.historical_reader.assert_not_called()

    def test_dirty_source_rejection_is_not_recovered(self) -> None:
        for dirty in (self.executor, self.artifact):
            def read(path: Path) -> dict[str, str]:
                if path == dirty:
                    raise SourceIdentityError("dirty source")
                return self.identities[path]

            with self.subTest(dirty=dirty), self.assertRaises(ExecutorSourceError):
                capture_frozen_release_sources(
                    self.executor,
                    source_reader=read,
                    historical_reader=self.historical_reader,
                )

    def test_executor_history_must_match_the_running_clean_source(self) -> None:
        self.historical_reader.return_value = ARTIFACT_IDENTITY
        with self.assertRaisesRegex(ExecutorSourceError, "Git objects differ"):
            self.capture()

    def test_missing_executor_history_is_rejected(self) -> None:
        self.historical_reader.side_effect = SourceIdentityError("unknown commit")
        with self.assertRaisesRegex(ExecutorSourceError, "Git objects"):
            self.capture()

    def test_either_source_changing_after_admission_is_rejected(self) -> None:
        sources = self.capture()
        for changed in (self.executor, self.artifact):
            previous = self.identities[changed]
            self.identities[changed] = {
                **previous, "releaseSourceSha256": "e" * 64
            }
            with self.subTest(changed=changed), self.assertRaisesRegex(
                ExecutorSourceError, "source changed"
            ):
                require_frozen_sources_unchanged(
                    sources, source_reader=self.source_reader
                )
            self.identities[changed] = previous


if __name__ == "__main__":
    unittest.main()
