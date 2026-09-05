from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from scripts.notarization_executor import (
    BINDING_NAME,
    DOCUMENT,
    NotarizationExecutorError,
    bind_executor,
)
from scripts.release_executor_source import (
    ExecutorSourceError,
    capture_executor_source,
    require_executor_unchanged,
)
from scripts.release_build_identity import ga_root
from scripts.repository_source_identity import SourceIdentityError


class NotarizationExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name).resolve()
        self.executor_repository = self.repository / "executor"
        self.executor_repository.mkdir()
        ga_root(self.repository).mkdir(parents=True, mode=0o700)
        self.identity = {"repositoryCommit": "c" * 40, "releaseSourceSha256": "d" * 64}
        self.executor = capture_executor_source(
            self.executor_repository, source_reader=lambda _root: self.identity
        )
        self.arguments = {
            "artifact_identity": {
                "repositoryCommit": "a" * 40,
                "releaseSourceSha256": "b" * 64,
            },
            "candidate_freeze_intent_sha256": "e" * 64,
            "signing_transformation_receipt_sha256": "f" * 64,
            "historical_reader": self.historical_identity,
        }

    def historical_identity(self, repository: Path, commit: str) -> dict[str, str]:
        self.assertEqual(repository, self.repository)
        self.assertEqual(commit, self.executor.repository_commit)
        return self.identity

    def bind(self, **overrides) -> Path:
        arguments = {**self.arguments, **overrides}
        return bind_executor(self.repository, self.executor, **arguments)

    def test_binding_preserves_distinct_product_and_executor_sources(self) -> None:
        path = self.bind()
        before = path.stat()
        data = path.read_bytes()
        document = json.loads(data)
        self.assertEqual(path, ga_root(self.repository) / "stage-inputs" / BINDING_NAME)
        self.assertEqual(document["document"], DOCUMENT)
        self.assertEqual(document["artifact_source"], self.arguments["artifact_identity"])
        self.assertEqual(document["executor_source"], self.identity)
        self.assertEqual(document["product"], {"version": "0.4.0", "build_number": "40042"})
        self.assertEqual(document["candidate_freeze_intent_sha256"], "e" * 64)
        self.assertEqual(document["signing_transformation_receipt_sha256"], "f" * 64)
        self.assertEqual(stat.S_IMODE(before.st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(self.bind(), path)
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(path.stat().st_ino, before.st_ino)
        self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)

    def test_binding_never_replaces_a_different_prior_record(self) -> None:
        path = self.bind()
        original = path.read_bytes()
        with self.assertRaisesRegex(NotarizationExecutorError, "cannot be replaced"):
            self.bind(candidate_freeze_intent_sha256="0" * 64)
        self.assertEqual(path.read_bytes(), original)

    def test_missing_or_different_historical_executor_fails_before_writing(self) -> None:
        def missing(_repository: Path, _commit: str) -> dict[str, str]:
            raise SourceIdentityError("missing Git object")

        for reader in (
            missing,
            lambda _repository, _commit: {**self.identity, "releaseSourceSha256": "0" * 64},
        ):
            with self.subTest(reader=reader):
                with self.assertRaises(NotarizationExecutorError):
                    self.bind(historical_reader=reader)
                self.assertFalse((ga_root(self.repository) / "stage-inputs").exists())

    def test_source_drift_and_dirty_source_are_explicit_errors(self) -> None:
        require_executor_unchanged(self.executor, source_reader=lambda _root: self.identity)
        with self.assertRaisesRegex(ExecutorSourceError, "source changed"):
            require_executor_unchanged(
                replace(self.executor, repository_commit="0" * 40),
                source_reader=lambda _root: self.identity,
            )

        def dirty(_repository: Path) -> dict[str, str]:
            raise SourceIdentityError("dirty source")

        with self.assertRaisesRegex(ExecutorSourceError, "source is unavailable"):
            capture_executor_source(self.executor_repository, source_reader=dirty)

    def test_executor_root_must_be_canonical_real_and_owned(self) -> None:
        link = self.repository / "executor-link"
        link.symlink_to(self.executor_repository, target_is_directory=True)
        roots = (
            link,
            self.executor_repository / ".." / "executor",
            Path("relative-executor"),
            self.repository / "missing",
        )
        for root in roots:
            with self.subTest(root=root):
                with self.assertRaises(ExecutorSourceError):
                    capture_executor_source(root, source_reader=lambda _root: self.identity)
        self.executor_repository.chmod(0o777)
        with self.assertRaises(ExecutorSourceError):
            capture_executor_source(
                self.executor_repository, source_reader=lambda _root: self.identity
            )

    def test_malformed_source_and_binding_identities_are_rejected(self) -> None:
        for identity in (
            {},
            {**self.identity, "extra": "field"},
            {**self.identity, "repositoryCommit": "C" * 40},
            {**self.identity, "releaseSourceSha256": "d" * 63},
        ):
            with self.subTest(identity=identity):
                with self.assertRaises(ExecutorSourceError):
                    capture_executor_source(
                        self.executor_repository,
                        source_reader=lambda _root, identity=identity: identity,
                    )
        for overrides in (
            {"artifact_identity": {}},
            {"candidate_freeze_intent_sha256": "E" * 64},
            {"signing_transformation_receipt_sha256": "f" * 63},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(NotarizationExecutorError):
                    self.bind(**overrides)
        self.assertFalse((ga_root(self.repository) / "stage-inputs").exists())

    def test_binding_rejects_linked_or_nonprivate_records_without_modifying_them(self) -> None:
        path = self.bind()
        original = path.read_bytes()
        path.chmod(0o644)
        with self.assertRaises(NotarizationExecutorError):
            self.bind()
        self.assertEqual(path.read_bytes(), original)
        path.chmod(0o600)
        alias = self.repository / "binding-alias"
        os.link(path, alias)
        with self.assertRaises(NotarizationExecutorError):
            self.bind()
        self.assertEqual(path.read_bytes(), original)

    def test_binding_rejects_a_symlinked_stage_inputs_directory(self) -> None:
        outside = self.repository / "outside"
        outside.mkdir(mode=0o700)
        stage_inputs = ga_root(self.repository) / "stage-inputs"
        stage_inputs.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(NotarizationExecutorError):
            self.bind()
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
