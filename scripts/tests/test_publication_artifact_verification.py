from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_publication_evidence, publication_evidence
from scripts.publication import closure, draft, finalize, verify
from scripts.publication.common import PublicationError
from scripts.publication.durable_file import DurabilityOutcomeUnknown
from scripts.publication.release_contract import (
    draft_path,
    evidence_root,
    native_products_root,
    prepared_root,
    require_fixed_path,
    review_template,
    signed_app,
)
from scripts.release_executor_source import (
    ExecutorSource,
    ExecutorSourceError,
    FrozenReleaseSources,
)


class PublicationArtifactVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        self.root = self.repository / "publication"
        self.root.mkdir()
        self.app = self.repository / "Clash for Mac.app"
        self.source = self.repository / "current.json"
        self.source.write_bytes(b'{"verified":true}\n')
        (self.root / "record.json").write_bytes(self.source.read_bytes())
        self.artifacts = [{"kind": "fixture-manifest", "path": "record.json"}]

    def invoke(self) -> None:
        verify._verify_artifact_inputs(
            self.repository, self.root, self.artifacts, self.app, "40044"
        )

    def test_artifact_reader_receives_explicit_closed_git_environment(self) -> None:
        # autospec exercises the real production reader's required argument
        # contract, including arguments which an unconstrained mock would hide.
        with patch.object(
            verify,
            "_artifact_sources",
            autospec=True,
            return_value={"fixture-manifest": self.source},
        ) as reader:
            self.invoke()
        reader.assert_called_once_with(
            self.repository,
            native_products_root(self.repository, "40044"),
            self.app,
            "40044",
            None,
            freeze_verifier=None,
        )

    def test_changed_artifact_is_rejected(self) -> None:
        self.source.write_bytes(b'{"verified":false}\n')
        with patch.object(
            verify,
            "_artifact_sources",
            autospec=True,
            return_value={"fixture-manifest": self.source},
        ), self.assertRaisesRegex(PublicationError, "differs from publication evidence"):
            self.invoke()

    def test_missing_artifact_is_rejected(self) -> None:
        self.artifacts = []
        with patch.object(
            verify,
            "_artifact_sources",
            autospec=True,
            return_value={"fixture-manifest": self.source},
        ), self.assertRaisesRegex(PublicationError, "manifest set is incomplete"):
            self.invoke()


class PublicationArtifactPathTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repository = self.root / "frozen"
        self.repository.mkdir()

    def test_fixed_path_is_relative_to_explicit_artifact_repository(self) -> None:
        output = draft_path(self.repository)
        require_fixed_path(output, output, "draft", repository=self.repository)

    def test_foreign_expected_path_cannot_escape_artifact_repository(self) -> None:
        output = draft_path(self.root)
        with self.assertRaisesRegex(PublicationError, "outside the repository"):
            require_fixed_path(output, output, "draft", repository=self.repository)

    def test_parent_traversal_cannot_hide_an_alternate_ancestor(self) -> None:
        output = draft_path(self.repository)
        actual = output.parent / "alternate" / ".." / output.name
        with self.assertRaisesRegex(PublicationError, "parent traversal"):
            require_fixed_path(actual, output, "draft", repository=self.repository)

    def test_symlinked_repository_is_rejected(self) -> None:
        alias = self.root / "alias"
        alias.symlink_to(self.repository, target_is_directory=True)
        output = draft_path(alias)
        with self.assertRaisesRegex(PublicationError, "canonical directory"):
            require_fixed_path(output, output, "draft", repository=alias)

    def test_symlinked_and_nondirectory_ancestors_are_rejected(self) -> None:
        ancestor = self.repository / "target"
        for symlink in (True, False):
            with self.subTest(symlink=symlink):
                if symlink:
                    ancestor.symlink_to(self.root, target_is_directory=True)
                else:
                    ancestor.write_bytes(b"not a directory")
                try:
                    output = draft_path(self.repository)
                    with self.assertRaisesRegex(PublicationError, "unsafe path ancestor"):
                        require_fixed_path(output, output, "draft", repository=self.repository)
                finally:
                    ancestor.unlink()

    def test_symlink_leaf_is_rejected_before_resolving_an_app_alias(self) -> None:
        app = signed_app(self.repository)
        app.parent.mkdir(parents=True)
        app.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(PublicationError, "is a symlink"):
            closure.build_machine_closure(
                prepared_root(self.repository), app, False, repository=self.repository
            )

    def test_production_entry_points_require_explicit_repository(self) -> None:
        for operation in (
            lambda: closure.build_machine_closure(self.root, self.root, False),
            lambda: draft.draft(self.root, self.root, self.root / "draft", False),
            lambda: finalize.finalize(
                self.root, self.root, self.root / "review", self.root / "final", False
            ),
            lambda: verify.verify(self.root, self.root, False),
            lambda: verify.verify_evidence(self.root, self.root, False),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                PublicationError, "explicit artifact repository"
            ):
                operation()

    def test_draft_passes_frozen_repository_to_closure_and_writes_fixed_output(self) -> None:
        output = draft_path(self.repository)
        output.parent.mkdir(parents=True)
        with patch.object(
            draft, "build_machine_closure", autospec=True, return_value={"fixture": "closure"}
        ) as build:
            digest = draft.draft(
                prepared_root(self.repository), signed_app(self.repository), output,
                False, repository=self.repository,
            )
        build.assert_called_once_with(
            prepared_root(self.repository), signed_app(self.repository), False,
            repository=self.repository,
        )
        self.assertEqual(output.read_bytes(), b'{"fixture":"closure"}\n')
        self.assertEqual(len(digest), 64)

    def test_finalization_forwards_repository_before_review(self) -> None:
        machine = {"components": [{"id": "application:fixture"}]}
        with (
            patch.object(finalize, "build_machine_closure", autospec=True, return_value=machine) as build,
            patch.object(finalize, "legal_review", side_effect=PublicationError("review rejected")),
            self.assertRaisesRegex(PublicationError, "review rejected"),
        ):
            finalize.finalize(
                prepared_root(self.repository), signed_app(self.repository), self.root / "review",
                evidence_root(self.repository), False, repository=self.repository,
            )
        build.assert_called_once_with(
            prepared_root(self.repository), signed_app(self.repository), False,
            repository=self.repository,
        )
        self.assertFalse(evidence_root(self.repository).exists())

    def test_verification_forwards_repository_to_artifact_reopening(self) -> None:
        evidence = evidence_root(self.repository)
        evidence.mkdir(parents=True)
        app = signed_app(self.repository)
        app.mkdir(parents=True)
        with patch.object(verify, "verify_evidence", autospec=True) as reopen:
            verify.verify(evidence, app, False, repository=self.repository)
        reopen.assert_called_once_with(evidence, app, False, repository=self.repository)


class PublicationCommandSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.executor = Path(temporary.name).resolve()
        self.repository = self.executor / "target/release-worktrees/40044"
        self.repository.mkdir(parents=True)
        self.sources = FrozenReleaseSources(
            ExecutorSource(self.executor, "a" * 40, "b" * 64),
            ExecutorSource(self.repository, "c" * 40, "d" * 64),
        )
        self.stdout = io.StringIO()

    def preparation_arguments(self, command: str) -> list[str]:
        arguments = ["prepare_publication_evidence.py", command, "--libbox-source", "/libbox"]
        if command == "prepare":
            arguments.extend(("--reviewed-components", "/reviewed.json"))
        return arguments

    def evidence_arguments(self, command: str) -> list[str]:
        arguments = ["publication_evidence.py", command, "--app", str(signed_app(self.repository))]
        if command == "verify":
            evidence = evidence_root(self.repository)
            evidence.mkdir(parents=True, exist_ok=True)
            return [*arguments, "--evidence", str(evidence)]
        output = draft_path(self.repository) if command == "draft" else evidence_root(self.repository)
        arguments.extend(("--prepared", str(prepared_root(self.repository)), "--output", str(output)))
        if command == "finalize":
            arguments.extend(("--review", "/review.json"))
        return arguments

    def test_preparation_uses_frozen_paths_and_rechecks_before_success(self) -> None:
        for command, name, output in (
            ("prepare", "prepare", prepared_root(self.repository)),
            ("review-template", "write_review_template", review_template(self.repository)),
        ):
            with (
                self.subTest(command=command),
                patch.object(sys, "argv", self.preparation_arguments(command)),
                patch.object(prepare_publication_evidence, "require_closed_release_runtime"),
                patch.object(
                    prepare_publication_evidence, "capture_frozen_release_sources", return_value=self.sources
                ) as capture,
                patch.object(prepare_publication_evidence, name, autospec=True, return_value=output) as operation,
                patch.object(
                    prepare_publication_evidence, "require_frozen_sources_unchanged",
                    side_effect=lambda _sources: self.assertEqual(self.stdout.getvalue(), ""),
                ) as recheck,
                redirect_stdout(self.stdout),
            ):
                prepare_publication_evidence.main()
            capture.assert_called_once_with(Path(prepare_publication_evidence.__file__).resolve().parent.parent)
            self.assertEqual(operation.call_args.kwargs["repository"], self.repository)
            self.assertEqual(operation.call_args.kwargs["output"], output)
            if command == "prepare":
                self.assertEqual(operation.call_args.kwargs["app"], signed_app(self.repository))
            recheck.assert_called_once_with(self.sources)
            self.assertIn(str(output), self.stdout.getvalue())
            self.stdout.seek(0)
            self.stdout.truncate(0)

    def test_publication_commands_share_frozen_source_admission(self) -> None:
        for command in ("draft", "finalize", "verify"):
            with (
                self.subTest(command=command),
                patch.object(sys, "argv", self.evidence_arguments(command)),
                patch.object(publication_evidence, "require_closed_release_runtime"),
                patch.object(publication_evidence, "capture_frozen_release_sources", return_value=self.sources),
                patch.object(publication_evidence, command, autospec=True, return_value="e" * 64) as operation,
                patch.object(
                    publication_evidence, "require_frozen_sources_unchanged",
                    side_effect=lambda _sources: self.assertEqual(self.stdout.getvalue(), ""),
                ) as recheck,
                redirect_stdout(self.stdout),
            ):
                publication_evidence.main()
            self.assertEqual(operation.call_args.kwargs, {"repository": self.repository})
            recheck.assert_called_once_with(self.sources)
            self.stdout.seek(0)
            self.stdout.truncate(0)

    def test_late_source_drift_preserves_unknown_write_outcome_without_success(self) -> None:
        for module, command, name in (
            (prepare_publication_evidence, "prepare", "prepare"),
            (prepare_publication_evidence, "review-template", "write_review_template"),
            (publication_evidence, "draft", "draft"),
            (publication_evidence, "finalize", "finalize"),
            (publication_evidence, "verify", "verify"),
        ):
            arguments = (
                self.preparation_arguments(command)
                if module is prepare_publication_evidence
                else self.evidence_arguments(command)
            )
            with (
                self.subTest(command=command),
                patch.object(sys, "argv", arguments),
                patch.object(module, "require_closed_release_runtime"),
                patch.object(module, "capture_frozen_release_sources", return_value=self.sources),
                patch.object(module, name, autospec=True, return_value="e" * 64),
                patch.object(
                    module, "require_frozen_sources_unchanged", side_effect=ExecutorSourceError("source drift")
                ),
                redirect_stdout(self.stdout),
                self.assertRaises(SystemExit) as raised,
            ):
                module.main()
            expected_error = ExecutorSourceError if command == "verify" else DurabilityOutcomeUnknown
            self.assertIsInstance(raised.exception.__cause__, expected_error)
            self.assertEqual(self.stdout.getvalue(), "")

    def test_failed_source_admission_does_not_start_preparation_or_publication(self) -> None:
        for module, command in (
            (prepare_publication_evidence, "prepare"), (publication_evidence, "draft")
        ):
            arguments = (
                self.preparation_arguments(command)
                if module is prepare_publication_evidence
                else self.evidence_arguments(command)
            )
            with (
                self.subTest(command=command),
                patch.object(sys, "argv", arguments),
                patch.object(module, "require_closed_release_runtime"),
                patch.object(module, "capture_frozen_release_sources", side_effect=ExecutorSourceError("dirty")),
                patch.object(module, command, autospec=True) as operation,
                redirect_stdout(self.stdout),
                self.assertRaises(SystemExit),
            ):
                module.main()
            operation.assert_not_called()
            self.assertEqual(self.stdout.getvalue(), "")

    def test_fixture_draft_does_not_select_a_production_repository(self) -> None:
        with (
            patch.object(sys, "argv", [*self.evidence_arguments("draft"), "--fixture"]),
            patch.object(publication_evidence, "require_closed_release_runtime") as runtime,
            patch.object(publication_evidence, "capture_frozen_release_sources") as capture,
            patch.object(publication_evidence, "draft", autospec=True, return_value="e" * 64) as operation,
            redirect_stdout(self.stdout),
        ):
            publication_evidence.main()
        runtime.assert_not_called()
        capture.assert_not_called()
        self.assertEqual(operation.call_args.kwargs, {"repository": None})

    def test_production_runtime_rejection_precedes_source_capture_and_work(self) -> None:
        for module, command in (
            (prepare_publication_evidence, "prepare"), (publication_evidence, "draft")
        ):
            arguments = (
                self.preparation_arguments(command)
                if module is prepare_publication_evidence
                else self.evidence_arguments(command)
            )
            with (
                self.subTest(command=command),
                patch.object(sys, "argv", arguments),
                patch.object(
                    module, "require_closed_release_runtime",
                    side_effect=module.ReleasePythonRuntimeError("closed runtime unavailable"),
                ),
                patch.object(module, "capture_frozen_release_sources") as capture,
                patch.object(module, command, autospec=True) as operation,
                redirect_stdout(self.stdout),
                self.assertRaises(SystemExit),
            ):
                module.main()
            capture.assert_not_called()
            operation.assert_not_called()
            self.assertEqual(self.stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
