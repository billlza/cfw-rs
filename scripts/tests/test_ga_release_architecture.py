from __future__ import annotations

import ast
from contextlib import contextmanager
from functools import partial
import inspect
import io
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

from scripts import candidate_freeze
from scripts import ga_runtime_acceptance
from scripts import ga_runtime_acceptance_cli
from scripts import release_artifact_set
from scripts import release_artifact_set_cli
from scripts.publication import ga_release_contract
from scripts.publication import orchestrator
from scripts.release_build_identity import PRODUCT_VERSION
from scripts.release_python_runtime import ReleasePythonRuntimeError


REPOSITORY = Path(__file__).resolve().parent.parent.parent


def _source(relative: str) -> str:
    return (REPOSITORY / relative).read_text(encoding="utf-8")


def _imports(relative: str) -> set[str]:
    tree = ast.parse(_source(relative), filename=relative)
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.add(node.module)
    return modules


class GAReleaseDependencyDirectionTests(unittest.TestCase):
    def test_artifact_and_runtime_cores_do_not_import_composition_layers(self) -> None:
        forbidden = {
            "scripts.publication.ga_release_contract",
            "scripts.publication.orchestrator",
            "publication.ga_release_contract",
            "publication.orchestrator",
        }
        for relative in (
            "scripts/release_artifact_set.py",
            "scripts/ga_runtime_acceptance.py",
        ):
            source = _source(relative)
            self.assertTrue(_imports(relative).isdisjoint(forbidden), relative)
            self.assertNotIn("ga_release_contract", source, relative)
            self.assertNotIn("publication.orchestrator", source, relative)

    def test_orchestrator_is_only_the_stage_mutation_owner(self) -> None:
        relative = "scripts/publication/orchestrator.py"
        source = _source(relative)
        tree = ast.parse(source, filename=relative)
        functions = {
            node.name for node in tree.body if isinstance(node, ast.FunctionDef)
        }
        self.assertEqual(
            functions,
            {
                "_publish_stage",
                "_publish_and_confirm_stage",
                "seal_prepackage",
                "seal_ga_acceptance",
                "seal_publication",
            },
        )
        self.assertIn("ga_release_contract", source)
        self.assertNotIn("release_artifact_set", source)
        self.assertNotIn("ga_runtime_acceptance", source)

    def test_read_only_contract_owns_stage_order_and_expectations(self) -> None:
        self.assertEqual(
            ga_release_contract.STAGES,
            ("prepackage", "ga-acceptance", "publication"),
        )
        for name in (
            "build_expected_stage_files",
            "verify_stage",
            "verify_prepackage_authorization",
            "verify_publication_authorization",
            "derive_runtime_expectation",
        ):
            self.assertTrue(callable(getattr(ga_release_contract, name)))
        contract_source = _source("scripts/publication/ga_release_contract.py")
        self.assertNotIn("def seal_prepackage", contract_source)
        self.assertNotIn("def seal_ga_acceptance", contract_source)
        self.assertNotIn("def seal_publication", contract_source)

    def test_core_entrypoints_require_injected_contracts(self) -> None:
        artifact_signature = inspect.signature(release_artifact_set.main)
        self.assertIsNone(
            artifact_signature.parameters["prepackage_stage_verifier"].default
        )
        self.assertIsNone(
            artifact_signature.parameters["publication_stage_verifier"].default
        )
        for function in (
            ga_runtime_acceptance.collect_ga_runtime_acceptance,
            ga_runtime_acceptance.recover_ga_runtime_collection,
            ga_runtime_acceptance.resume_ga_runtime_seal,
        ):
            self.assertIs(
                inspect.signature(function).parameters["expected"].default,
                inspect.Parameter.empty,
            )
        for function in (
            ga_runtime_acceptance.collect_ga_runtime_acceptance,
            ga_runtime_acceptance.resume_ga_runtime_seal,
            ga_runtime_acceptance.seal_ga_runtime_acceptance,
            ga_runtime_acceptance.validate_ga_runtime_acceptance,
        ):
            self.assertIs(
                inspect.signature(function).parameters[
                    "prepackage_stage_verifier"
                ].default,
                inspect.Parameter.empty,
            )


class GAReleaseCompositionRootTests(unittest.TestCase):
    def test_artifact_cli_injects_both_stage_authorizers(self) -> None:
        arguments = [str(Path(release_artifact_set_cli.__file__)), "self-check"]
        with patch.object(sys, "argv", arguments), patch.object(
            release_artifact_set, "main"
        ) as artifact_main:
            release_artifact_set_cli.main()
        artifact_main.assert_called_once_with(
            prepackage_stage_verifier=(
                ga_release_contract.verify_prepackage_authorization
            ),
            publication_stage_verifier=(
                ga_release_contract.verify_publication_authorization
            ),
        )

    def test_runtime_cli_injects_the_read_only_expectation_deriver(self) -> None:
        arguments = [str(Path(ga_runtime_acceptance_cli.__file__)), "verify"]
        repository = Path("/fixture/frozen-artifact")
        events: list[str] = []

        def freeze_verifier(path: Path) -> None:
            self.assertEqual(path, repository)

        @contextmanager
        def session(path: Path):
            self.assertEqual(path, repository)
            events.append("open")
            yield freeze_verifier
            events.append("close")

        with patch.object(sys, "argv", arguments), patch(
            "scripts.release_python_runtime.require_closed_release_runtime"
        ) as admission, patch.object(
            ga_runtime_acceptance, "_repository", return_value=repository
        ), patch.object(
            candidate_freeze, "frozen_candidate_verification_session", side_effect=session
        ) as verifier_session, patch.object(
            ga_runtime_acceptance, "main", return_value="runtime verified"
        ) as runtime_main, patch(
            "builtins.print", side_effect=lambda _message: events.append("print")
        ) as output:
            ga_runtime_acceptance_cli.main()
        admission.assert_called_once_with()
        verifier_session.assert_called_once_with(repository)
        runtime_main.assert_called_once()
        expectation, authorization = runtime_main.call_args.args
        for callback, function in (
            (expectation, ga_release_contract.derive_runtime_expectation),
            (authorization, ga_release_contract.verify_prepackage_authorization),
        ):
            self.assertIsInstance(callback, partial)
            self.assertIs(callback.func, function)
            self.assertEqual(callback.args, ())
            self.assertEqual(callback.keywords, {"freeze_verifier": freeze_verifier})
        self.assertEqual(events, ["open", "close", "print"])
        output.assert_called_once_with("runtime verified")

    def test_runtime_cli_self_check_is_exactly_source_only(self) -> None:
        arguments = [str(Path(ga_runtime_acceptance_cli.__file__)), "self-check"]
        with patch.object(sys, "argv", arguments), patch(
            "scripts.release_python_runtime.require_closed_release_runtime"
        ) as admission, patch.object(
            candidate_freeze, "frozen_candidate_verification_session"
        ) as verifier_session, patch.object(
            ga_runtime_acceptance, "main", return_value="source contract verified"
        ) as runtime_main, patch("builtins.print") as output:
            ga_runtime_acceptance_cli.main()
        admission.assert_not_called()
        verifier_session.assert_not_called()
        runtime_main.assert_called_once_with(
            ga_release_contract.derive_runtime_expectation,
            ga_release_contract.verify_prepackage_authorization,
        )
        output.assert_called_once_with("source contract verified")

    def test_runtime_cli_indents_every_line_of_a_rendered_exit_note(self) -> None:
        # A note on an already rendered exit, such as the escaped end of a
        # command's output, is shown under the error, never at the left margin.
        arguments = [str(Path(ga_runtime_acceptance_cli.__file__)), "self-check"]
        rendered = SystemExit("error: GA runtime acceptance: fixture refusal")
        rendered.add_note("output (12 bytes) ends with:\ncaused by OSError: forged")
        with patch.object(sys, "argv", arguments), patch.object(
            ga_runtime_acceptance, "main", side_effect=rendered
        ), self.assertRaises(SystemExit) as raised:
            ga_runtime_acceptance_cli.main()
        self.assertEqual(
            str(raised.exception),
            "error: GA runtime acceptance: fixture refusal\n"
            "  output (12 bytes) ends with:\n"
            "  caused by OSError: forged",
        )

    def test_runtime_cli_production_commands_never_fallback_on_admission(self) -> None:
        for command in ("collect", "recover", "resume-seal", "verify"):
            arguments = [str(Path(ga_runtime_acceptance_cli.__file__)), command]
            with self.subTest(command=command), patch.object(
                sys, "argv", arguments
            ), patch(
                "scripts.release_python_runtime.require_closed_release_runtime",
                side_effect=ReleasePythonRuntimeError("fixture admission rejected"),
            ) as admission, patch.object(
                ga_runtime_acceptance, "main"
            ) as runtime_main, self.assertRaisesRegex(
                SystemExit, "fixture admission rejected"
            ):
                ga_runtime_acceptance_cli.main()
            admission.assert_called_once_with()
            runtime_main.assert_not_called()

    def test_runtime_cli_does_not_broaden_the_source_only_command_shape(self) -> None:
        arguments = [
            str(Path(ga_runtime_acceptance_cli.__file__)),
            "self-check",
            "--unexpected",
        ]
        with patch.object(sys, "argv", arguments), patch(
            "scripts.release_python_runtime.require_closed_release_runtime",
            side_effect=ReleasePythonRuntimeError("fixture admission rejected"),
        ) as admission, patch.object(
            ga_runtime_acceptance, "main"
        ) as runtime_main, self.assertRaisesRegex(
            SystemExit, "fixture admission rejected"
        ):
            ga_runtime_acceptance_cli.main()
        admission.assert_called_once_with()
        runtime_main.assert_not_called()

    def test_ci_build_boundary_uses_the_source_only_cli_command(self) -> None:
        workflow = _source(".github/workflows/ci.yml")
        boundary = _source("scripts/verify_build_boundaries.sh")
        self.assertIn(
            "./scripts/run_release_ci_gate.sh --validation-python-executable "
            "'${{ steps.validation-python.outputs.python-path }}' "
            "build-script-boundary",
            workflow,
        )
        self.assertIn(
            '"$repo_root/scripts/ga_runtime_acceptance_cli.py" self-check',
            boundary,
        )

    def test_ci_boundary_checks_journal_export_without_running_a_mutation(self) -> None:
        boundary = _source("scripts/verify_build_boundaries.sh")
        for required in (
            "environment_self_check()",
            "journal_export_self_check()",
            "scripts/run_ga_acceptance_journal_export.sh",
        ):
            with self.subTest(required=required):
                self.assertIn(required, boundary)
        self.assertNotIn("run_ga_acceptance_journal_export.sh --export", boundary)

    def test_runtime_cli_self_check_runs_without_production_admission(self) -> None:
        arguments = [str(Path(ga_runtime_acceptance_cli.__file__)), "self-check"]
        with patch.object(sys, "argv", arguments), patch(
            "scripts.release_python_runtime.require_closed_release_runtime",
            side_effect=AssertionError("source-only self-check requested admission"),
        ), patch("sys.stdout", new_callable=io.StringIO) as stdout:
            ga_runtime_acceptance_cli.main()
        self.assertEqual(
            stdout.getvalue(),
            "GA runtime acceptance source contract verified\n",
        )

    def test_cli_composition_roots_accept_no_injected_collaborators(self) -> None:
        for function, expected in (
            (ga_runtime_acceptance_cli.main, []),
            (ga_runtime_acceptance_cli._run_runtime_command, []),
            (release_artifact_set_cli.main, []),
            (release_artifact_set_cli._run_verification_command, ["arguments"]),
        ):
            with self.subTest(function=function.__qualname__):
                self.assertEqual(
                    list(inspect.signature(function).parameters), expected
                )
        for module, expected in (
            (
                ga_runtime_acceptance_cli,
                {"_existing_runtime_outputs", "_run_runtime_command", "main"},
            ),
            (release_artifact_set_cli, {"_run_verification_command", "main"}),
        ):
            with self.subTest(module=module.__name__):
                self.assertEqual(
                    {
                        name
                        for name, value in vars(module).items()
                        if inspect.isfunction(value)
                        and value.__module__ == module.__name__
                    },
                    expected,
                )

    def test_runtime_cli_rejects_injected_arguments_before_any_session(self) -> None:
        for arguments in (
            ["verify", "--repository", "/fixture/other"],
            ["collect", "--freeze-verifier", "fixture"],
            ["self-check", "--unexpected"],
        ):
            with self.subTest(arguments=arguments), patch.object(
                sys,
                "argv",
                [str(Path(ga_runtime_acceptance_cli.__file__)), *arguments],
            ), patch(
                "scripts.release_python_runtime.require_closed_release_runtime"
            ), patch.object(
                ga_runtime_acceptance,
                "_repository",
                return_value=Path("/fixture/frozen-artifact"),
            ), patch.object(
                candidate_freeze, "frozen_candidate_verification_session"
            ) as verifier_session, patch.object(
                ga_runtime_acceptance, "self_check"
            ) as self_check, patch(
                "sys.stderr", new_callable=io.StringIO
            ), self.assertRaises(SystemExit) as rejected:
                ga_runtime_acceptance_cli.main()
            self.assertEqual(rejected.exception.code, 2)
            verifier_session.assert_not_called()
            self_check.assert_not_called()

    def test_artifact_cli_rejects_injected_arguments_before_any_session(self) -> None:
        for arguments in (
            [
                "verify-dmg",
                "--directory",
                "fixture",
                "--version",
                PRODUCT_VERSION,
                "--repository",
                "fixture",
                "--prepackage-stage-verifier",
                "fixture",
            ],
            [
                "verify-release",
                "--repository",
                "fixture",
                "--version",
                PRODUCT_VERSION,
                "--command-runner",
                "fixture",
            ],
            ["self-check", "--unexpected"],
        ):
            with self.subTest(arguments=arguments), patch.object(
                sys,
                "argv",
                [str(Path(release_artifact_set_cli.__file__)), *arguments],
            ), patch(
                "scripts.release_python_runtime.require_closed_release_runtime"
            ), patch.object(
                candidate_freeze, "frozen_candidate_verification_session"
            ) as verifier_session, patch.object(
                release_artifact_set, "_execute_command"
            ) as execute, patch.object(
                release_artifact_set, "self_check"
            ) as self_check, patch(
                "sys.stderr", new_callable=io.StringIO
            ), self.assertRaises(SystemExit) as rejected:
                release_artifact_set_cli.main()
            self.assertEqual(rejected.exception.code, 2)
            verifier_session.assert_not_called()
            execute.assert_not_called()
            self_check.assert_not_called()

    def test_composition_roots_are_private_executable_regular_files(self) -> None:
        for module in (release_artifact_set_cli, ga_runtime_acceptance_cli):
            metadata = Path(module.__file__).lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertFalse(stat.S_ISLNK(metadata.st_mode))
            self.assertEqual(metadata.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o755)


class SourceSelfCheckRegressionTests(unittest.TestCase):
    def test_runtime_self_check_does_not_claim_semantic_source_validation(self) -> None:
        self_check_source = inspect.getsource(ga_runtime_acceptance.self_check)
        for unrelated_source in (
            "launch.rs",
            "packet_host.py",
            "tauri_build_signed_candidate.sh",
        ):
            self.assertNotIn(unrelated_source, self_check_source)

    def test_dmg_commands_share_the_pinned_xcrun_constant(self) -> None:
        source = _source("scripts/dmg_notarization_transaction.py")
        self.assertEqual(source.count('"/usr/bin/xcrun"'), 2)


if __name__ == "__main__":
    unittest.main()
