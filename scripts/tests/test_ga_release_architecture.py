from __future__ import annotations

import ast
import inspect
import io
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

from scripts import ga_runtime_acceptance
from scripts import ga_runtime_acceptance_cli
from scripts import release_artifact_set
from scripts import release_artifact_set_cli
from scripts.publication import ga_release_contract
from scripts.publication import orchestrator
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
        ):
            self.assertIs(
                inspect.signature(function).parameters["expected"].default,
                inspect.Parameter.empty,
            )
        for function in (
            ga_runtime_acceptance.collect_ga_runtime_acceptance,
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
        with patch.object(sys, "argv", arguments), patch(
            "scripts.release_python_runtime.require_closed_release_runtime"
        ) as admission, patch.object(
            ga_runtime_acceptance, "main"
        ) as runtime_main:
            ga_runtime_acceptance_cli.main()
        admission.assert_called_once_with()
        runtime_main.assert_called_once_with(
            ga_release_contract.derive_runtime_expectation,
            ga_release_contract.verify_prepackage_authorization,
        )

    def test_runtime_cli_self_check_is_exactly_source_only(self) -> None:
        arguments = [str(Path(ga_runtime_acceptance_cli.__file__)), "self-check"]
        with patch.object(sys, "argv", arguments), patch(
            "scripts.release_python_runtime.require_closed_release_runtime"
        ) as admission, patch.object(
            ga_runtime_acceptance, "main"
        ) as runtime_main:
            ga_runtime_acceptance_cli.main()
        admission.assert_not_called()
        runtime_main.assert_called_once_with(
            ga_release_contract.derive_runtime_expectation,
            ga_release_contract.verify_prepackage_authorization,
        )

    def test_runtime_cli_production_commands_never_fallback_on_admission(self) -> None:
        for command in ("collect", "recover", "verify"):
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
            "scripts/run_ga_acceptance_journal_export.sh:"
            "cfw_seal_release_tool_environment production",
            "scripts/run_ga_acceptance_journal_export.sh:"
            "cfw_select_release_apple_toolchain",
            "scripts/run_ga_acceptance_journal_export.sh:cfw_run_release_python_script",
            "scripts/run_ga_acceptance_journal_export.sh:"
            "scripts/ga_acceptance_journal_export.py",
            "cfm-ga-journal-export-intent-v1",
            "cfm-ga-journal-export-receipt-v1",
            "cfw-current-service-transaction-v3",
            "cfw-dormant-app-install-v2",
            "cfm-ga-acceptance-seal-v2",
            "cfm-ga-publication-seal-v2",
            "cfm-ga-runtime-acceptance-v2",
            "cfm-ga-runtime-check-v2",
            "cfm-ga-command-observation-v2",
            "cfm-ga-runtime-collection-intent-v2",
            "cfm-ga-runtime-collection-event-v2",
            "ACCEPTANCE_INPUT_ROOT: Final = ACCEPTANCE_ROOT_RELATIVE",
            "MIGRATION_JOURNAL_INPUT: Final = MIGRATION_RELATIVE",
            "INSTALL_JOURNAL_INPUT: Final = INSTALL_RELATIVE",
            "SERVICE_JOURNAL_INPUT: Final = SERVICE_RELATIVE",
            "SERVICE_ENVIRONMENT_INPUT: Final = ENVIRONMENT_RELATIVE",
            "STAGE_SCHEMA_VERSIONS: Final = {",
            '"prepackage": 1',
            '"ga-acceptance": 2',
            '"publication": 2',
            "def _verified_migration_journals(repository: Path) -> dict[str, Any]:",
            "verified = verify_ga_acceptance_journal_export(repository)",
            "migration = _verified_migration_journals(repository)",
            '"migration_journals": {',
            "ENVIRONMENT_RELATIVE as JOURNAL_EXPORT_ENVIRONMENT_RELATIVE",
            "ENVIRONMENT_RELATIVE: Final = JOURNAL_EXPORT_ENVIRONMENT_RELATIVE",
        ):
            with self.subTest(required=required):
                self.assertIn(required, boundary)
        for stale in (
            "cfw-current-service-transaction-v2",
            "cfm-ga-acceptance-seal-v1",
            "cfm-ga-publication-seal-v1",
            "cfm-ga-runtime-acceptance-v1",
            "cfm-ga-runtime-check-v1",
            "cfm-ga-command-observation-v1",
            "cfm-ga-runtime-collection-intent-v1",
            "cfm-ga-runtime-collection-event-v1",
            "migration-journals/service-transaction/environment.json",
        ):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, boundary)
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
