from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
LAUNCHER = REPOSITORY / "scripts/release_python_launcher.sh"
DIRECT_REPOSITORY_PYTHON = re.compile(
    r'"\$python_bin"\s+-I\b[^\n]*"\$repo_root/scripts/[^"\n]+[.]py"'
)


def direct_repository_python_commands(source: str) -> tuple[str, ...]:
    logical_commands = source.replace("\\\n", " ")
    return tuple(DIRECT_REPOSITORY_PYTHON.findall(logical_commands))


class ReleasePythonLauncherTests(unittest.TestCase):
    def run_script(
        self,
        relative: str,
        *arguments: str,
        readonly_collision: bool = False,
        repository: Path = REPOSITORY,
    ) -> subprocess.CompletedProcess[bytes]:
        collision = "readonly python_bin=caller-owned; " if readonly_collision else ""
        return subprocess.run(
            [
                "/bin/bash",
                "-p",
                "-c",
                "set -euo pipefail; "
                'source "$1"; '
                + collision
                + 'cfw_run_release_python_script "$2" "$2/$3" "${@:4}"',
                "release-python-launcher-test",
                str(LAUNCHER),
                str(repository),
                relative,
                *arguments,
            ],
            cwd=repository,
            env=dict(os.environ),
            capture_output=True,
            check=False,
            timeout=30,
        )

    def test_candidate_boundary_scripts_import_under_isolated_launcher(self) -> None:
        commands = (
            ("scripts/repository_source_identity.py", "--help"),
            ("scripts/candidate_artifact_binding.py", "--help"),
            ("scripts/verify_artifact_manifest.py", "--help"),
            ("scripts/promote_signed_native_manifest.py", "--help"),
            ("scripts/verify_legacy_tombstone_provenance.py", "--help"),
            ("scripts/verify_candidate_bundle.py", "--help"),
            ("scripts/gatekeeper_assessment.py", "--help"),
            ("scripts/hash_artifact.py", "--help"),
            ("scripts/harness/physical_machine_identity.py", "--help"),
            ("scripts/verify_version_contract.py",),
            ("scripts/verify_native_product_graph.py",),
            ("scripts/hash_native_build_inputs.py",),
        )
        for relative, *arguments in commands:
            with self.subTest(script=relative):
                completed = self.run_script(relative, *arguments)
                diagnostics = completed.stderr.decode("utf-8", errors="replace")
                self.assertEqual(completed.returncode, 0, diagnostics)
                self.assertNotIn("ModuleNotFoundError", diagnostics)
                self.assertNotIn("Traceback", diagnostics)

    def test_migration_entrypoints_reach_the_closed_runtime_boundary(self) -> None:
        for relative in (
            "scripts/current_service_transaction.py",
            "scripts/dormant_app_install.py",
            "scripts/ga_acceptance_journal_export.py",
            "scripts/ga_runtime_acceptance_cli.py",
        ):
            with self.subTest(script=relative):
                completed = self.run_script(relative, "--help")
                self.assertNotIn(b"Traceback", completed.stderr)
                self.assertNotIn(b"ImportError", completed.stderr)
                if "CFW_UNSIGNED_VALIDATION_PYTHON" in os.environ:
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(
                        b"refuses unsigned-validation admission", completed.stderr
                    )
                else:
                    self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                    self.assertEqual(completed.stderr, b"")
                    self.assertIn(b"usage:", completed.stdout)

    def test_nested_module_keeps_package_identity_arguments_and_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            scripts = repository / "scripts"
            harness = scripts / "harness"
            harness.mkdir(parents=True)
            (harness / "__init__.py").write_text("", encoding="utf-8")
            (scripts / "dependency.py").write_text(
                'VALUE = "source-owned"\n', encoding="utf-8"
            )
            entry = harness / "entry.py"
            entry.write_text(
                "import json, sys\n"
                "from ..dependency import VALUE\n"
                "print(json.dumps({\n"
                '    "name": __name__, "package": __package__,\n'
                '    "file": __file__, "argv": sys.argv, "value": VALUE,\n'
                '    "isolated": sys.flags.isolated,\n'
                '    "no_site": sys.flags.no_site,\n'
                '    "dont_write_bytecode": sys.flags.dont_write_bytecode,\n'
                "}))\n",
                encoding="utf-8",
            )
            arguments = ("--label", "space value", "$(untrusted)")
            completed = self.run_script(
                "scripts/harness/entry.py", *arguments, repository=repository
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stderr, b"")
            self.assertEqual(
                json.loads(completed.stdout),
                {
                    "name": "__main__",
                    "package": "scripts.harness",
                    "file": str(entry),
                    "argv": [str(entry), *arguments],
                    "value": "source-owned",
                    "isolated": 1,
                    "no_site": 1,
                    "dont_write_bytecode": 1,
                },
            )
            self.assertEqual(list(repository.rglob("__pycache__")), [])

    def test_non_module_entrypoints_are_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            scripts = repository / "scripts"
            scripts.mkdir()
            for name, diagnostic in (
                ("entry.txt", b"is not a Python module"),
                ("invalid-name.py", b"module name is invalid"),
            ):
                with self.subTest(name=name):
                    (scripts / name).write_text(
                        'print("ENTRY_EXECUTED")\n', encoding="utf-8"
                    )
                    completed = self.run_script(
                        f"scripts/{name}", repository=repository
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(diagnostic, completed.stderr)
                    self.assertNotIn(b"ENTRY_EXECUTED", completed.stdout)

    def test_module_resolution_does_not_admit_a_symlinked_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            scripts = repository / "scripts"
            package = scripts / "actual"
            package.mkdir(parents=True)
            (package / "entry.py").write_text(
                'print("ENTRY_EXECUTED")\n', encoding="utf-8"
            )
            (scripts / "alias").symlink_to(package, target_is_directory=True)
            completed = self.run_script(
                "scripts/alias/entry.py", repository=repository
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"not a safe source file", completed.stderr)
            self.assertNotIn(b"ENTRY_EXECUTED", completed.stdout)

    def test_launcher_locals_do_not_collide_with_readonly_caller_names(self) -> None:
        completed = self.run_script(
            "scripts/candidate_artifact_binding.py",
            "--help",
            readonly_collision=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertNotIn(b"readonly variable", completed.stderr)

    def test_candidate_shells_do_not_directly_execute_repository_python_files(self) -> None:
        for relative in (
            "scripts/build_signed_candidate.sh",
            "scripts/build_unsigned_candidate.sh",
            "scripts/build_native_products.sh",
            "scripts/run_ga_signing_attempt.sh",
            "scripts/verify_release_app.sh",
        ):
            source = (REPOSITORY / relative).read_text(encoding="utf-8")
            with self.subTest(script=relative):
                self.assertIn("cfw_run_release_python_script", source)
                self.assertEqual(direct_repository_python_commands(source), ())

    def test_multiline_direct_repository_python_command_is_rejected(self) -> None:
        unsafe = (
            '"$python_bin" -I -S -B -W error \\\n'
            '  "$repo_root/scripts/promote_signed_native_manifest.py"'
        )
        self.assertTrue(direct_repository_python_commands(unsafe))


if __name__ == "__main__":
    unittest.main()
