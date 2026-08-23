from __future__ import annotations

import os
from pathlib import Path
import subprocess
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
LAUNCHER = REPOSITORY / "scripts/release_python_launcher.sh"


class ReleasePythonLauncherTests(unittest.TestCase):
    def run_script(
        self, relative: str, *arguments: str, readonly_collision: bool = False
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
                str(REPOSITORY),
                relative,
                *arguments,
            ],
            cwd=REPOSITORY,
            env=dict(os.environ),
            capture_output=True,
            check=False,
        )

    def test_candidate_boundary_scripts_import_under_isolated_launcher(self) -> None:
        commands = (
            ("scripts/repository_source_identity.py", "--help"),
            ("scripts/candidate_artifact_binding.py", "--help"),
            ("scripts/verify_artifact_manifest.py", "--help"),
            ("scripts/verify_candidate_bundle.py", "--help"),
            ("scripts/gatekeeper_assessment.py", "--help"),
            ("scripts/hash_artifact.py", "--help"),
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

    def test_launcher_locals_do_not_collide_with_readonly_caller_names(self) -> None:
        completed = self.run_script(
            "scripts/candidate_artifact_binding.py",
            "--help",
            readonly_collision=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertNotIn(b"readonly variable", completed.stderr)

    def test_candidate_shells_do_not_directly_execute_repository_python_files(self) -> None:
        forbidden = (
            'PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error \\\n'
            '  "$repo_root/scripts/',
            '"$python_bin" -I -S -B -W error "$repo_root/scripts/',
        )
        for relative in (
            "scripts/build_unsigned_candidate.sh",
            "scripts/build_native_products.sh",
            "scripts/verify_release_app.sh",
        ):
            source = (REPOSITORY / relative).read_text(encoding="utf-8")
            with self.subTest(script=relative):
                self.assertIn("cfw_run_release_python_script", source)
                for fragment in forbidden:
                    self.assertNotIn(fragment, source)


if __name__ == "__main__":
    unittest.main()
