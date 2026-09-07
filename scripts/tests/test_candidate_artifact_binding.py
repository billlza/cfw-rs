from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import candidate_artifact_binding as binding
from scripts.publication.bounded_process import BoundedProcessError
from scripts.publication.common import canonical_json
from scripts.repository_source_identity import current_identity
from scripts.release_python_runtime import ReleasePythonRuntimeError


class ArtifactToolchainReaderTests(unittest.TestCase):
    def test_dispatch_uses_frozen_source_and_exact_positional_output(self) -> None:
        values = [str(index) * 64 for index in range(9)]
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            completed = subprocess.CompletedProcess(
                [], 0, (" ".join(values) + "\n").encode("ascii"), b""
            )
            with (
                patch.object(binding, "require_closed_release_runtime") as runtime,
                patch.object(binding, "run_bounded_process", return_value=completed) as runner,
            ):
                result = binding.derive_artifact_toolchain_metadata(repository)
            runtime.assert_called_once_with()
            self.assertEqual(
                result, dict(zip(binding.TOOLCHAIN_METADATA_ORDER, values, strict=True))
            )
            command = runner.call_args.args[0]
            self.assertEqual(command[:3], ["/bin/bash", "-p", "-c"])
            self.assertIn('source "$1/scripts/release_python_launcher.sh"', command[3])
            self.assertIn('"$1/scripts/candidate_artifact_binding.py" --repository "$1"', command[3])
            self.assertEqual(command[-1], str(repository))
            self.assertEqual(runner.call_args.kwargs, {
                "cwd": repository,
                "environment": dict(os.environ),
                "timeout": 1800,
                "output_limit": 4 * 1024 * 1024,
            })

    def test_real_isolated_child_uses_artifact_module_not_operator_policy(self) -> None:
        values = [str(index) * 64 for index in range(9)]
        exact = " ".join(values) + "\n"
        launcher = Path(binding.__file__).parent / "release_python_launcher.sh"
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            scripts = repository / "scripts"
            scripts.mkdir()
            (scripts / "release_python_launcher.sh").write_bytes(launcher.read_bytes())
            (scripts / "candidate_artifact_binding.py").write_text(
                "from pathlib import Path\n"
                "import sys\n"
                "if sys.flags.isolated != 1 or sys.flags.no_site != 1:\n"
                "    raise RuntimeError('child interpreter is not isolated')\n"
                "if sys.argv[1:] != ['--repository', str(Path(__file__).parent.parent)]:\n"
                "    raise RuntimeError('child source arguments changed')\n"
                f"print({exact!r}, end='')\n",
                encoding="utf-8",
            )
            with (
                patch.object(binding, "require_closed_release_runtime"),
                patch.dict(os.environ, {"CFW_RELEASE_PYTHON_EXECUTABLE": sys.executable}),
                patch.object(
                    binding, "derive_candidate_toolchain_metadata",
                    side_effect=AssertionError("operator policy must not verify artifact inputs"),
                ) as operator_policy,
            ):
                result = binding.derive_artifact_toolchain_metadata(repository)
            operator_policy.assert_not_called()
            self.assertEqual(
                result, dict(zip(binding.TOOLCHAIN_METADATA_ORDER, values, strict=True))
            )

    def test_diagnostics_and_every_output_near_match_fail_closed(self) -> None:
        exact = (" ".join(str(index) * 64 for index in range(9)) + "\n").encode("ascii")
        malformed = (
            (1, exact, b""),
            (0, exact, b"warning\n"),
            (0, exact[:-1], b""),
            (0, exact + b"\n", b""),
            (0, b" " + exact, b""),
            (0, exact.replace(b" ", b"  ", 1), b""),
            (0, exact.replace(b"0", b"A", 1), b""),
            (0, b" ".join(exact.split(b" ")[:-1]) + b"\n", b""),
            (0, exact.replace(b"\n", b"\r\n"), b""),
            (0, exact + b"warning\n", b""),
            (0, b"\xff" + exact, b""),
            (0, b"", b""),
        )
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            for code, stdout, stderr in malformed:
                with (
                    self.subTest(code=code, stdout=stdout, stderr=stderr),
                    patch.object(binding, "require_closed_release_runtime"),
                    patch.object(
                        binding, "run_bounded_process",
                        return_value=subprocess.CompletedProcess([], code, stdout, stderr),
                    ) as runner,
                    self.assertRaises(binding.ArtifactToolchainError) as captured,
                ):
                    binding.derive_artifact_toolchain_metadata(repository)
                runner.assert_called_once()
                self.assertEqual(
                    captured.exception.code,
                    "artifact_toolchain_verification_failed" if code or stderr
                    else "artifact_toolchain_output_invalid",
                )

    def test_unsealed_runtime_prevents_any_child_verifier(self) -> None:
        with (
            patch.object(
                binding, "require_closed_release_runtime",
                side_effect=ReleasePythonRuntimeError("unsealed"),
            ),
            patch.object(binding, "run_bounded_process") as runner,
            self.assertRaises(ReleasePythonRuntimeError),
        ):
            binding.derive_artifact_toolchain_metadata(Path("/unused"))
        runner.assert_not_called()

    def test_unsafe_repository_paths_are_rejected_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            repository = parent / "repository"
            repository.mkdir()
            symlink = parent / "linked"
            symlink.symlink_to(repository, target_is_directory=True)
            regular = parent / "file"
            regular.write_text("not a repository\n", encoding="utf-8")
            for path in (Path("."), parent / "missing", symlink, regular):
                with (
                    self.subTest(path=path),
                    patch.object(binding, "require_closed_release_runtime"),
                    patch.object(binding, "run_bounded_process") as runner,
                    self.assertRaises(binding.ArtifactToolchainError) as captured,
                ):
                    binding.derive_artifact_toolchain_metadata(path)
                self.assertEqual(captured.exception.code, "artifact_toolchain_repository_invalid")
                runner.assert_not_called()
            repository.chmod(0o777)
            with (
                patch.object(binding, "require_closed_release_runtime"),
                patch.object(binding, "run_bounded_process") as runner,
                self.assertRaises(binding.ArtifactToolchainError),
            ):
                binding.derive_artifact_toolchain_metadata(repository)
            runner.assert_not_called()

    def test_foreign_repository_owner_is_rejected_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            owner = repository.stat().st_uid
            with (
                patch.object(binding, "require_closed_release_runtime"),
                patch.object(binding.os, "geteuid", return_value=owner + 1),
                patch.object(binding, "run_bounded_process") as runner,
                self.assertRaises(binding.ArtifactToolchainError) as captured,
            ):
                binding.derive_artifact_toolchain_metadata(repository)
            self.assertEqual(captured.exception.code, "artifact_toolchain_repository_invalid")
            runner.assert_not_called()

    def test_bounded_failures_keep_their_cause_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            failures: list[Exception] = [
                BoundedProcessError(reason, reason)
                for reason in ("start", "timeout", "output-limit", "descendant", "cleanup")
            ]
            failures.append(OSError("descriptor unavailable"))
            for failure in failures:
                with (
                    self.subTest(failure=failure),
                    patch.object(binding, "require_closed_release_runtime"),
                    patch.object(binding, "run_bounded_process", side_effect=failure) as runner,
                    self.assertRaises(binding.ArtifactToolchainError) as captured,
                ):
                    binding.derive_artifact_toolchain_metadata(repository)
                self.assertEqual(captured.exception.code, "artifact_toolchain_execution_failed")
                self.assertIs(captured.exception.__cause__, failure)
                runner.assert_called_once()


def _ci_identity(repository: Path, version: str = "1.0.0") -> dict:
    return {
        "document": binding.TOOLCHAIN_BINDING_KIND,
        "pins_path": "scripts/dependency_pins.env",
        "pins_sha256": hashlib.sha256((repository / "scripts/dependency_pins.env").read_bytes()).hexdigest(),
        "toolchain_versions": {name: version for name in ("go", "gomobile", "govulncheck", "node", "rust", "sing_box")},
        "toolchain_digests": {
            "go_darwin_arm64_sha256": "a" * 64,
            "gomobile_module_sum": "h1:fixed-module",
            "govulncheck_module_sum": "h1:fixed-module",
            "node_darwin_arm64_sha256": "b" * 64,
            "rust_release_toolchain_surface_sha256": "c" * 64,
        },
        "release_tree_sha256": {name: "d" * 64 for name in binding.RELEASE_TREE_METADATA},
        "apple_toolchain": {"macos_deployment_target": "15.0", "xcode_build_version": "17F42", "xcode_version": "26.6"},
        "resolved": {name: version for name in (
            "bash", "cargo", "cargo-audit", "cargo-deny", "cargo-tauri", "git", "go",
            "gomobile", "govulncheck", "node", "npm", "python3", "rust-toolchain-surface",
            "rustc", "swift", "xcodebuild", "xcodegen", "zsh",
        )},
    }


def _ci_output(identity: dict) -> bytes:
    return canonical_json(identity) + f"toolchain_sha256: {binding.toolchain_sha256(identity)}\n".encode("ascii")


class ArtifactCiToolchainReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        (self.repository / "scripts").mkdir()
        (self.repository / "scripts/dependency_pins.env").write_bytes(b"NODE_VERSION=1.0.0\n")
        self.identity = _ci_identity(self.repository)
        self.source = {"repositoryCommit": "a" * 40, "releaseSourceSha256": "b" * 64}

    def test_exact_full_binding_uses_artifact_entry_and_one_bound_environment(self) -> None:
        environment = {"PATH": "/usr/bin:/bin", "CFW_RELEASE_PYTHON_EXECUTABLE": sys.executable}
        with (
            patch.object(binding, "require_closed_release_runtime"),
            patch.object(binding, "current_identity", return_value=self.source) as source,
            patch.object(binding, "run_bounded_process", return_value=subprocess.CompletedProcess([], 0, _ci_output(self.identity), b"")) as run,
        ):
            digest, identity = binding.derive_artifact_ci_toolchain_binding(self.repository, environment)
        self.assertEqual(identity, self.identity)
        self.assertEqual(digest, binding.toolchain_sha256(identity))
        self.assertIn('"$1/scripts/sealed_evidence_manifest.py" ci-toolchain-binding', run.call_args.args[0][3])
        self.assertEqual(run.call_args.kwargs["environment"], environment)
        self.assertEqual(source.call_count, 2)
        for call in source.call_args_list:
            self.assertEqual(call.kwargs, {"require_clean": True, "environment": environment})

    def test_every_noncanonical_or_mismatched_binding_is_rejected(self) -> None:
        exact = _ci_output(self.identity)
        altered = {**self.identity, "unknown": "field"}
        missing = {key: value for key, value in self.identity.items() if key != "resolved"}
        wrong_pins = {**self.identity, "pins_sha256": "f" * 64}
        wrong_tree = {**self.identity, "release_tree_sha256": {"unexpected": "d" * 64}}
        wrong_schema = {**self.identity, "document": "unsigned-ci-toolchain-binding-v2"}
        malformed = (
            (1, exact, b""), (0, exact, b"warning\n"), (0, exact[:-1], b""),
            (0, exact + b"\n", b""), (0, b" " + exact, b""),
            (0, exact.replace(b"\n", b"\r\n"), b""),
            (0, exact.replace(b'"document":', b'"document":"duplicate","document":', 1), b""),
            (0, canonical_json(self.identity) + b"toolchain_sha256: " + b"e" * 64 + b"\n", b""),
            (0, exact.replace(b'"pins_sha256":"', b'"pins_sha256":NaN,"unused":"', 1), b""),
            (0, b"\xff" + exact, b""), (0, _ci_output(altered), b""),
            (0, _ci_output(missing), b""), (0, _ci_output(wrong_pins), b""),
            (0, _ci_output(wrong_tree), b""), (0, _ci_output(wrong_schema), b""),
        )
        for code, stdout, stderr in malformed:
            with (
                self.subTest(code=code, stdout=stdout, stderr=stderr),
                patch.object(binding, "require_closed_release_runtime"),
                patch.object(binding, "current_identity", return_value=self.source),
                patch.object(binding, "run_bounded_process", return_value=subprocess.CompletedProcess([], code, stdout, stderr)) as run,
                self.assertRaises(binding.ArtifactToolchainError) as raised,
            ):
                binding.derive_artifact_ci_toolchain_binding(self.repository)
            self.assertEqual(raised.exception.code, "artifact_toolchain_verification_failed" if code or stderr else "artifact_toolchain_output_invalid")
            run.assert_called_once()

    def test_source_drift_during_the_query_cannot_return_a_binding(self) -> None:
        with (
            patch.object(binding, "require_closed_release_runtime"),
            patch.object(binding, "current_identity", side_effect=[self.source, {**self.source, "releaseSourceSha256": "c" * 64}]),
            patch.object(binding, "run_bounded_process", return_value=subprocess.CompletedProcess([], 0, _ci_output(self.identity), b"")),
            self.assertRaises(binding.ArtifactToolchainError) as raised,
        ):
            binding.derive_artifact_ci_toolchain_binding(self.repository)
        self.assertEqual(raised.exception.code, "artifact_toolchain_source_changed")

    def test_real_different_source_policies_are_executed_in_their_own_isolated_children(self) -> None:
        launcher = Path(binding.__file__).parent / "release_python_launcher.sh"
        policy = (
            "from pathlib import Path\nimport sys\n"
            "EXPECTED = {expected!r}\n"
            "def require_policy(repository):\n"
            "    if (repository / 'scripts/dependency_pins.env').read_bytes() != EXPECTED:\n"
            "        raise RuntimeError('artifact bindings differ from release policy')\n"
            "if __name__ == '__main__':\n"
            "    require_policy(Path(sys.argv[1]))\n"
        )
        entry = (
            "import hashlib\nimport json\nfrom pathlib import Path\nimport sys\n"
            "from scripts.source_policy import require_policy\n"
            "if not sys.flags.isolated or not sys.flags.no_site or sys.argv[1:] != ['ci-toolchain-binding']:\n"
            "    raise RuntimeError('isolated artifact query contract changed')\n"
            "repository = Path(__file__).parent.parent\nrequire_policy(repository)\n"
            "identity = json.loads((repository / 'scripts/binding-fixture.json').read_bytes())\n"
            "payload = (json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\\n').encode()\n"
            "sys.stdout.buffer.write(payload)\n"
            "print('toolchain_sha256: ' + hashlib.sha256(payload).hexdigest())\n"
        )
        repositories = []
        for name, version in (("artifact", "1.0.0"), ("executor", "2.0.0")):
            repository = self.repository / name
            scripts = repository / "scripts"
            scripts.mkdir(parents=True)
            pins = f"NODE_VERSION={version}\n".encode()
            (scripts / "dependency_pins.env").write_bytes(pins)
            (scripts / "release_python_launcher.sh").write_bytes(launcher.read_bytes())
            (scripts / "source_policy.py").write_text(policy.format(expected=pins), encoding="utf-8")
            (scripts / "repository_source_identity.py").write_bytes(
                (launcher.parent / "repository_source_identity.py").read_bytes()
            )
            (scripts / "sealed_evidence_manifest.py").write_text(entry, encoding="utf-8")
            (scripts / "binding-fixture.json").write_bytes(canonical_json(_ci_identity(repository, version)))
            for arguments in (
                ["init", "-q", "--initial-branch=release"],
                ["add", "scripts"],
                ["-c", "user.name=Release", "-c", "user.email=release@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Record release policy"],
            ):
                subprocess.run(["/usr/bin/git", "-C", str(repository), *arguments], check=True, capture_output=True)
            repositories.append(repository)
        artifact, executor = repositories
        rejected = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(executor / "scripts/source_policy.py"), str(artifact)],
            capture_output=True, check=False,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(b"artifact bindings differ from release policy", rejected.stderr)
        before = [current_identity(repository, require_clean=True) for repository in repositories]
        with (
            patch.object(binding, "require_closed_release_runtime"),
            patch.object(binding, "derive_toolchain_binding", side_effect=AssertionError("executor policy must not inspect the artifact")),
            patch.dict(os.environ, {"CFW_RELEASE_PYTHON_EXECUTABLE": sys.executable}),
        ):
            artifact_digest, artifact_identity = binding.derive_artifact_ci_toolchain_binding(artifact)
            executor_digest, executor_identity = binding.derive_artifact_ci_toolchain_binding(executor)
        self.assertNotEqual(artifact_digest, executor_digest)
        self.assertEqual(artifact_identity["toolchain_versions"]["node"], "1.0.0")
        self.assertEqual(executor_identity["toolchain_versions"]["node"], "2.0.0")
        self.assertEqual([current_identity(repository, require_clean=True) for repository in repositories], before)


if __name__ == "__main__":
    unittest.main()
