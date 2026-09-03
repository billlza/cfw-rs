from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import candidate_artifact_binding as binding
from scripts.publication.bounded_process import BoundedProcessError
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


if __name__ == "__main__":
    unittest.main()
