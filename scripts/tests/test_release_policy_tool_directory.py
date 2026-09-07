from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
HELPER = REPOSITORY / "scripts/release_policy_tool_directory.sh"


class PolicyToolDirectoryTests(unittest.TestCase):
    def run_helper(
        self, function: str, *arguments: str
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "/bin/bash",
                "-p",
                "-c",
                'source "$1"; shift; "$@"',
                "policy-tool-helper-test",
                str(HELPER),
                function,
                *arguments,
            ],
            cwd=REPOSITORY,
            env=dict(os.environ),
            capture_output=True,
            check=False,
        )

    def test_creates_each_owner_only_directory_without_recursive_mkdir(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            parent = Path(temporary).resolve(strict=True)
            parent.chmod(0o700)
            first = parent / "release-tools"
            second = first / "policy"
            third = second / "bin"
            for directory in (first, second, third):
                completed = self.run_helper(
                    "cfw_require_private_policy_directory", str(directory)
                )
                self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_parent_symlink_is_rejected_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary).resolve(strict=True)
            real_parent = root / "real"
            real_parent.mkdir(mode=0o700)
            marker = real_parent / "marker"
            marker.write_text("unchanged", encoding="utf-8")
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)

            completed = self.run_helper(
                "cfw_require_private_policy_directory", str(linked_parent / "policy")
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((real_parent / "policy").exists())
            self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")

    def test_existing_root_and_bin_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary).resolve(strict=True)
            root.chmod(0o700)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            marker = outside / "marker"
            marker.write_text("unchanged", encoding="utf-8")
            for relative in ("policy", "real-policy/bin"):
                with self.subTest(relative=relative):
                    target = root / relative
                    target.parent.mkdir(mode=0o700, exist_ok=True)
                    target.symlink_to(outside, target_is_directory=True)
                    completed = self.run_helper(
                        "cfw_require_private_policy_directory", str(target)
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")
                    target.unlink()

    def test_group_writable_parent_and_noncanonical_path_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary).resolve(strict=True)
            root.chmod(0o720)
            completed = self.run_helper(
                "cfw_require_private_policy_directory", str(root / "policy")
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((root / "policy").exists())

            root.chmod(0o700)
            completed = self.run_helper(
                "cfw_require_private_policy_directory", str(root / "." / "policy") + "/"
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((root / "policy").exists())

    def test_existing_directory_must_already_have_exact_mode(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary).resolve(strict=True)
            root.chmod(0o700)
            policy = root / "policy"
            policy.mkdir(mode=0o755)
            completed = self.run_helper(
                "cfw_require_private_policy_directory", str(policy)
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(policy.stat().st_mode & 0o777, 0o755)


class WarningFreePolicyInstallTests(unittest.TestCase):
    def run_install(
        self, root: Path, script_body: str
    ) -> subprocess.CompletedProcess[bytes]:
        executable = root / "fake-cargo"
        executable.write_text(script_body, encoding="utf-8")
        executable.chmod(0o700)
        log = root / "install.log"
        completed = PolicyToolDirectoryTests().run_helper(
            "cfw_run_warning_free_policy_install",
            "fixture installation",
            str(log),
            str(executable),
        )
        self.assertFalse(log.exists())
        return completed

    def test_success_without_warning_is_accepted_and_log_is_removed(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary).resolve(strict=True)
            root.chmod(0o700)
            completed = self.run_install(
                root, "#!/bin/bash -p\nprintf 'installed\\n'\n"
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stdout, b"installed\n")

    def test_success_with_warning_is_release_blocking(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary).resolve(strict=True)
            root.chmod(0o700)
            completed = self.run_install(
                root, "#!/bin/bash -p\nprintf 'warning: degraded install\\n' >&2\n"
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"emitted a warning", completed.stderr)

    def test_nonzero_install_is_release_blocking(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary).resolve(strict=True)
            root.chmod(0o700)
            completed = self.run_install(
                root, "#!/bin/bash -p\nprintf 'failed\\n' >&2\nexit 7\n"
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"failed", completed.stderr)


if __name__ == "__main__":
    unittest.main()
