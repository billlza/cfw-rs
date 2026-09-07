from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import release_git


class ReleaseGitProcessBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()

    def _executable(self, body: str) -> Path:
        path = self.repository / "git-fixture"
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(0o700)
        return path

    def test_successful_output_is_returned(self) -> None:
        executable = self._executable("/bin/echo expected\n")
        with mock.patch.object(release_git, "GIT_EXECUTABLE", str(executable)):
            completed = release_git._invoke(self.repository, ["status"], None)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"expected\n")
        self.assertEqual(completed.stderr, b"")

    def test_successful_stderr_is_rejected(self) -> None:
        executable = self._executable("/bin/echo diagnostic >&2\n")
        with mock.patch.object(release_git, "GIT_EXECUTABLE", str(executable)):
            with self.assertRaisesRegex(release_git.ReleaseGitError, "emitted diagnostics"):
                release_git._invoke(self.repository, ["status"], None)

    def test_oversized_combined_output_is_stopped_during_execution(self) -> None:
        executable = self._executable("/usr/bin/yes x\n")
        with (
            mock.patch.object(release_git, "GIT_EXECUTABLE", str(executable)),
            mock.patch.object(release_git, "MAX_GIT_OUTPUT_BYTES", 1024),
            mock.patch.object(release_git, "GIT_TIMEOUT_SECONDS", 5),
        ):
            with self.assertRaisesRegex(release_git.ReleaseGitError, "output"):
                release_git._invoke(self.repository, ["status"], None)

    def test_successful_parent_with_live_descendant_is_rejected_and_cleaned(self) -> None:
        executable = self._executable(
            "/bin/sleep 30 </dev/null >/dev/null 2>/dev/null &\nexit 0\n"
        )
        with (
            mock.patch.object(release_git, "GIT_EXECUTABLE", str(executable)),
            mock.patch.object(release_git, "GIT_TIMEOUT_SECONDS", 5),
        ):
            with self.assertRaisesRegex(release_git.ReleaseGitError, "descendant"):
                release_git._invoke(self.repository, ["status"], None)


if __name__ == "__main__":
    unittest.main()
