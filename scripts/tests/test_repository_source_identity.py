from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.repository_source_identity import (
    SourceIdentityError,
    current_identity,
    identity_at_commit,
    release_source_digest,
    repository_commit,
    require_clean_repository,
)


def git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True)


def git_output(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def single_file_digest(path: str, data: bytes, *, executable: bool = False) -> str:
    entry = {
        "executable": executable,
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }
    encoded = json.dumps(entry, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((encoded + "\n").encode("utf-8")).hexdigest()


class RepositorySourceIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Release Test")
        git(self.root, "config", "user.email", "release-test@example.invalid")
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text("[workspace]\nmembers = []\n", encoding="utf-8")
        (self.root / "apps").mkdir()
        (self.root / "apps/app.rs").write_text("fn main() {}\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "initial source")

    def test_identity_binds_real_head_and_release_file_bytes(self) -> None:
        before = current_identity(self.root, require_clean=True)
        self.assertEqual(before["repositoryCommit"], repository_commit(self.root))
        self.assertEqual(before["releaseSourceSha256"], release_source_digest(self.root))

        (self.root / "apps/app.rs").write_text(
            'fn main() { println!("changed"); }\n',
            encoding="utf-8",
        )
        after = current_identity(self.root)
        self.assertEqual(after["repositoryCommit"], before["repositoryCommit"])
        self.assertNotEqual(after["releaseSourceSha256"], before["releaseSourceSha256"])

    def test_nonignored_new_release_file_changes_digest_and_blocks_clean_gate(self) -> None:
        before = release_source_digest(self.root)
        (self.root / "crates").mkdir()
        (self.root / "crates/new.rs").write_text("pub const VALUE: u8 = 1;\n", encoding="utf-8")
        self.assertNotEqual(release_source_digest(self.root), before)
        with self.assertRaisesRegex(SourceIdentityError, "tracked or untracked changes"):
            require_clean_repository(self.root)

    def test_ignored_build_output_is_not_read_into_release_identity(self) -> None:
        before = release_source_digest(self.root)
        (self.root / "target").mkdir()
        (self.root / "target/build.bin").write_bytes(b"generated")
        self.assertEqual(release_source_digest(self.root), before)
        require_clean_repository(self.root)

    def test_historical_identity_uses_target_commits_literal_path_closure(self) -> None:
        policy = self.root / "scripts/repository_source_identity.py"
        policy.parent.mkdir()
        old_data = b"old release input\n"
        (self.root / "old.txt").write_bytes(old_data)
        policy.write_text('RELEASE_PATHS = ("old.txt",)\n', encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "old closure")
        old_commit = git_output(self.root, "rev-parse", "HEAD")

        (self.root / "new.txt").write_text("new release input\n", encoding="utf-8")
        policy.write_text('RELEASE_PATHS = ("new.txt",)\n', encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "new closure")

        identity = identity_at_commit(self.root, old_commit)
        self.assertEqual(identity["repositoryCommit"], old_commit)
        self.assertEqual(
            identity["releaseSourceSha256"],
            single_file_digest("old.txt", old_data),
        )

    def test_historical_identity_rejects_missing_policy_blob(self) -> None:
        commit = git_output(self.root, "rev-parse", "HEAD")
        with self.assertRaisesRegex(SourceIdentityError, "policy blob"):
            identity_at_commit(self.root, commit)

    def test_historical_identity_rejects_dynamic_path_policy(self) -> None:
        policy = self.root / "scripts/repository_source_identity.py"
        policy.parent.mkdir()
        policy.write_text('RELEASE_PATHS = tuple(["apps"])\n', encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "dynamic closure")
        commit = git_output(self.root, "rev-parse", "HEAD")
        with self.assertRaisesRegex(SourceIdentityError, "literal sequence"):
            identity_at_commit(self.root, commit)


if __name__ == "__main__":
    unittest.main()
