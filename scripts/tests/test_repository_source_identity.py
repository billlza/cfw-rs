from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.repository_source_identity import (
    RELEASE_PATHS,
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
        self.root = Path(self._temporary.name).resolve()
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Release Test")
        git(self.root, "config", "user.email", "release-test@example.invalid")
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text("[workspace]\nmembers = []\n", encoding="utf-8")
        (self.root / "apps").mkdir()
        (self.root / "apps/app.rs").write_text("fn main() {}\n", encoding="utf-8")
        (self.root / "scripts").mkdir()
        (self.root / "scripts/repository_source_identity.py").write_text(
            f"RELEASE_PATHS = {RELEASE_PATHS!r}\n",
            encoding="utf-8",
        )
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

    def test_identity_ignores_ambient_git_binary_and_repository_controls(self) -> None:
        fake_bin = self.root / "target/fake-bin"
        fake_bin.mkdir(parents=True)
        marker = self.root / "ambient-git-ran"
        fake_git = fake_bin / "git"
        fake_git.write_text(
            f"#!/bin/sh\n/usr/bin/touch '{marker}'\nexit 97\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        baseline = current_identity(self.root, require_clean=True)

        with patch.dict(
            os.environ,
            {
                "PATH": str(fake_bin),
                "GIT_DIR": str(self.root / "target/attacker-git-dir"),
                "GIT_WORK_TREE": str(self.root / "target/attacker-work-tree"),
                "GIT_CONFIG_GLOBAL": str(self.root / "target/attacker.gitconfig"),
            },
            clear=False,
        ):
            observed = current_identity(self.root, require_clean=True)

        self.assertEqual(observed, baseline)
        self.assertFalse(marker.exists())

    def test_global_excludes_cannot_hide_a_dirty_release_input(self) -> None:
        hostile_home = self.root / "hostile-home"
        hostile_home.mkdir()
        excludes = hostile_home / "global-excludes"
        excludes.write_text("apps/hidden.rs\n", encoding="utf-8")
        (hostile_home / ".gitconfig").write_text(
            f"[core]\n\texcludesFile = {excludes}\n",
            encoding="utf-8",
        )
        (self.root / "apps/hidden.rs").write_text(
            "pub const HIDDEN: bool = true;\n", encoding="utf-8"
        )

        with patch.dict(os.environ, {"HOME": str(hostile_home)}, clear=False):
            with self.assertRaisesRegex(SourceIdentityError, "tracked or untracked"):
                current_identity(self.root, require_clean=True)

    def test_local_git_exclude_cannot_hide_a_dirty_release_input(self) -> None:
        local_exclude = Path(
            git_output(
                self.root,
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "info/exclude",
            )
        )
        local_exclude.write_text("apps/hidden.rs\n", encoding="utf-8")
        (self.root / "apps/hidden.rs").write_text(
            "pub const HIDDEN: bool = true;\n", encoding="utf-8"
        )

        with self.assertRaisesRegex(SourceIdentityError, "local exclude"):
            current_identity(self.root, require_clean=True)

    def test_repository_fsmonitor_cannot_execute_or_mask_source_queries(self) -> None:
        monitor = self.root / "target/hostile-fsmonitor"
        monitor.parent.mkdir()
        marker = self.root / "target/fsmonitor-ran"
        monitor.write_text(
            f"#!/bin/sh\n/usr/bin/touch '{marker}'\nprintf '0\\n'\n",
            encoding="utf-8",
        )
        monitor.chmod(0o755)
        git(self.root, "config", "core.fsmonitor", str(monitor))

        current_identity(self.root, require_clean=True)

        self.assertFalse(marker.exists())

    def test_local_clean_filter_cannot_execute_or_hide_modified_bytes(self) -> None:
        marker = self.root / "target/filter-ran"
        filter_program = self.root / "target/filter"
        filter_program.parent.mkdir()
        filter_program.write_text(
            f"#!/bin/sh\n/usr/bin/touch '{marker}'\n/bin/cat\n",
            encoding="utf-8",
        )
        filter_program.chmod(0o755)
        attributes = Path(
            git_output(
                self.root,
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "info/attributes",
            )
        )
        attributes.write_text("apps/app.rs filter=mask\n", encoding="utf-8")
        git(self.root, "config", "filter.mask.clean", str(filter_program))
        (self.root / "apps/app.rs").write_text(
            'fn main() { println!("changed"); }\n',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            SourceIdentityError, "attributes|filter|tracked or untracked"
        ):
            current_identity(self.root, require_clean=True)
        self.assertFalse(marker.exists())

    def test_local_core_worktree_cannot_redirect_source_queries(self) -> None:
        decoy = self.root.parent / f"{self.root.name}-decoy"
        shutil.copytree(self.root, decoy, ignore=shutil.ignore_patterns(".git"))
        self.addCleanup(shutil.rmtree, decoy, True)
        git(self.root, "config", "core.worktree", str(decoy))
        (self.root / "apps/app.rs").write_text(
            'fn main() { println!("real tree changed"); }\n',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(SourceIdentityError, "core.worktree"):
            current_identity(self.root, require_clean=True)

    def test_assume_unchanged_index_flag_is_rejected(self) -> None:
        git(self.root, "update-index", "--assume-unchanged", "apps/app.rs")

        with self.assertRaisesRegex(SourceIdentityError, "index contains"):
            current_identity(self.root, require_clean=True)

        (self.root / "apps/app.rs").write_text(
            'fn main() { println!("hidden change"); }\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SourceIdentityError, "index contains"):
            current_identity(self.root, require_clean=True)

    def test_skip_worktree_index_flag_is_rejected(self) -> None:
        git(self.root, "update-index", "--skip-worktree", "apps/app.rs")

        with self.assertRaisesRegex(SourceIdentityError, "index contains"):
            current_identity(self.root, require_clean=True)

        (self.root / "apps/app.rs").write_text(
            'fn main() { println!("hidden change"); }\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SourceIdentityError, "index contains"):
            current_identity(self.root, require_clean=True)

    def test_packet_endpoint_and_collector_bytes_are_in_release_source_digest(self) -> None:
        endpoint = self.root / "tools/packet-evidence-endpoint/main.go"
        collector = self.root / "tools/physical-collector/main.go"
        endpoint.parent.mkdir(parents=True)
        collector.parent.mkdir(parents=True)
        endpoint.write_text("package main\n", encoding="utf-8")
        collector.write_text("package main\n", encoding="utf-8")
        git(self.root, "add", "tools")
        git(self.root, "commit", "-q", "-m", "add release tools")
        baseline = release_source_digest(self.root)

        for path in (endpoint, collector):
            with self.subTest(path=path.relative_to(self.root).as_posix()):
                original = path.read_bytes()
                path.write_bytes(original + b"// changed\n")
                self.assertNotEqual(release_source_digest(self.root), baseline)
                path.write_bytes(original)
                self.assertEqual(release_source_digest(self.root), baseline)

    def test_historical_identity_uses_target_commits_literal_path_closure(self) -> None:
        policy = self.root / "scripts/repository_source_identity.py"
        policy.parent.mkdir(exist_ok=True)
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

    def test_git_replace_refs_cannot_substitute_historical_source_bytes(self) -> None:
        policy = self.root / "scripts/repository_source_identity.py"
        policy.parent.mkdir(exist_ok=True)
        policy.write_text('RELEASE_PATHS = ("apps",)\n', encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "add historical policy")
        commit = git_output(self.root, "rev-parse", "HEAD")
        baseline = identity_at_commit(self.root, commit)
        original_blob = git_output(self.root, "rev-parse", "HEAD:apps/app.rs")
        replacement = subprocess.run(
            ["git", "-C", str(self.root), "hash-object", "-w", "--stdin"],
            input=b"replacement bytes\n",
            check=True,
            capture_output=True,
        ).stdout.decode("ascii").strip()
        git(self.root, "replace", original_blob, replacement)
        self.assertEqual(
            subprocess.run(
                ["git", "-C", str(self.root), "cat-file", "blob", original_blob],
                check=True,
                capture_output=True,
            ).stdout,
            b"replacement bytes\n",
        )

        self.assertEqual(identity_at_commit(self.root, commit), baseline)

    def test_historical_identity_rejects_missing_policy_blob(self) -> None:
        git(self.root, "rm", "-q", "scripts/repository_source_identity.py")
        git(self.root, "commit", "-q", "-m", "remove historical policy")
        commit = git_output(self.root, "rev-parse", "HEAD")
        with self.assertRaisesRegex(SourceIdentityError, "policy blob"):
            identity_at_commit(self.root, commit)

    def test_historical_identity_rejects_dynamic_path_policy(self) -> None:
        policy = self.root / "scripts/repository_source_identity.py"
        policy.parent.mkdir(exist_ok=True)
        policy.write_text('RELEASE_PATHS = tuple(["apps"])\n', encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "dynamic closure")
        commit = git_output(self.root, "rev-parse", "HEAD")
        with self.assertRaisesRegex(SourceIdentityError, "literal sequence"):
            identity_at_commit(self.root, commit)


if __name__ == "__main__":
    unittest.main()
