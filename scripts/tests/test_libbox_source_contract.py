from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
CONTRACT = REPOSITORY / "scripts/libbox_source_contract.sh"


class LibboxSourceContractTests(unittest.TestCase):
    def test_endpoint_patch_reverse_check_keeps_zero_context_admission(self) -> None:
        contract = CONTRACT.read_text(encoding="utf-8")
        self.assertIn(
            'apply --whitespace=error-all --unidiff-zero --reverse --check \\\n'
            '    "$endpoint_conflict_patch_path"',
            contract,
        )

    def run_git(self, repository: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            env=self.environment,
            text=True,
        )
        return result.stdout

    def contract_digests(self, repository: Path) -> tuple[str, str]:
        result = subprocess.run(
            [
                "bash",
                "-c",
                (
                    'source "$1"\n'
                    'libbox_dependency_diff_sha256 "$2"\n'
                    'libbox_combined_diff_sha256 "$2"\n'
                ),
                "bash",
                str(CONTRACT),
                str(repository),
            ],
            check=True,
            capture_output=True,
            env=self.environment,
            text=True,
        )
        dependency, combined = result.stdout.splitlines()
        self.assertRegex(dependency, r"^[0-9a-f]{64}$")
        self.assertRegex(combined, r"^[0-9a-f]{64}$")
        return dependency, combined

    def validate_git_root(self, repository: Path) -> subprocess.CompletedProcess[str]:
        commit = self.run_git(repository, "rev-parse", "HEAD").strip()
        return subprocess.run(
            [
                "/bin/bash",
                "-p",
                "-c",
                'source "$1"; SING_BOX_COMMIT="$3"; libbox_validate_git_root "$2"',
                "libbox-git-contract",
                str(CONTRACT),
                str(repository.resolve()),
                commit,
            ],
            check=False,
            capture_output=True,
            env=self.environment,
            text=True,
        )

    def test_diff_digests_do_not_depend_on_git_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "source"
            home = root / "home"
            clean_home = root / "clean-home"
            system_config = root / "system.gitconfig"
            global_order = root / "global-order"
            system_order = root / "system-order"
            repository.mkdir()
            home.mkdir()
            clean_home.mkdir()
            global_order.write_text("tracked.go\ngo.sum\ngo.mod\nadded.go\n", encoding="utf-8")
            system_order.write_text("go.sum\ngo.mod\nadded.go\ntracked.go\n", encoding="utf-8")
            system_config.touch()
            self.environment = {
                **os.environ,
                "GIT_CONFIG_SYSTEM": str(system_config),
                "HOME": str(home),
            }

            self.run_git(repository, "init", "--quiet")
            self.run_git(repository, "config", "user.name", "CFW Release Test")
            self.run_git(repository, "config", "user.email", "release-test@example.invalid")
            base_module = [f"module line {index}" for index in range(40)]
            base_module[0] = "module example.invalid/base"
            base_module[20] = ""
            (repository / "go.mod").write_text(
                "\n".join(base_module) + "\n", encoding="utf-8"
            )
            (repository / "go.sum").write_text(
                "\n".join(f"base checksum {index}" for index in range(20)) + "\n",
                encoding="utf-8",
            )
            (repository / "tracked.go").write_text("package tracked\n", encoding="utf-8")
            self.run_git(repository, "add", ".")
            self.run_git(repository, "commit", "--quiet", "-m", "base")

            patched_module = list(base_module)
            patched_module[2] = "module line 2 patched"
            patched_module[35] = "module line 35 patched"
            (repository / "go.mod").write_text(
                "\n".join(patched_module) + "\n", encoding="utf-8"
            )
            (repository / "go.sum").write_text(
                "\n".join(
                    (
                        f"patched checksum {index}"
                        if index in {1, 18}
                        else f"base checksum {index}"
                    )
                    for index in range(20)
                )
                + "\n",
                encoding="utf-8",
            )
            (repository / "tracked.go").write_text(
                "package tracked\n\nconst Patched = true\n", encoding="utf-8"
            )
            (repository / "added.go").write_text("package added\n", encoding="utf-8")

            local_order = repository / ".git/local-order"
            local_order.write_text("go.sum\ntracked.go\nadded.go\ngo.mod\n", encoding="utf-8")
            for scope, order_file in (
                ("--global", global_order),
                ("--local", local_order),
                ("--file", system_config),
            ):
                prefix = ("config", scope)
                if scope == "--file":
                    prefix = ("config", scope, str(order_file))
                    order_file = system_order
                self.run_git(repository, *prefix, "core.abbrev", "7")
                self.run_git(repository, *prefix, "color.ui", "always")
                self.run_git(repository, *prefix, "diff.algorithm", "histogram")
                self.run_git(repository, *prefix, "diff.interHunkContext", "50")
                self.run_git(repository, *prefix, "diff.noprefix", "true")
                self.run_git(repository, *prefix, "diff.orderFile", str(order_file))
                self.run_git(repository, *prefix, "diff.suppressBlankEmpty", "true")

            configured_digests = self.contract_digests(repository)

            for key in (
                "core.abbrev",
                "color.ui",
                "diff.algorithm",
                "diff.interHunkContext",
                "diff.noprefix",
                "diff.orderFile",
                "diff.suppressBlankEmpty",
            ):
                self.run_git(repository, "config", "--local", "--unset-all", key)
            self.environment = {
                **os.environ,
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "HOME": str(clean_home),
            }
            clean_digests = self.contract_digests(repository)

            self.assertEqual(configured_digests, clean_digests)

    def test_git_controls_reject_local_configuration_and_hidden_index_flags(self) -> None:
        for control in (
            "worktree",
            "include",
            "include-if",
            "info-attributes",
            "assume-unchanged",
            "skip-worktree",
        ):
            with self.subTest(control=control), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                repository = root / "source"
                home = root / "home"
                repository.mkdir()
                home.mkdir()
                self.environment = {**os.environ, "HOME": str(home)}
                self.run_git(repository, "init", "--quiet")
                self.run_git(repository, "config", "user.name", "CFW Release Test")
                self.run_git(
                    repository,
                    "config",
                    "user.email",
                    "release-test@example.invalid",
                )
                (repository / "tracked.go").write_text(
                    "package tracked\n", encoding="utf-8"
                )
                self.run_git(repository, "add", "tracked.go")
                self.run_git(repository, "commit", "--quiet", "-m", "base")
                if control == "worktree":
                    decoy = root / "decoy"
                    decoy.mkdir()
                    self.run_git(repository, "config", "core.worktree", str(decoy))
                elif control == "include":
                    included = root / "included.gitconfig"
                    included.write_text("[core]\n\tfileMode = false\n", encoding="utf-8")
                    self.run_git(repository, "config", "include.path", str(included))
                elif control == "include-if":
                    included = root / "included.gitconfig"
                    included.write_text("[core]\n\tfileMode = false\n", encoding="utf-8")
                    self.run_git(
                        repository,
                        "config",
                        f"includeIf.gitdir:{repository}/.path",
                        str(included),
                    )
                elif control == "info-attributes":
                    (repository / ".git/info/attributes").write_text(
                        "tracked.go -text\n", encoding="utf-8"
                    )
                else:
                    self.run_git(repository, "update-index", f"--{control}", "tracked.go")

                completed = self.validate_git_root(repository)
                self.assertNotEqual(completed.returncode, 0)

    def test_git_replace_and_ambient_git_shadow_cannot_change_fixed_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = root / "source"
            home = root / "home"
            fake_bin = root / "fake-bin"
            repository.mkdir()
            home.mkdir()
            fake_bin.mkdir()
            marker = root / "ambient-git-ran"
            fake_git = fake_bin / "git"
            fake_git.write_text(
                f"#!/bin/sh\n/usr/bin/touch '{marker}'\nexit 97\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            self.environment = {**os.environ, "HOME": str(home)}
            self.run_git(repository, "init", "--quiet")
            self.run_git(repository, "config", "user.name", "CFW Release Test")
            self.run_git(
                repository,
                "config",
                "user.email",
                "release-test@example.invalid",
            )
            original = b"package tracked\n"
            (repository / "tracked.go").write_bytes(original)
            self.run_git(repository, "add", "tracked.go")
            self.run_git(repository, "commit", "--quiet", "-m", "base")
            original_blob = self.run_git(
                repository, "rev-parse", "HEAD:tracked.go"
            ).strip()
            replacement = subprocess.run(
                ["/usr/bin/git", "-C", str(repository), "hash-object", "-w", "--stdin"],
                input=b"replacement\n",
                check=True,
                capture_output=True,
            ).stdout.decode("ascii").strip()
            self.run_git(repository, "replace", original_blob, replacement)
            self.environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"

            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-p",
                    "-c",
                    'source "$1"; libbox_git "$2" cat-file blob "$3"',
                    "libbox-git-contract",
                    str(CONTRACT),
                    str(repository),
                    original_blob,
                ],
                check=False,
                capture_output=True,
                env=self.environment,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stdout, original)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
