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
            'apply --unidiff-zero --reverse --check \\\n'
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


if __name__ == "__main__":
    unittest.main()
