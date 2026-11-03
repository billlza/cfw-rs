"""No-network regressions for branch governance. Uses disposable local Git repositories."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit as branch_audit


def execute(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        execute(self.repo, "init", "-q", "-b", "main")
        execute(self.repo, "config", "user.name", "Contract Test")
        execute(self.repo, "config", "user.email", "example@example.invalid")
        self.commit("initial")
        execute(self.repo, "branch", "lza/windows")
        execute(self.repo, "branch", "release/ga")
        execute(self.repo, "switch", "-q", "lza/windows")
        self.commit("runtime")
        execute(self.repo, "branch", "stage/service")
        self.commit("desktop")
        execute(self.repo, "switch", "-q", "-c", "probe/job-retirement", "stage/service")
        self.commit("probe")
        execute(self.repo, "switch", "-q", "main")
        self.commit("main-update")
        execute(self.repo, "switch", "-q", "-c", "feat/mobile-observer", "main")
        self.commit("observer")
        execute(self.repo, "switch", "-q", "main")
        self.refresh_remote_refs()
        self.manifest = {
            "schema_version": 1,
            "observed_at": "2026-10-21",
            "repository": "billlza/cfw-rs",
            "windows_integration_branch": "lza/windows",
            "windows_snapshots": ["stage/service"],
            "windows_experiments": ["probe/job-retirement"],
            "independent_review_branches": ["feat/mobile-observer"],
            "historical_release_branches": ["release/ga"],
            "main_branch": "main",
        }
        self.path = self.root / "branches.json"
        self.write_manifest()

    def commit(self, message: str):
        with (self.repo / "events.txt").open("a", encoding="utf-8") as file:
            file.write(message + "\n")
        execute(self.repo, "add", "events.txt")
        execute(self.repo, "commit", "-qm", message)

    def refresh_remote_refs(self):
        for line in execute(self.repo, "for-each-ref", "--format=%(refname:short)", "refs/heads").splitlines():
            execute(self.repo, "update-ref", f"refs/remotes/origin/{line}",
                    execute(self.repo, "rev-parse", "refs/heads/" + line))

    def write_manifest(self):
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_classifies_containment_divergence_and_independent_review(self):
        manifest = branch_audit.load_manifest(self.path)
        output, valid = branch_audit.audit(self.repo, manifest, "origin")
        self.assertTrue(valid)
        by_branch = {entry["branch"]: entry for entry in output["records"]}
        self.assertEqual(by_branch["stage/service"]["status"], "contained_in_target")
        self.assertEqual(by_branch["stage/service"]["source_only_commits"], 0)
        self.assertEqual(by_branch["stage/service"]["target_only_commits"], 1)
        self.assertEqual(by_branch["probe/job-retirement"]["status"], "diverged")
        self.assertEqual(by_branch["feat/mobile-observer"]["status"], "target_behind_source")
        self.assertEqual(by_branch["release/ga"]["status"], "contained_in_target")
        self.assertEqual(output["audit_conclusion"], "expected_history")
        self.assertEqual(by_branch["feat/mobile-observer"]["decision"], "independent_review_no_automatic_merge")

    def test_audit_never_changes_branch_refs_or_worktree(self):
        before = execute(self.repo, "show-ref")
        original_files = (self.repo / "events.txt").read_bytes()
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(branch_audit.main([
                "--repository", str(self.repo), "--manifest", str(self.path),
                "--strict",
            ]), 0)
        self.assertEqual(execute(self.repo, "show-ref"), before)
        self.assertEqual((self.repo / "events.txt").read_bytes(), original_files)
        self.assertEqual(json.loads(output.getvalue())["audit_conclusion"], "expected_history")

    def test_diverged_snapshot_fails_strict_without_modifying_refs(self):
        execute(self.repo, "switch", "-q", "stage/service")
        self.commit("unaudited-new-work")
        self.refresh_remote_refs()
        before = execute(self.repo, "show-ref")
        result, valid = branch_audit.audit(self.repo, branch_audit.load_manifest(self.path), "origin")
        self.assertFalse(valid)
        self.assertEqual(result["audit_conclusion"], "unexpected_divergence")
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(branch_audit.main([
                "--repository", str(self.repo), "--manifest", str(self.path), "--strict",
            ]), 2)
        self.assertEqual(execute(self.repo, "show-ref"), before)

    def test_manifest_rejects_duplicate_members_and_fields(self):
        self.manifest["independent_review_branches"].append("stage/service")
        self.write_manifest()
        with self.assertRaises(branch_audit.AuditError):
            branch_audit.load_manifest(self.path)
        self.path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        with self.assertRaises(branch_audit.AuditError):
            branch_audit.load_manifest(self.path)

    def test_missing_remote_ref_or_bad_branch_fails_closed(self):
        self.manifest["windows_snapshots"] = ["stage/does-not-exist"]
        self.write_manifest()
        with self.assertRaises(branch_audit.AuditError):
            branch_audit.audit(self.repo, branch_audit.load_manifest(self.path), "origin")
        self.manifest["windows_snapshots"] = ["--upload-pack=/bad"]
        self.write_manifest()
        with self.assertRaises(branch_audit.AuditError):
            branch_audit.load_manifest(self.path)


if __name__ == "__main__":
    unittest.main()
