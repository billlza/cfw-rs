from __future__ import annotations

import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import select_ci_xcode as selector


class XcodeSelectionTests(unittest.TestCase):
    def installation(self, root: Path, name: str, version="27.0", build="27A5252f", bundle="25183.90.16"):
        application = root / name
        (application / "Contents/Developer").mkdir(parents=True)
        (application / "Contents/version.plist").write_bytes(plistlib.dumps({"CFBundleShortVersionString": version, "ProductBuildVersion": build, "CFBundleVersion": bundle}))
        return selector.read_installation(application, root)

    def test_final_is_newer_than_beta_with_same_marketing_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            beta = self.installation(root, "Xcode_beta.app")
            stable = self.installation(root, "Xcode.app", build="27A266a", bundle="25183.107.5")
            self.assertEqual(selector.newest_installation([stable, beta]), stable)

    def test_newer_marketing_version_and_beta_revisions_are_ordered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            older = self.installation(root, "Xcode_old.app")
            newer_beta = self.installation(root, "Xcode_beta.app", bundle="25183.92.1", build="27A5260a")
            newest = self.installation(root, "Xcode_new.app", version="27.1", bundle="25220.1", build="27B5001a")
            self.assertEqual(selector.newest_installation([older, newer_beta]), newer_beta)
            self.assertEqual(selector.newest_installation([newer_beta, newest]), newest)

    def test_aliases_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            selected = self.installation(root, "Xcode_beta.app")
            alias = root / "Xcode.app"
            alias.symlink_to(selected.application)
            self.assertEqual(selector.newest_installation([selected, selector.read_installation(alias, root)]), selected)

    def test_alias_outside_applications_and_symlinked_contents_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            applications = root / "Applications"
            applications.mkdir()
            outside = self.installation(root, "Xcode_outside.app")
            alias = applications / "Xcode.app"
            alias.symlink_to(outside.application)
            with self.assertRaisesRegex(selector.XcodeSelectionError, "escaped"):
                selector.read_installation(alias, applications)
            alias.unlink()
            alias.mkdir()
            (alias / "Contents").symlink_to(outside.application / "Contents")
            with self.assertRaisesRegex(selector.XcodeSelectionError, "unsafe directory"):
                selector.read_installation(alias, applications)

    def test_empty_and_conflicting_latest_inventories_fail(self):
        with self.assertRaises(selector.XcodeSelectionError):
            selector.newest_installation([])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            one = self.installation(root, "Xcode_one.app")
            other = self.installation(root, "Xcode_other.app", build="27A5253f")
            with self.assertRaisesRegex(selector.XcodeSelectionError, "disagree"):
                selector.newest_installation([one, other])

    def test_normalization_is_forbidden_outside_hosted_ci(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = self.installation(Path(directory).resolve(), "Xcode.app")
            with patch.dict(os.environ, {}, clear=True), patch.object(selector, "command") as command:
                with self.assertRaisesRegex(selector.XcodeSelectionError, "GitHub-hosted"):
                    selector.normalize_and_verify(selected)
                command.assert_not_called()

    def test_root_account_and_root_group_are_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = self.installation(Path(directory).resolve(), "Xcode.app")
            for uid, groups in ((0, [0]), (501, [20, 0, 80])):
                with self.subTest(uid=uid, groups=groups), patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}, clear=True), patch.object(os, "geteuid", return_value=uid), patch.object(os, "getgroups", return_value=groups), patch.object(selector, "command") as command:
                    with self.assertRaisesRegex(selector.XcodeSelectionError, "non-root"):
                        selector.normalize_and_verify(selected)
                    command.assert_not_called()

    def exercise_normalization(self, selected, *, unsafe_at=None, changed=False):
        calls = []
        scans = 0
        def execute(argv, **kwargs):
            nonlocal scans
            calls.append(argv)
            if argv[0] == "/usr/bin/xcodebuild":
                return f"Xcode {selected.version}\nBuild version {selected.build}"
            if argv[0] == "/usr/bin/find":
                scans += 1
                return "unsafe" if scans == unsafe_at else ""
            return ""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}, clear=True), patch.object(os, "geteuid", return_value=501), patch.object(os, "getgroups", return_value=[20, 80]), patch.object(selector, "command", side_effect=execute), patch.object(selector, "read_installation", return_value=None if changed else selected):
            selector.normalize_and_verify(selected)
        return calls

    def test_selected_only_ownership_and_identity_are_revalidated(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = self.installation(Path(directory).resolve(), "Xcode.app")
            calls = self.exercise_normalization(selected)
            self.assertEqual([call[0] for call in calls], ["/usr/sbin/spctl", "/usr/bin/xcodebuild", "/usr/bin/find", "/usr/bin/sudo", "/usr/bin/find", "/usr/sbin/spctl", "/usr/bin/xcodebuild"])
            sudo = next(call for call in calls if call[0] == "/usr/bin/sudo")
            self.assertIn(str(selected.application), sudo)
            self.assertIn("-P", sudo)
            self.assertIn("-x", sudo)
            self.assertIn("0:0", sudo)
            self.assertIn("-h", sudo)
            self.assertNotIn("chmod", " ".join(sudo))
            self.assertNotIn("/Applications", sudo)

    def test_unsafe_before_after_and_identity_drift_all_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = self.installation(Path(directory).resolve(), "Xcode.app")
            for kwargs in ({"unsafe_at": 1}, {"unsafe_at": 2}, {"changed": True}):
                with self.subTest(kwargs=kwargs), self.assertRaises(selector.XcodeSelectionError):
                    self.exercise_normalization(selected, **kwargs)

    def test_command_failure_is_not_suppressed(self):
        failed = subprocess.CompletedProcess(["/usr/bin/xcodebuild"], 1, "", "failed")
        with patch.object(subprocess, "run", return_value=failed), self.assertRaisesRegex(selector.XcodeSelectionError, "failed"):
            selector.command(["/usr/bin/xcodebuild", "-version"])


if __name__ == "__main__":
    unittest.main()
