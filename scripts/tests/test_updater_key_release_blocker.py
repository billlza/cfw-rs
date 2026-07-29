from __future__ import annotations

import builtins
import dataclasses
import tempfile
import unittest
from pathlib import Path

from scripts.updater_key_release_blocker import (
    DetectedUpdaterKey,
    SecurityResponse,
    UpdaterKeyReleaseBlock,
    assert_response_complete,
    build_security_response,
    evaluate_workspace,
    exposure_is_plausible,
    format_response,
    scan_workspace,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


class _NoFileReads:
    """Context manager that makes any attempt to open a file fail the test.

    The blocker must detect updater keys by path and name only; opening a
    candidate would be a contract violation.
    """

    def __enter__(self) -> "_NoFileReads":
        self._original_open = builtins.open

        def _forbidden(*args: object, **kwargs: object):
            raise AssertionError(
                f"updater-key blocker attempted to open a file: {args!r}"
            )

        builtins.open = _forbidden  # type: ignore[assignment]
        return self

    def __exit__(self, *exc: object) -> None:
        builtins.open = self._original_open  # type: ignore[assignment]


class ScanByPathAndNameTests(unittest.TestCase):
    def test_detects_key_files_without_opening_them(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            tauri = Path(root) / ".tauri"
            tauri.mkdir()
            (tauri / "cfw-rs.key").write_text("PRIVATE", encoding="utf-8")
            (Path(root) / "cert.pem").write_text("PRIVATE", encoding="utf-8")
            (Path(root) / "notes.txt").write_text("safe", encoding="utf-8")

            with _NoFileReads():
                detected = scan_workspace(root)

            names = sorted(item.name for item in detected)
            self.assertEqual(names, ["cert.pem", "cfw-rs.key"])
            for item in detected:
                self.assertTrue(item.path.endswith(item.name))

    def test_prunes_vendored_and_vcs_directories(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            for pruned in (".git", "target", "node_modules", ".build"):
                sub = Path(root) / pruned
                sub.mkdir()
                (sub / "buried.key").write_text("PRIVATE", encoding="utf-8")

            detected = scan_workspace(root)
            self.assertEqual(detected, [])

    def test_case_insensitive_suffix_match(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "UPPER.KEY").write_text("PRIVATE", encoding="utf-8")
            detected = scan_workspace(root)
            self.assertEqual([item.name for item in detected], ["UPPER.KEY"])


class ReportContentTests(unittest.TestCase):
    def test_response_reports_only_path_and_name(self) -> None:
        detected = DetectedUpdaterKey(path="/ws/.tauri/cfw-rs.key", name="cfw-rs.key")
        response = build_security_response(detected, "/ws")

        field_names = {f.name for f in dataclasses.fields(SecurityResponse)}
        # The only file-identity fields are the path and the name.
        self.assertEqual(
            field_names & {"detected_path", "detected_name"},
            {"detected_path", "detected_name"},
        )
        self.assertNotIn("contents", field_names)
        self.assertNotIn("bytes", field_names)

        rendered = format_response(response)
        self.assertIn("/ws/.tauri/cfw-rs.key", rendered)
        self.assertIn("cfw-rs.key", rendered)
        self.assertIn("contents never read", rendered)


class AtomicResponseTests(unittest.TestCase):
    def test_complete_response_passes_and_blocks(self) -> None:
        detected = DetectedUpdaterKey(path="/ws/backup/x.key", name="x.key")
        response = build_security_response(detected, "/ws")
        # Should not raise.
        assert_response_complete(response)
        self.assertTrue(response.block_release)
        self.assertTrue(response.relocation_required)

    def test_omitting_the_block_step_fails_closed(self) -> None:
        response = SecurityResponse(
            detected_path="/ws/x.key",
            detected_name="x.key",
            block_release=False,
            relocation_required=True,
            relocation_target="external",
            exposure_plausible=True,
            rotation_required=True,
            trust_migration_required=True,
        )
        with self.assertRaises(UpdaterKeyReleaseBlock):
            assert_response_complete(response)

    def test_omitting_the_relocation_step_fails_closed(self) -> None:
        response = SecurityResponse(
            detected_path="/ws/x.key",
            detected_name="x.key",
            block_release=True,
            relocation_required=False,
            relocation_target="",
            exposure_plausible=True,
            rotation_required=True,
            trust_migration_required=True,
        )
        with self.assertRaises(UpdaterKeyReleaseBlock):
            assert_response_complete(response)

    def test_rotation_without_trust_migration_fails_closed(self) -> None:
        response = SecurityResponse(
            detected_path="/ws/x.key",
            detected_name="x.key",
            block_release=True,
            relocation_required=True,
            relocation_target="external",
            exposure_plausible=True,
            rotation_required=True,
            trust_migration_required=False,
        )
        with self.assertRaises(UpdaterKeyReleaseBlock):
            assert_response_complete(response)


class ExposurePlausibilityTests(unittest.TestCase):
    def test_public_counterpart_makes_exposure_plausible(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            key = Path(root) / "cfw-rs.key"
            key.write_text("PRIVATE", encoding="utf-8")
            (Path(root) / "cfw-rs.key.pub").write_text("PUBLIC", encoding="utf-8")

            detected = DetectedUpdaterKey(path=str(key), name="cfw-rs.key")
            self.assertTrue(exposure_is_plausible(detected, root))
            response = build_security_response(detected, root)
            self.assertTrue(response.rotation_required)
            self.assertTrue(response.trust_migration_required)

    def test_backup_path_marker_makes_exposure_plausible(self) -> None:
        detected = DetectedUpdaterKey(
            path="/ws/backups/cfw-rs.key", name="cfw-rs.key"
        )
        self.assertTrue(exposure_is_plausible(detected, "/ws"))

    def test_git_repository_makes_exposure_plausible(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / ".git").mkdir()
            key = Path(root) / "cfw-rs.key"
            key.write_text("PRIVATE", encoding="utf-8")
            detected = DetectedUpdaterKey(path=str(key), name="cfw-rs.key")
            self.assertTrue(exposure_is_plausible(detected, root))

    def test_isolated_key_has_no_plausible_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            key = Path(root) / "cfw-rs.key"
            key.write_text("PRIVATE", encoding="utf-8")
            detected = DetectedUpdaterKey(path=str(key), name="cfw-rs.key")
            self.assertFalse(exposure_is_plausible(detected, root))
            response = build_security_response(detected, root)
            # Rotation is conditional; relocation and blocking are not.
            self.assertFalse(response.rotation_required)
            self.assertFalse(response.trust_migration_required)
            self.assertTrue(response.block_release)
            self.assertTrue(response.relocation_required)
            assert_response_complete(response)


class FailClosedInputTests(unittest.TestCase):
    def test_missing_workspace_root_fails_closed(self) -> None:
        with self.assertRaises(UpdaterKeyReleaseBlock):
            scan_workspace("/nonexistent/workspace/root/for/blocker/test")

    def test_symlinked_workspace_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            real = Path(parent) / "real"
            real.mkdir()
            link = Path(parent) / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(UpdaterKeyReleaseBlock):
                scan_workspace(link)

    def test_file_as_workspace_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            not_a_dir = Path(parent) / "file.txt"
            not_a_dir.write_text("x", encoding="utf-8")
            with self.assertRaises(UpdaterKeyReleaseBlock):
                scan_workspace(not_a_dir)


class RealRepositoryTests(unittest.TestCase):
    def test_real_repo_updater_key_state_is_explicit_without_reading_it(self) -> None:
        tauri_key = REPO_ROOT / ".tauri" / "cfw-rs.key"
        with _NoFileReads():
            responses = evaluate_workspace(REPO_ROOT)

        paths = {response.detected_path for response in responses}
        if not tauri_key.exists():
            self.assertNotIn(str(tauri_key), paths)
            self.assertEqual(responses, [], "any other workspace updater key must block release")
            return

        self.assertIn(str(tauri_key), paths)

        blocker_response = next(
            r for r in responses if r.detected_path == str(tauri_key)
        )
        self.assertTrue(blocker_response.block_release)
        self.assertTrue(blocker_response.relocation_required)
        # The repository is a git tree with a distributed .pub counterpart, so
        # rotation and updater trust migration are both required.
        self.assertTrue(blocker_response.exposure_plausible)
        self.assertTrue(blocker_response.rotation_required)
        self.assertTrue(blocker_response.trust_migration_required)
        # A populated response list means release is blocked.
        self.assertTrue(responses)


if __name__ == "__main__":
    unittest.main()
