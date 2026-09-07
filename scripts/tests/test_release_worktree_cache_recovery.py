from __future__ import annotations

import contextlib
from dataclasses import replace
import fcntl
import io
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import release_secret_material_blocker as blocker
from scripts.release_python_runtime import ReleasePythonRuntimeError
from scripts.release_secret_material_blocker import SecretMaterialReleaseBlock
from scripts.tests.test_release_secret_material_blocker import (
    REPO_ROOT,
    _create_registered_release_worktree,
    _run_git,
    _worktree_admin_directory,
)


def _shift_devices(
    scope: blocker.ReleaseWorktreeCacheScopeReceipt, offset: int
) -> blocker.ReleaseWorktreeCacheScopeReceipt:
    return replace(
        scope,
        **{
            field: replace(
                getattr(scope, field), device=getattr(scope, field).device + offset
            )
            for field in ("admin", "worktree", "marker", "target")
        },
    )


def _make_receipt_pre_reboot(
    worktree: Path,
) -> blocker.ReleaseWorktreeCacheScopeReceipt:
    receipt = (
        _worktree_admin_directory(worktree) / blocker.RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT
    )
    current = blocker.parse_scope_receipt(receipt.read_bytes())
    receipt.write_bytes(
        blocker.canonical_scope_receipt_bytes(_shift_devices(current, 1_000))
    )
    return current


def _file_snapshot(path: Path) -> tuple[bytes, int, int, int, int, int]:
    metadata = path.stat(follow_symlinks=False)
    return (
        path.read_bytes(),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_mtime_ns,
    )


class ReleaseWorktreeCacheRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.worktree = _create_registered_release_worktree(self.root)
        self.admin = _worktree_admin_directory(self.worktree)
        self.original = self.admin / blocker.RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT
        self.current = _make_receipt_pre_reboot(self.worktree)
        (self.worktree / "target/debug").mkdir()
        self.recovery = self.admin / blocker._scope_recovery_name(self.current)
        self.pending = self.admin / f".{self.recovery.name}.pending"
        self.original_snapshot = _file_snapshot(self.original)

    def recover(self) -> Path:
        return blocker.recover_release_worktree_cache_scope(self.root, "40028")

    def expected_recovery_bytes(self) -> bytes:
        return blocker.canonical_scope_recovery_bytes(
            blocker.ReleaseWorktreeCacheRecoveryReceipt(
                blocker.parse_scope_receipt(self.original.read_bytes()), self.current
            )
        )

    def assert_original_preserved(self) -> None:
        self.assertEqual(_file_snapshot(self.original), self.original_snapshot)

    def test_scan_never_renews_a_stale_receipt_implicitly(self) -> None:
        before = set(self.admin.iterdir())
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "identity is stale"):
            blocker.scan_workspace(self.root)
        self.assertEqual(set(self.admin.iterdir()), before)
        self.assert_original_preserved()

    def test_recovery_preserves_candidates_and_only_restores_managed_cache_scope(self) -> None:
        cache_key = self.worktree / "target/debug/fixture.key"
        candidate_key = self.worktree / "target/candidates/candidate.key"
        source_key = self.worktree / "source.p8"
        for path in (cache_key, candidate_key, source_key):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic fixture, not a credential")
        snapshots = {
            path: _file_snapshot(path)
            for path in (cache_key, candidate_key, source_key)
        }
        real_open = os.open

        def reject_candidate_reads(path, flags, *args, **kwargs):
            if Path(path).suffix in {".key", ".pem", ".p8"}:
                self.fail(f"secret candidate content was opened: {path}")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(blocker.os, "open", side_effect=reject_candidate_reads):
            self.assertEqual(self.recover(), self.recovery)
            self.assertCountEqual(
                [item.name for item in blocker.scan_workspace(self.root)],
                ["candidate.key", "source.p8"],
            )
        self.assertEqual(self.recovery.read_bytes(), self.expected_recovery_bytes())
        self.assertEqual(self.recovery.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.recovery.stat().st_nlink, 1)
        self.assertFalse(self.pending.exists())
        self.assert_original_preserved()
        for path, snapshot in snapshots.items():
            self.assertEqual(_file_snapshot(path), snapshot)

    def test_repeat_recovery_is_idempotent_without_rewriting_any_receipt(self) -> None:
        self.recover()
        snapshot = _file_snapshot(self.recovery)
        names = set(self.admin.iterdir())
        self.assertEqual(self.recover(), self.recovery)
        self.assertEqual(_file_snapshot(self.recovery), snapshot)
        self.assertEqual(set(self.admin.iterdir()), names)
        self.assert_original_preserved()

    def test_already_current_original_is_a_verified_no_op(self) -> None:
        self.original.write_bytes(blocker.canonical_scope_receipt_bytes(self.current))
        snapshot = _file_snapshot(self.original)
        self.assertEqual(self.recover(), self.original)
        self.assertEqual(_file_snapshot(self.original), snapshot)
        self.assertFalse(self.recovery.exists())

    def test_other_stale_builds_do_not_prevent_targeted_recovery(self) -> None:
        second = self.root / "target/release-worktrees/40029"
        _run_git(self.root, "worktree", "add", "--quiet", "--detach", str(second), "HEAD")
        (second / "target").mkdir()
        # Enroll before simulating either reboot; enrollment must not itself renew v1.
        self.original.write_bytes(blocker.canonical_scope_receipt_bytes(self.current))
        blocker.authorize_release_worktree_cache_scope(self.root, "40029")
        _make_receipt_pre_reboot(self.worktree)
        _make_receipt_pre_reboot(second)
        snapshot = _file_snapshot(_worktree_admin_directory(second) / self.original.name)
        self.recover()
        self.assertEqual(
            _file_snapshot(_worktree_admin_directory(second) / self.original.name),
            snapshot,
        )
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "identity is stale"):
            blocker.scan_workspace(self.root)
        blocker.recover_release_worktree_cache_scope(self.root, "40029")
        self.assertEqual(blocker.scan_workspace(self.root), [])

    def test_another_device_record_is_preserved_but_never_used_as_fallback(self) -> None:
        historical = blocker.ReleaseWorktreeCacheRecoveryReceipt(
            blocker.parse_scope_receipt(self.original.read_bytes()),
            _shift_devices(self.current, 2_000),
        )
        history_path = self.admin / blocker._scope_recovery_name(historical.recovered)
        history_path.write_bytes(blocker.canonical_scope_recovery_bytes(historical))
        history_path.chmod(0o600)
        snapshot = _file_snapshot(history_path)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "identity is stale"):
            blocker.scan_workspace(self.root)
        self.recover()
        self.assertEqual(_file_snapshot(history_path), snapshot)
        self.assert_original_preserved()

    def test_each_original_identity_mismatch_rejects_recovery_without_writes(self) -> None:
        original = blocker.parse_scope_receipt(self.original.read_bytes())
        variants = [
            replace(original, **{field: replace(getattr(original, field), inode=1)})
            for field in ("admin", "worktree", "marker", "target")
        ] + [
            replace(original, build="40029"),
            replace(original, worktree_path="/other/40028"),
            replace(original, head="0" * 40),
            replace(original, target=replace(original.target, device=original.target.device + 1)),
        ]
        for changed in variants:
            with self.subTest(changed=changed):
                self.original.write_bytes(blocker.canonical_scope_receipt_bytes(changed))
                snapshot = _file_snapshot(self.original)
                with self.assertRaisesRegex(SecretMaterialReleaseBlock, "recovery rejected"):
                    self.recover()
                self.assertEqual(_file_snapshot(self.original), snapshot)
                self.assertFalse(self.recovery.exists())
                self.assertFalse(self.pending.exists())

    def test_replaced_target_is_not_treated_as_a_reboot(self) -> None:
        target = self.worktree / "target"
        target.rename(self.worktree / "retained-target")
        target.mkdir()
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "cannot change an inode"):
            self.recover()
        self.assertFalse(self.recovery.exists())
        self.assert_original_preserved()

    def test_missing_original_cannot_be_recreated_from_recovery(self) -> None:
        self.recover()
        self.original.rename(self.admin / "retained-original.json")
        snapshot = _file_snapshot(self.recovery)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "original receipt"):
            self.recover()
        self.assertFalse(self.original.exists())
        self.assertEqual(_file_snapshot(self.recovery), snapshot)

    def test_unsafe_original_permissions_are_rejected(self) -> None:
        self.original.chmod(0o644)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "unsafe metadata"):
            self.recover()
        self.assertFalse(self.recovery.exists())

    def test_original_pending_state_is_not_completed_by_device_recovery(self) -> None:
        pending = self.admin / blocker.RELEASE_WORKTREE_CACHE_SCOPE_PENDING
        pending.write_bytes(self.original.read_bytes())
        pending.chmod(0o600)
        snapshot = _file_snapshot(pending)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "original.*incomplete"):
            self.recover()
        self.assertEqual(_file_snapshot(pending), snapshot)
        self.assertFalse(self.recovery.exists())
        self.assert_original_preserved()

    def test_malformed_current_recovery_fails_closed_without_fallback_or_overwrite(self) -> None:
        self.recovery.write_bytes(b" " + self.expected_recovery_bytes())
        self.recovery.chmod(0o600)
        snapshot = _file_snapshot(self.recovery)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "recovery is malformed"):
            blocker.scan_workspace(self.root)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "receipt is stale"):
            self.recover()
        self.assertEqual(_file_snapshot(self.recovery), snapshot)
        self.assert_original_preserved()

    def test_recovery_for_another_original_cannot_be_replayed(self) -> None:
        original = blocker.parse_scope_receipt(self.original.read_bytes())
        replay = blocker.ReleaseWorktreeCacheRecoveryReceipt(
            replace(original, head="1" * 40), replace(self.current, head="1" * 40)
        )
        self.recovery.write_bytes(blocker.canonical_scope_recovery_bytes(replay))
        self.recovery.chmod(0o600)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "recovery identity is stale"):
            blocker.scan_workspace(self.root)

    def test_symlinked_recovery_is_rejected_and_not_followed(self) -> None:
        retained = self.admin / "retained-recovery.json"
        retained.write_bytes(self.expected_recovery_bytes())
        retained.chmod(0o600)
        snapshot = _file_snapshot(retained)
        self.recovery.symlink_to(retained)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "file is unavailable"):
            self.recover()
        self.assertTrue(self.recovery.is_symlink())
        self.assertEqual(_file_snapshot(retained), snapshot)

    def test_partial_pending_is_preserved_and_never_grants_authority(self) -> None:
        self.pending.write_bytes(b'{"original":')
        self.pending.chmod(0o600)
        snapshot = _file_snapshot(self.pending)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "publication is incomplete"):
            blocker.scan_workspace(self.root)
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "pending receipt is stale"):
            self.recover()
        self.assertEqual(_file_snapshot(self.pending), snapshot)
        self.assertFalse(self.recovery.exists())
        self.assert_original_preserved()

    def test_conflicting_pending_and_final_are_not_replaced(self) -> None:
        self.recover()
        self.pending.write_bytes(self.expected_recovery_bytes())
        self.pending.chmod(0o600)
        snapshots = [_file_snapshot(path) for path in (self.pending, self.recovery)]
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "state is contradictory"):
            self.recover()
        self.assertEqual(
            [_file_snapshot(path) for path in (self.pending, self.recovery)], snapshots
        )

    def test_busy_scope_lock_prevents_publication(self) -> None:
        descriptor = os.open(self.admin / blocker.RELEASE_WORKTREE_CACHE_SCOPE_LOCK, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(SecretMaterialReleaseBlock, "already active"):
                self.recover()
            self.assertFalse(self.recovery.exists())
            self.assertFalse(self.pending.exists())
        finally:
            os.close(descriptor)
        self.assert_original_preserved()

    def test_recovery_record_replacement_after_discovery_is_rejected(self) -> None:
        self.recover()
        discovery = blocker._registered_release_worktree_targets

        def discover_then_replace(*args, **kwargs):
            registered = discovery(*args, **kwargs)
            self.recovery.rename(self.admin / "retained-recovery.json")
            self.recovery.write_bytes(self.expected_recovery_bytes())
            self.recovery.chmod(0o600)
            return registered

        with mock.patch.object(
            blocker, "_registered_release_worktree_targets",
            side_effect=discover_then_replace,
        ):
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock, "identity changed during the scan"
            ):
                blocker.scan_workspace(self.root)

    def test_same_inode_receipt_change_after_discovery_is_a_typed_failure(self) -> None:
        self.recover()
        discovery = blocker._registered_release_worktree_targets

        def discover_then_corrupt(*args, **kwargs):
            registered = discovery(*args, **kwargs)
            self.original.write_bytes(b"x" * self.original.stat().st_size)
            return registered

        with mock.patch.object(
            blocker, "_registered_release_worktree_targets",
            side_effect=discover_then_corrupt,
        ):
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock, "identity changed during the scan"
            ):
                blocker.scan_workspace(self.root)

    def test_changed_registration_control_is_rechecked_before_publication(self) -> None:
        publish = blocker._publish_scope_receipt

        def change_gitdir_then_publish(*args, **kwargs):
            (self.admin / "gitdir").write_bytes(b"/different/.git\n")
            return publish(*args, **kwargs)

        with mock.patch.object(
            blocker, "_publish_scope_receipt", side_effect=change_gitdir_then_publish
        ):
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock, "identity changed during the scan"
            ):
                self.recover()
        self.assertFalse(self.recovery.exists())
        self.assert_original_preserved()

    def test_real_process_death_after_link_is_recoverable(self) -> None:
        program = """
import os, signal, sys
sys.path.insert(0, sys.argv[1])
from scripts import release_secret_material_blocker as blocker
link = os.link
def link_then_stop(*args, **kwargs):
    link(*args, **kwargs)
    os.kill(os.getpid(), signal.SIGKILL)
blocker.os.link = link_then_stop
blocker.recover_release_worktree_cache_scope(sys.argv[2], '40028')
"""
        result = subprocess.run(
            [
                sys.executable, "-I", "-S", "-B", "-W", "error", "-c", program,
                str(REPO_ROOT), str(self.root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr.decode())
        self.assertEqual(self.recovery.stat().st_nlink, 2)
        self.assertTrue(os.path.samefile(self.recovery, self.pending))
        with self.assertRaisesRegex(SecretMaterialReleaseBlock, "publication is incomplete"):
            blocker.scan_workspace(self.root)
        self.assertEqual(self.recover(), self.recovery)
        self.assertFalse(self.pending.exists())
        self.assertEqual(blocker.scan_workspace(self.root), [])
        self.assert_original_preserved()

    def test_cli_requires_closed_runtime_before_recovery(self) -> None:
        with mock.patch(
            "scripts.release_python_runtime.require_closed_release_runtime",
            side_effect=ReleasePythonRuntimeError("fixture admission rejected"),
        ), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(
                blocker.main([str(self.root), "--recover-release-worktree", "40028"]),
                1,
            )
        self.assertIn("runtime admission failed", output.getvalue())
        self.assertFalse(self.recovery.exists())
        self.assert_original_preserved()

    def test_cli_recovery_uses_explicit_entrypoint(self) -> None:
        with (
            mock.patch(
                "scripts.release_python_runtime.require_closed_release_runtime"
            ) as admission,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                blocker.main([str(self.root), "--recover-release-worktree", "40028"]),
                0,
            )
        admission.assert_called_once_with()
        self.assertIn(str(self.recovery), output.getvalue())
        self.assert_original_preserved()


class ReleaseWorktreeCacheRecoveryDurabilityTests(unittest.TestCase):
    def test_every_fsync_failure_is_observable_and_retryable_without_history_loss(self) -> None:
        for failure_point in range(1, 5):
            with (
                self.subTest(failure_point=failure_point),
                tempfile.TemporaryDirectory() as parent,
            ):
                root = Path(parent).resolve()
                worktree = _create_registered_release_worktree(root)
                current = _make_receipt_pre_reboot(worktree)
                admin = _worktree_admin_directory(worktree)
                original = admin / blocker.RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT
                snapshot = _file_snapshot(original)
                fsync = os.fsync
                calls = 0

                def fail_fsync(descriptor):
                    nonlocal calls
                    calls += 1
                    if calls == failure_point:
                        raise OSError("injected fsync failure")
                    return fsync(descriptor)

                with mock.patch.object(blocker.os, "fsync", side_effect=fail_fsync):
                    with self.assertRaises(SecretMaterialReleaseBlock):
                        blocker.recover_release_worktree_cache_scope(root, "40028")
                synced_modes: list[int] = []

                def record_fsync(descriptor):
                    synced_modes.append(os.fstat(descriptor).st_mode)
                    return fsync(descriptor)

                with mock.patch.object(blocker.os, "fsync", side_effect=record_fsync):
                    recovered = blocker.recover_release_worktree_cache_scope(root, "40028")
                self.assertEqual(recovered, admin / blocker._scope_recovery_name(current))
                self.assertTrue(any(stat.S_ISREG(mode) for mode in synced_modes))
                self.assertTrue(any(stat.S_ISDIR(mode) for mode in synced_modes))
                self.assertEqual(_file_snapshot(original), snapshot)
                self.assertEqual(blocker.scan_workspace(root), [])


if __name__ == "__main__":
    unittest.main()
