from __future__ import annotations

import errno
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts.publication.common import PublicationError
from scripts.publication import durable_file


class DurableFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def private_file(self, name: str, data: bytes) -> Path:
        path = self.root / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            if data:
                os.write(descriptor, data)
        finally:
            os.close(descriptor)
        return path

    def private_directory(self, name: str, files: dict[str, bytes]) -> Path:
        directory = self.root / name
        directory.mkdir(mode=0o700)
        for entry_name, data in files.items():
            descriptor = os.open(
                directory / entry_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                if data:
                    os.write(descriptor, data)
            finally:
                os.close(descriptor)
        return directory

    def test_write_read_discard_and_promote_success(self) -> None:
        discarded = self.root / "discard.pending"
        durable_file.write_private_pending(discarded, b"partial")
        self.assertEqual(
            durable_file.read_private_pending(discarded, 32),
            b"partial",
        )
        durable_file.discard_private_pending(discarded, 32)
        self.assertFalse(discarded.exists())

        pending = self.root / "attempt.pending"
        destination = self.root / "attempt-0001.json"
        durable_file.write_private_pending(pending, b'{"status":"passed"}\n')
        durable_file.promote_private_pending(pending, destination)
        self.assertFalse(pending.exists())
        self.assertEqual(destination.read_bytes(), b'{"status":"passed"}\n')
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_empty_and_partial_pending_files_are_readable(self) -> None:
        empty = self.private_file("empty.pending", b"")
        partial = self.private_file("partial.pending", b'{"incomplete"')
        self.assertEqual(durable_file.read_private_pending(empty, 0), b"")
        self.assertEqual(
            durable_file.read_private_pending(partial, 1024),
            b'{"incomplete"',
        )
        written_empty = self.root / "written-empty.pending"
        durable_file.write_private_pending(written_empty, b"")
        self.assertEqual(durable_file.read_private_pending(written_empty, 0), b"")

    def test_identity_change_between_inspection_and_open_is_rejected(self) -> None:
        pending = self.private_file("changing.pending", b"before")
        directory_descriptor = os.open(
            self.root,
            durable_file._directory_open_flags(),
        )
        self.addCleanup(os.close, directory_descriptor)
        real_fstat = durable_file.os.fstat
        changed = False

        def change_before_fstat(descriptor: int) -> os.stat_result:
            nonlocal changed
            if not changed:
                changed = True
                pending.write_bytes(b"after-change")
            return real_fstat(descriptor)

        with patch.object(
            durable_file,
            "_open_owned_directory",
            side_effect=lambda _path: os.dup(directory_descriptor),
        ), patch.object(
            durable_file.os,
            "fstat",
            side_effect=change_before_fstat,
        ):
            with self.assertRaisesRegex(PublicationError, "changed while opening"):
                durable_file.read_private_pending(pending, 32)

    def test_symlink_is_rejected(self) -> None:
        target = self.private_file("target.pending", b"data")
        link = self.root / "link.pending"
        link.symlink_to(target)
        with self.assertRaisesRegex(PublicationError, "regular file|open"):
            durable_file.read_private_pending(link, 32)

    def test_hard_link_is_rejected(self) -> None:
        target = self.private_file("target.pending", b"data")
        link = self.root / "linked.pending"
        os.link(target, link)
        with self.assertRaisesRegex(PublicationError, "single-link"):
            durable_file.read_private_pending(target, 32)

    def test_non_private_mode_is_rejected(self) -> None:
        pending = self.private_file("mode.pending", b"data")
        pending.chmod(0o640)
        with self.assertRaisesRegex(PublicationError, "mode is not 0600"):
            durable_file.read_private_pending(pending, 32)

    def test_foreign_directory_owner_is_rejected(self) -> None:
        pending = self.private_file("owner.pending", b"data")
        with patch.object(durable_file.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(PublicationError, "not owned"):
                durable_file.read_private_pending(pending, 32)

    def test_foreign_pending_owner_is_rejected(self) -> None:
        pending = self.private_file("owner.pending", b"data")
        directory_descriptor = os.open(
            self.root,
            durable_file._directory_open_flags(),
        )
        self.addCleanup(os.close, directory_descriptor)
        with patch.object(
            durable_file,
            "_open_owned_directory",
            side_effect=lambda _path: os.dup(directory_descriptor),
        ), patch.object(
            durable_file.os,
            "geteuid",
            return_value=os.geteuid() + 1,
        ):
            with self.assertRaisesRegex(PublicationError, "pending file is not owned"):
                durable_file.read_private_pending(pending, 32)

    def test_write_failure_safely_removes_owned_partial(self) -> None:
        pending = self.root / "write-failure.pending"
        real_write = durable_file.os.write
        calls = 0

        def fail_after_partial(descriptor: int, data: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(descriptor, data[:1])
            raise OSError(errno.EIO, "injected write failure")

        with patch.object(durable_file.os, "write", side_effect=fail_after_partial):
            with self.assertRaisesRegex(PublicationError, "cannot write"):
                durable_file.write_private_pending(pending, b"payload")
        self.assertFalse(pending.exists())

    def test_existing_destination_is_never_replaced(self) -> None:
        pending = self.private_file("attempt.pending", b"new")
        destination = self.private_file("attempt.json", b"existing")
        with self.assertRaisesRegex(PublicationError, "already exists"):
            durable_file.promote_private_pending(pending, destination)
        self.assertEqual(pending.read_bytes(), b"new")
        self.assertEqual(destination.read_bytes(), b"existing")

    def test_promotion_uses_exclusive_no_follow_rename_flags(self) -> None:
        pending = self.private_file("attempt.pending", b"data")
        destination = self.root / "attempt.json"
        observed: list[tuple[int, int, int]] = []
        real_rename = durable_file._renameatx_np

        def capture(
            source_directory_descriptor: int,
            source_name: str,
            destination_directory_descriptor: int,
            destination_name: str,
            flags: int,
        ) -> None:
            self.assertEqual(source_name, pending.name)
            self.assertEqual(destination_name, destination.name)
            observed.append(
                (
                    source_directory_descriptor,
                    destination_directory_descriptor,
                    flags,
                )
            )
            real_rename(
                source_directory_descriptor,
                source_name,
                destination_directory_descriptor,
                destination_name,
                flags,
            )

        with patch.object(durable_file, "_renameatx_np", side_effect=capture):
            durable_file.promote_private_pending(pending, destination)
        self.assertEqual(len(observed), 1)
        source_descriptor, destination_descriptor, flags = observed[0]
        self.assertEqual(source_descriptor, destination_descriptor)
        self.assertEqual(
            flags,
            durable_file.RENAME_EXCL | durable_file.RENAME_NOFOLLOW_ANY,
        )

    def test_private_directory_verification_and_promotion_are_exact(self) -> None:
        expected = {"one.json": b'{"passed":true}\n'}
        pending = self.private_directory("sealed.pending", expected)
        destination = self.root / "sealed"

        durable_file.verify_private_directory_contents(pending, expected)
        durable_file.promote_private_directory(pending, destination)

        self.assertFalse(pending.exists())
        self.assertEqual((destination / "one.json").read_bytes(), expected["one.json"])
        durable_file.verify_private_directory_contents(destination, expected)

        (destination / "extra.json").write_bytes(b"{}\n")
        with self.assertRaisesRegex(PublicationError, "entries differ"):
            durable_file.verify_private_directory_contents(destination, expected)

    def test_private_directory_promotion_never_replaces_destination(self) -> None:
        destination = self.private_directory("sealed", {"old.json": b"old"})
        pending = self.private_directory("sealed.pending", {"new.json": b"new"})

        with self.assertRaisesRegex(PublicationError, "already exists"):
            durable_file.promote_private_directory(pending, destination)

        self.assertEqual((destination / "old.json").read_bytes(), b"old")
        self.assertEqual((pending / "new.json").read_bytes(), b"new")

    def test_private_directory_destination_race_never_replaces_winner(self) -> None:
        pending = self.private_directory("sealed.pending", {"new.json": b"new"})
        destination = self.root / "sealed"
        real_rename = durable_file._renameatx_np

        def create_winner_then_rename(
            source_directory_descriptor: int,
            source_name: str,
            destination_directory_descriptor: int,
            destination_name: str,
            flags: int,
        ) -> None:
            winner = self.private_directory("sealed", {"winner.json": b"winner"})
            self.assertEqual(winner, destination)
            real_rename(
                source_directory_descriptor,
                source_name,
                destination_directory_descriptor,
                destination_name,
                flags,
            )

        with patch.object(
            durable_file,
            "_renameatx_np",
            side_effect=create_winner_then_rename,
        ):
            with self.assertRaisesRegex(PublicationError, "already exists"):
                durable_file.promote_private_directory(pending, destination)

        self.assertEqual((destination / "winner.json").read_bytes(), b"winner")
        self.assertEqual((pending / "new.json").read_bytes(), b"new")

    def test_private_directory_promotion_uses_exclusive_no_follow_flags(self) -> None:
        pending = self.private_directory("sealed.pending", {"one.json": b"one"})
        destination = self.root / "sealed"
        real_rename = durable_file._renameatx_np
        observed: list[int] = []

        def capture(
            source_directory_descriptor: int,
            source_name: str,
            destination_directory_descriptor: int,
            destination_name: str,
            flags: int,
        ) -> None:
            self.assertEqual(source_name, pending.name)
            self.assertEqual(destination_name, destination.name)
            self.assertEqual(source_directory_descriptor, destination_directory_descriptor)
            observed.append(flags)
            real_rename(
                source_directory_descriptor,
                source_name,
                destination_directory_descriptor,
                destination_name,
                flags,
            )

        with patch.object(durable_file, "_renameatx_np", side_effect=capture):
            durable_file.promote_private_directory(pending, destination)

        self.assertEqual(
            observed,
            [durable_file.RENAME_EXCL | durable_file.RENAME_NOFOLLOW_ANY],
        )

    def test_private_directory_parent_fsync_failure_is_typed_unknown_outcome(self) -> None:
        pending = self.private_directory("sealed.pending", {"one.json": b"one"})
        destination = self.root / "sealed"
        parent_identity = (self.root.stat().st_dev, self.root.stat().st_ino)
        real_full_fsync = durable_file.full_fsync

        def fail_parent_after_rename(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if (
                stat.S_ISDIR(metadata.st_mode)
                and (metadata.st_dev, metadata.st_ino) == parent_identity
                and destination.exists()
            ):
                raise OSError(errno.EIO, "injected parent full-fsync failure")
            real_full_fsync(descriptor)

        with patch.object(
            durable_file,
            "full_fsync",
            side_effect=fail_parent_after_rename,
        ):
            with self.assertRaises(durable_file.DurabilityOutcomeUnknown):
                durable_file.promote_private_directory(pending, destination)

        self.assertFalse(pending.exists())
        self.assertEqual((destination / "one.json").read_bytes(), b"one")

    def test_private_directory_mode_change_during_parent_barrier_is_unknown(self) -> None:
        pending = self.private_directory("sealed.pending", {"one.json": b"one"})
        destination = self.root / "sealed"
        real_parent_barrier = durable_file.fsync_locked_directory

        def weaken_before_parent_barrier(descriptor: int, parent: Path) -> None:
            destination.chmod(0o777)
            real_parent_barrier(descriptor, parent)

        with patch.object(
            durable_file,
            "fsync_locked_directory",
            side_effect=weaken_before_parent_barrier,
        ):
            with self.assertRaises(durable_file.DurabilityOutcomeUnknown):
                durable_file.promote_private_directory(pending, destination)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o777)

    def test_private_directory_parent_replacement_is_typed_unknown_outcome(self) -> None:
        parent = self.root / "parent"
        parent.mkdir(mode=0o700)
        pending = parent / "sealed.pending"
        pending.mkdir(mode=0o700)
        descriptor = os.open(
            pending / "one.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        os.write(descriptor, b"one")
        os.close(descriptor)
        destination = parent / "sealed"
        displaced = self.root / "displaced"
        real_rename = durable_file._renameatx_np

        def replace_parent_then_rename(*arguments: object) -> None:
            parent.rename(displaced)
            parent.mkdir(mode=0o700)
            real_rename(*arguments)

        with patch.object(
            durable_file,
            "_renameatx_np",
            side_effect=replace_parent_then_rename,
        ):
            with self.assertRaises(durable_file.DurabilityOutcomeUnknown):
                durable_file.promote_private_directory(pending, destination)

        self.assertFalse(destination.exists())
        self.assertEqual((displaced / "sealed/one.json").read_bytes(), b"one")

    def test_rooted_lock_rejects_an_intermediate_symlink(self) -> None:
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (outside / "release").mkdir(mode=0o700)
        trusted = self.root / "trusted"
        trusted.mkdir(mode=0o700)
        (trusted / "target").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(PublicationError, "rooted publication directory"):
            with durable_file.exclusive_rooted_directory_lock(
                trusted,
                trusted / "target/release",
            ):
                self.fail("rooted lock followed an intermediate symlink")

    def test_rooted_lock_rejects_a_rebound_intermediate_directory(self) -> None:
        trusted = self.root / "trusted"
        ancestor = trusted / "ancestor"
        target = ancestor / "target"
        target.mkdir(parents=True, mode=0o700)
        displaced = trusted / "ancestor-displaced"
        before = len(os.listdir("/dev/fd"))

        with self.assertRaises(durable_file.RootedDirectoryChanged):
            with durable_file.exclusive_rooted_directory_lock(
                trusted,
                target,
            ):
                ancestor.rename(displaced)
                ancestor.mkdir(mode=0o700)
                (displaced / target.name).rename(ancestor / target.name)

        self.assertTrue(target.is_dir())
        self.assertEqual(len(os.listdir("/dev/fd")), before)

    def test_private_rooted_lock_failure_closes_all_descriptors(self) -> None:
        child = self.root / "non-private"
        child.mkdir(mode=0o755)
        before = len(os.listdir("/dev/fd"))
        for _attempt in range(32):
            with self.assertRaisesRegex(PublicationError, "mode is not 0700"):
                with durable_file.exclusive_rooted_directory_lock(
                    self.root,
                    child,
                    require_private=True,
                ):
                    self.fail("non-private rooted directory was accepted")
        self.assertEqual(len(os.listdir("/dev/fd")), before)

    def test_private_directory_detects_file_rewrite_before_directory_barrier(self) -> None:
        directory = self.private_directory("sealed", {"one.json": b"good\n"})
        real_directory_barrier = durable_file._full_fsync_directory_descriptor
        mutated = False

        def mutate_before_barrier(descriptor: int, path: Path) -> None:
            nonlocal mutated
            if path == directory and not mutated:
                mutated = True
                (directory / "one.json").write_bytes(b"evil\n")
            real_directory_barrier(descriptor, path)

        with patch.object(
            durable_file,
            "_full_fsync_directory_descriptor",
            side_effect=mutate_before_barrier,
        ):
            with self.assertRaisesRegex(PublicationError, "file changed"):
                durable_file.verify_private_directory_contents(
                    directory,
                    {"one.json": b"good\n"},
                )

    def test_locked_private_file_detects_rewrite_before_parent_barrier(self) -> None:
        path = self.private_file("candidate.json", b"good\n")
        real_parent_barrier = durable_file.fsync_locked_directory
        mutated = False

        def mutate_before_parent_barrier(descriptor: int, directory: Path) -> None:
            nonlocal mutated
            if not mutated:
                mutated = True
                path.write_bytes(b"evil\n")
            real_parent_barrier(descriptor, directory)

        with durable_file.exclusive_directory_lock(self.root) as descriptor, patch.object(
            durable_file,
            "fsync_locked_directory",
            side_effect=mutate_before_parent_barrier,
        ):
            with self.assertRaisesRegex(PublicationError, "after parent fsync"):
                durable_file.read_private_pending_locked(
                    descriptor,
                    self.root,
                    path.name,
                    len(b"good\n"),
                )

    def test_locked_private_write_detects_rewrite_before_parent_barrier(self) -> None:
        path = self.root / "candidate.json"
        real_parent_barrier = durable_file.fsync_locked_directory
        mutated = False

        def mutate_before_parent_barrier(descriptor: int, directory: Path) -> None:
            nonlocal mutated
            if path.exists() and not mutated:
                mutated = True
                path.write_bytes(b"evil\n")
            real_parent_barrier(descriptor, directory)

        with durable_file.exclusive_directory_lock(self.root) as descriptor, patch.object(
            durable_file,
            "fsync_locked_directory",
            side_effect=mutate_before_parent_barrier,
        ):
            with self.assertRaisesRegex(PublicationError, "after directory fsync"):
                durable_file.write_private_pending_locked(
                    descriptor,
                    self.root,
                    path.name,
                    b"good\n",
                )

    def test_ensure_private_directory_rechecks_mode_after_parent_barrier(self) -> None:
        child = self.root / "child"
        real_parent_barrier = durable_file.fsync_locked_directory

        def weaken_before_parent_barrier(descriptor: int, directory: Path) -> None:
            child.chmod(0o755)
            real_parent_barrier(descriptor, directory)

        with durable_file.exclusive_directory_lock(self.root) as descriptor, patch.object(
            durable_file,
            "fsync_locked_directory",
            side_effect=weaken_before_parent_barrier,
        ):
            with self.assertRaisesRegex(PublicationError, "mode is not 0700"):
                durable_file.ensure_private_directory_locked(
                    descriptor,
                    self.root,
                    child.name,
                )

    def test_locked_directory_publish_rechecks_files_after_parent_barrier(self) -> None:
        destination = self.root / "sealed"
        real_parent_barrier = durable_file.fsync_locked_directory
        destination_barriers = 0

        def mutate_during_final_parent_barrier(
            descriptor: int,
            directory: Path,
        ) -> None:
            nonlocal destination_barriers
            if destination.exists():
                destination_barriers += 1
                if destination_barriers == 2:
                    (destination / "one.json").write_bytes(b"evil")
            real_parent_barrier(descriptor, directory)

        with durable_file.exclusive_directory_lock(self.root) as descriptor, patch.object(
            durable_file,
            "fsync_locked_directory",
            side_effect=mutate_during_final_parent_barrier,
        ):
            with self.assertRaisesRegex(PublicationError, "file changed after parent fsync"):
                durable_file.publish_private_directory_locked(
                    descriptor,
                    self.root,
                    destination.name,
                    {"one.json": b"good"},
                )

    def test_private_directory_fullsyncs_files_before_directory(self) -> None:
        directory = self.private_directory("sealed", {"one.json": b"one"})
        real_full_fsync = durable_file.full_fsync
        synchronized: list[str] = []

        def observe(descriptor: int) -> None:
            synchronized.append(
                "directory"
                if stat.S_ISDIR(os.fstat(descriptor).st_mode)
                else "file"
            )
            real_full_fsync(descriptor)

        with patch.object(durable_file, "full_fsync", side_effect=observe):
            durable_file.verify_private_directory_contents(
                directory,
                {"one.json": b"one"},
            )
        self.assertEqual(synchronized, ["file", "directory", "directory"])

    def test_private_directory_promotion_fullsyncs_files_before_namespaces(self) -> None:
        pending = self.private_directory("sealed.pending", {"one.json": b"one"})
        destination = self.root / "sealed"
        real_full_fsync = durable_file.full_fsync
        synchronized: list[str] = []

        def observe(descriptor: int) -> None:
            synchronized.append(
                "directory"
                if stat.S_ISDIR(os.fstat(descriptor).st_mode)
                else "file"
            )
            real_full_fsync(descriptor)

        with patch.object(durable_file, "full_fsync", side_effect=observe):
            durable_file.promote_private_directory(pending, destination)

        self.assertEqual(synchronized, ["file", "directory", "directory"])
        self.assertEqual((destination / "one.json").read_bytes(), b"one")

    def test_promotion_fullfsyncs_file_before_parent_directory(self) -> None:
        pending = self.private_file("attempt.pending", b"data")
        destination = self.root / "attempt.json"
        real_full_fsync = durable_file.full_fsync
        synchronized: list[str] = []

        def observe(descriptor: int) -> None:
            kind = (
                "directory"
                if stat.S_ISDIR(os.fstat(descriptor).st_mode)
                else "file"
            )
            synchronized.append(kind)
            real_full_fsync(descriptor)

        with patch.object(durable_file, "full_fsync", side_effect=observe):
            durable_file.promote_private_pending(pending, destination)
        self.assertEqual(synchronized, ["file", "file", "directory"])

    def test_private_pending_promotion_detects_rewrite_during_rename(self) -> None:
        pending = self.private_file("attempt.pending", b"good\n")
        destination = self.root / "attempt.json"
        real_rename = durable_file._renameatx_np

        def mutate_then_rename(*arguments: object) -> None:
            pending.write_bytes(b"evil\n")
            real_rename(*arguments)

        with patch.object(
            durable_file,
            "_renameatx_np",
            side_effect=mutate_then_rename,
        ):
            with self.assertRaises(durable_file.DurabilityOutcomeUnknown):
                durable_file.promote_private_pending(pending, destination)
        self.assertEqual(destination.read_bytes(), b"evil\n")

    def test_write_fullfsyncs_file_before_directory(self) -> None:
        pending = self.root / "attempt.pending"
        real_full_fsync = durable_file.full_fsync
        synchronized: list[str] = []

        def observe(descriptor: int) -> None:
            kind = (
                "directory"
                if stat.S_ISDIR(os.fstat(descriptor).st_mode)
                else "file"
            )
            synchronized.append(kind)
            real_full_fsync(descriptor)

        with patch.object(durable_file, "full_fsync", side_effect=observe):
            durable_file.write_private_pending(pending, b"data")
        self.assertEqual(synchronized, ["file", "directory"])

    def test_lock_contention_fails_without_waiting(self) -> None:
        with durable_file.exclusive_directory_lock(self.root) as descriptor:
            self.assertTrue(os.path.isdir(f"/dev/fd/{descriptor}"))
            with self.assertRaisesRegex(PublicationError, "already held"):
                with durable_file.exclusive_directory_lock(self.root):
                    self.fail("contended non-blocking directory lock was acquired")

    def test_locked_directory_fsync_rejects_path_replacement(self) -> None:
        journal = self.root / "journal"
        journal.mkdir(mode=0o700)
        displaced = self.root / "displaced"
        with durable_file.exclusive_directory_lock(journal) as descriptor:
            durable_file.fsync_locked_directory(descriptor, journal)
            journal.rename(displaced)
            journal.mkdir(mode=0o700)
            with self.assertRaisesRegex(PublicationError, "path changed"):
                durable_file.fsync_locked_directory(descriptor, journal)

    def test_locked_directory_rejects_path_replacement_after_full_barrier(self) -> None:
        journal = self.root / "journal"
        journal.mkdir(mode=0o700)
        displaced = self.root / "displaced"
        real_full_fsync = durable_file.full_fsync
        replaced = False

        def replace_after_barrier(descriptor: int) -> None:
            nonlocal replaced
            real_full_fsync(descriptor)
            if not replaced:
                replaced = True
                journal.rename(displaced)
                journal.mkdir(mode=0o700)

        with durable_file.exclusive_directory_lock(journal) as descriptor, patch.object(
            durable_file,
            "full_fsync",
            side_effect=replace_after_barrier,
        ):
            with self.assertRaisesRegex(PublicationError, "changed after fsync"):
                durable_file.fsync_locked_directory(descriptor, journal)

    def test_unexpected_lock_error_is_not_reported_as_contention(self) -> None:
        with patch.object(
            durable_file.fcntl,
            "flock",
            side_effect=OSError(errno.EIO, "injected lock failure"),
        ):
            with self.assertRaisesRegex(PublicationError, "cannot lock"):
                with durable_file.exclusive_directory_lock(self.root):
                    self.fail("lock unexpectedly succeeded")

    def test_promotion_fsync_failure_reports_unknown_outcome(self) -> None:
        pending = self.private_file("attempt.pending", b"data")
        destination = self.root / "attempt.json"
        real_full_fsync = durable_file.full_fsync

        def fail_directory_fsync(descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "injected directory fsync failure")
            real_full_fsync(descriptor)

        with patch.object(
            durable_file,
            "full_fsync",
            side_effect=fail_directory_fsync,
        ):
            with self.assertRaisesRegex(PublicationError, "outcome is unknown"):
                durable_file.promote_private_pending(pending, destination)
        self.assertFalse(pending.exists())
        self.assertEqual(destination.read_bytes(), b"data")

    def test_pending_fsync_failure_does_not_attempt_promotion(self) -> None:
        pending = self.private_file("attempt.pending", b"data")
        destination = self.root / "attempt.json"
        real_full_fsync = durable_file.full_fsync

        def fail_file_fsync(descriptor: int) -> None:
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "injected pending fsync failure")
            real_full_fsync(descriptor)

        with patch.object(
            durable_file,
            "full_fsync",
            side_effect=fail_file_fsync,
        ), patch.object(durable_file, "_renameatx_np") as rename:
            with self.assertRaisesRegex(PublicationError, "before promotion"):
                durable_file.promote_private_pending(pending, destination)
        rename.assert_not_called()
        self.assertEqual(pending.read_bytes(), b"data")
        self.assertFalse(destination.exists())

    def test_write_file_fullfsync_failure_cleans_partial_without_success(self) -> None:
        pending = self.root / "attempt.pending"
        real_full_fsync = durable_file.full_fsync

        def fail_file_fsync(descriptor: int) -> None:
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "injected pending fullfsync failure")
            real_full_fsync(descriptor)

        with patch.object(
            durable_file,
            "full_fsync",
            side_effect=fail_file_fsync,
        ):
            with self.assertRaisesRegex(PublicationError, "durability is unknown"):
                durable_file.write_private_pending(pending, b"data")
        self.assertFalse(pending.exists())

    def test_write_directory_fullfsync_failure_preserves_recovery_bytes(self) -> None:
        pending = self.root / "attempt.pending"
        real_full_fsync = durable_file.full_fsync

        def fail_directory_fsync(descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "injected directory full-fsync failure")
            real_full_fsync(descriptor)

        with patch.object(
            durable_file,
            "full_fsync",
            side_effect=fail_directory_fsync,
        ):
            with self.assertRaisesRegex(PublicationError, "outcome is unknown"):
                durable_file.write_private_pending(pending, b"recovery")
        self.assertEqual(pending.read_bytes(), b"recovery")

    def test_discard_directory_fullfsync_failure_reports_unknown_outcome(self) -> None:
        pending = self.private_file("attempt.pending", b"recovery")
        real_full_fsync = durable_file.full_fsync

        def fail_directory_fsync(descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "injected directory full-fsync failure")
            real_full_fsync(descriptor)

        with patch.object(
            durable_file,
            "full_fsync",
            side_effect=fail_directory_fsync,
        ):
            with self.assertRaisesRegex(PublicationError, "outcome is unknown"):
                durable_file.discard_private_pending(pending, 32)
        self.assertFalse(pending.exists())

    def test_fullfsync_error_is_reported_as_unknown_durability(self) -> None:
        with patch.object(
            durable_file,
            "full_fsync",
            side_effect=OSError(errno.EIO, "injected full-fsync failure"),
        ):
            with self.assertRaisesRegex(PublicationError, "durability is unknown"):
                durable_file.fsync_directory(self.root)

    def test_fsync_directory_rejects_a_symlink(self) -> None:
        real = self.root / "real"
        real.mkdir()
        link = self.root / "directory-link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(PublicationError, "not a real directory|symlink"):
            durable_file.fsync_directory(link)


if __name__ == "__main__":
    unittest.main()
