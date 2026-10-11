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
from scripts.tests.metadata_change_fixture import change_only_ctime


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

    def test_private_tree_publication_tolerates_metadata_only_bundle_writes(
        self,
    ) -> None:
        # macOS rewrites com.apple.macl and provenance attributes on a bundle
        # without touching any byte; only the status-change time moves.
        source = self.root / "work.pending"
        executable = source / "Clash for Mac.app/Contents/MacOS/clash-for-mac"
        executable.parent.mkdir(parents=True, mode=0o700)
        source.chmod(0o700)
        executable.write_bytes(b"signed")
        executable.chmod(0o700)
        destination = self.root / "work"
        real_sync = durable_file._sync_regular_file
        changed: list[Path] = []

        def change_metadata_then_sync(path: Path, expected: os.stat_result) -> None:
            tree = source if source.exists() else destination
            for entry in (tree / "Clash for Mac.app", path):
                change_only_ctime(entry)
                changed.append(entry)
            real_sync(path, expected)

        with patch.object(
            durable_file,
            "_sync_regular_file",
            side_effect=change_metadata_then_sync,
        ):
            durable_file.publish_private_directory_exclusive(source, destination)
            durable_file.confirm_private_directory_published(source, destination)

        self.assertEqual(
            changed,
            [
                source / "Clash for Mac.app",
                executable,
                destination / "Clash for Mac.app",
                destination / "Clash for Mac.app/Contents/MacOS/clash-for-mac",
            ],
        )
        self.assertEqual(
            (destination / "Clash for Mac.app/Contents/MacOS/clash-for-mac").read_bytes(),
            b"signed",
        )

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

    def _publication_directories(self) -> tuple[Path, Path]:
        staging = self.root / "staging"
        destination = staging / "collection"
        destination.mkdir(parents=True, mode=0o700)
        staging.chmod(0o700)
        return staging, destination

    @staticmethod
    def _staged_names(directory: Path) -> list[str]:
        return sorted(
            name
            for name in os.listdir(directory)
            if name.startswith(durable_file.FILE_STAGING_PREFIX)
        )

    def _publish(
        self,
        staging: Path,
        destination: Path,
        name: str,
        data: bytes,
    ) -> None:
        with durable_file.exclusive_rooted_directory_lock_with_parent(
            self.root, destination, require_private=True
        ) as (staging_descriptor, destination_descriptor):
            if staging == destination:
                staging_descriptor = destination_descriptor
            durable_file.publish_private_file_locked(
                staging_descriptor=staging_descriptor,
                staging_directory=staging,
                destination_descriptor=destination_descriptor,
                destination_directory=destination,
                name=name,
                data=data,
            )

    def test_published_file_appears_complete_through_one_exclusive_rename(self) -> None:
        staging, destination = self._publication_directories()
        real_rename = durable_file._renameatx_np
        renames: list[tuple[str, str, int]] = []

        def capture(
            source_descriptor: int,
            source_name: str,
            destination_descriptor: int,
            destination_name: str,
            flags: int,
        ) -> None:
            self.assertEqual(
                os.fstat(source_descriptor).st_ino, staging.stat().st_ino
            )
            self.assertEqual(
                os.fstat(destination_descriptor).st_ino, destination.stat().st_ino
            )
            self.assertEqual(
                (staging / source_name).read_bytes(), b'{"sequence":0}\n'
            )
            self.assertFalse((destination / destination_name).exists())
            renames.append((source_name, destination_name, flags))
            real_rename(
                source_descriptor,
                source_name,
                destination_descriptor,
                destination_name,
                flags,
            )

        with patch.object(durable_file, "_renameatx_np", side_effect=capture):
            self._publish(staging, destination, "event-000.json", b'{"sequence":0}\n')
        self.assertEqual(len(renames), 1)
        source_name, destination_name, flags = renames[0]
        self.assertTrue(source_name.startswith(durable_file.FILE_STAGING_PREFIX))
        self.assertEqual(destination_name, "event-000.json")
        self.assertEqual(
            flags, durable_file.RENAME_EXCL | durable_file.RENAME_NOFOLLOW_ANY
        )
        published = destination / "event-000.json"
        self.assertEqual(published.read_bytes(), b'{"sequence":0}\n')
        self.assertEqual(published.stat().st_mode & 0o777, 0o600)
        self.assertEqual(os.listdir(destination), ["event-000.json"])
        self.assertEqual(self._staged_names(staging), [])

    def test_publication_syncs_the_file_before_both_directories(self) -> None:
        staging, destination = self._publication_directories()
        real_full_fsync = durable_file.full_fsync
        synchronized: list[tuple[str, int]] = []

        def observe(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "file"
            synchronized.append((kind, metadata.st_ino))
            real_full_fsync(descriptor)

        real_rename = durable_file._renameatx_np

        def rename(*arguments: object) -> None:
            real_rename(*arguments)
            synchronized.append(("rename", 0))

        with patch.object(durable_file, "full_fsync", side_effect=observe), patch.object(
            durable_file, "_renameatx_np", side_effect=rename
        ):
            self._publish(staging, destination, "event-000.json", b"data")
        # Exactly the barriers that matter: the bytes before the rename, then
        # the destination entry and the staging directory's removal.
        file_inode = (destination / "event-000.json").stat().st_ino
        self.assertEqual(
            synchronized,
            [
                ("file", file_inode),
                ("rename", 0),
                ("directory", destination.stat().st_ino),
                ("directory", staging.stat().st_ino),
            ],
        )

        synchronized.clear()
        with patch.object(durable_file, "full_fsync", side_effect=observe), patch.object(
            durable_file, "_renameatx_np", side_effect=rename
        ):
            self._publish(staging, staging, "runtime-acceptance.json", b"adapter")
        adapter_inode = (staging / "runtime-acceptance.json").stat().st_ino
        self.assertEqual(
            synchronized,
            [("file", adapter_inode), ("rename", 0), ("directory", staging.stat().st_ino)],
        )
        self.assertEqual(self._staged_names(staging), [])

    def test_publication_never_replaces_an_existing_destination(self) -> None:
        staging, destination = self._publication_directories()
        existing = destination / "event-000.json"
        existing.write_bytes(b"existing")
        existing.chmod(0o600)
        with patch.object(
            durable_file, "_write_private_pending_at"
        ) as staged_write, self.assertRaisesRegex(
            PublicationError, "private destination already exists"
        ):
            self._publish(staging, destination, "event-000.json", b"new")
        staged_write.assert_not_called()
        self.assertEqual(existing.read_bytes(), b"existing")
        self.assertEqual(self._staged_names(staging), [])

    def test_publication_rename_keeps_a_destination_that_appears_first(self) -> None:
        staging, destination = self._publication_directories()
        existing = destination / "event-000.json"
        real_rename = durable_file._renameatx_np

        def competing_writer_wins(*arguments: object) -> None:
            existing.write_bytes(b"winner")
            existing.chmod(0o600)
            real_rename(*arguments)

        with patch.object(
            durable_file, "_renameatx_np", side_effect=competing_writer_wins
        ), self.assertRaisesRegex(PublicationError, "private destination already exists"):
            self._publish(staging, destination, "event-000.json", b"loser")
        self.assertEqual(existing.read_bytes(), b"winner")
        self.assertEqual(self._staged_names(staging), [])

    def test_interrupted_publication_never_exposes_a_partial_destination(self) -> None:
        staging, destination = self._publication_directories()
        published = destination / "event-000.json"
        real_write = durable_file.os.write
        present: list[bool] = []

        class Interrupted(BaseException):
            pass

        def interrupt_after_half(descriptor: int, data: object) -> int:
            payload = bytes(data)
            present.append(os.path.lexists(published))
            real_write(descriptor, payload[: len(payload) // 2])
            present.append(os.path.lexists(published))
            raise Interrupted

        with patch.object(
            durable_file.os, "write", side_effect=interrupt_after_half
        ), self.assertRaises(Interrupted):
            self._publish(staging, destination, published.name, b'{"complete":true}\n')
        self.assertEqual(present, [False, False])
        self.assertFalse(os.path.lexists(published))
        self.assertEqual(self._staged_names(staging), [])

    def test_publication_barrier_failure_after_rename_is_unknown_outcome(self) -> None:
        staging, destination = self._publication_directories()
        real_rename = durable_file._renameatx_np
        real_full_fsync = durable_file.full_fsync
        renamed = False

        def rename(*arguments: object) -> None:
            nonlocal renamed
            real_rename(*arguments)
            renamed = True

        def fail_directory_after_rename(descriptor: int) -> None:
            if renamed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "injected directory full-fsync failure")
            real_full_fsync(descriptor)

        with patch.object(durable_file, "_renameatx_np", side_effect=rename), patch.object(
            durable_file, "full_fsync", side_effect=fail_directory_after_rename
        ), self.assertRaises(durable_file.DurabilityOutcomeUnknown):
            self._publish(staging, destination, "event-000.json", b"data")
        self.assertEqual((destination / "event-000.json").read_bytes(), b"data")
        self.assertEqual(self._staged_names(staging), [])

    def test_failed_staging_cleanup_keeps_the_file_and_the_original_cause(self) -> None:
        staging, destination = self._publication_directories()
        existing = destination / "event-000.json"
        real_rename = durable_file._renameatx_np

        def competing_writer_wins(*arguments: object) -> None:
            existing.write_bytes(b"winner")
            existing.chmod(0o600)
            real_rename(*arguments)

        with patch.object(
            durable_file, "_renameatx_np", side_effect=competing_writer_wins
        ), patch.object(
            durable_file,
            "_remove_created_pending",
            side_effect=PublicationError("injected staging cleanup failure"),
        ), self.assertRaisesRegex(
            PublicationError, "injected staging cleanup failure"
        ) as raised:
            self._publish(staging, destination, "event-000.json", b"loser")
        self.assertRegex(str(raised.exception.__cause__), "private destination already exists")
        staged = self._staged_names(staging)
        self.assertEqual(len(staged), 1)
        self.assertEqual((staging / staged[0]).read_bytes(), b"loser")
        self.assertEqual(existing.read_bytes(), b"winner")

    def test_staging_name_collision_never_removes_the_other_file(self) -> None:
        staging, destination = self._publication_directories()
        fixed = durable_file.uuid.UUID(int=7)
        foreign = staging / f"{durable_file.FILE_STAGING_PREFIX}{fixed.hex}"
        foreign.write_bytes(b"not ours")
        foreign.chmod(0o600)
        with patch.object(
            durable_file.uuid, "uuid4", return_value=fixed
        ), self.assertRaisesRegex(PublicationError, "private pending file already exists"):
            self._publish(staging, destination, "event-000.json", b"ours")
        self.assertEqual(foreign.read_bytes(), b"not ours")
        self.assertFalse((destination / "event-000.json").exists())

    def test_staging_that_vanishes_before_rename_is_a_typed_error(self) -> None:
        staging, destination = self._publication_directories()
        inspect = durable_file._inspect_private_pending_at

        def inspect_then_vanish(directory_descriptor: int, name: str, path: Path, **values):
            opened = inspect(directory_descriptor, name, path, **values)
            if values["maximum"] is None:
                # Only the promotion's inspection, after the verified write.
                os.unlink(name, dir_fd=directory_descriptor)
            return opened

        with patch.object(
            durable_file, "_inspect_private_pending_at", side_effect=inspect_then_vanish
        ), self.assertRaisesRegex(
            PublicationError, "cannot inspect private pending before promotion"
        ):
            self._publish(staging, destination, "event-000.json", b"data")
        self.assertFalse((destination / "event-000.json").exists())
        self.assertEqual(self._staged_names(staging), [])

    def test_replaced_staging_file_is_never_promoted_as_synchronized(self) -> None:
        # The rename skips the file barriers only for the inode the staging
        # write synchronized; a file swapped in under that name is refused.
        staging, destination = self._publication_directories()
        write = durable_file._write_private_pending_at

        def write_then_swap(directory_descriptor, name, path, data, *, staging):
            created = write(directory_descriptor, name, path, data, staging=staging)
            os.unlink(name, dir_fd=directory_descriptor)
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_descriptor
            )
            try:
                os.write(descriptor, data)
            finally:
                os.close(descriptor)
            return created

        with patch.object(
            durable_file, "_write_private_pending_at", side_effect=write_then_swap
        ), self.assertRaisesRegex(
            PublicationError, "cannot safely clean up failed private pending write"
        ) as raised:
            self._publish(staging, destination, "event-000.json", b"data")
        self.assertRegex(
            str(raised.exception.__cause__), "private staging file changed before promotion"
        )
        self.assertFalse((destination / "event-000.json").exists())
        # The swapped-in file is not the one this write created, so it stays.
        staged = self._staged_names(staging)
        self.assertEqual(len(staged), 1)
        self.assertEqual((staging / staged[0]).read_bytes(), b"data")

    def test_interrupt_after_the_rename_keeps_the_published_file(self) -> None:
        staging, destination = self._publication_directories()

        class Interrupted(BaseException):
            pass

        with patch.object(
            durable_file, "fsync_locked_directory", side_effect=Interrupted
        ), self.assertRaises(Interrupted):
            self._publish(staging, destination, "event-000.json", b"complete")
        self.assertEqual((destination / "event-000.json").read_bytes(), b"complete")
        self.assertEqual(self._staged_names(staging), [])

    def test_failed_cleanup_after_an_interrupt_keeps_the_interrupt(self) -> None:
        class Interrupted(BaseException):
            pass

        real_write = durable_file.os.write

        def interrupt_after_half(descriptor: int, data: object) -> int:
            payload = bytes(data)
            real_write(descriptor, payload[: len(payload) // 2])
            raise Interrupted

        for case, interruption in (
            ("staging write", patch.object(durable_file.os, "write", side_effect=interrupt_after_half)),
            ("rename", patch.object(durable_file, "_renameatx_np", side_effect=Interrupted)),
        ):
            with self.subTest(case=case):
                staging, destination = self._publication_directories()
                with interruption, patch.object(
                    durable_file,
                    "_remove_created_pending",
                    side_effect=PublicationError("injected staging cleanup failure"),
                ), self.assertRaises(Interrupted) as raised:
                    self._publish(staging, destination, "event-000.json", b"interrupted")
                self.assertIn(
                    "private staging cleanup failed: injected staging cleanup failure",
                    getattr(raised.exception, "__notes__", []),
                )
                self.assertEqual(len(self._staged_names(staging)), 1)
                self.assertFalse((destination / "event-000.json").exists())
                for name in self._staged_names(staging):
                    (staging / name).unlink()
                destination.rmdir()
                staging.rmdir()

    def test_interrupted_pending_write_keeps_its_recovery_semantics(self) -> None:
        # Only staging writes remove their file on an interrupt; an ordinary
        # pending write is left for its owner's recovery as before.
        pending = self.root / "attempt.pending"
        real_write = durable_file.os.write

        class Interrupted(BaseException):
            pass

        def interrupt_after_half(descriptor: int, data: object) -> int:
            payload = bytes(data)
            real_write(descriptor, payload[: len(payload) // 2])
            raise Interrupted

        with patch.object(
            durable_file.os, "write", side_effect=interrupt_after_half
        ), self.assertRaises(Interrupted):
            durable_file.write_private_pending(pending, b"recovery bytes")
        self.assertEqual(pending.read_bytes(), b"recovery bytes"[:7])

    def test_rooted_lock_with_parent_yields_the_verified_unlocked_parent(self) -> None:
        trusted = self.root / "trusted"
        ancestor = trusted / "ancestor"
        target = ancestor / "target"
        target.mkdir(parents=True, mode=0o700)
        ancestor.chmod(0o700)
        with durable_file.exclusive_rooted_directory_lock_with_parent(
            trusted, target, require_private=True
        ) as (parent_descriptor, descriptor):
            self.assertEqual(os.fstat(parent_descriptor).st_ino, ancestor.stat().st_ino)
            self.assertEqual(os.fstat(descriptor).st_ino, target.stat().st_ino)
            with self.assertRaisesRegex(PublicationError, "already held"):
                with durable_file.exclusive_rooted_directory_lock(trusted, target):
                    self.fail("the locked directory was locked twice")
            with durable_file.exclusive_rooted_directory_lock(trusted, ancestor):
                pass

        displaced = trusted / "ancestor-displaced"
        before = len(os.listdir("/dev/fd"))
        with self.assertRaises(durable_file.RootedDirectoryChanged):
            with durable_file.exclusive_rooted_directory_lock_with_parent(
                trusted, target
            ):
                ancestor.rename(displaced)
                ancestor.mkdir(mode=0o700)
                (displaced / target.name).rename(ancestor / target.name)
        self.assertEqual(len(os.listdir("/dev/fd")), before)

        ancestor.chmod(0o755)
        with self.assertRaisesRegex(PublicationError, "mode is not 0700"):
            with durable_file.exclusive_rooted_directory_lock_with_parent(
                trusted, target, require_private=True
            ):
                self.fail("a non-private parent was accepted")
        with self.assertRaisesRegex(PublicationError, "no parent below its root"):
            with durable_file.exclusive_rooted_directory_lock_with_parent(
                trusted, trusted
            ):
                self.fail("the trusted root was given a parent")
        self.assertEqual(len(os.listdir("/dev/fd")), before)


if __name__ == "__main__":
    unittest.main()
