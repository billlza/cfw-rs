from __future__ import annotations

import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import dormant_app_install
from scripts import macos_durability
from scripts import notarization_transaction
from scripts.publication import durable_file
from scripts.publication.common import PublicationError


class MacOSDurabilityTests(unittest.TestCase):
    def test_full_fsync_accepts_file_and_directory_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file_descriptor = os.open(
                root / "payload",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            directory_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.write(file_descriptor, b"payload")
                macos_durability.full_fsync(file_descriptor)
                macos_durability.full_fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
                os.close(file_descriptor)

    def test_invalid_descriptor_fails_closed(self) -> None:
        for descriptor in (-1, True, "1"):
            with self.subTest(descriptor=descriptor), self.assertRaises(OSError) as raised:
                macos_durability.full_fsync(descriptor)
            self.assertEqual(raised.exception.errno, errno.EINVAL)

    def test_missing_operation_fails_closed(self) -> None:
        with patch.object(macos_durability.fcntl, "F_FULLFSYNC", None):
            with self.assertRaises(OSError) as raised:
                macos_durability.full_fsync(0)
        self.assertEqual(raised.exception.errno, errno.ENOTSUP)

    def test_kernel_error_and_nonzero_result_fail_closed(self) -> None:
        with patch.object(
            macos_durability.fcntl,
            "fcntl",
            side_effect=OSError(errno.EIO, "injected full-fsync failure"),
        ):
            with self.assertRaises(OSError) as raised:
                macos_durability.full_fsync(0)
        self.assertEqual(raised.exception.errno, errno.EIO)

        with patch.object(macos_durability.fcntl, "fcntl", return_value=1):
            with self.assertRaises(OSError) as raised:
                macos_durability.full_fsync(0)
        self.assertEqual(raised.exception.errno, errno.EIO)

    def test_release_directory_boundaries_use_the_shared_full_barrier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observations: list[str] = []

            def observe(descriptor: int) -> None:
                self.assertTrue(os.path.isdir(f"/dev/fd/{descriptor}"))
                observations.append("directory")

            with patch.object(notarization_transaction, "full_fsync", side_effect=observe):
                notarization_transaction._fsync_directory(root)
            with patch.object(dormant_app_install, "full_fsync", side_effect=observe):
                dormant_app_install.fsync_tree(root)
            with patch.object(durable_file, "full_fsync", side_effect=observe):
                durable_file.fsync_directory(root)

        self.assertEqual(observations, ["directory", "directory", "directory"])

    def test_tree_sync_uses_one_final_full_barrier_per_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "nested/leaf").mkdir(parents=True)

            notary_barriers: list[int] = []
            with patch.object(
                notarization_transaction,
                "full_fsync",
                side_effect=lambda descriptor: notary_barriers.append(descriptor),
            ):
                notarization_transaction._fsync_tree(root)
            self.assertEqual(len(notary_barriers), 1)

            install_barriers: list[int] = []
            with patch.object(
                dormant_app_install,
                "full_fsync",
                side_effect=lambda descriptor: install_barriers.append(descriptor),
            ):
                dormant_app_install.fsync_tree(root)
            self.assertEqual(len(install_barriers), 1)

    def test_release_directory_barrier_failures_keep_typed_context(self) -> None:
        failure = OSError(errno.EIO, "injected stable-storage failure")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                notarization_transaction,
                "full_fsync",
                side_effect=failure,
            ), self.assertRaisesRegex(OSError, "injected stable-storage failure"):
                notarization_transaction._fsync_directory(root)

            with patch.object(
                dormant_app_install,
                "full_fsync",
                side_effect=failure,
            ), self.assertRaisesRegex(
                dormant_app_install.InstallError,
                "stable-storage durability is unknown",
            ):
                dormant_app_install.fsync_tree(root)

            with patch.object(
                durable_file,
                "full_fsync",
                side_effect=failure,
            ), self.assertRaisesRegex(
                PublicationError,
                "stable-storage durability is unknown",
            ):
                durable_file.fsync_directory(root)


if __name__ == "__main__":
    unittest.main()
