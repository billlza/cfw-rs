import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.validate_updater_archive import ArchiveContractError, validate_archive
from scripts.validate_updater_archive import MAX_EXTENSION_ENTRY_BYTES


ROOT = "Clash for Mac.app"


def directory(name: str) -> tarfile.TarInfo:
    entry = tarfile.TarInfo(name)
    entry.type = tarfile.DIRTYPE
    entry.mode = 0o755
    return entry


def regular(name: str, data: bytes) -> tuple[tarfile.TarInfo, io.BytesIO]:
    entry = tarfile.TarInfo(name)
    entry.type = tarfile.REGTYPE
    entry.mode = 0o755 if name.endswith("clash-for-mac") else 0o644
    entry.size = len(data)
    return entry, io.BytesIO(data)


def symlink(name: str, target: str) -> tarfile.TarInfo:
    entry = tarfile.TarInfo(name)
    entry.type = tarfile.SYMTYPE
    entry.mode = 0o777
    entry.linkname = target
    return entry


class ArchiveBuilder:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "update.tar.gz"
        self.archive = tarfile.open(self.path, "w:gz")

    def add(self, entry: tarfile.TarInfo, data: io.BytesIO | None = None) -> None:
        self.archive.addfile(entry, data)

    def add_layout(self) -> None:
        for name in [f"{ROOT}/", f"{ROOT}/Contents/", f"{ROOT}/Contents/MacOS/"]:
            self.add(directory(name))
        self.add(*regular(f"{ROOT}/Contents/Info.plist", b"plist"))
        self.add(*regular(f"{ROOT}/Contents/MacOS/clash-for-mac", b"binary"))

    def close(self) -> str:
        self.archive.close()
        return str(self.path)

    def cleanup(self) -> None:
        self.temporary.cleanup()


class UpdaterArchiveContractTests(unittest.TestCase):
    def test_accepts_canonical_bounded_layout_and_internal_symlink(self) -> None:
        archive = ArchiveBuilder()
        try:
            archive.add_layout()
            archive.add(symlink(f"{ROOT}/Contents/current", "MacOS"))
            count, expanded = validate_archive(archive.close(), ROOT)
            self.assertEqual(count, 6)
            self.assertEqual(expanded, len(b"plistbinary"))
        finally:
            archive.cleanup()

    def test_rejects_duplicate_special_and_escaping_symlink(self) -> None:
        for mutate in ["duplicate", "fifo", "escape"]:
            with self.subTest(mutate=mutate):
                archive = ArchiveBuilder()
                try:
                    archive.add_layout()
                    if mutate == "duplicate":
                        archive.add(*regular(f"{ROOT}/Contents/Info.plist", b"again"))
                    elif mutate == "fifo":
                        entry = tarfile.TarInfo(f"{ROOT}/fifo")
                        entry.type = tarfile.FIFOTYPE
                        entry.mode = 0o600
                        archive.add(entry)
                    else:
                        archive.add(symlink(f"{ROOT}/escape", "../../outside"))
                    with self.assertRaises(ArchiveContractError):
                        validate_archive(archive.close(), ROOT)
                finally:
                    archive.cleanup()

    def test_rejects_symlink_ancestor_conflict_in_either_order(self) -> None:
        for symlink_first in [True, False]:
            with self.subTest(symlink_first=symlink_first):
                archive = ArchiveBuilder()
                try:
                    archive.add_layout()
                    link = symlink(f"{ROOT}/alias", "Contents")
                    child = regular(f"{ROOT}/alias/payload", b"x")
                    if symlink_first:
                        archive.add(link)
                        archive.add(*child)
                    else:
                        archive.add(*child)
                        archive.add(link)
                    with self.assertRaises(ArchiveContractError):
                        validate_archive(archive.close(), ROOT)
                finally:
                    archive.cleanup()

    def test_rejects_entry_and_expansion_limits(self) -> None:
        archive = ArchiveBuilder()
        try:
            archive.add_layout()
            path = archive.close()
            with patch("scripts.validate_updater_archive.MAX_ENTRY_COUNT", 4):
                with self.assertRaises(ArchiveContractError):
                    validate_archive(path, ROOT)
            with patch("scripts.validate_updater_archive.MAX_SINGLE_FILE_BYTES", 5):
                with self.assertRaises(ArchiveContractError):
                    validate_archive(path, ROOT)
            with patch("scripts.validate_updater_archive.MAX_EXPANDED_BYTES", 8):
                with self.assertRaises(ArchiveContractError):
                    validate_archive(path, ROOT)
        finally:
            archive.cleanup()

    def test_rejects_unusable_directory_and_main_executable_modes(self) -> None:
        for target in [f"{ROOT}/Contents/", f"{ROOT}/Contents/MacOS/clash-for-mac"]:
            with self.subTest(target=target):
                archive = ArchiveBuilder()
                try:
                    for name in [f"{ROOT}/", f"{ROOT}/Contents/", f"{ROOT}/Contents/MacOS/"]:
                        entry = directory(name)
                        if name == target:
                            entry.mode = 0o644
                        archive.add(entry)
                    archive.add(*regular(f"{ROOT}/Contents/Info.plist", b"plist"))
                    executable, body = regular(
                        f"{ROOT}/Contents/MacOS/clash-for-mac", b"binary"
                    )
                    if target.endswith("clash-for-mac"):
                        executable.mode = 0o644
                    archive.add(executable, body)
                    with self.assertRaises(ArchiveContractError):
                        validate_archive(archive.close(), ROOT)
                finally:
                    archive.cleanup()

    def test_rejects_oversized_extension_metadata_before_parsing_it(self) -> None:
        archive = ArchiveBuilder()
        try:
            metadata = b"a" * (MAX_EXTENSION_ENTRY_BYTES + 1)
            entry = tarfile.TarInfo("PaxHeader")
            entry.type = tarfile.XHDTYPE
            entry.mode = 0o644
            entry.size = len(metadata)
            archive.add(entry, io.BytesIO(metadata))
            archive.add_layout()
            with self.assertRaises(ArchiveContractError):
                validate_archive(archive.close(), ROOT)
        finally:
            archive.cleanup()


if __name__ == "__main__":
    unittest.main()
