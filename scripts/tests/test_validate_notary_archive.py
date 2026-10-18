from __future__ import annotations

import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

from scripts.validate_notary_archive import (
    NotaryArchiveError,
    validate_notarization_zip,
)


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.app = self.root / "Clash for Mac.app"
        self.executable = self.app / "Contents/MacOS/clash-for-mac"
        self.executable.parent.mkdir(parents=True)
        self.executable.write_bytes(b"signed executable")
        self.executable.chmod(0o755)
        info = self.app / "Contents/Info.plist"
        info.write_bytes(b"plist")
        info.chmod(0o644)
        resources = self.app / "Contents/Resources"
        resources.mkdir()
        (resources / "payload.dat").write_bytes(b"payload")
        (resources / "alpha.bin").write_bytes(b"alpha")
        (resources / "bravo.bin").write_bytes(b"bravo")
        os.symlink("MacOS", self.app / "Contents/current")
        self.archive = self.root / "notary.zip"
        self.write_archive()

    def close(self) -> None:
        self.temporary.cleanup()

    def _entries(self) -> list[Path]:
        entries: list[Path] = []

        def visit(path: Path) -> None:
            entries.append(path)
            if path.is_dir() and not path.is_symlink():
                for child in sorted(path.iterdir(), key=lambda value: value.name):
                    visit(child)

        visit(self.app)
        return entries

    def write_archive(self, *, extra_name: str | None = None) -> None:
        with zipfile.ZipFile(
            self.archive,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            for path in self._entries():
                metadata = os.lstat(path)
                relative = path.relative_to(self.app.parent).as_posix()
                if stat.S_ISDIR(metadata.st_mode):
                    relative += "/"
                    body = b""
                    compression = zipfile.ZIP_STORED
                elif stat.S_ISLNK(metadata.st_mode):
                    body = os.readlink(path).encode("utf-8")
                    compression = zipfile.ZIP_DEFLATED
                else:
                    body = path.read_bytes()
                    compression = zipfile.ZIP_DEFLATED
                entry = zipfile.ZipInfo(relative)
                mtime = int(metadata.st_mtime)
                entry.date_time = time.localtime(mtime + mtime % 2)[:6]
                entry.create_system = 3
                entry.external_attr = metadata.st_mode << 16
                entry.compress_type = compression
                archive.writestr(entry, body)
            if extra_name is not None:
                entry = zipfile.ZipInfo(extra_name)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, b"unexpected")


class NotaryArchiveContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_accepts_exact_app_tree_with_internal_symlink(self) -> None:
        result = validate_notarization_zip(
            self.fixture.archive,
            self.fixture.app,
        )
        self.assertEqual(result.entry_count, len(self.fixture._entries()))
        self.assertGreater(result.expanded_bytes, 0)
        self.assertEqual(result.archive_bytes, self.fixture.archive.stat().st_size)

    def test_accepts_real_ditto_odd_second_and_minute_rollover_timestamps(self) -> None:
        for second in (27, 59):
            with self.subTest(second=second), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                app = root / "Clash for Mac.app"
                executable = app / "Contents/MacOS/clash-for-mac"
                executable.parent.mkdir(parents=True)
                executable.write_bytes(b"signed")
                executable.chmod(0o755)
                (app / "Contents/Info.plist").write_bytes(b"plist")
                timestamp = int(time.mktime((2026, 1, 1, 0, 0, second, 0, 0, -1)))
                os.utime(executable, (timestamp, timestamp))
                archive = root / "notary.zip"
                completed = subprocess.run(
                    [
                        "/usr/bin/ditto",
                        "-c",
                        "-k",
                        "--keepParent",
                        "--norsrc",
                        "--noextattr",
                        "--noqtn",
                        "--noacl",
                        app.name,
                        archive.name,
                    ],
                    cwd=app.parent,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, "")
                validate_notarization_zip(archive, app)

    def test_rejects_apple_metadata_and_noncanonical_paths(self) -> None:
        for name in (
            "__MACOSX/._Clash for Mac.app",
            "Clash for Mac.app/Contents/._payload",
            "Clash for Mac.app/.DS_Store",
            "../Clash for Mac.app/escape",
            "/Clash for Mac.app/absolute",
            "Clash for Mac.app//double",
            "Other.app/payload",
        ):
            with self.subTest(name=name):
                self.fixture.write_archive(extra_name=name)
                with self.assertRaises(NotaryArchiveError):
                    validate_notarization_zip(
                        self.fixture.archive,
                        self.fixture.app,
                    )

    def test_rejects_duplicate_canonical_path(self) -> None:
        data = bytearray(self.fixture.archive.read_bytes())
        central = data.index(b"PK\x01\x02")
        while central >= 0:
            name_size, extra_size, comment_size = struct.unpack_from(
                "<3H", data, central + 28
            )
            name_start = central + 46
            name_end = name_start + name_size
            if data[name_start:name_end].endswith(b"bravo.bin"):
                data[name_start:name_end] = data[name_start:name_end].replace(
                    b"bravo.bin", b"alpha.bin"
                )
                break
            central = data.find(
                b"PK\x01\x02",
                name_end + extra_size + comment_size,
            )
        else:
            self.fail("fixture central-directory entry was not found")
        self.fixture.archive.write_bytes(data)
        with self.assertRaisesRegex(NotaryArchiveError, "duplicate canonical path"):
            validate_notarization_zip(self.fixture.archive, self.fixture.app)

    def test_rejects_source_content_mode_and_symlink_drift(self) -> None:
        for mutation in ("content", "mode", "special-mode", "symlink"):
            with self.subTest(mutation=mutation):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                if mutation == "content":
                    fixture.executable.write_bytes(b"different content")
                elif mutation == "mode":
                    fixture.executable.chmod(0o744)
                elif mutation == "special-mode":
                    fixture.executable.chmod(0o4755)
                else:
                    (fixture.app / "Contents/current").unlink()
                    os.symlink("../../outside", fixture.app / "Contents/current")
                with self.assertRaises(NotaryArchiveError):
                    validate_notarization_zip(fixture.archive, fixture.app)

    def test_rejects_forbidden_entry_type_and_encrypted_flag(self) -> None:
        with zipfile.ZipFile(self.fixture.archive, "a") as archive:
            entry = zipfile.ZipInfo("Clash for Mac.app/Contents/fifo")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFIFO | 0o600) << 16
            archive.writestr(entry, b"")
        with self.assertRaisesRegex(NotaryArchiveError, "forbidden entry type"):
            validate_notarization_zip(self.fixture.archive, self.fixture.app)

        self.fixture.write_archive()
        data = bytearray(self.fixture.archive.read_bytes())
        local_flags = struct.unpack_from("<H", data, 6)[0]
        struct.pack_into("<H", data, 6, local_flags | 1)
        central = data.index(b"PK\x01\x02")
        central_flags = struct.unpack_from("<H", data, central + 8)[0]
        struct.pack_into("<H", data, central + 8, central_flags | 1)
        self.fixture.archive.write_bytes(data)
        with self.assertRaisesRegex(NotaryArchiveError, "encrypted flags"):
            validate_notarization_zip(self.fixture.archive, self.fixture.app)

        self.fixture.write_archive()
        data = bytearray(self.fixture.archive.read_bytes())
        central = data.index(b"PK\x01\x02")
        external = struct.unpack_from("<L", data, central + 38)[0]
        encoded_mode = external >> 16
        struct.pack_into(
            "<L",
            data,
            central + 38,
            ((encoded_mode | stat.S_ISVTX) << 16) | (external & 0xFFFF),
        )
        self.fixture.archive.write_bytes(data)
        with self.assertRaisesRegex(NotaryArchiveError, "permissions are unsafe"):
            validate_notarization_zip(self.fixture.archive, self.fixture.app)

    def test_rejects_multidisk_prefix_and_local_header_drift(self) -> None:
        for mutation in ("multidisk", "prefix", "local"):
            with self.subTest(mutation=mutation):
                self.fixture.write_archive()
                data = bytearray(self.fixture.archive.read_bytes())
                if mutation == "multidisk":
                    eocd = data.rindex(b"PK\x05\x06")
                    struct.pack_into("<H", data, eocd + 4, 1)
                elif mutation == "prefix":
                    data[:0] = b"hidden-prefix"
                else:
                    method = struct.unpack_from("<H", data, 8)[0]
                    struct.pack_into("<H", data, 8, method ^ 1)
                self.fixture.archive.write_bytes(data)
                with self.assertRaises(NotaryArchiveError):
                    validate_notarization_zip(
                        self.fixture.archive,
                        self.fixture.app,
                    )

    def test_rejects_hidden_bytes_after_a_valid_deflate_stream(self) -> None:
        with zipfile.ZipFile(self.fixture.archive, "r") as archive:
            target = max(
                (
                    info
                    for info in archive.infolist()
                    if info.compress_type == zipfile.ZIP_DEFLATED
                ),
                key=lambda info: info.header_offset,
            )
            expected_body = archive.read(target)

        data = bytearray(self.fixture.archive.read_bytes())
        name_size, extra_size = struct.unpack_from(
            "<2H", data, target.header_offset + 26
        )
        payload_start = target.header_offset + 30 + name_size + extra_size
        insertion = payload_start + target.compress_size
        hidden = b"SECRET-HIDDEN-BYTES"
        data[insertion:insertion] = hidden
        struct.pack_into(
            "<L",
            data,
            target.header_offset + 18,
            target.compress_size + len(hidden),
        )

        old_eocd = data.rindex(b"PK\x05\x06")
        old_central_offset = struct.unpack_from("<L", data, old_eocd + 16)[0]
        central = old_central_offset + len(hidden)
        while central < old_eocd:
            self.assertEqual(data[central : central + 4], b"PK\x01\x02")
            central_name_size, central_extra_size, central_comment_size = (
                struct.unpack_from("<3H", data, central + 28)
            )
            central_name_start = central + 46
            central_name_end = central_name_start + central_name_size
            if data[central_name_start:central_name_end] == target.filename.encode(
                "utf-8"
            ):
                struct.pack_into(
                    "<L",
                    data,
                    central + 20,
                    target.compress_size + len(hidden),
                )
                break
            central = (
                central_name_end + central_extra_size + central_comment_size
            )
        else:
            self.fail("target central-directory entry was not found")
        struct.pack_into(
            "<L",
            data,
            old_eocd + 16,
            old_central_offset + len(hidden),
        )
        self.fixture.archive.write_bytes(data)

        with zipfile.ZipFile(self.fixture.archive, "r") as archive:
            self.assertEqual(archive.read(target.filename), expected_body)
        with self.assertRaisesRegex(NotaryArchiveError, "bytes after"):
            validate_notarization_zip(self.fixture.archive, self.fixture.app)

    def test_rejects_central_record_declared_beyond_its_boundary(self) -> None:
        data = bytearray(self.fixture.archive.read_bytes())
        eocd = data.rindex(b"PK\x05\x06")
        central_size, central_offset = struct.unpack_from("<2L", data, eocd + 12)
        cursor = central_offset
        last = -1
        while cursor < central_offset + central_size:
            self.assertEqual(data[cursor : cursor + 4], b"PK\x01\x02")
            name_size, extra_size, comment_size = struct.unpack_from(
                "<3H", data, cursor + 28
            )
            last = cursor
            cursor += 46 + name_size + extra_size + comment_size
        self.assertEqual(cursor, central_offset + central_size)
        self.assertGreaterEqual(last, 0)
        struct.pack_into("<H", data, last + 32, 64)
        self.fixture.archive.write_bytes(data)
        with self.assertRaisesRegex(NotaryArchiveError, "exceeds its boundary"):
            validate_notarization_zip(self.fixture.archive, self.fixture.app)

    def test_enforces_archive_entry_single_file_and_expanded_limits(self) -> None:
        cases = (
            ("MAX_ARCHIVE_BYTES", self.fixture.archive.stat().st_size - 1),
            ("MAX_ENTRY_COUNT", 2),
            ("MAX_SINGLE_FILE_BYTES", 4),
            ("MAX_EXPANDED_BYTES", 8),
        )
        for constant, limit in cases:
            with self.subTest(constant=constant):
                with patch(f"scripts.validate_notary_archive.{constant}", limit):
                    with self.assertRaises(NotaryArchiveError):
                        validate_notarization_zip(
                            self.fixture.archive,
                            self.fixture.app,
                        )


if __name__ == "__main__":
    unittest.main()
