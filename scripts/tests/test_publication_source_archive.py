from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
from typing import Any
import unittest
from unittest.mock import patch

from scripts.publication.common import PublicationError, tree_digest
from scripts.publication import source_archive


def empty_manifest() -> dict[str, object]:
    entries: list[dict[str, object]] = []
    return {
        "algorithm": "sha256-tree-v1",
        "entries": entries,
        "root": "corresponding-source",
        "schema_version": 1,
        "sha256": tree_digest(entries),
        "total_file_bytes": 0,
    }


class PublicationSourceArchiveTests(unittest.TestCase):
    def assert_rejected_before_hash_or_tar(self, archive: Path) -> None:
        with patch.object(
            source_archive,
            "_sha256_opened_archive",
            side_effect=AssertionError("archive hashing must not start"),
        ), patch.object(
            source_archive.tarfile,
            "open",
            side_effect=AssertionError("tar parsing must not start"),
        ):
            with self.assertRaises(PublicationError):
                source_archive.verify_source_archive(
                    archive, empty_manifest(), "0" * 64
                )

    def test_oversized_sparse_archive_is_rejected_before_hash_or_tar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "corresponding-source.tar.gz"
            with archive.open("wb") as stream:
                stream.truncate(source_archive.MAX_SOURCE_ARCHIVE_BYTES + 1)
            self.assert_rejected_before_hash_or_tar(archive)

    def test_manifest_schema_version_requires_a_json_integer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "corresponding-source.tar.gz"
            archive.write_bytes(b"archive")
            for invalid in (1.0, True):
                with self.subTest(invalid=invalid):
                    manifest = empty_manifest()
                    manifest["schema_version"] = invalid
                    with self.assertRaisesRegex(PublicationError, "unsupported"):
                        source_archive.verify_source_archive(
                            archive, manifest, hashlib.sha256(b"archive").hexdigest()
                        )

    def test_oversized_dense_regular_archive_is_rejected_before_hash_or_tar(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "corresponding-source.tar.gz"
            archive.write_bytes(b"x" * 17)
            with patch.object(source_archive, "MAX_SOURCE_ARCHIVE_BYTES", 16):
                self.assert_rejected_before_hash_or_tar(archive)

    def test_linked_archives_are_rejected_before_hash_or_tar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular.tar.gz"
            regular.write_bytes(b"archive")
            hardlink = root / "hardlink.tar.gz"
            os.link(regular, hardlink)
            self.assert_rejected_before_hash_or_tar(hardlink)

            symlink_target = root / "symlink-target.tar.gz"
            symlink_target.write_bytes(b"archive")
            symlink = root / "symlink.tar.gz"
            symlink.symlink_to(symlink_target)
            self.assert_rejected_before_hash_or_tar(symlink)

    def test_valid_archive_is_hashed_and_parsed_from_the_admitted_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "README.md").write_text("source fixture\n", encoding="utf-8")
            manifest = source_archive.build_source_manifest(source)
            archive = root / "corresponding-source.tar.gz"
            source_archive.write_source_archive(source, archive)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()

            stream_identities: dict[str, int] = {}
            real_hash = source_archive._sha256_opened_archive
            real_tar_open = source_archive.tarfile.open

            def hash_opened(stream: Any, opened: os.stat_result) -> str:
                stream_identities["hash"] = id(stream)
                return real_hash(stream, opened)

            def open_tar(*args: Any, **kwargs: Any) -> Any:
                stream_identities["tar"] = id(kwargs["fileobj"])
                return real_tar_open(*args, **kwargs)

            with patch.object(
                source_archive,
                "_sha256_opened_archive",
                side_effect=hash_opened,
            ), patch.object(
                source_archive.tarfile,
                "open",
                side_effect=open_tar,
            ):
                source_archive.verify_source_archive(archive, manifest, digest)

            self.assertEqual(stream_identities["hash"], stream_identities["tar"])


if __name__ == "__main__":
    unittest.main()
