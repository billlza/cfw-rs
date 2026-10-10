#!/usr/bin/env python3
"""Security invariants for the release artifact-tree v2 contract."""

from __future__ import annotations

from contextlib import redirect_stdout
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import scripts.hash_artifact as hash_artifact
import scripts.verify_artifact_manifest as verify_artifact_manifest


SCRIPTS = Path(__file__).resolve().parent.parent
HASH = SCRIPTS / "hash_artifact.py"
VERIFY = SCRIPTS / "verify_artifact_manifest.py"


class ArtifactManifestV2SecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "tree"
        (self.root / "bin").mkdir(parents=True)
        (self.root / "bin/tool").write_text("tool\n", encoding="utf-8")
        self.manifest = self.base / "tree.manifest.json"

    def hash(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(HASH),
                str(self.root),
                "--output",
                str(self.manifest),
                "--algorithm",
                "sha256-tree-v2",
                "--metadata",
                "kind=test",
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_internal_relative_symlink_is_accepted(self) -> None:
        (self.root / "current").symlink_to("bin/tool")
        completed = self.hash()
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_absolute_symlink_is_rejected_even_when_target_is_inside_root(self) -> None:
        (self.root / "current").symlink_to((self.root / "bin/tool").resolve())
        completed = self.hash()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("must be relative", completed.stderr)

    def test_parent_and_chained_symlink_escapes_are_rejected(self) -> None:
        outside = self.base / "outside"
        outside.write_text("outside\n", encoding="utf-8")

        for setup in (
            lambda: (self.root / "current").symlink_to("../outside"),
            lambda: (
                (self.root / "hop").symlink_to("../outside"),
                (self.root / "current").symlink_to("hop"),
            ),
        ):
            with self.subTest(setup=setup):
                setup()
                completed = self.hash()
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("within the artifact root", completed.stderr)
                for name in ("current", "hop"):
                    path = self.root / name
                    if path.is_symlink():
                        path.unlink()

    def test_dangling_symlink_is_rejected(self) -> None:
        (self.root / "current").symlink_to("missing")
        completed = self.hash()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("within the artifact root", completed.stderr)

    def test_verifier_returns_digest_from_successful_verification(self) -> None:
        self.assertEqual(self.hash().returncode, 0)
        expected = json.loads(self.manifest.read_text(encoding="utf-8"))["sha256"]
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(VERIFY),
                str(self.root),
                str(self.manifest),
                "--algorithm",
                "sha256-tree-v2",
                "--exact-metadata",
                "--metadata",
                "kind=test",
                "--print-tree-sha256",
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, f"{expected}\n")

    def test_manifest_hardlink_added_while_reading_is_rejected(self) -> None:
        self.assertEqual(self.hash().returncode, 0)
        original = os.read
        linked = False

        def racing_read(descriptor: int, size: int) -> bytes:
            nonlocal linked
            data = original(descriptor, size)
            if data and not linked:
                linked = True
                os.link(self.manifest, self.base / "manifest-hardlink")
            return data

        with patch(
            "scripts.verify_artifact_manifest.os.read",
            side_effect=racing_read,
        ):
            with self.assertRaisesRegex(SystemExit, "changed while reading"):
                verify_artifact_manifest._read_manifest(self.manifest)

    def test_manifest_changed_during_artifact_scan_is_rejected(self) -> None:
        self.assertEqual(self.hash().returncode, 0)
        original = verify_artifact_manifest.build_manifest
        changed = False

        def racing_build(*arguments: object, **keywords: object) -> dict[str, object]:
            nonlocal changed
            actual = original(*arguments, **keywords)
            if not changed:
                changed = True
                document = json.loads(self.manifest.read_text(encoding="utf-8"))
                document["metadata"]["kind"] = "tampered"
                self.manifest.write_text(
                    json.dumps(document, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            return actual

        arguments = [
            str(VERIFY),
            str(self.root),
            str(self.manifest),
            "--algorithm",
            "sha256-tree-v2",
            "--exact-metadata",
            "--metadata",
            "kind=test",
        ]
        with (
            patch(
                "scripts.verify_artifact_manifest.build_manifest",
                side_effect=racing_build,
            ),
            patch.object(sys, "argv", arguments),
            redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(SystemExit, "changed during verification"):
                verify_artifact_manifest.main()

    def test_hardlink_added_during_hashing_is_rejected(self) -> None:
        target = self.root / "bin/tool"
        original = hash_artifact._descriptor_digest
        changed = False

        def racing_digest(descriptor: int, expected_size: int, relative: str) -> str:
            nonlocal changed
            digest = original(descriptor, expected_size, relative)
            if not changed:
                changed = True
                os.link(target, self.base / "tool-hardlink")
            return digest

        with patch(
            "scripts.hash_artifact._descriptor_digest",
            side_effect=racing_digest,
        ):
            with self.assertRaisesRegex(ValueError, "changed while hashing"):
                hash_artifact.build_manifest(
                    self.root,
                    {"kind": "test"},
                    algorithm="sha256-tree-v2",
                )

    @unittest.skipIf(os.geteuid() == 0, "root can traverse mode-000 directories")
    def test_unreadable_subdirectory_is_rejected_for_every_algorithm(self) -> None:
        hidden = self.root / "hidden"
        hidden.mkdir()
        (hidden / "secret").write_text("secret\n", encoding="utf-8")
        hidden.chmod(0)
        try:
            for algorithm in hash_artifact.SUPPORTED_ALGORITHMS:
                with self.subTest(algorithm=algorithm):
                    with self.assertRaisesRegex(
                        ValueError,
                        "failed to open artifact entry hidden",
                    ):
                        hash_artifact.build_manifest(self.root, algorithm=algorithm)
        finally:
            hidden.chmod(0o700)

    @unittest.skipIf(os.geteuid() == 0, "root can traverse mode-000 directories")
    def test_unreadable_root_is_rejected_for_every_algorithm(self) -> None:
        self.root.chmod(0)
        try:
            for algorithm in hash_artifact.SUPPORTED_ALGORITHMS:
                with self.subTest(algorithm=algorithm):
                    with self.assertRaisesRegex(
                        ValueError,
                        "failed to open root artifact entry",
                    ):
                        hash_artifact.build_manifest(self.root, algorithm=algorithm)
        finally:
            self.root.chmod(0o700)

    def test_scandir_iteration_error_is_not_treated_as_end_of_tree(self) -> None:
        original = os.scandir
        first_iterator = True

        class FailingIterator:
            def __init__(self, descriptor: int) -> None:
                self.inner = original(descriptor)
                self.yielded = False

            def __enter__(self) -> FailingIterator:
                self.inner.__enter__()
                return self

            def __exit__(self, *arguments: object) -> object:
                return self.inner.__exit__(*arguments)

            def __iter__(self) -> FailingIterator:
                return self

            def __next__(self) -> os.DirEntry[str]:
                if self.yielded:
                    raise PermissionError(errno.EACCES, "injected scandir failure")
                self.yielded = True
                return next(self.inner)

        def injected_scandir(descriptor: int) -> object:
            nonlocal first_iterator
            if first_iterator:
                first_iterator = False
                return FailingIterator(descriptor)
            return original(descriptor)

        with patch("scripts.hash_artifact.os.scandir", side_effect=injected_scandir):
            with self.assertRaisesRegex(ValueError, "failed to enumerate directory"):
                hash_artifact.build_manifest(
                    self.root,
                    algorithm="sha256-tree-v2",
                )

    def test_internal_directory_symlink_is_recorded_without_traversing_alias(self) -> None:
        actual = self.root / "actual"
        actual.mkdir()
        (actual / "secret").write_text("secret\n", encoding="utf-8")
        (self.root / "alias").symlink_to("actual", target_is_directory=True)

        manifest = hash_artifact.build_manifest(
            self.root,
            algorithm="sha256-tree-v2",
        )
        entries = {str(entry["path"]): entry for entry in manifest["entries"]}
        self.assertEqual(entries["alias"]["type"], "symlink")
        self.assertIn("actual/secret", entries)
        self.assertNotIn("alias/secret", entries)

    def test_external_directory_symlink_is_rejected(self) -> None:
        outside = self.base / "outside-directory"
        outside.mkdir()
        (outside / "secret").write_text("outside\n", encoding="utf-8")
        (self.root / "alias").symlink_to(
            "../outside-directory",
            target_is_directory=True,
        )

        with self.assertRaisesRegex(ValueError, "within the artifact root"):
            hash_artifact.build_manifest(
                self.root,
                algorithm="sha256-tree-v2",
            )

    def test_symlink_directory_suffix_cannot_coerce_a_file_target(self) -> None:
        for target in ("bin/tool/", "bin/tool/."):
            with self.subTest(target=target):
                link = self.root / "current"
                link.symlink_to(target)
                try:
                    with self.assertRaisesRegex(ValueError, "within the artifact root"):
                        hash_artifact.build_manifest(
                            self.root,
                            algorithm="sha256-tree-v2",
                        )
                finally:
                    link.unlink()

    def test_symlink_directory_suffix_accepts_a_directory_target(self) -> None:
        (self.root / "current").symlink_to("bin/", target_is_directory=True)
        manifest = hash_artifact.build_manifest(
            self.root,
            algorithm="sha256-tree-v2",
        )
        current = next(
            entry for entry in manifest["entries"] if entry["path"] == "current"
        )
        self.assertEqual(current["target"], "bin/")

    def test_legal_path_may_revisit_a_symlink_after_parent_resolution(self) -> None:
        (self.root / "s").symlink_to("bin", target_is_directory=True)
        (self.root / "t").symlink_to("s/../s/tool")
        manifest = hash_artifact.build_manifest(
            self.root,
            algorithm="sha256-tree-v2",
        )
        paths = {entry["path"] for entry in manifest["entries"]}
        self.assertIn("s", paths)
        self.assertIn("t", paths)

    def test_path_substitution_cannot_change_open_file_digest(self) -> None:
        target = self.root / "bin/tool"
        parked = self.base / "parked-tool"
        replacement = self.base / "replacement-tool"
        replacement.write_bytes(b"evil\n")
        original = hash_artifact._descriptor_digest
        substituted = False

        def substituting_digest(
            descriptor: int,
            expected_size: int,
            relative: str,
        ) -> str:
            nonlocal substituted
            if not substituted:
                substituted = True
                target.rename(parked)
                replacement.rename(target)
                try:
                    return original(descriptor, expected_size, relative)
                finally:
                    target.rename(replacement)
                    parked.rename(target)
            return original(descriptor, expected_size, relative)

        with patch(
            "scripts.hash_artifact._descriptor_digest",
            side_effect=substituting_digest,
        ):
            with self.assertRaisesRegex(ValueError, "changed while hashing"):
                hash_artifact.build_manifest(
                    self.root,
                    algorithm="sha256-tree-v2",
                )

    def test_file_rebound_after_hashing_is_rejected(self) -> None:
        target = self.root / "bin/tool"
        parked = self.base / "parked-tool"
        original = hash_artifact._descriptor_digest
        replaced = False

        def replacing_digest(
            descriptor: int,
            expected_size: int,
            relative: str,
        ) -> str:
            nonlocal replaced
            digest = original(descriptor, expected_size, relative)
            if not replaced:
                replaced = True
                target.rename(parked)
                target.write_text("replacement\n", encoding="utf-8")
            return digest

        with patch(
            "scripts.hash_artifact._descriptor_digest",
            side_effect=replacing_digest,
        ):
            with self.assertRaisesRegex(ValueError, "changed while hashing"):
                hash_artifact.build_manifest(
                    self.root,
                    algorithm="sha256-tree-v2",
                )

    def test_file_changed_while_later_sibling_is_hashed_is_rejected(self) -> None:
        (self.root / "second").write_bytes(b"second")
        original = hash_artifact._descriptor_digest
        paths_by_digest = {
            hashlib.sha256(path.read_bytes()).hexdigest(): path
            for path in (self.root / "bin/tool", self.root / "second")
        }
        previously_hashed: Path | None = None
        changed = False

        def racing_digest(descriptor: int, expected_size: int, relative: str) -> str:
            nonlocal previously_hashed, changed
            digest = original(descriptor, expected_size, relative)
            if previously_hashed is not None and not changed:
                data = previously_hashed.read_bytes()
                replacement = bytes([data[0] ^ 1]) + data[1:]
                previously_hashed.write_bytes(replacement)
                changed = True
            previously_hashed = paths_by_digest[digest]
            return digest

        with patch(
            "scripts.hash_artifact._descriptor_digest",
            side_effect=racing_digest,
        ):
            with self.assertRaisesRegex(ValueError, "final verification"):
                hash_artifact.build_manifest(
                    self.root,
                    algorithm="sha256-tree-v2",
                )

    def test_hardlink_added_while_later_sibling_is_hashed_is_rejected(self) -> None:
        (self.root / "second").write_bytes(b"second")
        original = hash_artifact._descriptor_digest
        paths_by_digest = {
            hashlib.sha256(path.read_bytes()).hexdigest(): path
            for path in (self.root / "bin/tool", self.root / "second")
        }
        previously_hashed: Path | None = None
        changed = False

        def racing_digest(descriptor: int, expected_size: int, relative: str) -> str:
            nonlocal previously_hashed, changed
            digest = original(descriptor, expected_size, relative)
            if previously_hashed is not None and not changed:
                os.link(previously_hashed, self.base / "external-hardlink")
                changed = True
            previously_hashed = paths_by_digest[digest]
            return digest

        with patch(
            "scripts.hash_artifact._descriptor_digest",
            side_effect=racing_digest,
        ):
            with self.assertRaisesRegex(ValueError, "final verification"):
                hash_artifact.build_manifest(
                    self.root,
                    algorithm="sha256-tree-v2",
                )

    def test_entries_use_global_posix_sort_order(self) -> None:
        (self.root / "a").mkdir()
        (self.root / "a/z").write_text("z\n", encoding="utf-8")
        (self.root / "a-").write_text("dash\n", encoding="utf-8")

        first = hash_artifact.build_manifest(
            self.root,
            algorithm="sha256-tree-v2",
        )
        second = hash_artifact.build_manifest(
            self.root,
            algorithm="sha256-tree-v2",
        )
        paths = [entry["path"] for entry in first["entries"]]
        self.assertLess(paths.index("a"), paths.index("a-"))
        self.assertLess(paths.index("a-"), paths.index("a/z"))
        self.assertEqual(first["sha256"], second["sha256"])

    def test_entry_limit_fails_on_first_excess_entry(self) -> None:
        with patch.object(hash_artifact, "MAX_ARTIFACT_ENTRIES", 1):
            with self.assertRaisesRegex(ValueError, "more than 1 entries"):
                hash_artifact.build_manifest(
                    self.root,
                    algorithm="sha256-tree-v2",
                )

    def test_descriptor_hash_never_reads_beyond_the_captured_size(self) -> None:
        requested: list[int] = []

        def endless_read(_descriptor: int, count: int) -> bytes:
            requested.append(count)
            return b"x" * count

        with patch("scripts.hash_artifact.os.read", side_effect=endless_read):
            with self.assertRaisesRegex(ValueError, "changed while hashing"):
                hash_artifact._descriptor_digest(123, 7, "growing-file")
        self.assertEqual(requested, [7, 1])


if __name__ == "__main__":
    unittest.main()
