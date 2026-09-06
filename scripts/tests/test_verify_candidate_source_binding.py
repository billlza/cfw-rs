from __future__ import annotations

import unittest
from pathlib import Path

from scripts.verify_candidate_bundle import (
    CandidateError,
    verify_native_manifest_metadata,
)


class NativeSourceBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = {
            "libboxManifestSha256": "a" * 64,
            "libboxTreeSha256": "b" * 64,
            "nativeSourceSha256": "c" * 64,
            "releaseSourceSha256": "d" * 64,
            "repositoryCommit": "e" * 40,
        }
        self.metadata = {"buildNumber": "42", **self.current}
        self.manifest = Path("CFWNativeBridge.framework.manifest.json")

    def test_exact_current_source_and_libbox_identity_is_accepted(self) -> None:
        verify_native_manifest_metadata(
            self.metadata, self.manifest, "42", self.current
        )

    def test_stale_native_source_digest_is_rejected(self) -> None:
        stale = {**self.metadata, "nativeSourceSha256": "d" * 64}
        with self.assertRaisesRegex(CandidateError, "nativeSourceSha256"):
            verify_native_manifest_metadata(stale, self.manifest, "42", self.current)

    def test_stale_libbox_manifest_or_tree_is_rejected(self) -> None:
        for key in ("libboxManifestSha256", "libboxTreeSha256"):
            with self.subTest(key=key):
                stale = {**self.metadata, key: "d" * 64}
                with self.assertRaisesRegex(CandidateError, key):
                    verify_native_manifest_metadata(
                        stale, self.manifest, "42", self.current
                    )

    def test_stale_release_source_or_repository_commit_is_rejected(self) -> None:
        for key, value in (
            ("releaseSourceSha256", "f" * 64),
            ("repositoryCommit", "f" * 40),
        ):
            with self.subTest(key=key):
                stale = {**self.metadata, key: value}
                with self.assertRaisesRegex(CandidateError, key):
                    verify_native_manifest_metadata(
                        stale, self.manifest, "42", self.current
                    )


if __name__ == "__main__":
    unittest.main()
