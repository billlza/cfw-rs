from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.publication import verify
from scripts.publication.common import PublicationError
from scripts.publication.release_contract import native_products_root


class PublicationArtifactVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        self.root = self.repository / "publication"
        self.root.mkdir()
        self.app = self.repository / "Clash for Mac.app"
        self.source = self.repository / "current.json"
        self.source.write_bytes(b'{"verified":true}\n')
        (self.root / "record.json").write_bytes(self.source.read_bytes())
        self.artifacts = [{"kind": "fixture-manifest", "path": "record.json"}]

    def invoke(self) -> None:
        verify._verify_artifact_inputs(
            self.repository, self.root, self.artifacts, self.app, "40044"
        )

    def test_artifact_reader_receives_explicit_closed_git_environment(self) -> None:
        # autospec exercises the real production reader's required argument
        # contract, including arguments which an unconstrained mock would hide.
        with patch.object(
            verify,
            "_artifact_sources",
            autospec=True,
            return_value={"fixture-manifest": self.source},
        ) as reader:
            self.invoke()
        reader.assert_called_once_with(
            self.repository,
            native_products_root(self.repository, "40044"),
            self.app,
            "40044",
            None,
            freeze_verifier=None,
        )

    def test_changed_artifact_is_rejected(self) -> None:
        self.source.write_bytes(b'{"verified":false}\n')
        with patch.object(
            verify,
            "_artifact_sources",
            autospec=True,
            return_value={"fixture-manifest": self.source},
        ), self.assertRaisesRegex(PublicationError, "differs from publication evidence"):
            self.invoke()

    def test_missing_artifact_is_rejected(self) -> None:
        self.artifacts = []
        with patch.object(
            verify,
            "_artifact_sources",
            autospec=True,
            return_value={"fixture-manifest": self.source},
        ), self.assertRaisesRegex(PublicationError, "manifest set is incomplete"):
            self.invoke()


if __name__ == "__main__":
    unittest.main()
