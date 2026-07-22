from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.publication.artifact_preparation import _reject_absolute_graph_paths
from scripts.publication.closure import ALLOWED_CODE_PATHS, scan_app_code
from scripts.publication.common import PublicationError


class PublicationClosureTests(unittest.TestCase):
    def make_app_code(self, app: Path) -> None:
        for relative in ALLOWED_CODE_PATHS:
            path = app / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"MZfixture")
            path.chmod(0o755)

    def test_unknown_executable_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Clash for Mac.app"
            self.make_app_code(app)
            unknown = app / "Contents/MacOS/unmanifested"
            unknown.write_bytes(b"MZunknown")
            unknown.chmod(0o755)
            with self.assertRaises(PublicationError):
                scan_app_code(app, fixture=False)

    def test_exact_code_closure_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Clash for Mac.app"
            self.make_app_code(app)
            scan_app_code(app, fixture=False)

    def test_reference_reverse_tree_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Clash for Mac.app"
            self.make_app_code(app)
            payload = app / "Contents/Resources/reverse/reference.bin"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"reference")
            with self.assertRaises(PublicationError):
                scan_app_code(app, fixture=False)

    def test_absolute_build_graph_path_fails_closed(self) -> None:
        with self.assertRaisesRegex(PublicationError, "absolute path"):
            _reject_absolute_graph_paths({"targets": [{"path": "/Users/example/project"}]})

    def test_relative_build_graph_paths_are_accepted(self) -> None:
        _reject_absolute_graph_paths(
            {"targets": [{"path": "Sources/CFWNative"}], "repository": "pkg:swift/cfwnative"}
        )


if __name__ == "__main__":
    unittest.main()
