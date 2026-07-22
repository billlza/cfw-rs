from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.publication.common import PublicationError
from scripts.publication.native_collector import _normalize_native_graph


class NativeCollectorTests(unittest.TestCase):
    def test_project_root_is_normalized_and_relative_paths_remain_relative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "Sources/CFWNative"
            source.mkdir(parents=True)
            graph = {
                "path": str(root),
                "targets": [{"name": "CFWNative", "path": "Sources/CFWNative"}],
            }
            self.assertEqual(
                _normalize_native_graph(graph, root),
                {
                    "path": ".",
                    "targets": [{"name": "CFWNative", "path": "Sources/CFWNative"}],
                },
            )

    def test_absolute_path_outside_project_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaisesRegex(PublicationError, "escaped"):
                _normalize_native_graph({"path": "/private/tmp/other"}, root)

    def test_non_path_absolute_string_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaisesRegex(PublicationError, "absolute path"):
                _normalize_native_graph({"command": "/usr/bin/swift"}, root)


if __name__ == "__main__":
    unittest.main()
