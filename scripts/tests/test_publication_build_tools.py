from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from scripts.publication.build_tool_preparation import build_tool_specs
from scripts.publication.graph_model import ComponentSeed
from scripts.publication.license_resolution import resolve_license
from scripts.publication.source_preparation import source_input_evidence


MIT_TEXT = """MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
"""


class PublicationBuildToolTests(unittest.TestCase):
    def test_external_build_tool_keeps_hashes_but_not_corresponding_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            root = repository / "tool"
            root.mkdir()
            metadata = root / "package.json"
            metadata.write_text(
                '{"name":"fixture-tool","version":"1.0.0","license":"MIT"}',
                encoding="utf-8",
            )
            (root / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
            executable = root / "fixture-tool"
            executable.write_bytes(b"build-tool-binary")
            hardlink = root / "fixture-tool-hardlink"
            os.link(executable, hardlink)
            seed = ComponentSeed(
                identifier="npm:fixture-tool:0000000000000000",
                name="fixture-tool",
                version="1.0.0",
                ecosystem="npm",
                scope="build",
                purl="pkg:npm/fixture-tool@1.0.0",
                source_root=None,
                license_root=root,
                metadata_path=metadata,
                declared_license="MIT",
                external_build_tool=True,
                provenance_paths=(hardlink,),
            )
            review = {
                "source_evidence": source_input_evidence(repository, seed, None),
                "license_resolution": resolve_license(seed),
            }
            specs = build_tool_specs(repository, {seed.identifier: seed}, {seed.identifier: review})
            self.assertEqual(len(specs), 1)
            self.assertEqual(specs[0]["distribution"], "external-build-tool-not-distributed")
            self.assertEqual(specs[0]["executables"][0]["size"], len(b"build-tool-binary"))
            self.assertNotIn("source_path", specs[0])


if __name__ == "__main__":
    unittest.main()
